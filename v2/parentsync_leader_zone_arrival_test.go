/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A zone whose set of providers changes moves to another provider group. On
 * a test fleet the group it arrived in already had its leader, in a running
 * term: nothing asked that leader for the zone, and the zone's NS change
 * reached the parent 49 minutes later, at the next lease renewal.
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	arrivalA = "a.agent.example."
	arrivalB = "b.agent.example."
	arrivalC = "c.agent.example."
)

// zoneEdit is the owner's word on a zone's providers: listed have an HSYNC3
// record, and serving hold the servers role in HSYNCPARAM, which makes them
// the members of the zone's provider group, each with a vote. parentsync
// says that the zone syncs with its parent through its agents.
type zoneEdit struct {
	listed, serving []string
	parentsync      bool
}

// serve is the edit that lists these providers and has each of them serve.
func serve(providers ...string) zoneEdit {
	return zoneEdit{listed: providers, serving: providers}
}

// apex returns the zone's apex with the edit in it.
func (e zoneEdit) apex(t *testing.T, zd *tdns.ZoneData) *tdns.OwnerData {
	t.Helper()
	served, err := zd.GetOwner(zd.ZoneName)
	if err != nil || served == nil {
		t.Fatalf("apex of %s: %v", zd.ZoneName, err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: zd.ZoneName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	apex := tdns.NewOwnerData(zd.ZoneName)
	if soa, ok := served.RRtypes.Get(dns.TypeSOA); ok {
		apex.RRtypes.Set(dns.TypeSOA, soa)
	}
	var h3s []dns.RR
	for _, id := range e.listed {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3),
			Data: &core.HSYNC3{State: 1, Label: shortLabel(id), Identity: id, Upstream: "."}})
	}
	var servers []string
	for _, id := range e.serving {
		servers = append(servers, shortLabel(id))
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: servers}}}
	if e.parentsync {
		hp.Value = append(hp.Value, &core.HSYNCPARAMParentSync{Value: core.HsyncParentSyncAgent})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	return apex
}

// apply puts the edit into the served zone, as a refresh's flip does.
func (e zoneEdit) apply(t *testing.T, zd *tdns.ZoneData) {
	t.Helper()
	zd.Data.Set(zd.ZoneName, *e.apex(t, zd))
	zd.InstallInitialSnapshot()
}

// incoming is the zone as a refresh has received it, with the edit in it and
// not served yet.
func (e zoneEdit) incoming(t *testing.T, zd *tdns.ZoneData) *tdns.ZoneData {
	t.Helper()
	next := &tdns.ZoneData{
		ZoneName:  zd.ZoneName,
		ZoneStore: zd.ZoneStore,
		ZoneType:  zd.ZoneType,
		Logger:    zd.Logger,
		Data:      core.NewNameMap[tdns.OwnerData](),
		Options:   map[tdns.ZoneOption]bool{},
	}
	for opt, on := range zd.Options {
		next.Options[opt] = on
	}
	next.Data.Set(zd.ZoneName, *e.apex(t, zd))
	return next
}

// providerZone is a Ready zone that the given providers serve.
func providerZone(t *testing.T, name string, providers ...string) *tdns.ZoneData {
	t.Helper()
	zd := seedZoneWithHSYNC3(t, name)
	zd.Logger = log.New(io.Discard, "", 0)
	serve(providers...).apply(t, zd)
	return zd
}

// asked is one call of a leader's callback, the election's (onLeaderElected)
// or the arrival's (onZoneJoined): who was asked, for which zone, and whether
// it was the zone's leader then, which is what the delegation sync the call
// asks for requires.
type asked struct {
	agent AgentId
	zone  ZoneName
	leads bool
}

// groupRig is a set of agents, each with a provider group manager, an
// election manager and a gossip table of its own, wired as the agent wires
// them. Their provider groups are the real ones: each manager computes them
// from the zones' HSYNC3 and HSYNCPARAM records. The election of one of the
// groups runs between its members, in process (electionNet).
type groupRig struct {
	net  *electionNet
	lems map[AgentId]*LeaderElectionManager
	pgms map[AgentId]*ProviderGroupManager
	gsts map[AgentId]*GossipStateTable

	mu    sync.Mutex
	calls []asked
}

// newGroupRig makes the agents. electing are the members of the group whose
// election the rig carries: each of them is among the agents, except in a
// rig of one agent, which hears of its peers through gossip only.
func newGroupRig(t *testing.T, electing []string, agents ...string) *groupRig {
	t.Helper()
	r := &groupRig{
		net: &electionNet{
			group:   ComputeGroupHash(electing),
			members: electing,
			mgrs:    map[AgentId]*LeaderElectionManager{},
			wake:    make(chan struct{}, 1),
		},
		lems: map[AgentId]*LeaderElectionManager{},
		pgms: map[AgentId]*ProviderGroupManager{},
		gsts: map[AgentId]*GossipStateTable{},
	}
	for _, m := range agents {
		id := AgentId(m)
		lem := NewLeaderElectionManager(id, time.Hour, func(_ ZoneName, rfiType string, records map[string][]string) error {
			if len(r.net.mgrs) < len(r.net.members) {
				return nil // a rig of one agent: its peers are not here to be sent to
			}
			return r.net.broadcast(id, rfiType, records)
		})
		pgm := NewProviderGroupManager(m)
		lem.SetProviderGroupManager(pgm)
		ask := func(zone ZoneName) error {
			leads := lem.IsLeader(zone)
			r.mu.Lock()
			r.calls = append(r.calls, asked{agent: id, zone: zone, leads: leads})
			r.mu.Unlock()
			return nil
		}
		lem.SetOnLeaderElected(ask)
		lem.SetOnZoneJoined(ask)
		gst := NewGossipStateTable(m)
		conf := &Config{Config: &tdns.Config{}}
		conf.InternalMp.LeaderElectionManager = lem
		wireAgentGossipCallbacks(conf, &AgentRegistry{ProviderGroupManager: pgm, GossipStateTable: gst})
		r.lems[id], r.pgms[id], r.gsts[id] = lem, pgm, gst
		for _, e := range electing {
			if e == m {
				r.net.mgrs[id] = lem
			}
		}
	}
	r.net.start(t)
	t.Cleanup(func() {
		for _, lem := range r.lems {
			stopElectionTimers(lem)
		}
	})
	return r
}

// stopElectionTimers stops the timers of every group election of a manager.
// The elections are copied out first and each is locked after the manager's
// lock is released: finalizing a confirm takes the manager's lock while it
// holds the election's, and a cleanup can run while one is delivered.
func stopElectionTimers(lem *LeaderElectionManager) {
	lem.mu.RLock()
	les := make([]*LeaderElection, 0, len(lem.groupElections))
	for _, le := range lem.groupElections {
		les = append(les, le)
	}
	lem.mu.RUnlock()
	for _, le := range les {
		le.mu.Lock()
		for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
			if tm != nil {
				tm.Stop()
			}
		}
		le.mu.Unlock()
	}
}

// refresh is every agent's refresh of a zone whose HSYNC3 or HSYNCPARAM
// records changed: it ends in a recompute of the agent's provider groups.
func (r *groupRig) refresh() {
	for _, pgm := range r.pgms {
		pgm.RecomputeGroups()
	}
}

// operational makes the rig's group mutually OPERATIONAL at each of its
// members, as the beats between them do: every member holds every member's
// row, with every peer OPERATIONAL in it. The first member in the order of
// the identities then calls the group's election.
func (r *groupRig) operational() {
	rows := map[string]*MemberState{}
	for _, m := range r.net.members {
		peers := map[string]string{}
		for _, p := range r.net.members {
			if p != m {
				peers[p] = AgentStateToString[AgentStateOperational]
			}
		}
		rows[m] = &MemberState{Identity: m, PeerStates: peers, Timestamp: time.Now()}
	}
	for _, m := range r.net.members {
		gst := r.gsts[AgentId(m)]
		gst.MergeGossip(&GossipMessage{GroupHash: r.net.group, Members: rows})
		gst.CheckGroupState(r.net.group, r.net.members)
	}
}

// gossipLeader is the word of the group's election as it reaches an agent in
// a peer's beat.
func (r *groupRig) gossipLeader(agent, leader string, term uint32) {
	r.gsts[AgentId(agent)].MergeGossip(&GossipMessage{GroupHash: r.net.group,
		Election: GroupElectionState{Leader: leader, Term: term, LeaderExpiry: time.Now().Add(time.Hour)}})
}

// leader returns the leader the rig's group elected in term, once every
// member has settled on it.
func (r *groupRig) leader(t *testing.T, term uint64) AgentId {
	t.Helper()
	r.net.waitSettled(t, term, 2*time.Second)
	_, _, leader := r.net.state(AgentId(r.net.members[0]))
	return leader
}

// take waits for want calls of the leader's callbacks, then a moment longer for
// one that should not come, and returns the calls made since the last take.
func (r *groupRig) take(want int) []asked {
	count := func() int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.calls)
	}
	for deadline := time.Now().Add(2 * time.Second); count() < want && time.Now().Before(deadline); {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	r.mu.Lock()
	defer r.mu.Unlock()
	got := r.calls
	r.calls = nil
	return got
}

// inGroup fails the test unless the group manager has the zone in the group
// of exactly these providers.
func inGroup(t *testing.T, pgm *ProviderGroupManager, zone *tdns.ZoneData, providers ...string) {
	t.Helper()
	pg := pgm.GetGroupForZone(ZoneName(zone.ZoneName))
	if pg == nil || pg.GroupHash != ComputeGroupHash(providers) {
		t.Fatalf("%s has %s in group %+v, want the group of %v", pgm.LocalID, zone.ZoneName, pg, providers)
	}
}

// A zone moves into a group that has its leader. That leader asks for the
// zone what it asked for the group's zones when it was elected, once, as the
// zone's leader; nobody else asks, and nothing is asked again for the zones
// the group had. Both directions were seen: a zone that lost a provider and
// joined the group of those that were left, and a zone that gained one.
func TestALeaderAsksForAZoneThatJoinsItsGroup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		before, led []string
	}{
		{"a provider is taken out of the zone", []string{arrivalA, arrivalB, arrivalC}, []string{arrivalA, arrivalB}},
		{"a provider is added to the zone", []string{arrivalA, arrivalB}, []string{arrivalA, arrivalB, arrivalC}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newGroupRig(t, tc.led, arrivalA, arrivalB, arrivalC)
			providerZone(t, "stays1.arrival.example.", tc.led...)
			providerZone(t, "stays2.arrival.example.", tc.led...)
			mover := providerZone(t, "mover.arrival.example.", tc.before...)
			r.refresh()
			inGroup(t, r.pgms[arrivalA], mover, tc.before...)

			// The group elects its leader, who asks for the two zones it has.
			r.operational()
			leader := r.leader(t, 1)
			elected := r.take(2)
			if len(elected) != 2 {
				t.Fatalf("the election of %s asked %+v, want it asked for the group's two zones", leader, elected)
			}
			for _, c := range elected {
				if c.agent != leader || c.zone == ZoneName(mover.ZoneName) {
					t.Fatalf("the election asked %s for %s; the leader is %s, and the zone is not in its group yet", c.agent, c.zone, leader)
				}
			}

			// The owner's edit reaches every agent.
			serve(tc.led...).apply(t, mover)
			r.refresh()
			inGroup(t, r.pgms[arrivalA], mover, tc.led...)
			got := r.take(1)
			if len(got) != 1 || got[0].agent != leader || got[0].zone != ZoneName(mover.ZoneName) {
				t.Fatalf("after the zone joined the group led by %s: asked %+v, want the leader asked once, for %s", leader, got, mover.ZoneName)
			}
			if !got[0].leads {
				t.Errorf("the leader was asked for %s before it was the zone's leader: the delegation sync it asks for is refused", mover.ZoneName)
			}

			// Refreshes that move no zone ask nothing.
			r.refresh()
			r.refresh()
			if again := r.take(0); len(again) != 0 {
				t.Errorf("a recompute that moved no zone asked again: %+v", again)
			}
		})
	}
}

// A zone that joins a group another member leads asks nothing at this agent:
// that member asks, told by its own group manager.
func TestAZoneThatJoinsAGroupAnotherMemberLeadsAsksNothingHere(t *testing.T) {
	r := newGroupRig(t, []string{arrivalA, arrivalB}, arrivalA)
	providerZone(t, "stays.other.arrival.example.", arrivalA, arrivalB)
	mover := providerZone(t, "mover.other.arrival.example.", arrivalA, arrivalB, arrivalC)
	r.refresh()
	r.gossipLeader(arrivalA, arrivalB, 1)

	serve(arrivalA, arrivalB).apply(t, mover)
	r.refresh()
	inGroup(t, r.pgms[arrivalA], mover, arrivalA, arrivalB)
	if got := r.take(0); len(got) != 0 {
		t.Fatalf("the zone joined a group that %s leads, and %s was asked: %+v", arrivalB, arrivalA, got)
	}
}

// A zone that arrives in a group with no leader, here a group that is new,
// is asked for by the election that follows, and by nothing before it: once.
func TestAZoneInANewGroupIsAskedForByItsElectionOnly(t *testing.T) {
	r := newGroupRig(t, []string{arrivalA, arrivalB}, arrivalA, arrivalB, arrivalC)
	mover := providerZone(t, "mover.new.arrival.example.", arrivalA, arrivalB, arrivalC)
	r.refresh()

	serve(arrivalA, arrivalB).apply(t, mover)
	r.refresh()
	inGroup(t, r.pgms[arrivalA], mover, arrivalA, arrivalB)
	if got := r.take(0); len(got) != 0 {
		t.Fatalf("the zone's new group has no leader, and somebody was asked: %+v", got)
	}

	r.operational()
	leader := r.leader(t, 1)
	got := r.take(1)
	if len(got) != 1 || got[0].agent != leader || got[0].zone != ZoneName(mover.ZoneName) || !got[0].leads {
		t.Fatalf("after the new group elected %s: asked %+v, want the leader asked once, for %s", leader, got, mover.ZoneName)
	}
}

// An agent that restarts inside its own term is told by its peers that it
// leads, and asks for the zones of the group it has loaded by then. A zone
// that loaded later, or a group none of whose zones were loaded yet, had to
// wait for the lease renewal: gossip tells of a term once.
func TestALeaderNamedByGossipAsksForAZoneThatLoadsLater(t *testing.T) {
	r := newGroupRig(t, []string{arrivalA, arrivalB}, arrivalA)

	// Told before any zone of the group is loaded: nothing to ask for yet.
	r.gossipLeader(arrivalA, arrivalA, 7)
	if got := r.take(0); len(got) != 0 {
		t.Fatalf("leadership of a group with no zone here asked: %+v", got)
	}

	// The group's zones load, one after the other: each is asked for once.
	for _, name := range []string{"first.later.arrival.example.", "second.later.arrival.example."} {
		zone := providerZone(t, name, arrivalA, arrivalB)
		r.refresh()
		got := r.take(1)
		if len(got) != 1 || got[0].zone != ZoneName(zone.ZoneName) || !got[0].leads {
			t.Fatalf("after %s loaded into a group this agent leads: asked %+v, want it asked once, for that zone", name, got)
		}
	}

	// The same term in a later beat is no news, and asks nothing more.
	r.gossipLeader(arrivalA, arrivalA, 7)
	r.refresh()
	if got := r.take(0); len(got) != 0 {
		t.Errorf("the same term heard again asked once more: %+v", got)
	}
}

// roleConf is the configuration of an agent or an auditor as its start has
// it before the engines run: the registry with its group manager and gossip
// table, and the refresh callbacks on the given zones.
func roleConf(t *testing.T, app tdns.AppType, role, identity string, zones ...*tdns.ZoneData) *Config {
	t.Helper()
	oldApp, oldMp := tdns.Globals.App.Type, wiredMpConfig.Load()
	t.Cleanup(func() {
		tdns.Globals.App.Type = oldApp
		wiredMpConfig.Store(oldMp)
	})
	tdns.Globals.App.Type = app

	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: role, Identity: identity})
	conf.InternalMp.IdentityReady = newIdentityReadiness()
	conf.InternalMp.AgentRegistry = conf.NewAgentRegistry()
	conf.InternalMp.MPTransport = &MPTransportBridge{agentRegistry: conf.InternalMp.AgentRegistry}
	for _, zd := range zones {
		zd.Options[tdns.OptMultiProvider] = true
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, zd.ZoneName)
	}
	conf.RegisterMPRefreshCallbacks()
	return conf
}

// refreshWith is a refresh of a zone that brings the owner's edit: the
// callbacks the role registered on the zone, run as tdns runs them, before
// and after the flip.
func refreshWith(t *testing.T, zd *tdns.ZoneData, e zoneEdit) {
	t.Helper()
	next := e.incoming(t, zd)
	for _, cb := range zd.OnZonePreRefresh {
		cb(zd, next)
	}
	e.apply(t, zd)
	for _, cb := range zd.OnZonePostRefresh {
		cb(zd)
	}
}

// The same through the agent's refresh of the zone, down to the delegation
// sync that the leader's callback asks for: it is queued, once. The refresh
// that moves the zone is also the one that finds parentsync=agent in its
// HSYNCPARAM, as a zone's first load is: the option is in place before the
// group manager tells of the move, or the leader's ask would find a zone
// that does not sync with its parent through its agents.
func TestARefreshThatMovesAZoneHasItsNewLeaderSyncIt(t *testing.T) {
	stays := providerZone(t, "stays.refresh.arrival.example.", arrivalA, arrivalB)
	mover := providerZone(t, "mover.refresh.arrival.example.", arrivalA, arrivalB, arrivalC)
	conf := roleConf(t, AppTypeMPAgent, "agent", arrivalA, stays, mover)
	ar := conf.InternalMp.AgentRegistry
	pgm := ar.ProviderGroupManager
	NewHsyncDataEngine(conf)

	// The election manager, as StartMPAgent wires it; of the leader's
	// callback, the delegation sync.
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem
	lem.SetProviderGroupManager(pgm)
	lem.SetOnLeaderElected(func(zone ZoneName) error {
		conf.requestDelegationSync(context.Background(), string(zone), "this agent was elected the zone's delegation sync leader")
		return nil
	})
	lem.SetOnZoneJoined(func(zone ZoneName) error {
		conf.requestDelegationSync(context.Background(), string(zone), "the zone joined a provider group this agent leads")
		return nil
	})
	syncs := make(chan tdns.DelegationSyncRequest, 8)
	mover.DelegationSyncQ = syncs

	// The zones are loaded, and a peer's beat says that this agent leads the
	// group of a and b.
	pgm.RecomputeGroups()
	ar.GossipStateTable.MergeGossip(&GossipMessage{GroupHash: ComputeGroupHash([]string{arrivalA, arrivalB}),
		Election: GroupElectionState{Leader: arrivalA, Term: 3, LeaderExpiry: time.Now().Add(time.Hour)}})
	if !lem.IsLeader(ZoneName(stays.ZoneName)) || lem.IsLeader(ZoneName(mover.ZoneName)) {
		t.Fatalf("before the edit this agent leads %s: %v, %s: %v; want the first only",
			stays.ZoneName, lem.IsLeader(ZoneName(stays.ZoneName)), mover.ZoneName, lem.IsLeader(ZoneName(mover.ZoneName)))
	}

	// What the group manager's word of the move finds: the zone's parentsync
	// option, and whether this agent is the zone's leader, which it is once
	// the zone is in its new group. The word then goes on to whoever the
	// manager tells.
	pgm.mu.Lock()
	told := pgm.onZoneJoinedGroup
	pgm.mu.Unlock()
	optionAtTheMove, leaderAtTheMove := false, false
	pgm.SetOnZoneJoinedGroup(func(zone ZoneName, from, to string) {
		if string(zone) == mover.ZoneName {
			optionAtTheMove = mover.Options[tdns.OptParentSync]
			leaderAtTheMove = lem.IsLeader(zone)
		}
		if told != nil {
			told(zone, from, to)
		}
	})

	// The owner's edit: c keeps its HSYNC3 record and loses its role, and the
	// zone syncs with its parent through its agents.
	refreshWith(t, mover, zoneEdit{
		listed:     []string{arrivalA, arrivalB, arrivalC},
		serving:    []string{arrivalA, arrivalB},
		parentsync: true,
	})
	inGroup(t, pgm, mover, arrivalA, arrivalB)

	select {
	case req := <-syncs:
		if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.ZoneName != mover.ZoneName {
			t.Errorf("the request on the delegation sync queue: %+v", req)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("the zone joined a group this agent leads, and no delegation sync was asked for it")
	}
	select {
	case req := <-syncs:
		t.Errorf("a second delegation sync was asked for the one move: %+v", req)
	case <-time.After(100 * time.Millisecond):
	}
	if !optionAtTheMove {
		t.Errorf("the group manager told of the move before the zone's parentsync option was set")
	}
	if !leaderAtTheMove {
		t.Errorf("the group manager told of the move before it had the zone in its new group")
	}
}

// The auditor recomputes its provider groups too, at its start and at every
// refresh that changes HSYNC3 or HSYNCPARAM. It leads nothing and has no
// election manager: its group manager tells nobody of a zone that moves.
func TestAnAuditorsRecomputeTellsNobody(t *testing.T) {
	zone := providerZone(t, "audited.arrival.example.", arrivalA, arrivalB, arrivalC)
	conf := roleConf(t, AppTypeMPAuditor, "auditor", "auditor.arrival.example.", zone)
	ar := conf.InternalMp.AgentRegistry
	pgm := ar.ProviderGroupManager

	// As StartMPAuditor: the audit state, the engine, the first recompute.
	state := NewAuditStateManager()
	ar.AuditState = state
	NewAuditorEngine(conf, state)
	pgm.RecomputeGroups()
	inGroup(t, pgm, zone, arrivalA, arrivalB, arrivalC)

	// c loses its role: the zone moves to the group of a and b.
	refreshWith(t, zone, zoneEdit{
		listed:  []string{arrivalA, arrivalB, arrivalC},
		serving: []string{arrivalA, arrivalB},
	})
	inGroup(t, pgm, zone, arrivalA, arrivalB)

	if pgm.onZoneJoinedGroup != nil {
		t.Errorf("the auditor's group manager reports the zones that move to somebody")
	}
	if pgm.onGroupGone != nil {
		t.Errorf("the auditor's group manager reports the groups that are gone to somebody")
	}
	if ar.LeaderElectionManager != nil || conf.InternalMp.LeaderElectionManager != nil {
		t.Errorf("the auditor has an election manager")
	}
}

// A zone that arrives in a group this agent leads has had a leader, and may
// have a SIG(0) key that leader made and the parent holds. The agent that it
// arrives at makes no new key in its place: only a zone that publishes none
// gets one there. An election's winner makes one when it has none, as before.
func TestAZoneThatArrivesWithAKeyGetsNoNewOne(t *testing.T) {
	zd := seedZoneWithHSYNC3(t, "keyed.example.")
	t.Cleanup(func() { tdns.Zones.Remove(zd.ZoneName) })
	mpzd := &MPZoneData{ZoneData: zd}

	if zonePublishesKey(mpzd) {
		t.Fatal("precondition: the seeded zone publishes a KEY")
	}
	if !mayGenerateZoneKey(false, mpzd, 0) {
		t.Error("a zone that publishes no key, and whose every voting member said it holds none, may not be given one: nothing would")
	}
	// A provider that has just joined shows no KEY in its own copy of a zone
	// that has one. While a voting member has not answered, it makes none.
	if mayGenerateZoneKey(false, mpzd, 1) {
		t.Error("a zone that joins a group may be given a key while a voting member has not said it holds none")
	}

	key, err := dns.NewRR("keyed.example. 3600 IN KEY 512 3 15 l02Woqwl4Uca9VQhrPQYG5cM3bxPV1RJxbr1iZqt6KE=")
	if err != nil {
		t.Fatal(err)
	}
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		t.Fatal("the seeded zone has no apex")
	}
	apex.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: []dns.RR{key}})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()

	if !zonePublishesKey(mpzd) {
		t.Fatal("the zone serves a KEY at its apex and reads as publishing none")
	}
	if mayGenerateZoneKey(false, mpzd, 0) {
		t.Error("a zone that joins a group with a key of its own may be given a new one: the parent holds the one it has")
	}
	if !mayGenerateZoneKey(true, mpzd, 0) || !mayGenerateZoneKey(true, mpzd, 2) {
		t.Error("an election's winner may no longer make a key when it has none")
	}
	if zonePublishesKey(nil) || !mayGenerateZoneKey(false, nil, 0) {
		t.Error("an unknown zone reads as publishing a key")
	}
}

// An election's setup and an arrival's setup of the same zone, and a later
// round of the arrival's, never run at the same time: each would otherwise
// find no SIG(0) key and make one. Another zone's setup is not held up.
func TestKeySetupsOfAZoneRunOneAtATime(t *testing.T) {
	lem := NewLeaderElectionManager("a.setup.example.", time.Hour, nil)
	var running, most atomic.Int32
	setup := func(ZoneName) error {
		n := running.Add(1)
		for {
			m := most.Load()
			if n <= m || most.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return nil
	}
	lem.SetOnLeaderElected(setup)
	lem.SetOnZoneJoined(setup)
	const zone ZoneName = "one.setup.example."
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); _ = lem.onLeaderElected(zone) }()
		go func() { defer wg.Done(); _ = lem.onZoneJoined(zone) }()
		go func() {
			defer wg.Done()
			_ = lem.inKeySetup(zone, func() error { return setup(zone) })
		}()
	}
	wg.Wait()
	if got := most.Load(); got != 1 {
		t.Errorf("%d key setups of one zone ran at the same time, want 1", got)
	}

	// Another zone's setup goes ahead while one runs.
	release := make(chan struct{})
	go func() {
		_ = lem.inKeySetup(zone, func() error { <-release; return nil })
	}()
	time.Sleep(10 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		_ = lem.onZoneJoined("other.setup.example.")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("another zone's setup waited for this zone's")
	}
	close(release)
}

// The owner takes the role of the provider that led the zone's group, C,
// and keeps its HSYNC3 record for now. C holds the zone's SIG(0) key. It has
// no role, so it is no voting member and none of the zone's agents
// (GetZoneAgentData has the role holders only): the agents asked had no key
// to hand over, the new leader made none while the zone published one, and
// the zone's delegation sync waited for good. The key setup asks every agent
// the zone lists ON with no role, read from the zone as it is: an agent that
// restarts, or leads a zone whose old group it was never in, asks the same.
func TestTheKeySetupAsksAProviderListedWithoutARole(t *testing.T) {
	const arrivalD = "d.agent.example."
	zd := providerZone(t, "roleless.key.arrival.example.", arrivalA, arrivalB, arrivalC, arrivalD)
	zone := ZoneName(zd.ZoneName)
	ar := keyHolderRegistry(arrivalA, arrivalB, arrivalC, arrivalD)

	// Every listed provider has a role: the voting members are asked, once.
	if asked := keyAsked(t, zone, ar); !slices.Equal(asked, []AgentId{arrivalB, arrivalC, arrivalD}) {
		t.Fatalf("with every provider holding a role the key setup asks %v, want the voting members B, C and D", asked)
	}

	// The owner takes the roles of C and of D, in one edit or in two, and
	// keeps their records.
	zoneEdit{listed: []string{arrivalA, arrivalB, arrivalC, arrivalD}, serving: []string{arrivalA, arrivalB}}.apply(t, zd)
	if asked := keyAsked(t, zone, ar); !slices.Equal(asked, []AgentId{arrivalB, arrivalC, arrivalD}) {
		t.Errorf("with C and D listed and no role the key setup asks %v, want B, and C and D from the registry", asked)
	}

	// A record set OFF, or gone, is not asked.
	apex, _ := zd.Data.Get(zd.ZoneName)
	h3s := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
	for _, rr := range h3s.RRs {
		if h3 := rr.(*dns.PrivateRR).Data.(*core.HSYNC3); h3.Identity == arrivalD {
			h3.State = 0
		}
	}
	apex.RRtypes.Set(core.TypeHSYNC3, h3s)
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
	if asked := keyAsked(t, zone, ar); !slices.Equal(asked, []AgentId{arrivalB, arrivalC}) {
		t.Errorf("with D's record OFF the key setup asks %v, want B and C", asked)
	}
	zoneEdit{listed: []string{arrivalA, arrivalB}, serving: []string{arrivalA, arrivalB}}.apply(t, zd)
	if asked := keyAsked(t, zone, ar); !slices.Equal(asked, []AgentId{arrivalB}) {
		t.Errorf("with C's and D's records gone the key setup asks %v, want only B", asked)
	}
}

// keyHolderRegistry is an agent registry, as this agent's, that knows the
// other agents.
func keyHolderRegistry(local string, others ...string) *AgentRegistry {
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: local}}
	for _, id := range others {
		ar.S.Set(AgentId(id), NewAgent(AgentId(id)))
	}
	return ar
}

// keyAsked is who the key setup's step b asks for the zone's key: the
// voting members among the zone's agents, and the agents it lists with no
// role.
func keyAsked(t *testing.T, zone ZoneName, ar *AgentRegistry) []AgentId {
	t.Helper()
	zad, err := ar.GetZoneAgentData(zone)
	if err != nil {
		t.Fatalf("the zone's agents: %v", err)
	}
	var asked []AgentId
	for _, a := range zoneKeyPeers(zone, zad.Agents, AgentId(ar.LocalAgent.Identity), ar.roleLessKeyHolders(zone)) {
		asked = append(asked, a.ID)
	}
	return asked
}
