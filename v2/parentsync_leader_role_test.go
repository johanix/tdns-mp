/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The identities of these tests. Each has an HSYNC3 record whose label is
// its first label.
const (
	roleA = "a.role.example." // a provider
	roleB = "b.role.example." // another provider
	roleN = "n.role.example." // a record and no role
	roleX = "x.role.example." // an auditor
)

// seedRoles seeds a Ready zone with an ON HSYNC3 record for every identity
// given: servers under servers=, auditors under auditors=, and the noRole
// ones with a record and no role.
func seedRoles(t *testing.T, zone string, servers, auditors, noRole []string) *tdns.ZoneData {
	t.Helper()
	all := append(append(append([]string{}, servers...), auditors...), noRole...)
	zd := seedZoneWithHSYNC3(t, zone, all...)
	setRoles(t, zd, servers, auditors)
	return zd
}

// setRoles replaces the zone's HSYNCPARAM with one that has servers= and
// auditors= as given, at the next serial, as the owner's edit of the roles
// does.
func setRoles(t *testing.T, zd *tdns.ZoneData, servers, auditors []string) {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex not found for %s: %v", zd.ZoneName, err)
	}
	labels := func(ids []string) []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = shortLabel(id)
		}
		return out
	}
	var kv []core.HSYNCPARAMKeyValue
	if len(servers) > 0 {
		kv = append(kv, &core.HSYNCPARAMServers{Servers: labels(servers)})
	}
	if len(auditors) > 0 {
		kv = append(kv, &core.HSYNCPARAMAuditors{Auditors: labels(auditors)})
	}
	setHSYNCPARAM(apex, zd.ZoneName, kv...)
	zd.Data.Set(zd.ZoneName, *apex)
	zd.InstallInitialSnapshot()
	Zones.Invalidate(zd.ZoneName)
}

// electRecorder is an election manager's way out: what it broadcasts, and
// the zones it ran the leader's setup for.
type electRecorder struct {
	mu      sync.Mutex
	sent    []string
	elected []ZoneName
}

func (r *electRecorder) broadcast(_ ZoneName, rfiType string, _ map[string][]string) error {
	r.mu.Lock()
	r.sent = append(r.sent, rfiType)
	r.mu.Unlock()
	return nil
}

func (r *electRecorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.sent {
		if s == "ELECT-CALL" {
			n++
		}
	}
	return n
}

func (r *electRecorder) sentCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func (r *electRecorder) setups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.elected)
}

// newRoleLEM is the election manager of the agent id, with the counts the
// agent wires (start_agent.go): every voting peer counted is OPERATIONAL.
// Its timers are stopped when the test ends.
func newRoleLEM(t *testing.T, id string, ttl time.Duration) (*LeaderElectionManager, *electRecorder) {
	t.Helper()
	rec := &electRecorder{}
	lem := NewLeaderElectionManager(AgentId(id), ttl, rec.broadcast)
	lem.SetConfiguredPeersFunc(func(z ZoneName) int { return configuredVotingPeers(z, AgentId(id)) })
	lem.SetOperationalPeersFunc(func(z ZoneName) int { return configuredVotingPeers(z, AgentId(id)) })
	lem.SetOnLeaderElected(func(z ZoneName) error {
		rec.mu.Lock()
		rec.elected = append(rec.elected, z)
		rec.mu.Unlock()
		return nil
	})
	t.Cleanup(func() { stopAllElectionTimers(lem) })
	return lem, rec
}

// stopAllElectionTimers is stopElectionTimers for the zones' elections too.
func stopAllElectionTimers(lem *LeaderElectionManager) {
	lem.mu.RLock()
	var all []*LeaderElection
	for _, le := range lem.elections {
		all = append(all, le)
	}
	for _, le := range lem.groupElections {
		all = append(all, le)
	}
	lem.mu.RUnlock()
	for _, le := range all {
		le.mu.Lock()
		for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
			if tm != nil {
				tm.Stop()
			}
		}
		le.mu.Unlock()
	}
}

// zoneState is the zone's per-zone election at lem: its term, whether it
// runs, and its leader.
func zoneState(lem *LeaderElectionManager, zone ZoneName) (term uint64, active bool, leader AgentId) {
	lem.mu.RLock()
	le := lem.elections[zone]
	lem.mu.RUnlock()
	if le == nil {
		return 0, false, ""
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.Term, le.Active, le.Leader
}

// An agent with a record and no role in a zone starts no election for it,
// from any of its callers. Its count is not zero: it counts the zone's
// voting member. From the lease renewal, the operator's parentsync-election,
// NotifyPeerOperational and the retry after no consensus it is the guard in
// startElection that stops it. At the first load and at every HSYNC change
// zoneChanged drops the zone's own election and starts nothing (step 8), and
// the first-load callback does nothing for a zone with an HSYNC3 RRset.
func TestAnAgentWithNoRoleStartsNoElection(t *testing.T) {
	const ttl = 300 * time.Millisecond
	zoneName := "norole.elect.example."
	zone := ZoneName(zoneName)
	quiet := func(t *testing.T, lem *LeaderElectionManager, rec *electRecorder, wantTerm uint64) {
		t.Helper()
		if n := rec.calls(); n != 0 {
			t.Errorf("an agent with no role called %d elections", n)
		}
		if n := rec.setups(); n != 0 {
			t.Errorf("an agent with no role ran the leader's setup %d times", n)
		}
		if term, active, leader := zoneState(lem, zone); term != wantTerm || active || (leader != "" && leader != AgentId(roleN)) {
			t.Errorf("the zone's election moved: term %d, active %v, leader %q", term, active, leader)
		}
	}

	t.Run("the lease renewal", func(t *testing.T) {
		seedRoles(t, zoneName, []string{roleA}, nil, []string{roleN})
		lem, rec := newRoleLEM(t, roleN, ttl)
		if n := lem.configuredPeers(zone); n != 1 {
			t.Fatalf("the agent with no role counts %d peers, want the zone's voting member", n)
		}
		// a per-zone lease it held from before it lost its role
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		le.Leader, le.Term, le.leaderTerm = AgentId(roleN), 1, 1
		le.LeaderExpiry = time.Now().Add(ttl)
		lem.scheduleReelection(le)
		le.mu.Unlock()
		time.Sleep(ttl + 200*time.Millisecond)
		quiet(t, lem, rec, 1)
	})

	t.Run("the operator's parentsync-election", func(t *testing.T) {
		seedRoles(t, zoneName, []string{roleA}, nil, []string{roleN})
		lem, rec := newRoleLEM(t, roleN, ttl)
		conf := &Config{Config: &tdns.Config{}}
		conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleN})
		conf.InternalMp.LeaderElectionManager = lem
		conf.InternalMp.AgentRegistry = &AgentRegistry{}
		body, _ := json.Marshal(AgentMgmtPost{Command: "parentsync-election", Zone: zone})
		w := httptest.NewRecorder()
		conf.APIagent(t.Context(), nil, nil)(w, httptest.NewRequest(http.MethodPost, "/api/v1/agent", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("the API answered %d", w.Code)
		}
		quiet(t, lem, rec, 0)
	})

	t.Run("NotifyPeerOperational", func(t *testing.T) {
		seedRoles(t, zoneName, []string{roleA}, nil, []string{roleN})
		lem, rec := newRoleLEM(t, roleN, ttl)
		lem.DeferElection(zone)
		lem.NotifyPeerOperational([]ZoneName{zone})
		quiet(t, lem, rec, 0)
	})

	t.Run("the retry after no consensus", func(t *testing.T) {
		zd := seedRoles(t, zoneName, []string{roleA, roleB}, nil, nil)
		lem, rec := newRoleLEM(t, roleB, ttl)
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		le.Active, le.Term, le.ExpectedPeers = true, 1, 1
		le.Confirms = map[AgentId]AgentId{AgentId(roleA): AgentId(roleA), AgentId(roleB): AgentId(roleB)}
		le.mu.Unlock()
		// the agent loses its vote between the election and the retry
		setRoles(t, zd, []string{roleA}, nil)
		lem.finalizeElection(zone, 1)
		time.Sleep(1700 * time.Millisecond) // the retry fires within 1.5 s
		quiet(t, lem, rec, 1)
	})

	t.Run("the first load and an HSYNC change", func(t *testing.T) {
		zd := seedRoles(t, zoneName, []string{roleA}, nil, []string{roleN})
		zd.Options[tdns.OptParentSync] = true
		lem, rec := newRoleLEM(t, roleN, ttl)
		// a per-zone result it holds from before it lost its role
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		le.Leader, le.leaderTerm = AgentId(roleN), 0
		le.LeaderExpiry = time.Now().Add(time.Hour)
		le.mu.Unlock()
		lem.electAtFirstLoad(zd)
		lem.zoneChanged(zone)
		quiet(t, lem, rec, 0)
		lem.mu.RLock()
		_, held := lem.elections[zone]
		lem.mu.RUnlock()
		if held {
			t.Error("the agent with no role still holds the zone's own election")
		}
	})
}

// A group's election is started only by one of the group's voting members
// as the group manager has them when it starts: not by an agent that has
// lost its vote, also when its caller still lists it, and not for a group
// that is gone. It counts those voting members too, not the caller's list.
// On main every caller checks the vote before it calls, with the group's
// list; the guard keeps the rule in the function too.
func TestAGroupElectionIsStartedOnlyByAVotingMember(t *testing.T) {
	const group = "0123456789abcdef"
	stale := []string{roleA, roleB}
	lem, rec := newRoleLEM(t, roleB, time.Minute)
	pgm := NewProviderGroupManager(roleB)
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: []string{roleA, roleB, roleX},
		VotingMembers: []string{roleA, roleX}, Zones: []ZoneName{"lost.group.example."}}
	lem.SetProviderGroupManager(pgm)
	lem.StartGroupElection(group, stale, pgm.Groups[group].Zones)
	if n := rec.calls(); n != 0 {
		t.Errorf("an agent without a vote in the group called %d elections", n)
	}

	// The election counts the group's voting members as the manager has
	// them, not its caller's list: here b alone votes now, and elects itself.
	pgm.Groups[group].VotingMembers = []string{roleB}
	lem.StartGroupElection(group, stale, pgm.Groups[group].Zones)
	if n := rec.calls(); n != 0 {
		t.Errorf("the only voting member called %d elections, counting its caller's list", n)
	}
	if leader, ok := lem.GetGroupLeader(group); !ok || leader != AgentId(roleB) {
		t.Errorf("the only voting member did not elect itself: %q %v", leader, ok)
	}

	delete(pgm.Groups, group)
	lem.mu.Lock()
	delete(lem.groupElections, group)
	lem.mu.Unlock()
	lem.StartGroupElection(group, stale, []ZoneName{"lost.group.example."})
	if n := rec.calls(); n != 0 {
		t.Errorf("%d elections called for a group that is gone", n)
	}
	lem.mu.RLock()
	_, held := lem.groupElections[group]
	lem.mu.RUnlock()
	if held {
		t.Error("an election entry was made for a group that is gone")
	}
}

// A count of zero voting peers no longer means a single participant: an
// auditor is not counted. Where a group covers the zone, the group's
// election decides, and no per-zone self-election is held.
func TestAZeroPeerCountDefersToAGroupThatCoversTheZone(t *testing.T) {
	zoneName := "audited.elect.example."
	zone := ZoneName(zoneName)
	zd := seedRoles(t, zoneName, []string{roleA}, []string{roleX}, nil)
	zd.Options[tdns.OptParentSync] = true
	lem, rec := newRoleLEM(t, roleA, time.Minute)
	pgm := NewProviderGroupManager(roleA)
	pgm.Groups["0123456789abcdef"] = &ProviderGroup{GroupHash: "0123456789abcdef",
		Members: []string{roleA, roleX}, VotingMembers: []string{roleA}, Zones: []ZoneName{zone}}
	lem.SetProviderGroupManager(pgm)
	if n := lem.configuredPeers(zone); n != 0 {
		t.Fatalf("the provider counts %d peers, want 0: the auditor is not counted", n)
	}

	lem.electAtFirstLoad(zd)
	lem.StartElection(zone, 0)
	time.Sleep(50 * time.Millisecond)
	if _, ok := lem.GetLeader(zone); ok {
		t.Error("a per-zone self-election in a zone that a group covers")
	}
	if n := rec.setups(); n != 0 {
		t.Errorf("the leader's setup ran %d times, for no election", n)
	}
}

// A zone with no HSYNC3 RRset is no multi-provider zone: it has no
// standings, and elects as before, alone or with its peers.
func TestAZoneWithoutHSYNC3ElectsAsBefore(t *testing.T) {
	t.Run("alone", func(t *testing.T) {
		seedZoneWithHSYNC3(t, "plain.elect.example.")
		lem, rec := newRoleLEM(t, roleA, time.Minute)
		lem.StartElection("plain.elect.example.", 0)
		if leader, ok := lem.GetLeader("plain.elect.example."); !ok || leader != AgentId(roleA) {
			t.Errorf("the single agent did not elect itself: %q %v", leader, ok)
		}
		for deadline := time.Now().Add(2 * time.Second); rec.setups() == 0; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the leader's setup did not run")
			}
		}
	})
	t.Run("with a peer", func(t *testing.T) {
		seedZoneWithHSYNC3(t, "zone.example.")
		n := newZoneElectionNet(t, time.Minute, roleA, roleB)
		if leader := n.firstZoneElection(t); leader == "" {
			t.Error("no leader")
		}
	})
}

// The counts an election takes are the voting members: an auditor and a
// record with no role are not counted, whichever agent counts.
func TestThePeerCountsAreTheVotingMembers(t *testing.T) {
	zone := ZoneName("counts.elect.example.")
	seedRoles(t, string(zone), []string{roleA, roleB}, []string{roleX}, []string{roleN})
	peers := transport.NewPeerRegistry()
	for _, id := range []string{roleA, roleB, roleX, roleN} {
		peers.GetOrCreate(id).SetState(transport.PeerStateOperational, "test")
	}
	ar := &AgentRegistry{TransportManager: &transport.TransportManager{PeerRegistry: peers}}
	for _, tc := range []struct {
		who  string
		want int
	}{
		{roleA, 1}, // b
		{roleX, 2}, // a and b
		{roleN, 2}, // a and b
	} {
		if n := configuredVotingPeers(zone, AgentId(tc.who)); n != tc.want {
			t.Errorf("%s counts %d configured peers, want %d", tc.who, n, tc.want)
		}
		if n := ar.operationalVotingPeers(zone, AgentId(tc.who)); n != tc.want {
			t.Errorf("%s counts %d OPERATIONAL peers, want %d", tc.who, n, tc.want)
		}
		if votes := isVotingMember(zone, tc.who); votes != (tc.who == roleA) {
			t.Errorf("isVotingMember(%s) = %v", tc.who, votes)
		}
	}
	peers.GetOrCreate(roleB).SetState(transport.PeerStateDegraded, "test")
	if n := ar.operationalVotingPeers(zone, AgentId(roleA)); n != 0 {
		t.Errorf("a counts %d OPERATIONAL peers with b DEGRADED, want 0", n)
	}
}

// In a zone's own election a CALL, a VOTE or a CONFIRM counts only from a
// voting member of the zone, and only a voting member takes part.
func TestAPerZoneVoteCountsOnlyFromAVotingMember(t *testing.T) {
	zoneName := "votes.elect.example."
	zone := ZoneName(zoneName)
	seedRoles(t, zoneName, []string{roleA, roleB}, []string{roleX}, []string{roleN})
	vote := map[string][]string{"_vote": {"7"}, "_term": {"1"}}

	lemA, _ := newRoleLEM(t, roleA, time.Minute)
	lemA.StartElection(zone, 1)
	lemA.HandleMessage(zone, AgentId(roleN), "ELECT-VOTE", vote)
	lemA.HandleMessage(zone, AgentId(roleX), "ELECT-VOTE", vote)
	le := lemA.getOrCreate(zone)
	le.mu.Lock()
	votes := len(le.Votes)
	le.mu.Unlock()
	if votes != 1 {
		t.Errorf("%d votes held after votes from members that do not vote, want this agent's own", votes)
	}
	lemA.HandleMessage(zone, AgentId(roleB), "ELECT-VOTE", vote)
	le.mu.Lock()
	votes = len(le.Votes)
	le.mu.Unlock()
	if votes != 2 {
		t.Errorf("%d votes held after the voting member's, want 2", votes)
	}

	// A CALL from a member that does not vote is not joined; one from a
	// voting member is, but not by a member that does not vote.
	call := map[string][]string{"_term": {"1"}}
	lemB, recB := newRoleLEM(t, roleB, time.Minute)
	lemB.HandleMessage(zone, AgentId(roleN), "ELECT-CALL", call)
	if term, active, _ := zoneState(lemB, zone); term != 0 || active || recB.sentCount() != 0 {
		t.Errorf("a voting member joined a CALL from a member with no role: term %d, active %v, sent %d", term, active, recB.sentCount())
	}
	lemN, recN := newRoleLEM(t, roleN, time.Minute)
	lemN.HandleMessage(zone, AgentId(roleA), "ELECT-CALL", call)
	if term, active, _ := zoneState(lemN, zone); term != 0 || active || recN.sentCount() != 0 {
		t.Errorf("a member with no role joined the election: term %d, active %v, sent %d", term, active, recN.sentCount())
	}
}

// A winner that is not a voting member is not taken, in a zone's election or
// a group's: the election counts as having found no consensus.
func TestAWinnerThatDoesNotVoteIsNotTaken(t *testing.T) {
	t.Run("a zone's election", func(t *testing.T) {
		zoneName := "winner.elect.example."
		zone := ZoneName(zoneName)
		seedRoles(t, zoneName, []string{roleA, roleB}, nil, []string{roleN})
		lem, rec := newRoleLEM(t, roleA, time.Minute)
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		le.Active, le.Term, le.ExpectedPeers = true, 1, 1
		le.Confirms = map[AgentId]AgentId{AgentId(roleA): AgentId(roleN), AgentId(roleB): AgentId(roleN)}
		le.mu.Unlock()
		lem.finalizeElection(zone, 1)
		if _, _, leader := zoneState(lem, zone); leader != "" {
			t.Errorf("the zone's leader is %q, a member that does not vote", leader)
		}
		if rec.setups() != 0 {
			t.Error("the leader's setup ran for a winner that does not vote")
		}
		time.Sleep(1700 * time.Millisecond) // the retry fires within 1.5 s
		if term, _, _ := zoneState(lem, zone); term != 2 {
			t.Errorf("the election was not held again: term %d, want 2", term)
		}
	})
	t.Run("a group's election", func(t *testing.T) {
		const group = "0123456789abcdef"
		members := []string{roleA, roleB}
		lem, rec := newRoleLEM(t, roleA, time.Minute)
		pgm := NewProviderGroupManager(roleA)
		pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: append(members, roleX), VotingMembers: members,
			Zones: []ZoneName{"winner.group.example."}}
		lem.SetProviderGroupManager(pgm)
		le := &LeaderElection{Zone: group, Active: true, Term: 1, ExpectedPeers: 1, Votes: map[AgentId]uint32{},
			Confirms: map[AgentId]AgentId{AgentId(roleA): AgentId(roleX), AgentId(roleB): AgentId(roleX)}}
		lem.mu.Lock()
		lem.groupElections[group] = le
		lem.mu.Unlock()
		lem.finalizeGroupElection(group, 1, members, pgm.Groups[group].Zones)
		if leader, ok := lem.GetGroupLeader(group); ok {
			t.Errorf("the group's leader is %q, a member that does not vote", leader)
		}
		if rec.setups() != 0 {
			t.Error("the leader's setup ran for a winner that does not vote")
		}
	})
}

// An agent that does not vote in a group, and learns its leader from
// gossip, arms no renewal of the lease. (A renewal armed while it voted
// starts nothing once it does not: TestAGroupMemberWithoutAVoteRenewsNothing.)
func TestAnObserverArmsNoRenewalTimer(t *testing.T) {
	const group = "0123456789abcdef"
	lem, _ := newRoleLEM(t, roleX, time.Minute)
	pgm := NewProviderGroupManager(roleX)
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: []string{roleA, roleB, roleX},
		VotingMembers: []string{roleA, roleB}, Zones: []ZoneName{"observed.group.example."}}
	lem.SetProviderGroupManager(pgm)
	lem.ApplyGossipElection(group, GroupElectionState{Leader: roleA, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	if leader, ok := lem.GetGroupLeader(group); !ok || leader != AgentId(roleA) {
		t.Fatalf("the observer did not take the leader from gossip: %q %v", leader, ok)
	}
	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()
	le.mu.Lock()
	armed := le.ReelectTimer != nil
	le.mu.Unlock()
	if armed {
		t.Error("an agent that does not vote armed the lease's renewal")
	}
}

// h3rec is one HSYNC3 record of a zone: its identity, and whether it is ON.
type h3rec struct {
	id string
	on bool
}

// memberLabel is an identity's HSYNC3 label in servedMembers: the whole
// name, as the rig's two agents share their first label.
func memberLabel(id string) string {
	return strings.ReplaceAll(strings.TrimSuffix(id, "."), ".", "-")
}

// servedMembers puts the zone's HSYNC3 records and its HSYNCPARAM in place as
// a refresh brings them: servers= as given, and parentsync=agent, at the next
// serial.
func servedMembers(t *testing.T, mpzd *MPZoneData, recs []h3rec, servers []string) {
	t.Helper()
	zone := mpzd.ZoneName
	apex, ok := mpzd.Data.Get(zone)
	if !ok {
		t.Fatalf("the zone %s has no apex", zone)
	}
	var rrs []dns.RR
	for _, r := range recs {
		h3 := &core.HSYNC3{Label: memberLabel(r.id), Identity: r.id, Upstream: "."}
		if r.on {
			h3.State = 1
		}
		rrs = append(rrs, &dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600}, Data: h3})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: rrs})
	labels := make([]string, len(servers))
	for i, s := range servers {
		labels[i] = memberLabel(s)
	}
	setHSYNCPARAM(&apex, zone,
		&core.HSYNCPARAMServers{Servers: labels},
		&core.HSYNCPARAMParentSync{Value: core.HsyncParentSyncAgent})
	mpzd.Data.Set(zone, apex)
	mpzd.InstallInitialSnapshot()
}

const (
	usAgent    = "agent.us.example." // the leader sync rig's agent
	otherAgent = "agent.eu.example."
)

// keyPollRig runs the zone's key poll through the agent's wrapper, with a
// poll that stands in for tdns's: it waits on its context, as tdns's poll
// does while it waits for the key to be served and for a re-bootstrap round.
type keyPollRig struct {
	*leaderSyncRig
	starts   atomic.Int32
	started  chan struct{}
	returned chan struct{}
	stop     context.CancelFunc
	done     chan struct{}
}

func newKeyPollRig(t *testing.T, zone string) *keyPollRig {
	t.Helper()
	r := &keyPollRig{leaderSyncRig: newLeaderSyncRig(t, zone), started: make(chan struct{}, 8), returned: make(chan struct{}, 8)}
	r.mpzd.Ready = true // loaded: the zone's members are read from it as it is served
	r.leader(usAgent)
	r.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, _ string, _ uint16, _ uint8) {
		r.starts.Add(1)
		r.started <- struct{}{}
		<-ctx.Done()
		r.returned <- struct{}{}
	}
	return r
}

// poll starts the wrapper, and waits for the poll to start.
func (r *keyPollRig) poll(t *testing.T) {
	t.Helper()
	ctx, stop := context.WithCancel(r.ctx)
	r.stop, r.done = stop, make(chan struct{})
	go func() {
		defer close(r.done)
		r.conf.ParentSyncAfterKeyPublication(ctx, ZoneName(r.mpzd.ZoneName), r.mpzd.ZoneName, 1, dns.ED25519)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("the key poll's wrapper did not return with its context")
		}
	})
	r.wait(t, r.started, "the key poll did not start")
}

func (r *keyPollRig) wait(t *testing.T, ch chan struct{}, why string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal(why)
	}
}

// chain gives the zone a delegation sync chain, as a failed sync leaves.
func (r *keyPollRig) chain() {
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	if c.zones == nil {
		c.zones = map[string]*delegationSyncChain{}
	}
	c.zones[r.mpzd.ZoneName] = &delegationSyncChain{failures: 1}
	c.mu.Unlock()
}

// The parentsync option follows HSYNCPARAM only for a zone whose records
// name this agent. For a zone that does not, it is off, at the first load
// too, and what this agent had scheduled for the zone's parent ends: the
// chain and the key poll. A zone that names this agent again turns it on,
// and that is no give-back: no leader's setup runs.
func TestParentSyncFollowsHSYNCPARAMOnlyForAZoneThatListsThisAgent(t *testing.T) {
	asMPAgent(t)
	r := newKeyPollRig(t, "listed.parentsync.example.")
	setups := make(chan ZoneName, 4)
	r.lem.SetOnLeaderElected(func(z ZoneName) error { setups <- z; return nil })
	named := []h3rec{{usAgent, true}, {otherAgent, true}}
	notNamed := []h3rec{{otherAgent, true}}

	// a first load of a zone that does not name this agent
	servedMembers(t, r.mpzd, notNamed, []string{otherAgent})
	refreshed(t, r.conf, r.mpzd)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the option is on for a zone that does not name this agent")
	}

	servedMembers(t, r.mpzd, named, []string{usAgent, otherAgent})
	refreshed(t, r.conf, r.mpzd)
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the option is off for a zone that names this agent")
	}
	select {
	case <-setups:
		t.Error("a zone that names this agent anew ran the leader's setup as a give-back")
	case <-time.After(200 * time.Millisecond):
	}

	r.chain()
	r.poll(t)
	servedMembers(t, r.mpzd, notNamed, []string{otherAgent})
	refreshed(t, r.conf, r.mpzd)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Error("the option stayed on for a zone that no longer names this agent")
	}
	r.wait(t, r.returned, "the key poll went on for a zone that no longer names this agent")
	if r.chains() != 0 {
		t.Error("the zone's chain was left")
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.starts.Load(); n != 1 {
		t.Errorf("the key poll was started %d times, want once", n)
	}

	servedMembers(t, r.mpzd, named, []string{usAgent, otherAgent})
	refreshed(t, r.conf, r.mpzd)
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the option is off for a zone that names this agent again")
	}
	select {
	case <-setups:
		t.Error("a zone that names this agent again ran the leader's setup as a give-back")
	case <-time.After(200 * time.Millisecond):
	}
}

// chains is the number of delegation sync chains the rig's agent holds.
func (r *keyPollRig) chains() int {
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.zones)
}

// A refresh after which this agent no longer takes part in the zone, its
// record OFF or its roles taken, ends the zone's chain and its key poll,
// while the poll waits. Also when this agent is the zone's only provider:
// then nobody takes part after the refresh. With its roles taken the option
// stays on; with its record OFF the records no longer name this agent (an
// OFF record gives no label, plan S3), and the option goes off.
func TestAKeyPollEndsWhenThisAgentNoLongerTakesPart(t *testing.T) {
	asMPAgent(t)
	both, two := []h3rec{{usAgent, true}, {otherAgent, true}}, []string{usAgent, otherAgent}
	alone, one := []h3rec{{usAgent, true}}, []string{usAgent}
	for _, tc := range []struct {
		name         string
		startRecs    []h3rec
		startServers []string
		recs         []h3rec
		servers      []string
		optionStays  bool
	}{
		{"its record turns OFF", both, two, []h3rec{{usAgent, false}, {otherAgent, true}}, two, false},
		{"its roles are taken", both, two, both, []string{otherAgent}, true},
		{"the only provider's record turns OFF", alone, one, []h3rec{{usAgent, false}}, one, false},
		{"the only provider's role is taken", alone, one, alone, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newKeyPollRig(t, "takespart.parentsync.example.")
			servedMembers(t, r.mpzd, tc.startRecs, tc.startServers)
			refreshed(t, r.conf, r.mpzd)
			r.chain()
			r.poll(t)

			servedMembers(t, r.mpzd, tc.recs, tc.servers)
			refreshed(t, r.conf, r.mpzd)
			r.wait(t, r.returned, "the key poll went on")
			if r.chains() != 0 {
				t.Error("the zone's chain was left")
			}
			if got := r.mpzd.Options[tdns.OptParentSync]; got != tc.optionStays {
				t.Errorf("the option is %v after the refresh, want %v", got, tc.optionStays)
			}
			time.Sleep(100 * time.Millisecond)
			if n := r.starts.Load(); n != 1 {
				t.Errorf("the key poll was started %d times, want once", n)
			}
		})
	}
}

// The wrapper starts no key poll for a zone in which this agent takes no
// part, also when it leads the zone by an earlier lease.
func TestAKeyPollIsNotStartedWhereThisAgentTakesNoPart(t *testing.T) {
	asMPAgent(t)
	for _, tc := range []struct {
		name    string
		recs    []h3rec
		servers []string
	}{
		{"its record is OFF", []h3rec{{usAgent, false}, {otherAgent, true}}, []string{usAgent, otherAgent}},
		{"it has no role", []h3rec{{usAgent, true}, {otherAgent, true}}, []string{otherAgent}},
		// nobody takes part: under an HSYNC3 RRset this agent does not
		// either, and the option is off for a zone that does not name it
		{"no record names it, and nobody takes part", []h3rec{{otherAgent, false}}, []string{otherAgent}},
		// the only provider's record OFF, or its only role taken
		{"it is the only provider and its record is OFF", []h3rec{{usAgent, false}}, []string{usAgent}},
		{"it is the only provider and has no role", []h3rec{{usAgent, true}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newKeyPollRig(t, "nopart.parentsync.example.")
			servedMembers(t, r.mpzd, tc.recs, tc.servers)
			refreshed(t, r.conf, r.mpzd)
			// bounded: a poll that is started waits for its context
			ctx, cancel := context.WithTimeout(r.ctx, time.Second)
			defer cancel()
			r.conf.ParentSyncAfterKeyPublication(ctx, ZoneName(r.mpzd.ZoneName), r.mpzd.ZoneName, 1, dns.ED25519)
			if n := r.starts.Load(); n != 0 {
				t.Errorf("the key poll was started %d times", n)
			}
		})
	}
}

// A poll whose run was cancelled is started again when this agent takes part
// in the zone by then: here its record was set OFF and back ON during the
// wait. A poll that returns by itself is not started again: the parent
// trusts the key, the poll gave up, or a poll for the key runs already. From
// the wrapper's side those three are one case: the poll returns, its run not
// cancelled.
func TestACancelledKeyPollStartsAgainOnlyWhenCancelled(t *testing.T) {
	asMPAgent(t)
	on := []h3rec{{usAgent, true}, {otherAgent, true}}
	servers := []string{usAgent, otherAgent}

	t.Run("set OFF and back ON", func(t *testing.T) {
		r := newKeyPollRig(t, "again.parentsync.example.")
		servedMembers(t, r.mpzd, on, servers)
		refreshed(t, r.conf, r.mpzd)
		cancelled, release := make(chan struct{}, 1), make(chan struct{})
		r.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, _ string, _ uint16, _ uint8) {
			first := r.starts.Add(1) == 1
			r.started <- struct{}{}
			<-ctx.Done()
			if first {
				cancelled <- struct{}{}
				<-release // the record is ON again before this poll has returned
			}
		}
		r.poll(t)
		servedMembers(t, r.mpzd, []h3rec{{usAgent, false}, {otherAgent, true}}, servers)
		refreshed(t, r.conf, r.mpzd)
		r.wait(t, cancelled, "the key poll was not cancelled")
		servedMembers(t, r.mpzd, on, servers)
		refreshed(t, r.conf, r.mpzd)
		close(release)
		r.wait(t, r.started, "the key poll was not started again")
		if n := r.starts.Load(); n != 2 {
			t.Errorf("the key poll was started %d times, want twice", n)
		}
	})

	t.Run("it returns by itself", func(t *testing.T) {
		r := newKeyPollRig(t, "once.parentsync.example.")
		servedMembers(t, r.mpzd, on, servers)
		refreshed(t, r.conf, r.mpzd)
		r.conf.InternalMp.keyPoll = func(context.Context, ZoneName, string, uint16, uint8) { r.starts.Add(1) }
		r.conf.ParentSyncAfterKeyPublication(r.ctx, ZoneName(r.mpzd.ZoneName), r.mpzd.ZoneName, 1, dns.ED25519)
		if n := r.starts.Load(); n != 1 {
			t.Errorf("the key poll was started %d times, want once", n)
		}
	})
}

// A zone with one provider, and a second agent that has a record and no
// role, has one leader: the provider's agent. At the first load zoneChanged
// elects the provider's agent, and starts nothing at the other (step 8); the
// other starts nothing either when the provider is OPERATIONAL. At each
// lease renewal the provider elects itself again, and nobody else.
func TestOneProviderAndAnAgentWithNoRoleHaveOneLeader(t *testing.T) {
	const ttl = 400 * time.Millisecond
	zd := seedRoles(t, "zone.example.", []string{roleA}, nil, []string{roleN})
	zd.Options[tdns.OptParentSync] = true
	n := newZoneElectionNetCounting(t, ttl, func(id AgentId) func(ZoneName) int {
		return func(z ZoneName) int { return configuredVotingPeers(z, id) } // as the agent counts
	}, roleA, roleN)
	a, other := n.mgrs[AgentId(roleA)], n.mgrs[AgentId(roleN)]
	if ca, cn := a.configuredPeers(n.zone), other.configuredPeers(n.zone); ca != 0 || cn != 1 {
		t.Fatalf("the counts are %d and %d, want 0 for the provider and 1 for the agent with no role", ca, cn)
	}

	a.zoneChanged(n.zone)
	other.zoneChanged(n.zone)
	other.NotifyPeerOperational([]ZoneName{n.zone})
	if _, _, leader := n.state(AgentId(roleA)); leader != AgentId(roleA) {
		t.Errorf("the provider's agent did not elect itself: leader %q", leader)
	}
	if _, _, leader := n.state(AgentId(roleN)); leader != "" {
		t.Errorf("the agent with no role has a leader of its own: %q", leader)
	}

	time.Sleep(ttl + 200*time.Millisecond) // one renewal
	n.mu.Lock()
	elected := append([]AgentId(nil), n.elected...)
	n.mu.Unlock()
	if len(elected) < 2 {
		t.Errorf("the provider was elected %d times, want at its start and at its renewal", len(elected))
	}
	for _, id := range elected {
		if id != AgentId(roleA) {
			t.Errorf("%s was elected", id)
		}
	}
	if calls := n.callers(); len(calls) != 0 {
		t.Errorf("elections were called by %v: a single provider elects itself with no call", calls)
	}
}

// A refresh after which this agent takes no part in the zone stops the sync
// under way, as the owner's take-over does, here an UPDATE in tdns's retry
// loop. That is no failure: nothing asks again, and no warning says that
// the sync failed. Also when this agent is the zone's only provider, and
// nobody takes part after the refresh.
func TestASyncStoppedBecauseThisAgentLeftIsNoFailure(t *testing.T) {
	asMPAgent(t)
	for _, tc := range []struct {
		name string
		zone string
		// the zone's records before and after the refresh, by who is
		// us and who is the peer
		before, after func(us, peer string) ([]h3rec, []string)
	}{
		{"its role is taken", "left.update.example.",
			func(us, peer string) ([]h3rec, []string) { return []h3rec{{us, true}, {peer, true}}, []string{us, peer} },
			func(us, peer string) ([]h3rec, []string) { return []h3rec{{us, true}, {peer, true}}, []string{peer} }},
		{"the only provider's record turns OFF", "off.alone.update.example.",
			func(us, _ string) ([]h3rec, []string) { return []h3rec{{us, true}}, []string{us} },
			func(us, _ string) ([]h3rec, []string) { return []h3rec{{us, false}}, []string{us} }},
		{"the only provider's role is taken", "norole.alone.update.example.",
			func(us, _ string) ([]h3rec, []string) { return []h3rec{{us, true}}, []string{us} },
			func(us, _ string) ([]h3rec, []string) { return []h3rec{{us, true}}, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) { syncStoppedBecauseThisAgentLeft(t, tc.zone, tc.before, tc.after) })
	}
}

func syncStoppedBecauseThisAgentLeft(t *testing.T, zone string, before, after func(us, peer string) ([]h3rec, []string)) {
	r := newNotifyRig(t, zone, "UPDATE", repeat(30*time.Millisecond, 400)...)
	us, peer := r.us.Identity, r.peer.Identity
	recs, servers := before(us, peer)
	servedMembers(t, r.mpzd, recs, servers)
	refreshed(t, r.conf, r.mpzd)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	r.parent.refuses()
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.ask()
	underWay := func() int {
		c := &r.conf.InternalMp.delegationSyncChains
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.runs[z])
	}
	for deadline := time.Now().Add(10 * time.Second); r.parent.updatesSeen() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no UPDATE reached the parent")
		}
	}
	if underWay() != 1 {
		t.Fatal("the refused UPDATE is not being retried")
	}

	recs, servers = after(us, peer)
	servedMembers(t, r.mpzd, recs, servers)
	refreshed(t, r.conf, r.mpzd)
	for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the sync went on after this agent left the zone")
		}
	}
	time.Sleep(300 * time.Millisecond)
	if l := r.log.String(); strings.Contains(l, `msg="the delegation sync failed; asking again"`) {
		t.Errorf("a sync stopped because this agent left was taken as a failure:\n%s", l)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left for a zone this agent takes no part in", n)
	}
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one sent before this agent left", n)
	}
}

// The leader's key setup is for a zone in which this agent votes. A group's
// winner that does not vote in one of the group's zones looks up no parent
// and asks no peer for that zone's key.
func TestTheKeySetupIsOnlyForAZoneThisAgentVotesIn(t *testing.T) {
	const zone = "keysetup.role.example."
	seedRoles(t, zone, []string{roleA}, nil, []string{roleN}).Options[tdns.OptParentSync] = true
	mpzd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("the zone is not registered")
	}
	if ok, why := keySetupApplies(mpzd, AgentId(roleA)); !ok {
		t.Errorf("the voting member gets no key setup: %s", why)
	}
	for _, id := range []string{roleN, "absent.role.example."} {
		if ok, _ := keySetupApplies(mpzd, AgentId(id)); ok {
			t.Errorf("%s, which does not vote in the zone, gets the key setup", id)
		}
	}
	mpzd.Options[tdns.OptParentSync] = false
	if ok, _ := keySetupApplies(mpzd, AgentId(roleA)); ok {
		t.Error("a zone with the parentsync option off gets the key setup")
	}
}
