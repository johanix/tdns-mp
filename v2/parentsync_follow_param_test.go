/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servedParentSync puts the zone's HSYNCPARAM in place as a refresh brings
// it: the roles it had, with parentsync="agent" or "owner", or with no
// parentsync at all (nil). Without an HSYNCPARAM to start from the record
// has the parentsync alone; gone removes the record.
func servedParentSync(t *testing.T, mpzd *MPZoneData, parentsync *uint8, gone bool) {
	t.Helper()
	zone := mpzd.ZoneName
	apex, ok := mpzd.Data.Get(zone)
	if !ok {
		t.Fatalf("the zone %s has no apex", zone)
	}
	if gone {
		apex.RRtypes.Delete(core.TypeHSYNCPARAM)
	} else {
		var roles []core.HSYNCPARAMKeyValue
		if old, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM); ok && len(old.RRs) > 0 {
			for _, kv := range old.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM).Value {
				if _, ps := kv.(*core.HSYNCPARAMParentSync); !ps {
					roles = append(roles, kv)
				}
			}
		}
		if parentsync != nil {
			roles = append(roles, &core.HSYNCPARAMParentSync{Value: *parentsync})
		}
		hdr := dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr, Data: numbered(&core.HSYNCPARAM{Value: roles})}}})
	}
	mpzd.Data.Set(zone, apex)
	mpzd.InstallInitialSnapshot() // the analysis reads the zone as it is served
}

// namedInTheZone gives the zone an ON HSYNC3 record for the agent, and the
// agent the role servers= in a new HSYNCPARAM. The delegation sync follows
// HSYNCPARAM only for a zone whose records name this agent.
func namedInTheZone(t *testing.T, mpzd *MPZoneData, identity string) {
	t.Helper()
	zone := mpzd.ZoneName
	apex, ok := mpzd.Data.Get(zone)
	if !ok {
		t.Fatalf("the zone %s has no apex", zone)
	}
	label := shortLabel(identity)
	h3 := &dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNC3{State: 1, Label: label, Identity: dns.Fqdn(identity), Upstream: "."}}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{h3}})
	hp := &dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: numbered(&core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: []string{label}}}})}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{hp}})
	mpzd.Data.Set(zone, apex)
	mpzd.InstallInitialSnapshot()
}

// refreshed runs the post-refresh callbacks that the daemon registers for a
// multi-provider zone (RegisterMPRefreshCallbacks), as a refresh does that
// found the HSYNC records changed.
func refreshed(t *testing.T, conf *Config, mpzd *MPZoneData) {
	t.Helper()
	if !slices.Contains(conf.InternalMp.MPZoneNames, mpzd.ZoneName) {
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, mpzd.ZoneName)
		conf.RegisterMPRefreshCallbacks()
	}
	mpzd.EnsureMP()
	mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{HsyncChanged: true}
	for _, cb := range mpzd.OnZonePostRefresh {
		cb(mpzd.ZoneData)
	}
}

var (
	parentSyncAgent = core.HsyncParentSyncAgent
	parentSyncOwner = core.HsyncParentSyncOwner
)

// parentSyncStep gives the parent sync to parentsync as a step of the zone's
// reconciliation does (plan S20): the copy says so, the store's active reading
// is that copy's and its sets hold it, and the agent acts by the sets. A
// refresh alone changes nothing: TestTheAgentsStopSyncingAtTheirStepAndNotAtTheRefresh.
func parentSyncStep(t *testing.T, conf *Config, mpzd *MPZoneData, parentsync uint8) {
	t.Helper()
	servedParentSync(t, mpzd, &parentsync, false)
	activeFromCopy(t, conf, mpzd)
}

// activeFromCopy makes the zone's copy its active reading, in a store of
// serials of the test's, and has the agent act by the sets.
func activeFromCopy(t *testing.T, conf *Config, mpzd *MPZoneData) {
	t.Helper()
	s := instrStore.Load()
	if s == nil {
		s = newStore(t)
		withStore(t, s)
	}
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("the apex: %v", err)
	}
	in, err := ReadInstructions(apex)
	if err != nil || in == nil {
		t.Fatalf("the served instructions: %v", err)
	}
	activeAs(t, s, mpzd.ZoneName, in)
	conf.onSetsChanged(mpzd, true)
}

// The agent's delegation sync of a multi-provider zone follows the zone's
// HSYNCPARAM in both directions. It was turned on when HSYNCPARAM said
// parentsync=agent and never off (tdns-mp #200): once the owner had taken
// the sync over, the leader went on syncing the parent at every lease
// renewal, and could put back what the owner had removed there.
func TestTheDelegationSyncFollowsHSYNCPARAM(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "follow.parentsync.example.")
	namedInTheZone(t, r.mpzd, "agent.us.example.")
	r.leader("agent.us.example.")
	z := r.mpzd.ZoneName
	r.mpzd.SetOption(tdns.OptParentSync, false)
	// the agent's store of serials is the one the test installs, as a
	// refresh notes the copy's instructions in it (noteInstructions)
	store := newStore(t)
	withStore(t, store)
	r.conf.InternalMp.Instructions = store

	steps := []struct {
		what       string
		parentsync *uint8
		gone       bool
		want       bool
	}{
		{"parentsync=agent", &parentSyncAgent, false, true},
		{"the owner takes the sync over", &parentSyncOwner, false, false},
		{"the agents again", &parentSyncAgent, false, true},
		{"no parentsync key: the owner's", nil, false, false},
		{"the agents once more", &parentSyncAgent, false, true},
		// an owner error (#308): the zone holds at its last reading
		{"no HSYNCPARAM", nil, true, true},
	}
	for _, s := range steps {
		servedParentSync(t, r.mpzd, s.parentsync, s.gone)
		// a copy with no HSYNCPARAM is a refresh's, as production has it:
		// its instructions noted, then the sets acted on
		if s.gone {
			refreshed(t, r.conf, r.mpzd)
		} else {
			activeFromCopy(t, r.conf, r.mpzd)
		}
		if got := r.mpzd.Options[tdns.OptParentSync]; got != s.want {
			t.Fatalf("%s: the delegation sync is %v, want %v", s.what, got, s.want)
		}
		// what an election, a lease renewal included, asks for
		asked := r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader")
		if n := r.requests(t); asked != s.want || n != map[bool]int{true: 1, false: 0}[s.want] {
			t.Errorf("%s: a renewal asked=%v and queued %d syncs", s.what, asked, n)
		}
	}
}

// A parentsync option in the agent's own configuration does not outweigh
// the owner's HSYNCPARAM: the owner syncs a zone whose HSYNCPARAM does not
// say parentsync=agent, whatever the agent's configuration says.
func TestTheOwnersHSYNCPARAMOutweighsTheAgentsConfig(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "static.parentsync.example.")
	namedInTheZone(t, r.mpzd, "agent.us.example.")
	r.leader("agent.us.example.")
	// the rig's zone has the option on, as from the agent's configuration
	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("an agent configured with parentsync syncs a zone whose owner syncs it")
	}
}

// Another role leaves the option alone: only an agent syncs a zone's
// delegation through the agents.
func TestOnlyAnAgentFollowsHSYNCPARAM(t *testing.T) {
	old := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPCombiner
	t.Cleanup(func() { tdns.Globals.App.Type = old })
	r := newLeaderSyncRig(t, "combiner.parentsync.example.")
	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)
	if !r.mpzd.Options[tdns.OptParentSync] {
		t.Error("a combiner's refresh changed the delegation sync option")
	}
}

const logDroppedOwner = `msg="the held NOTIFY is dropped: the zone's owner syncs its delegation"`

// The owner takes the sync over while a NOTIFY is held: the step that gives
// it to the owner drops the NOTIFY and ends the chain, and nothing asks
// again, a lease renewal included. When a step gives the sync back to the
// agents, the next change is synced.
func TestTheOwnerTakingTheSyncOverDropsAHeldNotify(t *testing.T) {
	asMPAgent(t)
	const wait = time.Second
	r := newNotifyRig(t, "owner.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.ask()
	r.logged(t, 1, logHeld)

	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner) // before the wait is over
	if l := r.log.String(); !strings.Contains(l, logDroppedOwner+" zone="+z+" notify=CSYNC") {
		t.Errorf("the step did not drop the held NOTIFY:\n%s", l)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the held NOTIFY was dropped", n)
	}
	if r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Error("a lease renewal asked for a sync of a zone whose owner syncs it")
	}
	r.ask()
	r.quiet(t, wait+300*time.Millisecond, "for a zone whose owner syncs it")
	r.untold(t, 0, "for a zone whose owner syncs it")
	if r.chains() != 0 {
		t.Error("a chain was started for a zone whose owner syncs it")
	}
	if l := r.log.String(); strings.Contains(l, logLeft) || strings.Contains(l, logCheckAgain) {
		t.Errorf("a NOTIFY that was dropped left, or was checked:\n%s", l)
	}

	parentSyncStep(t, r.conf, r.mpzd, parentSyncAgent)
	r.propagation(0)
	r.ask()
	r.notified(t, "the agents sync the zone again", dns.TypeCSYNC)
}

// A request that was on the syncher's queue when the owner took the sync
// over is not sent: the syncher asks the option again, as it asks whether
// this agent is still the leader.
func TestASyncQueuedBeforeTheOwnerTookOverIsNotSent(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "queued.notify.example.", "NOTIFY", time.Hour)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	// what a refresh that found a delegation change queued, while the
	// agents still synced the zone
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)
	if r.mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the owner took the sync over, and the agent still syncs the zone")
	}

	r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, SyncStatus: dss}
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, Response: resp}
	select {
	case st := <-resp:
		if want := "the zone's owner syncs its delegation, skipping DDNS"; st.Msg != want {
			t.Errorf("the explicit sync answered %q, want %q", st.Msg, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the explicit sync did not answer")
	}
	r.quiet(t, 300*time.Millisecond, "for a request queued before the owner took over")
	r.untold(t, 0, "for a request queued before the owner took over")
}

// An election, a lease renewal and gossip each start the leader's
// setup in a goroutine of their own. For one zone the setups run one at a
// time, so two cannot both find no SIG(0) key and make one each. Setups for
// different zones still run together.
func TestTheLeadersSetupRunsOneAtATimePerZone(t *testing.T) {
	lem := NewLeaderElectionManager("agent.us.example.", time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	const a, b = ZoneName("a.example."), ZoneName("b.example.")
	var inA, mostInA atomic.Int32
	bRunning := make(chan struct{})
	lem.SetOnLeaderElected(func(z ZoneName) error {
		if z == b {
			close(bRunning)
			return nil
		}
		n := inA.Add(1)
		for {
			m := mostInA.Load()
			if n <= m || mostInA.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inA.Add(-1)
		return nil
	})

	done := make(chan struct{}, 4)
	for range 4 {
		go func() { _ = lem.onLeaderElected(a); done <- struct{}{} }()
	}
	// a's setups hold its lock; b's runs anyway
	go func() { _ = lem.onLeaderElected(b) }()
	select {
	case <-bRunning:
	case <-time.After(5 * time.Second):
		t.Fatal("a setup for another zone waited for this zone's")
	}
	for range 4 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a setup did not end")
		}
	}
	if m := mostInA.Load(); m != 1 {
		t.Errorf("%d setups for one zone ran at once, want 1", m)
	}
}

const logSyncStopped = `msg="the delegation sync under way is stopped: the zone's owner syncs its delegation"`

// The owner takes the sync over while the leader's UPDATE is in tdns's retry
// loop: the parent answered REFUSED, and the loop sends the UPDATE again after
// its wait. The refresh that brings the owner's word stops the sync, and the
// UPDATE is not sent again. It was: a multi-host run saw an ADD, refused
// before the owner's edit, applied after it.
func TestTheOwnerTakingTheSyncOverStopsAnUpdateBeingRetried(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "retried.update.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, r.mpzd.KeyDB, z)
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

	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner) // before the retry's wait is over
	if l := r.log.String(); !strings.Contains(l, logSyncStopped+" zone="+z+" syncs=1") {
		t.Errorf("the step did not stop the sync under way:\n%s", l)
	}
	for deadline := time.Now().Add(10 * time.Second); underWay() > 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the sync went on after the owner took the sync over")
		}
	}
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one sent before the owner took over", n)
	}
	r.untold(t, 0, "for a sync the owner stopped")
}

// A sync that starts after the owner took the sync over sends nothing, also
// when the takeover came after the syncher's own check. It went down the
// plain path, as for a zone with one provider: on the syncher's context, and
// the peers were told it was done.
func TestASyncThatStartsAfterTheTakeoverSendsNothing(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "late.update.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, r.mpzd.KeyDB, z)
	r.parent.holdsNS("ns1."+z, r.oldNS)
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	// the owner takes over after the syncher has checked the option
	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)

	hdb := &HsyncDB{KeyDB: r.mpzd.KeyDB}
	ds := tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, SyncStatus: dss}
	_, _, _, pending, err := hdb.syncDelegation(r.ctx, r.conf, r.notifyq, ds, dss, (&Imr{r.conf.Config.Internal.ImrEngine}).Imr)
	if err == nil || pending {
		t.Errorf("a sync that started after the takeover returned err=%v pending=%v, want the owner's refusal", err, pending)
	}
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("the parent got %d UPDATEs after the owner took the sync over", n)
	}
}

// The owner takes the sync over after a sync last looked at the option, and
// before it hands its NOTIFY over. The takeover ended the zone's chain, and
// the handoff made it again, without the CSYNC the takeover forgot, and sent
// the NOTIFY on. It now finds its run cancelled, under the same lock, and
// sends nothing.
func TestANotifyHandedOverAfterTheTakeoverIsNotSent(t *testing.T) {
	asMPAgent(t)
	for _, wait := range []time.Duration{0, time.Hour} { // sent at once, and held
		t.Run(fmt.Sprintf("wait %v", wait), func(t *testing.T) {
			handedOverAfterTheTakeover(t, wait)
		})
	}
}

func handedOverAfterTheTakeover(t *testing.T, wait time.Duration) {
	r := newNotifyRig(t, "handoff.notify.example.", "NOTIFY", repeat(time.Hour, 3)...)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	z := r.mpzd.ZoneName
	run, done := r.conf.delegationSyncRun(r.ctx, z) // a sync under way, past its last look
	defer done()

	parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)

	out := make(chan tdns.NotifyRequest, 4)
	held, failed := r.conf.delegationSyncNotifiedWith(r.ctx, z, delegationNotifies{
		requests: []tdns.NotifyRequest{{ZoneName: z, RRtype: dns.TypeCSYNC}}, out: out, run: run, wait: wait}, repeat(time.Hour, 3))
	if failed == nil || held {
		t.Errorf("the handoff after the takeover: held=%v failed=%v, want the owner's refusal", held, failed)
	}
	if len(out) != 0 {
		t.Errorf("%d NOTIFYs were sent on after the owner took the sync over", len(out))
	}
	if n := r.chains(); n != 0 {
		t.Errorf("the handoff made the zone's chain again: %d chains", n)
	}
}

// The same takeover, through the sync itself: it lands after the sync's last
// look at the option and before the handoff. The handoff refuses, and the
// sync does not take that for a failure to ask again: that made the chain
// again, right after the takeover had ended it, and scheduled an ask.
func TestATakeoverJustBeforeTheHandoffLeavesNoChain(t *testing.T) {
	asMPAgent(t)
	r := newNotifyRig(t, "beforehandoff.notify.example.", "NOTIFY", repeat(time.Hour, 3)...)
	servedParentSync(t, r.mpzd, &parentSyncAgent, false)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	took := false
	saved := delegationSyncBeforeHandoff
	delegationSyncBeforeHandoff = func(zone string) {
		if zone == z && !took {
			took = true
			parentSyncStep(t, r.conf, r.mpzd, parentSyncOwner)
		}
	}
	t.Cleanup(func() { delegationSyncBeforeHandoff = saved })

	hdb := &HsyncDB{KeyDB: r.mpzd.KeyDB}
	ds := tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, SyncStatus: dss}
	_, _, _, pending, err := hdb.syncDelegation(r.ctx, r.conf, r.notifyq, ds, dss, (&Imr{r.conf.Config.Internal.ImrEngine}).Imr)
	if !took {
		t.Fatal("the sync handed nothing over: no NOTIFY to judge")
	}
	if err == nil || pending {
		t.Errorf("the sync returned err=%v pending=%v, want the handoff's refusal", err, pending)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains after a takeover just before the handoff, want none", n)
	}
	if l := r.log.String(); strings.Contains(l, "the delegation sync failed; asking again") {
		t.Errorf("the refused handoff was taken for a failure to ask again:\n%s", l)
	}
	r.quiet(t, 300*time.Millisecond, "after a takeover just before the handoff")
}

// The owner's edit removes this agent from the zone and changes the
// delegation. PostRefresh queues the delegation sync before it applies the
// HSYNC diff, so the syncher could judge the lead on the old groups and sync
// once as a leader the agent no longer is. It now asks first whether the agent
// still participates in the zone, which the refresh has already published.
func TestAnAgentTheZoneNoLongerHasSyncsNothing(t *testing.T) {
	asMPAgent(t)
	// With the option off too, as for an agent the zone's records do not
	// name: the reason given is still that it no longer participates.
	for _, optionOn := range []bool{true, false} {
		t.Run(fmt.Sprintf("option %v", optionOn), func(t *testing.T) {
			noLongerParticipates(t, optionOn)
		})
	}
}

func noLongerParticipates(t *testing.T, optionOn bool) {
	r := newNotifyRig(t, "removed.update.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
	r.propagation(0)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, r.mpzd.KeyDB, z)
	r.parent.holdsNS("ns1."+z, r.oldNS)
	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}

	// The zone as the owner's edit left it: two providers, neither this
	// agent; the agents still sync it, and the leader map still says this
	// agent leads.
	apex, _ := r.mpzd.Data.Get(z)
	var h3 []dns.RR
	for _, id := range []string{"eu.provider.example.", "as.provider.example."} {
		h3 = append(h3, &dns.PrivateRR{Hdr: dns.RR_Header{Name: z, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
			Data: &core.HSYNC3{State: 1, Label: shortLabel(id), Identity: id, Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3})
	hp, err := dns.NewRR(z + ` 3600 IN HSYNCPARAM servers="eu,as" parentsync="agent" serial="2"`)
	if err != nil {
		t.Fatalf("HSYNCPARAM: %v", err)
	}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{hp}})
	r.mpzd.Data.Set(z, apex)
	r.mpzd.InstallInitialSnapshot()
	// the lease still names this agent; the lead no longer counts where it
	// does not vote (IsLeader, decision 34), and the syncher's first test
	// is whether it takes part at all
	if leader, ok := r.lem.GetLeader(ZoneName(z)); !ok || leader != AgentId(r.us.Identity) {
		t.Fatal("the rig does not start with this agent's lease for the zone")
	}
	if !optionOn {
		r.mpzd.SetRuntimeOption(tdns.OptParentSync, false)
	}

	r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, SyncStatus: dss}
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, Response: resp}
	select {
	case st := <-resp:
		if want := "this agent no longer participates in the zone, skipping DDNS"; st.Msg != want {
			t.Errorf("the explicit sync answered %q, want %q", st.Msg, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the explicit sync did not answer")
	}
	time.Sleep(300 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("the parent got %d UPDATEs from an agent the zone no longer has", n)
	}
	r.untold(t, 0, "from an agent the zone no longer has")
}
