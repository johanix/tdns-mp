/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// holdRig is the notify rig with the leader's catch-up tracker, in place
// before the syncher starts, as initMPAgent gives it. The zone is not
// caught up until caughtUp: its own read is not done, and its peer has not
// answered.
type holdRig struct {
	*notifyRig
	tr *catchUpTracker
}

func newHoldRig(t *testing.T, zone, scheme string, signed bool, delays ...time.Duration) *holdRig {
	t.Helper()
	h := &holdRig{}
	h.notifyRig = newNotifyRigWith(t, zone, scheme, signed, func(r *notifyRig) {
		tr := newCatchUpTracker(AgentId(r.us.Identity), []string{zone}, time.Hour)
		tr.askSync, tr.owedApplies = r.conf.askOwedDelegationSync, r.conf.owedSyncApplies
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		tr.run(r.ctx, zdr)
		r.conf.InternalMp.CatchUp, r.us.Bridge.catchUp = tr, tr
		h.tr = tr
	}, delays...)
	return h
}

// caughtUp: the zone's own read is done, and the peer has answered
// complete.
func (h *holdRig) caughtUp() {
	z := ZoneName(h.mpzd.ZoneName)
	h.tr.mu.Lock()
	zdr := h.tr.zdr
	e := h.tr.entryLocked(z, AgentId(h.peer.Identity))
	e.State, e.Complete, e.Answered = catchUpIdle, true, time.Now()
	h.tr.mu.Unlock()
	zdr.markOwnState(z, true, "")
}

// notCaughtUp: a new request to the peer is outstanding (the operator's).
func (h *holdRig) notCaughtUp() {
	h.tr.Ask(ZoneName(h.mpzd.ZoneName), AgentId(h.peer.Identity), catchUpManual)
}

func (h *holdRig) owed() bool {
	owed, _ := h.tr.owedState(ZoneName(h.mpzd.ZoneName))
	return owed
}

// askOwed is what the data engine does after the answer that completes the
// catch-up.
func (h *holdRig) askOwed() {
	h.tr.askOwed(h.ctx, ZoneName(h.mpzd.ZoneName))
}

func (h *holdRig) waitOwed(t *testing.T, what string) {
	t.Helper()
	waitUntil(t, what+": the sync was not owed\n"+h.log.String(), h.owed)
}

// A leader's sync with the parent is held while the zone is not caught up:
// nothing is sent, and the sync is owed. Once the zone is caught up, the
// owed sync is asked for, looks at the parent, and sends.
func TestALeadersSyncIsHeldUntilTheZoneIsCaughtUp(t *testing.T) {
	h := newHoldRig(t, "held.sync.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.parent.holdsDS() // the parent has no DS
	h.inventory(h.ksk) // the DS set changes: a sync is asked for
	h.waitOwed(t, "the DS change")
	h.quiet(t, 200*time.Millisecond, "while the zone is not caught up")

	h.caughtUp()
	h.askOwed()
	h.notified(t, "the owed sync", dns.TypeCDS)
	if h.owed() {
		t.Error("the sync is still owed after it was asked for")
	}
}

// A parent that does not answer, while the zone catches up and after: the
// sync is not lost. While the zone is not caught up the sync is held, and
// the parent is not asked. Once it is caught up, a query that fails leaves
// the sync owed; it is asked again while it is owed, and sent once the
// parent answers.
func TestASyncWhoseParentDoesNotAnswerStaysOwed(t *testing.T) {
	h := newHoldRig(t, "silent.owed.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.parent.holdsDS() // the parent has no DS
	h.parent.quiet(true)
	before := h.parent.queriesSeen()
	h.inventory(h.ksk) // the DS set changes: a sync is asked for
	h.waitOwed(t, "the DS change")
	time.Sleep(200 * time.Millisecond)
	if n := h.parent.queriesSeen() - before; n != 0 {
		t.Errorf("the parent was asked %d questions while the zone was not caught up", n)
	}

	h.caughtUp()
	asked := h.parent.queriesSeen()
	h.askOwed() // the parent does not answer
	waitUntil(t, "the owed sync did not ask the parent", func() bool { return h.parent.queriesSeen() > asked })
	h.waitOwed(t, "the sync whose query failed")
	h.quiet(t, 200*time.Millisecond, "while the parent did not answer")

	h.parent.quiet(false)
	h.askOwed()
	h.notified(t, "the owed sync, once the parent answers", dns.TypeCDS)
	if h.owed() {
		t.Error("the sync is still owed after it was sent")
	}
}

// Both sync commands are held: the implicit sync of a refresh and the
// explicit one, so that NS and glue wait as the DS does.
func TestBothSyncCommandsAreHeld(t *testing.T) {
	h := newHoldRig(t, "both.held.example.", "UPDATE", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	if _, err := h.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	h.parent.holdsNS("ns1."+z, h.oldNS) // the parent has an NS the zone no longer lists
	h.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData,
		SyncStatus: tdns.DelegationSyncStatus{ZoneName: z}}
	h.waitOwed(t, "the implicit sync")
	h.tr.clearOwed(ZoneName(z))
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData}
	h.waitOwed(t, "the explicit sync")
	time.Sleep(200 * time.Millisecond)
	if n := h.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent while the zone was not caught up", n)
	}
	h.caughtUp()
	h.askOwed()
	waitUntil(t, "the owed sync sent no UPDATE\n"+h.log.String(), func() bool { return h.parent.updatesSeen() > 0 })
}

// The operator's delegation sync of a held zone is answered at once: the
// sync is held, and whom it waits for, with no error.
func TestAHeldExplicitSyncAnswersTheOperator(t *testing.T) {
	h := newHoldRig(t, "operator.held.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	resp := make(chan tdns.DelegationSyncStatus, 1)
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 4*time.Second) // the API waits 4 s
	if !ok {
		t.Fatal("the operator got no answer")
	}
	if got.Error || !strings.Contains(got.Msg, "held until the zone is caught up") || !strings.Contains(got.Msg, h.peer.Identity) ||
		!strings.Contains(got.Msg, "this agent's own state") {
		t.Errorf("the operator's answer: error=%v %q", got.Error, got.Msg)
	}
}

// The owed sync looks at the parent before it sends: a parent that came
// into step during the hold gets nothing. A held sync is not sent as it
// was.
func TestAHeldSyncLooksAtTheParentBeforeItSends(t *testing.T) {
	h := newHoldRig(t, "looks.first.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.parent.holdsDS()
	h.inventory(h.ksk)
	h.waitOwed(t, "the DS change")
	h.parent.holdsDS(h.ds) // the parent got the DS by itself
	h.caughtUp()
	h.askOwed()
	h.quiet(t, 300*time.Millisecond, "a parent in step with the zone")
	if h.owed() {
		t.Error("the sync is still owed")
	}
}

// A NOTIFY that waits for the zone's wait is dropped when the zone stops
// being caught up before it leaves, and the sync is owed. Caught up again,
// the owed sync sends anew, after a new wait.
func TestAWaitingNotifyIsDroppedWhenTheZoneIsNoLongerCaughtUp(t *testing.T) {
	const wait = 300 * time.Millisecond
	h := newHoldRig(t, "dropped.wait.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.propagation(wait)
	h.caughtUp()
	h.parent.holdsDS()
	h.inventory(h.ksk)
	h.logged(t, 1, logHeld)
	h.notCaughtUp() // the operator asks the peer again during the wait
	h.logged(t, 1, `msg="the held NOTIFY is dropped: the zone is not caught up; the sync is owed"`)
	h.quiet(t, wait, "after the drop")
	if !h.owed() {
		t.Fatal("the dropped NOTIFY's sync is not owed")
	}
	h.caughtUp()
	h.askOwed()
	h.logged(t, 2, logHeld)
	h.notified(t, "the owed sync, after its wait", dns.TypeCDS)
}

// An agent that does not lead the zone holds nothing and owes nothing: its
// syncs are refused as before.
func TestAnAgentThatDoesNotLeadHoldsNothing(t *testing.T) {
	h := newHoldRig(t, "notleader.held.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.leader(AgentId(h.peer.Identity))
	z := h.mpzd.ZoneName
	resp := make(chan tdns.DelegationSyncStatus, 1)
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 4*time.Second)
	if !ok || !strings.Contains(got.Msg, "not the delegation sync leader") {
		t.Errorf("the answer: %+v", got)
	}
	if h.owed() {
		t.Error("an agent that does not lead owes a sync")
	}
}

// The owed mark is cleared when the lead is lost: by the syncher, for a
// sync that finds this agent no longer leads, and by the ask, which then
// asks nothing.
func TestTheOwedMarkIsClearedWhenTheLeadIsLost(t *testing.T) {
	h := newHoldRig(t, "lead.lost.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	h.parent.holdsDS()
	h.inventory(h.ksk)
	h.waitOwed(t, "the DS change")
	h.leader(AgentId(h.peer.Identity))
	h.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData}
	waitUntil(t, "the owed mark was kept after the lead was lost", func() bool { return !h.owed() })

	// the ask of an agent that no longer leads asks nothing, and clears the mark
	h.leader(h.lem.localID)
	h.tr.owe(ZoneName(z))
	h.leader(AgentId(h.peer.Identity))
	h.caughtUp()
	h.tr.askAllOwed(h.ctx, false)
	if h.owed() {
		t.Error("the owed mark was kept by an ask of an agent that does not lead")
	}
	h.quiet(t, 200*time.Millisecond, "after the lead was lost")
}

// The owed mark is cleared when this agent stops taking part in the zone
// (step 1's end of the zone's work), and when the owner takes the sync
// over.
func TestTheOwedMarkIsClearedWhenTheAgentLeavesTheZone(t *testing.T) {
	h := newHoldRig(t, "agent.leaves.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	z := ZoneName(h.mpzd.ZoneName)
	h.tr.owe(z)
	h.conf.endDelegationSyncWork(string(z))
	if h.owed() {
		t.Error("the owed mark was kept when the agent left the zone")
	}
	h.tr.owe(z)
	h.conf.delegationSyncOwnerSyncs(string(z))
	if h.owed() {
		t.Error("the owed mark was kept when the owner took the sync over")
	}
}

// The leader of a signed zone that is not caught up makes no CSYNC for an
// NS change: the hold is before the CSYNC. Caught up, the owed sync makes
// it, and its NOTIFY waits for the providers' confirmations.
func TestALeaderThatIsNotCaughtUpMakesNoCSYNC(t *testing.T) {
	awaitedEvery(t, time.Hour)
	h := newHoldRig(t, "nocsync.held.example.", "NOTIFY", true, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	h.parent.holdsNS("ns1."+z, h.oldNS)
	h.ask()
	h.waitOwed(t, "the NS change")
	time.Sleep(200 * time.Millisecond)
	if l := h.log.String(); strings.Contains(l, logCsyncMade) {
		t.Fatalf("a CSYNC was made while the zone was not caught up\n%s", l)
	}
	for _, info := range h.repo(t)[h.lem.localID][dns.TypeCSYNC] {
		t.Fatalf("the leader holds a CSYNC: %s", info.RR)
	}
	h.caughtUp()
	h.askOwed()
	h.csync(t, "")
	h.logs(t, logCsyncWaits)
}

// An NS change during the hold of a sync whose NOTIFY(CSYNC) went out: the
// chain forgets that NOTIFY, so the owed sync is not taken for the chain's
// check of it. It makes a new CSYNC for the new difference, and its NOTIFY
// waits for the confirmations (#151).
func TestAnNSChangeDuringTheHoldGetsANewCSYNCAndAHeldNotify(t *testing.T) {
	awaitedEvery(t, time.Hour)
	h := newHoldRig(t, "nschange.held.example.", "NOTIFY", true, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	peer := h.peer.Identity
	h.caughtUp()
	h.parent.holdsNS("ns1."+z, h.oldNS)
	h.ask()
	info, _ := h.csync(t, "")
	h.confirms(rigCombiner, info.DistributionID, info.RR)
	h.confirms(peer, info.DistributionID, info.RR)
	h.notified(t, "the first CSYNC's NOTIFY", dns.TypeCSYNC)

	// the zone stops being caught up, and a sync is held while the chain's
	// NOTIFY is out
	h.notCaughtUp()
	h.ask()
	h.waitOwed(t, "the held sync")
	if notified, rechecks := h.chainNotified(z); notified != "" || rechecks != 0 {
		t.Fatalf("the chain still has its NOTIFY(%s) out, with %d checks, after the hold", notified, rechecks)
	}

	// the zone's NS set changes during the hold: the parent now differs
	// otherwise, and the owed sync makes a new CSYNC and holds its NOTIFY
	h.parent.holdsNS("ns1."+z, h.oldNS, "another.gone.example.")
	h.caughtUp()
	h.askOwed()
	second, _ := h.csync(t, info.RR)
	if second.RR == info.RR {
		t.Fatal("the owed sync made no new CSYNC")
	}
	h.logged(t, 2, logCsyncWaits)
	h.quiet(t, 200*time.Millisecond, "before the new CSYNC was confirmed")
}

// A zone with one voting member, this agent, waits for its own read only.
// The hold's line says what it waits for.
func TestAZoneWithOneVotingMemberWaitsForItsOwnReadOnly(t *testing.T) {
	const zone = "alone.held.example."
	catchUpZone(t, zone, []string{roleA}, nil, nil)
	mpzd, _ := Zones.Get(zone)
	mpzd.Options[tdns.OptParentSync] = true
	r := newTrackerRig(t, roleA)
	r.run()
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.CatchUp = r.t
	var buf lockedBuffer
	saved := lg
	lg = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg = saved })
	ds := tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: zone, ZoneData: mpzd.ZoneData}
	if held, waiting := conf.holdLeaderSync(ds); !held || !strings.Contains(waiting, "this agent's own state") || strings.Contains(waiting, ".role.example.") {
		t.Fatalf("before the own read: held=%v, waiting for %q", held, waiting)
	}
	if !strings.Contains(buf.String(), `msg="DelegationSyncher: the sync with the parent is held until the zone is caught up" zone=`+zone) {
		t.Errorf("the hold's line: %s", buf.String())
	}
	r.zdr.markOwnState(zone, true, "")
	if held, _ := conf.holdLeaderSync(ds); held {
		t.Error("held after the own read")
	}
}

// An owed sync that finds the delegation sync queue full stays owed, one
// warning per pass, and is queued once there is room.
func TestAnOwedSyncWaitsForRoomInAFullQueue(t *testing.T) {
	r, tr := owedRig(t, "full.queue.example.", true)
	z := ZoneName(r.mpzd.ZoneName)
	var buf lockedBuffer
	saved := lg
	lg = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg = saved })
	for range cap(r.q) {
		r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: string(z)}
	}
	tr.owe(z)
	tr.askAllOwed(r.ctx, false)
	tr.askAllOwed(r.ctx, true)
	if owed, room := tr.owedState(z); !owed || !room {
		t.Fatalf("with the queue full: owed=%v room=%v", owed, room)
	}
	if n := strings.Count(buf.String(), `msg="the delegation sync queue is full: owed syncs wait for room" waiting=1`); n != 2 {
		t.Errorf("%d warnings for two passes, want 2\n%s", n, buf.String())
	}
	<-r.q
	tr.askAllOwed(r.ctx, true)
	if owed, _ := tr.owedState(z); owed {
		t.Error("the sync is still owed after it was queued")
	}
	var got []string
	for len(r.q) > 0 {
		got = append(got, (<-r.q).Command)
	}
	if n := strings.Count(strings.Join(got, " "), "EXPLICIT-SYNC-DELEGATION"); n != 1 {
		t.Errorf("the queue holds %v, want one explicit sync", got)
	}
}

// A pass stops at the first full queue: one warning, naming how many zones
// wait, and the zones after it are not tried; they wait for room too, and
// are asked again within seconds.
func TestAPassStopsAtTheFirstFullQueue(t *testing.T) {
	r, tr := owedRig(t, "a.stops.example.", true)
	second := newLeaderSyncRig(t, "b.stops.example.")
	second.mpzd.Ready = true
	second.mpzd.DelegationSyncQ = r.q // one queue for every zone of the agent
	z1, z2 := ZoneName(r.mpzd.ZoneName), ZoneName(second.mpzd.ZoneName)
	r.lem.mu.Lock()
	r.lem.elections[z2] = &LeaderElection{Zone: z2, Leader: usAgent, LeaderExpiry: time.Now().Add(time.Hour)}
	r.lem.mu.Unlock()
	tr.zdr.markOwnState(z2, true, "")
	var buf lockedBuffer
	saved := lg
	lg = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg = saved })
	for range cap(r.q) {
		r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: string(z1)}
	}
	tr.owe(z1)
	tr.owe(z2)
	tr.askAllOwed(r.ctx, false)
	if n := strings.Count(buf.String(), `msg="the delegation sync queue is full: owed syncs wait for room" waiting=2`); n != 1 {
		t.Errorf("the pass warned %d times with both zones waiting, want once\n%s", n, buf.String())
	}
	if _, room := tr.owedState(z2); !room {
		t.Error("the zone after the full queue does not wait for room")
	}
}

// The engine's ask at catch-up and the tracker's retry, at once, queue the
// owed sync once.
func TestAnOwedSyncIsNotAskedTwice(t *testing.T) {
	r, tr := owedRig(t, "asked.once.example.", true)
	z := ZoneName(r.mpzd.ZoneName)
	for range 50 {
		tr.owe(z)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); tr.askOwed(r.ctx, z) }()
		go func() { defer wg.Done(); tr.askAllOwed(r.ctx, false) }()
		wg.Wait()
		if n := len(r.q); n != 1 {
			t.Fatalf("%d syncs queued for one owed sync", n)
		}
		<-r.q
	}
}

// owedRig is a leader's zone, with its delegation sync queue and nothing
// reading it, and the tracker asking for owed syncs on it. The zone has no
// other voting member: it is caught up once its own read is done (ownRead).
func owedRig(t *testing.T, zone string, ownRead bool) (*leaderSyncRig, *catchUpTracker) {
	t.Helper()
	r := newLeaderSyncRig(t, zone)
	r.mpzd.Ready = true
	r.leader(usAgent)
	tr := newCatchUpTracker(usAgent, nil, time.Hour)
	tr.askSync, tr.owedApplies = r.conf.askOwedDelegationSync, r.conf.owedSyncApplies
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tr.run(ctx, zdr)
	if ownRead {
		zdr.markOwnState(ZoneName(r.mpzd.ZoneName), true, "")
	}
	r.conf.InternalMp.CatchUp = tr
	return r, tr
}

// The status says that the leader's sync is held, or owed and waiting for
// room in the queue.
func TestTheStatusSaysTheSyncIsHeldOrOwed(t *testing.T) {
	r, tr := owedRig(t, "status.owed.example.", false)
	z := ZoneName(r.mpzd.ZoneName)
	ar := &AgentRegistry{MPTransport: &MPTransportBridge{catchUp: tr}}
	status := func() string { return r.lem.GetParentSyncStatus(z, nil, nil, nil, ar, nil).ParentSync }
	if got := status(); got != "" {
		t.Errorf("nothing owed: %q", got)
	}
	tr.owe(z)
	if got := status(); got != "held until the zone is caught up" {
		t.Errorf("owed, not caught up: %q", got)
	}
	tr.zdr.markOwnState(z, true, "")
	for range cap(r.q) {
		r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: string(z)}
	}
	tr.askAllOwed(r.ctx, false)
	if got := status(); got != "owed, the delegation sync queue is full" {
		t.Errorf("owed, waiting for room: %q", got)
	}
	r.leader(otherAgent)
	if got := status(); got != "" {
		t.Errorf("an agent that does not lead shows %q", got)
	}
}

// With NS and glue in step with the parent and no DS set to compare, for a
// zone that names a signer, the leader does not say "in sync": it says that
// the DS set is unknown, and whom it waits for.
func TestNSInSyncAndDSUnknownIsNotReportedInSync(t *testing.T) {
	const zone = "dsunknown.insync.example."
	h := &holdRig{}
	h.notifyRig = newNotifyRigWith(t, zone, "NOTIFY", false, func(r *notifyRig) {
		tr := newCatchUpTracker(AgentId(r.us.Identity), []string{zone}, time.Hour)
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		tr.run(r.ctx, zdr)
		r.conf.InternalMp.CatchUp, r.us.Bridge.catchUp = tr, tr
		h.tr = tr
		// the other provider signs the zone, and our agent computes its DS set
		r.conf.InternalMp.KeyLifecycleOwner.SetComputedDSSource(r.conf.computedDSIntent)
		apex, _ := r.mpzd.OwnerForAnalysis(zone)
		hp := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM).RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
		hp.Value = append(hp.Value, &core.HSYNCPARAMSigners{Signers: []string{shortLabel(r.peer.Identity)}})
		r.mpzd.Data.Set(zone, *apex)
		r.mpzd.InstallInitialSnapshot()
	}, repeat(time.Hour, 4)...)
	h.caughtUp()
	resp := make(chan tdns.DelegationSyncStatus, 1)
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zone, ZoneData: h.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 4*time.Second)
	if !ok {
		t.Fatal("no answer")
	}
	want := "NS and glue are in sync with the parent; the DS set is unknown, waiting for " + h.peer.Identity + " (not spoken)"
	if got.Msg != want {
		t.Errorf("the answer: %q, want %q", got.Msg, want)
	}
	h.quiet(t, 100*time.Millisecond, "an unknown DS set")

	// A chain that sent a NOTIFY ends the same way, and nobody is told that
	// the parent is in sync with the zone.
	c := &h.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	if c.zones == nil {
		c.zones = map[string]*delegationSyncChain{}
	}
	c.zones[zone] = &delegationSyncChain{notified: "CSYNC", rechecks: 1}
	c.mu.Unlock()
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zone, ZoneData: h.mpzd.ZoneData, Response: resp}
	if got, ok = recvWithin(resp, 4*time.Second); !ok || got.Msg != want {
		t.Fatalf("the answer after a NOTIFY: %q, want %q", got.Msg, want)
	}
	if notified, rechecks := h.chainNotified(zone); notified != "" || rechecks != 0 {
		t.Errorf("the chain still has %q out with %d checks", notified, rechecks)
	}
	h.logged(t, 1, `msg="NS and glue are in sync with the parent after the NOTIFY; the DS set is unknown, so the peers are not told that the sync is done" zone=`+zone+" notify=CSYNC checks=1")
	h.untold(t, 300*time.Millisecond, "the DS set unknown after a NOTIFY")
}

// The answer that completes the catch-up asks, from the data engine, for the
// sync that was owed.
func TestTheAnswerThatCompletesTheCatchUpAsksForTheOwedSync(t *testing.T) {
	const zone = "answer.owed.example."
	tr := newTrackerRig(t, roleA)
	tr.setUp(roleB, true)
	var asked, spoke atomic.Int32
	var r *engineRig
	// the sync computes the DS set from what the answer said about keys:
	// that is noted before the sync is asked for
	tr.t.askSync = func(context.Context, ZoneName) owedResult {
		asked.Add(1)
		if len(r.keyStates(roleB)) == 1 {
			spoke.Add(1)
		}
		return owedQueued
	}
	r = newEngineRigWith(t, zone, func(conf *Config) {
		zd, _ := Zones.Get(zone)
		zd.Options[tdns.OptMultiProvider] = true
		zd.EnsureMP()
		zd.MP.MPdata = &MPdata{WeAreProvider: true}
		conf.InternalMp.CatchUp = tr.t
	})
	tr.t.Ask(ZoneName(zone), roleB, catchUpStart)
	sent := tr.waitSends(t, 1)
	tr.t.owe(ZoneName(zone))
	tr.t.mu.Lock()
	zdr := tr.t.zdr
	tr.t.mu.Unlock()
	zdr.markOwnState(ZoneName(zone), true, "")
	if n := asked.Load(); n != 0 {
		t.Fatalf("%d asks before the answer", n)
	}
	r.remote(t, roleB, time.Now(), "d1", completeAnswer(sent[0].request), dnskeyOp(t, zone, KeyStateActive, true))
	waitUntil(t, "the answer did not ask for the owed sync", func() bool { return asked.Load() == 1 })
	if spoke.Load() != 1 {
		t.Error("the owed sync was asked for before the answer's key states were noted")
	}
	if owed, _ := tr.t.owedState(ZoneName(zone)); owed {
		t.Error("the sync is still owed")
	}
}

// A zone can become caught up with no answer: here a refresh takes the
// voting member it waited for away. The engine's tick asks for the owed
// sync.
func TestAZoneThatIsCaughtUpByARefreshAsksForTheOwedSync(t *testing.T) {
	const zone = "refresh.owed.example."
	saved := ownReadInterval
	ownReadInterval = 20 * time.Millisecond
	t.Cleanup(func() { ownReadInterval = saved })
	tr := newTrackerRig(t, roleA)
	var asked atomic.Int32
	tr.t.askSync = func(context.Context, ZoneName) owedResult { asked.Add(1); return owedQueued }
	var zd *tdns.ZoneData
	newEngineRigWith(t, zone, func(conf *Config) {
		mpzd, _ := Zones.Get(zone)
		zd = mpzd.ZoneData
		mpzd.Options[tdns.OptMultiProvider] = true
		mpzd.EnsureMP()
		mpzd.MP.MPdata = &MPdata{WeAreProvider: true}
		conf.InternalMp.CatchUp = tr.t
	})
	waitUntil(t, "the engine did not run the tracker", func() bool {
		tr.t.mu.Lock()
		defer tr.t.mu.Unlock()
		return tr.t.zdr != nil
	})
	tr.t.mu.Lock()
	zdr := tr.t.zdr
	tr.t.mu.Unlock()
	zdr.markOwnState(ZoneName(zone), true, "")
	tr.t.owe(ZoneName(zone))
	time.Sleep(100 * time.Millisecond)
	if n := asked.Load(); n != 0 {
		t.Fatalf("%d asks while the zone waited for its other voting member", n)
	}
	setRoles(t, zd, []string{roleA}, nil) // the refresh: b.role.example. has no role any more
	waitUntil(t, "the tick did not ask for the owed sync", func() bool { return asked.Load() == 1 })
}

// An owed sync is not asked for by an agent that does not lead the zone, nor
// for a zone that is gone: the mark is cleared and nothing is queued.
func TestAnOwedSyncIsNotAskedWhereItNoLongerApplies(t *testing.T) {
	r, tr := owedRig(t, "notasked.owed.example.", false)
	z := ZoneName(r.mpzd.ZoneName)
	r.leader(otherAgent)
	// not caught up either: the mark goes all the same
	tr.owe(z)
	tr.askAllOwed(r.ctx, false)
	if owed, _ := tr.owedState(z); owed {
		t.Error("an agent that does not lead kept its mark while the zone was not caught up")
	}
	tr.zdr.markOwnState(z, true, "")
	tr.owe(z)
	tr.askAllOwed(r.ctx, false)
	if owed, _ := tr.owedState(z); owed || len(r.q) != 0 {
		t.Errorf("an agent that does not lead: owed=%v, %d queued", owed, len(r.q))
	}
	r.leader(usAgent)
	tr.owe(z)
	tdns.Zones.Remove(string(z))
	tr.askAllOwed(r.ctx, false)
	if owed, _ := tr.owedState(z); owed || len(r.q) != 0 {
		t.Errorf("a zone that is gone: owed=%v, %d queued", owed, len(r.q))
	}
}

// A zone that names no signer has no DS set to wait for: NS and glue in
// step with the parent are "in sync", as before.
func TestAZoneThatNamesNoSignerIsReportedInSync(t *testing.T) {
	h := newHoldRig(t, "nosigner.insync.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	h.conf.InternalMp.KeyLifecycleOwner.SetComputedDSSource(h.conf.computedDSIntent)
	h.caughtUp()
	resp := make(chan tdns.DelegationSyncStatus, 1)
	h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: h.mpzd.ZoneName, ZoneData: h.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 4*time.Second)
	if !ok || !got.InSync || strings.Contains(got.Msg, "unknown") || strings.Contains(got.Msg, "held") {
		t.Errorf("the answer: ok=%v in sync=%v %q", ok, got.InSync, got.Msg)
	}
}

// An owed sync that found the delegation sync queue full is asked for again
// by the data engine within seconds, not at the next tick of the own read.
func TestAnOwedSyncThatFoundNoRoomIsAskedAgainSoon(t *testing.T) {
	const zone = "room.retry.example."
	savedRoom := catchUpRoomRetry
	catchUpRoomRetry = 20 * time.Millisecond
	t.Cleanup(func() { catchUpRoomRetry = savedRoom })
	tr := newTrackerRig(t, roleA)
	var asked atomic.Int32
	tr.t.askSync = func(context.Context, ZoneName) owedResult {
		if asked.Add(1) == 1 {
			return owedQueueFull
		}
		return owedQueued
	}
	newEngineRigWith(t, zone, func(conf *Config) {
		mpzd, _ := Zones.Get(zone)
		mpzd.Options[tdns.OptMultiProvider] = true
		conf.InternalMp.CatchUp = tr.t
	})
	setRolesOf(t, zone, []string{roleA})
	waitUntil(t, "the engine did not run the tracker", func() bool {
		tr.t.mu.Lock()
		defer tr.t.mu.Unlock()
		return tr.t.zdr != nil
	})
	tr.t.mu.Lock()
	zdr := tr.t.zdr
	tr.t.mu.Unlock()
	zdr.markOwnState(ZoneName(zone), true, "")
	tr.t.owe(ZoneName(zone))
	tr.t.askOwed(context.Background(), ZoneName(zone)) // the queue is full
	waitUntil(t, "the owed sync was not asked for again", func() bool { return asked.Load() == 2 })
	if owed, _ := tr.t.owedState(ZoneName(zone)); owed {
		t.Error("the sync is still owed")
	}
}

// setRolesOf is setRoles for a zone by its name.
func setRolesOf(t *testing.T, zone string, servers []string) {
	t.Helper()
	zd, ok := tdns.Zones.Get(zone)
	if !ok {
		t.Fatalf("no zone %s", zone)
	}
	setRoles(t, zd, servers, nil)
}

// chainNotified is what the zone's chain has out: its NOTIFY and its
// checks.
func (h *holdRig) chainNotified(zone string) (string, int) {
	c := &h.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch := c.zones[zone]; ch != nil {
		return ch.notified, ch.rechecks
	}
	return "", 0
}

// A held NOTIFY that is dropped ends what the chain had of an earlier
// NOTIFY too: its NOTIFY, its checks, its hold and what it waited for. The
// owed sync is then not taken for the chain's own check of that NOTIFY: its
// NOTIFY waits for the zone's wait, and its first check is the first of a
// new chain.
func TestADroppedNotifyEndsWhatTheChainHadOut(t *testing.T) {
	const wait = 300 * time.Millisecond
	h := newHoldRig(t, "dropped.chain.example.", "NOTIFY", false, time.Hour, 100*time.Millisecond)
	z := h.mpzd.ZoneName
	h.caughtUp()
	h.parent.holdsDS()
	h.inventory(h.ksk) // with no wait yet: the NOTIFY leaves at once
	h.notified(t, "the first NOTIFY", dns.TypeCDS)
	if notified, rechecks := h.chainNotified(z); notified != "CDS" || rechecks != 1 {
		t.Fatalf("after the first NOTIFY the chain has %q out with %d checks", notified, rechecks)
	}
	// a second sync, while the check waits, is held for the zone's wait;
	// the zone stops being caught up before it ends
	h.propagation(wait)
	h.conf.requestDelegationSync(h.ctx, z, "test: another change")
	h.logged(t, 1, logHeld)
	h.notCaughtUp()
	h.logged(t, 1, `msg="the held NOTIFY is dropped: the zone is not caught up; the sync is owed"`)
	c := &h.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[z]
	if ch != nil && (ch.hold != nil || ch.waiting || ch.notified != "" || ch.rechecks != 0) {
		t.Errorf("after the drop the chain has hold=%v waiting=%v notified=%q rechecks=%d", ch.hold != nil, ch.waiting, ch.notified, ch.rechecks)
	}
	c.mu.Unlock()

	// caught up again: the owed sync's NOTIFY waits for the zone's wait,
	// and its first check is a new chain's, an hour away
	h.caughtUp()
	h.askOwed()
	h.quiet(t, wait/2, "before the owed sync's wait was over")
	h.notified(t, "the owed sync's NOTIFY", dns.TypeCDS)
	h.quiet(t, 300*time.Millisecond, "after the owed sync's NOTIFY")
}
