package tdnsmp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The leader during a freeze (plan S6): nothing new goes to the parent but
// the DS sync of a rollover, which carries the whole delegation by the sets
// the parts hold.

// freezeServed has conf's store keep the zone at the instructions its
// served copy carries, enforced, and agree on the same instructions with
// another suffix one serial up: the zone is frozen, as S7 will have it.
func freezeServed(t *testing.T, conf *Config, mpzd *MPZoneData) {
	t.Helper()
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("the apex: %v", err)
	}
	n, err := ReadInstructions(apex)
	if err != nil || n == nil {
		t.Fatalf("the served instructions: %v", err)
	}
	v := *n
	v.Serial, v.Suffix = n.Serial+1, "frozen"
	s := newStore(t)
	prev := instrStore.Load()
	instrStore.Store(s)
	t.Cleanup(func() { instrStore.Store(prev) })
	conf.InternalMp.Instructions = s
	s.Note(mpzd.ZoneName, n, nil)
	enforced(t, s, mpzd.ZoneName)
	s.Note(mpzd.ZoneName, &v, nil)
	if why := conf.zoneFrozen(mpzd.ZoneName); len(why) == 0 {
		t.Fatal("the zone is not frozen")
	}
}

// updateKey gives the zone the SIG(0) key an UPDATE is signed with.
func updateKey(t *testing.T, r *notifyRig) {
	t.Helper()
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
}

func TestTheLeaderSendsNothingNewToTheParentDuringATransition(t *testing.T) {
	t.Run("the explicit sync", func(t *testing.T) {
		r := newNotifyRig(t, "explicit.frozen.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
		updateKey(t, r)
		r.parent.holdsNS("ns1."+r.mpzd.ZoneName, r.oldNS)
		freezeServed(t, r.conf, r.mpzd)
		r.ask()
		time.Sleep(300 * time.Millisecond)
		if n := r.parent.updatesSeen(); n != 0 {
			t.Errorf("the parent got %d UPDATEs during the freeze", n)
		}
		r.untold(t, 0, "during the freeze")
	})
	t.Run("a refresh's sync", func(t *testing.T) {
		r := newNotifyRig(t, "refresh.frozen.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
		z := r.mpzd.ZoneName
		r.parent.holdsNS("ns1."+z, r.oldNS)
		freezeServed(t, r.conf, r.mpzd)
		changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, z+" 3600 IN NS ns2.provider.example."))
		if err != nil || !changed {
			t.Fatalf("the refresh: changed=%v err=%v", changed, err)
		}
		r.mpzd.EnsureMP()
		r.mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{DelegationChanged: changed, DelegationStatus: dss}
		r.mpzd.PostRefresh(nil, nil)
		r.quiet(t, 300*time.Millisecond, "a refresh's sync during the freeze")
	})
	t.Run("a waiting NOTIFY", func(t *testing.T) {
		r := heldDuringFreeze(t, "waiting.frozen.example.")
		r.notified(t, "the waiting NOTIFY(CDS)", dns.TypeCDS)
		r.quiet(t, 300*time.Millisecond, "the NOTIFY(CSYNC) that waited during the freeze")
	})
	t.Run("the key's bootstrap", func(t *testing.T) {
		r := newNotifyRig(t, "bootstrap.frozen.example.", "UPDATE")
		var polled atomic.Int32
		r.conf.InternalMp.keyPoll = func(context.Context, ZoneName, string, uint16, uint8) { polled.Add(1) }
		freezeServed(t, r.conf, r.mpzd)
		z := ZoneName(r.mpzd.ZoneName)
		if held := r.conf.ParentSyncAfterKeyPublication(r.ctx, z, r.mpzd.ZoneName, 4711, dns.ED25519); !held {
			t.Error("the poll did not say the freeze held it")
		}
		// as the operator's parentsync-bootstrap launches it: the poll the
		// freeze held is not booked as run, so the take-up's set-up polls
		r.conf.launchKeyPoll(r.ctx, nil, z, r.mpzd.ZoneName, 4711, dns.ED25519)
		waitUntil(t, "the held poll did not end", func() bool { running, _, _ := r.conf.InternalMp.keyPolls.state(z); return running == 0 })
		if n := polled.Load(); n != 0 {
			t.Errorf("the key's poll ran %d times during the freeze", n)
		}
		if _, _, ended := r.conf.InternalMp.keyPolls.state(z); ended.keyid != 0 {
			t.Errorf("a poll the freeze held is booked as run (key %d): the take-up's renewal would not poll", ended.keyid)
		}
	})
	t.Run("the KEY's publication", func(t *testing.T) {
		r := newNotifyRig(t, "publish.frozen.example.", "UPDATE")
		updateKey(t, r)
		freezeServed(t, r.conf, r.mpzd)
		if err := r.conf.publishZoneKey(r.ctx, ZoneName(r.mpzd.ZoneName), nil, false, 0); !errors.Is(err, errHeldDuringTransition) {
			t.Errorf("the KEY's publication during the freeze: %v", err)
		}
	})
	t.Run("DELEGATION-SYNC-SETUP", func(t *testing.T) {
		r := newNotifyRig(t, "setup.frozen.example.", "UPDATE")
		freezeServed(t, r.conf, r.mpzd)
		r.q <- tdns.DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: r.mpzd.ZoneName, ZoneData: r.mpzd.ZoneData}
		time.Sleep(200 * time.Millisecond)
		if n := r.parent.updatesSeen(); n != 0 {
			t.Errorf("the parent got %d UPDATEs from the setup's arm", n)
		}
		if active, err := activeSig0KeyIDs(NewHsyncDB(r.mpzd.KeyDB), r.mpzd.ZoneName); err != nil || len(active) != 0 {
			t.Errorf("the setup's arm made a key: %v %v", active, err)
		}
	})
}

// The DS sync of a rollover passes the freeze: the inventory changes the DS
// set, and the NOTIFY(CDS) leaves. A NOTIFY that waited with a NOTIFY(CSYNC)
// beside it leaves alone.
func TestTheDSSyncOfARolloverUnderWayPasses(t *testing.T) {
	t.Run("the inventory's sync", func(t *testing.T) {
		r := newNotifyRig(t, "ds.frozen.example.", "NOTIFY", repeat(time.Minute, 4)...)
		r.parent.holdsDS() // the parent has no DS yet
		freezeServed(t, r.conf, r.mpzd)
		r.inventory(r.ksk)
		r.notified(t, "the rollover's DS sync during the freeze", dns.TypeCDS)
	})
	t.Run("a waiting NOTIFY", func(t *testing.T) {
		r := heldDuringFreeze(t, "dswait.frozen.example.")
		r.notified(t, "the waiting NOTIFY(CDS)", dns.TypeCDS)
		r.quiet(t, 300*time.Millisecond, "the NOTIFY(CSYNC) beside it")
	})
}

// A sync's NOTIFYs that leave at once during a freeze, with no wait before
// them, leave as held ones do: the NOTIFY(CDS) alone, and the sync is owed.
// They leave at once when the providers announce no wait, and when the sync
// is the chain's own: the check after a rollover's NOTIFY(CDS) that the
// parent has not acted on yet.
func TestANotifyThatLeavesAtOnceDuringAFreezeIsTheCDSAlone(t *testing.T) {
	z := "atonce.frozen.example."
	r := newNotifyRigWith(t, z, "NOTIFY", false, func(r *notifyRig) {
		r.conf.InternalMp.CatchUp = newCatchUpTracker(AgentId(r.us.Identity), []string{z}, time.Hour)
	}, repeat(time.Minute, 4)...)
	freezeServed(t, r.conf, r.mpzd)
	to := []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.parent.port)))}
	both := delegationNotifies{requests: []tdns.NotifyRequest{{ZoneName: z, RRtype: dns.TypeCSYNC, Targets: to},
		{ZoneName: z, RRtype: dns.TypeCDS, Targets: to}}, out: r.notifyq}
	if held, err := r.conf.delegationSyncNotifiedWith(r.ctx, z, both, repeat(time.Minute, 4)); held || err != nil {
		t.Fatalf("the NOTIFYs with no wait: held %v, %v", held, err)
	}
	r.notified(t, "the rollover's NOTIFY(CDS)", dns.TypeCDS)
	r.quiet(t, 0, "the NOTIFY(CSYNC) during the freeze")
	if !r.conf.InternalMp.CatchUp.freezeOwed(ZoneName(z)) {
		t.Error("the sync the freeze kept back is not owed")
	}

	// A sync that brings a NOTIFY(CSYNC) alone lets nothing leave. The
	// chain forgets the NOTIFY(CDS) and its check, as a release that lets
	// nothing leave does: the sync after the thaw is no check's, and waits.
	csync := delegationNotifies{requests: []tdns.NotifyRequest{{ZoneName: z, RRtype: dns.TypeCSYNC, Targets: to}}, out: r.notifyq}
	if held, err := r.conf.delegationSyncNotifiedWith(r.ctx, z, csync, repeat(time.Minute, 4)); !held || err != nil {
		t.Fatalf("the NOTIFY(CSYNC) alone: held %v, %v", held, err)
	}
	r.quiet(t, 0, "the NOTIFY(CSYNC) alone during the freeze")
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[z]
	var got delegationSyncChain
	if ch != nil {
		got = *ch
	}
	c.mu.Unlock()
	if got.hold != nil || got.waiting || got.notified != "" || got.rechecks != 0 {
		t.Errorf("the chain after a sync the freeze let nothing of: hold %v, waiting %v, notified %q, rechecks %d",
			got.hold != nil, got.waiting, got.notified, got.rechecks)
	}
}

// heldDuringFreeze is a rig whose zone is frozen first, and whose signer's
// inventory then changes the DS set while the parent also holds a
// nameserver the zone no longer lists. That sync passes the freeze, and its
// NOTIFY(CSYNC) and NOTIFY(CDS) are held for the zone's wait. When the wait
// ends the zone is frozen, whatever the timing: the release's own check
// decides which leaves.
func heldDuringFreeze(t *testing.T, zone string) *notifyRig {
	t.Helper()
	r := newNotifyRig(t, zone, "NOTIFY", repeat(time.Minute, 4)...)
	r.propagation(400 * time.Millisecond)
	r.parent.holdsDS()
	r.parent.holdsNS("ns1."+r.mpzd.ZoneName, r.oldNS)
	freezeServed(t, r.conf, r.mpzd)
	r.inventory(r.ksk)
	r.logged(t, 1, logHeld+" zone="+r.mpzd.ZoneName+" notify=\"CSYNC, CDS\"")
	return r
}

// The rollover's sync during a freeze carries the whole delegation: the DS
// set the parts hold and the NS RRset the zone serves, which is what the
// parent lacks. No CSYNC is made for it.
func TestARolloversSyncDuringAFreezeCarriesTheSetsThePartsHold(t *testing.T) {
	r := newNotifyRig(t, "sets.frozen.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
	updateKey(t, r)
	z := r.mpzd.ZoneName
	r.parent.holdsDS()
	r.parent.holdsNS("ns1."+z, r.oldNS)
	freezeServed(t, r.conf, r.mpzd)
	r.inventory(r.ksk)
	r.told(t, "the rollover's DS sync")
	u := r.parent.lastUpdate()
	if u == nil {
		t.Fatal("the parent got no UPDATE")
	}
	var dsAdded, oldNSRemoved, servedNSRemoved bool
	for _, rr := range u.Ns {
		switch x := rr.(type) {
		case *dns.DS:
			dsAdded = dsAdded || x.Hdr.Class == dns.ClassINET && x.KeyTag == r.ds.(*dns.DS).KeyTag
		case *dns.NS:
			oldNSRemoved = oldNSRemoved || x.Hdr.Class == dns.ClassNONE && x.Ns == r.oldNS
			servedNSRemoved = servedNSRemoved || x.Hdr.Class == dns.ClassNONE && x.Ns == "ns1."+z
		case *dns.ANY:
			servedNSRemoved = servedNSRemoved || x.Hdr.Rrtype == dns.TypeNS
		}
	}
	// the parent holds the NS the zone serves already: the UPDATE keeps it
	if !dsAdded || !oldNSRemoved || servedNSRemoved {
		t.Errorf("the UPDATE: DS added %v, the old NS removed %v, the served NS removed %v\n%s", dsAdded, oldNSRemoved, servedNSRemoved, u)
	}
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	made := c.csyncs[z] != nil
	c.mu.Unlock()
	if made {
		t.Error("a CSYNC was made during the freeze")
	}
}

// Over the wire: an operator's edit at alice during a transition reaches
// bob only once the transition is done.
func TestTransportBoundary_AnEditDuringATransitionReachesNoPeer(t *testing.T) {
	n := newCatchUpNet(t, "edit.frozen.example.")
	mpzd, _ := Zones.Get(string(n.zone))
	kept, err := loadKeptLists(nil)
	if err != nil {
		t.Fatal(err)
	}
	n.conf.InternalMp.Kept = kept
	freezeServed(t, n.conf, mpzd)
	n.conf.InternalMp.Instructions.onFreeze = n.conf.onFreeze

	edit := string(n.zone) + " 3600 IN NS ns1.alice.example."
	answer := make(chan *AgentMsgResponse, 1)
	n.conf.InternalMp.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: n.zone, AgentId: AgentId(n.alice), UpdateType: "local",
		Update:   &ZoneUpdate{Zone: n.zone, AgentId: AgentId(n.alice), Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{edit}}}},
		Response: answer}
	a, ok := recvWithin(answer, 10*time.Second)
	if !ok || a.Kept == "" {
		t.Fatalf("the edit during the transition: %+v", a)
	}
	if m, ok := recvMsgWithin(t, n.env.Bob.MsgQs.Msg, 500*time.Millisecond); ok {
		t.Fatalf("bob heard %s during the transition", AgentMsgToString[m.MessageType])
	}

	s := n.conf.InternalMp.Instructions
	st := s.Status(string(n.zone))
	if err := s.Activate(string(n.zone), Thaw{From: *st.Active, To: *st.Agreeing}); err != nil {
		t.Fatal(err)
	}
	if err := s.Done(string(n.zone)); err != nil {
		t.Fatal(err)
	}
	m, ok := recvMsgWithin(t, n.env.Bob.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("bob did not hear the kept edit after the transition was done")
	}
	if len(m.Operations) != 1 || m.Operations[0].RRtype != "NS" || len(m.Operations[0].Records) != 1 {
		t.Fatalf("bob heard %+v", m.Operations)
	}
	if rr, err := dns.NewRR(m.Operations[0].Records[0]); err != nil || rr.(*dns.NS).Ns != "ns1.alice.example." {
		t.Errorf("bob heard the NS %q, want the kept edit's", m.Operations[0].Records[0])
	}
}

// The take-up runs the key's set-up under the zone's key-setup lock, as an
// election's does: it waits while another set-up of the zone runs
// (CodeRabbit's review of eee6363).
func TestTheTakeUpRunsUnderTheZonesKeySetupLock(t *testing.T) {
	r := newLeaderSyncRig(t, "takeup.lock.example.")
	r.leader(r.lem.localID)
	zone := ZoneName(r.mpzd.ZoneName)
	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- r.lem.inKeySetup(zone, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	done := make(chan struct{})
	go func() { r.conf.takeUp(r.ctx, zone); close(done) }()
	select {
	case <-done:
		t.Fatal("the take-up ran while another key set-up of the zone held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the take-up did not run once the lock was let go")
	}
	<-held
}
