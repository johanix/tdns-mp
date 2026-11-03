/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A removal whose parent does not move (decision 110).

// refusesKey has the leader hold the zone's key, the parent's last word on it a
// refusal.
func (r *leaverRig) refusesKey() (*tdns.KeyDB, uint16) {
	r.t.Helper()
	kdb := newMPTestKeyDB(r.t)
	r.conf.Config.Internal.KeyDB = kdb
	k := testSig0Key(r.t, kdb, r.zone)
	tdns.UpdateParentState(kdb, r.zone, k.keyid, edns0.KeyStateRefused)
	return kdb, k.keyid
}

// The status of a watch says that the parent refuses the zone's key and what
// that leaves. Past leaving-timeout it warns too, once an hour, and with the key
// no longer refused it says no more.
func TestAWatchOnAParentThatRefusesTheKeySaysSoAndWarnsOnceAnHour(t *testing.T) {
	r := newLeaverRig(t, "refused.remove.example.", "agent")
	logbuf := &lockedBuffer{}
	logTo(t, lg, slog.NewJSONHandler(logbuf, nil))
	warned := func() int { return strings.Count(logbuf.String(), "a removal's step waits for a parent that refuses") }
	r.next()
	r.next()
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent no longer names") || strings.Contains(line, "refuses") {
		t.Fatalf("the watch with the key not refused: %q", line)
	}
	kdb, keyid := r.refusesKey()
	r.next()
	line := r.conf.thawLine(r.zone)
	for _, want := range []string{"until the parent no longer names", fmt.Sprintf("the parent refuses the zone's SIG(0) key %d", keyid), "agent parentsync go-on"} {
		if !strings.Contains(line, want) {
			t.Errorf("the watch's status lacks %q: %q", want, line)
		}
	}
	if warned() != 0 {
		t.Fatalf("a warning before leaving-timeout:\n%s", logbuf)
	}
	r.aged(leavingTimeoutFor(r.conf.MpConfig()) + time.Minute)
	r.next()
	r.next()
	if warned() != 1 {
		t.Fatalf("%d warnings past leaving-timeout, want one an hour:\n%s", warned(), logbuf)
	}
	rb := &r.conf.InternalMp.reconciles
	rb.mu.Lock()
	rb.zone(canonicalName(r.zone)).warnedAt = time.Now().Add(-refusalWarnEvery)
	rb.mu.Unlock()
	r.next()
	if warned() != 2 {
		t.Fatalf("%d warnings an hour on, want a second:\n%s", warned(), logbuf)
	}
	tdns.UpdateParentState(kdb, r.zone, keyid, edns0.KeyStateTrusted)
	r.next()
	if line := r.conf.thawLine(r.zone); strings.Contains(line, "refuses") {
		t.Errorf("the status with the key trusted again: %q", line)
	}
}

// The DS step's watch says it too.
func TestTheDSWatchSaysThatTheParentRefusesTheKey(t *testing.T) {
	r := newLeaverRig(t, "refusedds.remove.example.", "agent")
	r.toDSStep()
	_, keyid := r.refusesKey()
	r.next()
	line := r.conf.thawLine(r.zone)
	for _, want := range []string{"until the parent no longer serves its DS", fmt.Sprintf("the parent refuses the zone's SIG(0) key %d", keyid)} {
		if !strings.Contains(line, want) {
			t.Errorf("the DS watch's status lacks %q: %q", want, line)
		}
	}
}

// The join: the parent refuses the zone's key and offers no NOTIFY, so the
// step's sync is held and nothing reaches the parent. The names leave the parent
// by hand, and the step's look at the parent, over the wire, goes on to its TTL.
func TestAStepHeldByARefusedKeyGoesOnWhenTheNamesLeaveTheParentByHand(t *testing.T) {
	r := newKeyHoldRig(t, "byhand.removal.example.")
	r.notifyRig.us.Bridge.combinerID = rigCombiner
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, edns0.KeyStateRefused)
	freezeServed(t, r.conf, r.mpzd)
	z := string(r.zone)
	if err := r.conf.InternalMp.Instructions.update(z, func(zs *zoneSerials) error {
		zs.Removals = []Removal{{Label: "n", Identity: roleN, NSNames: []string{canonicalName(r.oldNS)}, Since: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wait := func() string { return r.conf.removalNSWait(z, "n", roleN, false) }
	lookAgain := func() {
		rb := &r.conf.InternalMp.reconciles
		rb.mu.Lock()
		defer rb.mu.Unlock()
		rb.zone(canonicalName(z)).lookedAt = time.Time{}
	}
	waitUntil(t, "the step did not come to watch the parent\n"+r.log.String(), func() bool {
		lookAgain()
		return strings.Contains(wait(), "until the parent no longer names "+canonicalName(r.oldNS))
	})
	if got := wait(); !strings.Contains(got, fmt.Sprintf("the parent refuses the zone's SIG(0) key %d", r.key.keyid)) {
		t.Errorf("the watch does not say the parent refuses the key: %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached a parent that refuses the key\n%s", n, r.log)
	}
	r.parent.holdsNS("ns1." + r.mpzd.ZoneName) // by hand
	waitUntil(t, "the step did not go on once the names had left the parent\n"+r.log.String(), func() bool {
		lookAgain()
		return strings.HasPrefix(wait(), "for the NS TTL until ")
	})
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached a parent that refuses the key\n%s", n, r.log)
	}
}

// A parent that takes UPDATE alone: the sync needs the key, and stays held.
// The look at the parent takes time, and the key's hold can end during it. The
// release then finds nothing owed, so the sync must not be owed after it, or
// nothing asks for it until the 30 s ticker: it goes out now.
func TestAHoldThatEndsDuringTheLookAtTheParentLeavesNoSyncOwed(t *testing.T) {
	saved := parentNotifyTarget
	t.Cleanup(func() { parentNotifyTarget = saved })
	r := newKeyHoldRig(t, "during.look.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, edns0.KeyStateRefused)
	parentNotifyTarget = func(ctx context.Context, conf *Config, _ *tdns.ZoneData) *tdns.DsyncTarget {
		trustKey(r.mpzd.KeyDB, string(r.zone), r.key.keyid)
		conf.releaseKeyHold(ctx, r.zone)
		return nil
	}
	if got := r.explicit(t); strings.Contains(got.Msg, "waits for the zone's SIG(0) key") {
		t.Errorf("held by a hold that has ended: %q", got.Msg)
	}
	if r.keyOwed() {
		t.Error("the sync is owed for a key that has come, with nothing to ask for it")
	}
	waitUntil(t, "the sync went out", func() bool { return r.parent.updatesSeen() > 0 })
}

func TestASyncThatNeedsTheKeyStaysHeldWhileTheParentRefusesIt(t *testing.T) {
	r := newKeyHoldRig(t, "update.refused.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, edns0.KeyStateRefused)
	if got := r.explicit(t); !strings.Contains(got.Msg, "waits for the zone's SIG(0) key") {
		t.Errorf("the explicit sync's answer: %q", got.Msg)
	}
	if !r.keyOwed() {
		t.Error("the sync held is not owed for the key")
	}
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("%d UPDATEs reached a parent that refuses the key", n)
	}
}

// The send reads the hold again. Its look can find no NOTIFY target where the
// look at the hold found one, or the hold can have come since: no UPDATE goes
// with that key. The sync fails, is asked again, and the hold takes it.
func TestASendHeldByTheKeyWithNoNotifyTargetSendsNoUpdate(t *testing.T) {
	saved := parentNotifyTarget
	t.Cleanup(func() { parentNotifyTarget = saved })
	r := newKeyHoldRig(t, "second.look.example.")
	failureDelays(t, 50*time.Millisecond)
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, edns0.KeyStateRefused)
	var looks atomic.Int32
	parentNotifyTarget = func(context.Context, *Config, *tdns.ZoneData) *tdns.DsyncTarget {
		if looks.Add(1) == 1 {
			return &tdns.DsyncTarget{}
		}
		return nil
	}
	if got := r.explicit(t); !got.Error || !strings.Contains(got.ErrorMsg, "no NOTIFY target") {
		t.Errorf("the sync's answer: %+v", got)
	}
	waitUntil(t, "the sync asked again is owed for the key", r.keyOwed)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("%d UPDATEs went with the key that holds them", n)
	}
}

// A parent that takes both: a NOTIFY needs no key, so the sync is not held. It
// goes alone: no UPDATE signed with the refused key goes first, though the parent
// takes UPDATE, and nothing is owed for the key.
func TestASyncThatNeedsNoKeyGoesAloneByNotifyWhileTheParentRefusesTheKey(t *testing.T) {
	awaitedEvery(t, time.Hour)
	h := newHoldRig(t, "both.refused.example.", "BOTH", true, repeat(time.Hour, 4)...)
	// the operator prefers UPDATE: tdns's walk would try it first
	cs, ps, prev := *tdns.ChildSyncConfig(), *tdns.ParentSyncConfig(), *tdns.ParentSyncConfig()
	t.Cleanup(func() { _ = tdns.SetDelegationSyncConfig(cs, prev) })
	ps.Schemes = []string{"update", "notify"}
	if err := tdns.SetDelegationSyncConfig(cs, ps); err != nil {
		t.Fatal(err)
	}
	z := h.mpzd.ZoneName
	k := testSig0Key(t, h.mpzd.KeyDB, z)
	tdns.UpdateParentState(h.mpzd.KeyDB, z, k.keyid, edns0.KeyStateRefused)
	if _, why := h.conf.keyHold(h.ctx, ZoneName(z)); why == "" {
		t.Fatal("the key does not hold an UPDATE")
	}
	h.parent.holdsNS("ns1."+z, h.oldNS)
	h.caughtUp()
	h.ask()
	info, _ := h.csync(t, "")
	h.confirms(rigCombiner, info.DistributionID, info.RR)
	h.confirms(h.peer.Identity, info.DistributionID, info.RR)
	h.notified(t, "the sync by NOTIFY, past the key's hold", dns.TypeCSYNC)
	if n := h.parent.updatesSeen(); n != 0 {
		t.Errorf("%d UPDATEs went before the NOTIFY\n%s", n, h.log)
	}
}

// The parent's plan is what tdns's walk reads: no NOTIFY target from a parent
// that offers none.
func TestTheNotifyTargetIsThePlans(t *testing.T) {
	both := newNotifyRigFor(t, "both.plan.example.", "BOTH", true, repeat(time.Hour, 4)...)
	if parentNotifyTarget(both.ctx, both.conf, both.mpzd.ZoneData) == nil {
		t.Error("no target from a parent that takes NOTIFY, for a signed zone")
	}
	update := newNotifyRigFor(t, "update.plan.example.", "UPDATE", true, repeat(time.Hour, 4)...)
	if parentNotifyTarget(update.ctx, update.conf, update.mpzd.ZoneData) != nil {
		t.Error("a target from a parent that takes UPDATE alone")
	}
}

// The word of the leader's operator ends each watch, and only the watch: the
// TTLs after it are counted from the word, the word survives a restart, and it
// is gone when the transition is done. It is refused with no watch to end.
func TestTheOperatorsWordEndsTheWatchAndNotWhatFollowsIt(t *testing.T) {
	r := newLeaverRig(t, "word.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	if _, err := r.conf.goOnPastParent(r.zone); err == nil {
		t.Fatal("the word is taken with no step that watches the parent")
	}
	logbuf := &lockedBuffer{}
	logTo(t, lg, slog.NewJSONHandler(logbuf, nil))
	r.next() // names
	r.next() // ns
	r.next() // its wait
	if slices.Contains(r.taken(), "confirmers") {
		t.Fatalf("the watch ended by itself: %v", r.taken())
	}
	if _, err := r.conf.goOnPastParent(r.zone); err != nil {
		t.Fatalf("the word at the NS watch: %v", err)
	}
	if !strings.Contains(logbuf.String(), `"level":"WARN"`) || !strings.Contains(logbuf.String(), `"step":"remove n ns"`) {
		t.Errorf("the word is not logged as a warning:\n%s", logbuf)
	}
	if _, err := r.conf.goOnPastParent(r.zone); err == nil {
		t.Error("the word is taken again with the watch ended")
	}
	r.restart()
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "for the NS TTL until") {
		t.Fatalf("after the word and a restart: %q", line)
	}
	if slices.Contains(r.taken(), "confirmers") {
		t.Fatalf("the word passed the NS TTL too: %v", r.taken())
	}
	r.aged(2 * time.Hour)
	r.next()
	if !slices.Contains(r.taken(), "confirmers") {
		t.Fatalf("the NS step did not end after the word and the TTL: %v", r.taken())
	}
	r.next() // ds
	r.next() // its wait
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent no longer serves its DS") {
		t.Fatalf("the DS watch: %q", line)
	}
	if _, err := r.conf.goOnPastParent(r.zone); err != nil {
		t.Fatalf("the word at the DS watch: %v", err)
	}
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "for the DS TTL until") {
		t.Fatalf("after the word at the DS watch: %q", line)
	}
	r.aged(3 * time.Hour)
	r.next() // dnskey
	r.next() // done
	r.next() // last
	r.next() // transition done
	st := status(t, r.store, r.zone)
	if st.Phase != PhaseSteady || len(st.Removals) != 0 {
		t.Fatalf("the removal did not end: %+v", st)
	}
	if r.store.parentWord(r.zone, removalKey("n", "ns")) || r.store.parentWord(r.zone, removalKey("n", "ds")) {
		t.Error("the word outlives the transition")
	}

	// The leaving provider's status tells what the parent still names, as far as
	// it has been read.
	mp := r.conf.MpConfig()
	id, names := mp.Identity, mp.Local.Nameservers
	mp.Identity, mp.Local.Nameservers = roleN, []string{"ns1.n.example."}
	defer func() { mp.Identity, mp.Local.Nameservers = id, names }()
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; safe to remove, though the parent still names ns1.n.example.") {
		t.Errorf("n's status with the parent naming it: %q", line)
	}
	r.served(parentSeen{ns: []string{"ns1.a.example.", "ns1.b.example."}, nsTTL: 600})
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; safe to remove") {
		t.Errorf("n's status with the parent no longer naming it: %q", line)
	}
	r.conf.InternalMp.reconciles.forget(canonicalName(r.zone))
	r.parentErr = fmt.Errorf("no answer")
	if line := r.conf.thawLine(r.zone); !strings.HasSuffix(line, "; safe to remove (what the parent names has not been read yet)") {
		t.Errorf("n's status with the parent not read: %q", line)
	}
}

// The operator may name the zone in any case: the word is kept all the same,
// and the turn it asks for comes.
func TestTheWordIsKeptWhateverCaseTheZoneIsNamedIn(t *testing.T) {
	r := newLeaverRig(t, "case.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next() // names
	r.next() // ns
	r.next() // its wait
	named := strings.ToUpper(r.zone)
	if _, err := r.conf.goOnPastParent(named); err != nil {
		t.Fatalf("the word: %v", err)
	}
	step := removalKey("n", "ns")
	if !r.store.parentWord(r.zone, step) || !r.store.parentWord(named, step) {
		t.Fatalf("the word was not kept: under the store's name %v, as named %v",
			r.store.parentWord(r.zone, step), r.store.parentWord(named, step))
	}
	b := &r.conf.InternalMp.thaws
	b.mu.Lock()
	asked := b.pending[canonicalName(r.zone)]
	b.mu.Unlock()
	if !asked {
		t.Error("the word asked for no turn")
	}
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "for the NS TTL until") {
		t.Errorf("after the word: %q", line)
	}
}

// A word given for one step's watch does not end another's: the DS watch still
// watches after the word at the NS watch.
func TestAWordAtTheNSWatchLeavesTheDSWatch(t *testing.T) {
	r := newLeaverRig(t, "oneword.remove.example.", "agent")
	r.dsThere = func(seen parentSeen) bool { return !slices.Contains(seen.ds, 2) }
	r.next()
	r.next()
	r.next()
	if _, err := r.conf.goOnPastParent(r.zone); err != nil {
		t.Fatal(err)
	}
	r.next()
	r.aged(2 * time.Hour)
	r.next()
	r.next()
	r.next()
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, "until the parent no longer serves its DS") {
		t.Errorf("after the word at the NS watch only: %q", line)
	}
}

// The leader's operator gives the word: the command is refused at an agent that
// does not lead the zone, and at one with no watch to end.
func TestTheGoOnCommandIsTheLeaders(t *testing.T) {
	r := newAgentAPIRig(t, roleA, "goon.lead.example.")
	resp := r.post(t, AgentMgmtPost{Command: "parentsync-go-on"})
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "is not the delegation sync leader") {
		t.Errorf("at an agent that does not lead: error=%v %q", resp.Error, resp.ErrorMsg)
	}
	lem := r.conf.InternalMp.LeaderElectionManager
	lem.mu.Lock()
	lem.elections[r.zone] = &LeaderElection{Zone: r.zone, Leader: AgentId(roleA), LeaderExpiry: time.Now().Add(time.Hour)}
	lem.mu.Unlock()
	resp = r.post(t, AgentMgmtPost{Command: "parentsync-go-on"})
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "no removal's step here watches the parent") {
		t.Errorf("at the leader with no watch: error=%v %q", resp.Error, resp.ErrorMsg)
	}
}
