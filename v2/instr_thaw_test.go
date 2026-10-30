package tdnsmp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// The thaw (plan S7), on the freeze rig: agent a, in a zone that a and b
// serve and n has a record in, active at 41 (n) and agreeing on 42 (v), a
// change of suffix with nothing to carry out.

// thawRig is the freeze rig with a stamp table, payload encryption on, and
// an election manager that names the zone's leader.
type thawRig struct {
	*freezeRig
	stamps *stampTable
	lem    *LeaderElectionManager
	seq    uint64
}

func newThawRig(t *testing.T, zone string, leader string) *thawRig {
	t.Helper()
	r := &thawRig{freezeRig: newFreezeRig(t, zone)}
	r.withSigner()
	r.stamps = newStampTable(roleA, r.store, 1, true, nil)
	r.stamps.rollover = r.conf.InternalMp.MPTransport.rolloverAt
	r.conf.InternalMp.MPTransport.stamps = r.stamps
	r.lem = NewLeaderElectionManager(roleA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(r.lem) })
	if leader != "" {
		r.lead(leader, time.Now().Add(time.Hour))
	}
	r.conf.InternalMp.LeaderElectionManager = r.lem
	return r
}

// lead has the zone's election name leader, with its lease to expiry.
func (r *thawRig) lead(leader string, expiry time.Time) {
	r.lem.mu.Lock()
	defer r.lem.mu.Unlock()
	r.lem.elections[ZoneName(r.zone)] = &LeaderElection{Zone: ZoneName(r.zone), Leader: AgentId(leader), LeaderExpiry: expiry}
}

// hold has this agent's signer confirm the hold, now: it holds the
// hand-over with the hold (S11), and its inventory says so.
func (r *thawRig) hold() {
	r.confirm(true)
}

// hear notes a beat of id's, over DNS, that tells st of the zone, with id's
// payload encryption as crypto.
func (r *thawRig) hear(id string, st InstrStamp, crypto bool) {
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		id: {Identity: id, Timestamp: time.Now(), Epoch: 1, Seq: r.seq, Crypto: crypto, Instr: map[string]InstrStamp{r.zone: st}}}}, id, transport.MechanismDNS)
}

// agreeing is a member's telling of active n and agreeing on v, with its
// signer's hold.
func (r *thawRig) agreeing() InstrStamp {
	st := tells(r.n, r.v)
	st.Agreeing, st.AgreeingDigest, st.Hold = r.v.Serial, r.v.Digest(), true
	return st
}

func (r *thawRig) view() thawView {
	r.t.Helper()
	v, ok := r.conf.thawView(r.zone, time.Now())
	if !ok {
		r.t.Fatal("the zone agrees on nothing")
	}
	return v
}

func (r *thawRig) active() uint32 {
	r.t.Helper()
	return status(r.t, r.store, r.zone).Active.Serial
}

// holdUnjudged has the agent hold in above its active serial, since since,
// as the serial agreed on whatever the judge says of it: the kinds of change
// a leaving or a new voting member makes are refused until their steps are
// built (S17b, S18a), and these tests stand in for those.
func (r *thawRig) holdUnjudged(in *Instructions, since time.Time) {
	r.t.Helper()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Held = append(z.Held, heldSerial{SerialDigest: sd(in), Reading: in, Since: since})
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

// The leader thaws once every other voting member tells, first hand and
// fresh, active N and agreeing V with its signer's hold, and its own signer
// has confirmed the hold. The reconciliation follows (S12): the zone stays
// frozen, at step 0, until it is done.
func TestTheLeaderThawsWhenEveryVotingMemberTellsActiveNAndAgreeingV(t *testing.T) {
	r := newThawRig(t, "leader.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("thawed before b told anything")
	}
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	st := status(t, r.store, r.zone)
	if st.Active.Serial != 42 || st.From == nil || st.From.Serial != 41 || st.Phase != PhaseReconciling || st.LastThaw == nil || st.LastThaw.From != sd(r.n) || st.LastThaw.To != sd(r.v) {
		t.Fatalf("after the thaw: %+v", st)
	}
	if why := r.conf.zoneFrozen(r.zone); !slices.Equal(why, []string{"reconciling from 41 to 42"}) {
		t.Errorf("frozen after the thaw: %v", why)
	}
	if line := r.conf.thawLine(r.zone); !strings.HasPrefix(line, "reconciling 41->42: step 0 (the sets held)") {
		t.Errorf("the status: %q", line)
	}
}

// What holds the thaw, member by member, and how the status names it.
func TestWhatAMembersTellingLacksHoldsTheThaw(t *testing.T) {
	r := newThawRig(t, "lacks.thaw.example.", roleA)
	r.agree()
	r.hold()
	for _, c := range []struct {
		name   string
		st     func() InstrStamp
		crypto bool
		want   string
	}{
		// TestNoThawWhileAVotingMemberTellsAnotherActiveSerial
		{"another active serial", func() InstrStamp {
			st := r.agreeing()
			st.Active = 40
			return st
		}, true, "b.role.example. (tells 40)"},
		// TestNoThawOnADigestMismatch
		{"another digest", func() InstrStamp {
			st := r.agreeing()
			st.ActiveDigest = "0000000000000000"
			return st
		}, true, "b.role.example. (tells 41)"},
		// TestATellingWithoutTheSignersHoldDoesNotCount
		{"no hold", func() InstrStamp {
			st := r.agreeing()
			st.Hold = false
			return st
		}, true, "b.role.example. (no hold yet)"},
		// TestNoThawWhileAVotingMemberRefuses
		{"a refusal", func() InstrStamp {
			st := tells(r.n, r.v)
			st.Refused = RefusedNotBuilt
			return st
		}, true, "b.role.example. (refuses 42: " + RefusedNotBuilt + ")"},
		{"an owner error", func() InstrStamp {
			st := r.agreeing()
			st.Error = "serial 42 with two digests"
			return st
		}, true, "b.role.example. (owner error)"},
		// TestNoThawWhileARolloverIsUnderWay, a member's
		{"a rollover", func() InstrStamp {
			st := r.agreeing()
			st.Rollover = true
			return st
		}, true, "b.role.example. (rollover under way)"},
		// TestNoThawWithPayloadEncryptionOffAtAVotingMember
		{"payload encryption off", r.agreeing, false, "b.role.example. (payload encryption off)"},
	} {
		r.hear(roleB, c.st(), c.crypto)
		v := r.view()
		if v.ready() || len(v.waits) != 1 || v.waits[0] != c.want {
			t.Errorf("%s: waits %q, want %q", c.name, v.waits, c.want)
		}
	}
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Error("thawed while b's telling did not count")
	}
	// a refusal of a serial above V holds nothing
	st := r.agreeing()
	st.Newest, st.NewestDigest, st.Refused = 43, "1111111111111111", RefusedNotBuilt
	r.hear(roleB, st, true)
	if v := r.view(); !v.ready() {
		t.Errorf("a refusal of 43 holds the thaw to 42: %q", v.waits)
	}
}

// A telling counts only from the member's own row of a beat it sent:
// another member's row relayed in it, and a beat's answer, are not noted.
func TestATellingRelayedInAnotherMembersRowDoesNotCount(t *testing.T) {
	r := newThawRig(t, "relayed.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		roleB: {Identity: roleB, Timestamp: time.Now(), Epoch: 1, Seq: 1, Crypto: true, Instr: map[string]InstrStamp{r.zone: r.agreeing()}}}}, roleN, transport.MechanismDNS)
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleB+" (not heard)" {
		t.Errorf("b's row relayed by n counted: %q", v.waits)
	}
}

// A telling heard longer ago than leaving-timeout does not count: what it
// says of rollovers may have changed.
func TestATellingHeardLongerAgoThanTheConfiguredTimeDoesNotCount(t *testing.T) {
	r := newThawRig(t, "stale.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	later := time.Now().Add(leavingTimeoutDefault + time.Minute)
	v, _ := r.conf.thawView(r.zone, later)
	if v.ready() || len(v.waits) != 1 || !strings.HasPrefix(v.waits[0], roleB+" (not heard since ") {
		t.Errorf("a telling older than the time counted: %q", v.waits)
	}
}

// The leader's own signer must have confirmed the hold, and its own
// provider have no rollover under way, and its payload encryption be on.
func TestNoThawWithoutTheLeadersOwnHold(t *testing.T) {
	r := newThawRig(t, "ownhold.thaw.example.", roleA)
	r.agree()
	r.hear(roleB, r.agreeing(), true)
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleA+" (no hold yet)" {
		t.Fatalf("without its own hold: %q", v.waits)
	}
	r.hold()
	r.conf.InternalMp.MPTransport.pendingDnskeyPropagations["k"] = &PendingDnskeyPropagation{Zone: ZoneName(r.zone)}
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleA+" (rollover under way)" {
		t.Fatalf("with its own rollover: %q", v.waits)
	}
	delete(r.conf.InternalMp.MPTransport.pendingDnskeyPropagations, "k")
	r.stamps.crypto = false
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleA+" (payload encryption off)" {
		t.Fatalf("with its own payload encryption off: %q", v.waits)
	}
	r.stamps.crypto = true
	if v := r.view(); !v.ready() {
		t.Fatalf("not ready: %q", v.waits)
	}
}

// Only voting members under the active serial are waited for: a record with
// no role (n) and an auditor tell nothing the thaw needs.
func TestOnlyVotingMembersUnderTheActiveSerialCount(t *testing.T) {
	r := newThawRig(t, "voters.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.hear(roleN, InstrStamp{}, false)
	if v := r.view(); !v.ready() {
		t.Errorf("n, with no role, holds the thaw: %q", v.waits)
	}
}

// A member that is not the leader thaws nothing, and says so.
func TestAMemberDoesNotThaw(t *testing.T) {
	r := newThawRig(t, "member.thaw.example.", roleB)
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("a member thawed")
	}
	if line := r.conf.thawLine(r.zone); line != "agreeing: every voting member agrees, waiting for the leader's thaw" {
		t.Errorf("the status: %q", line)
	}
}

// No thaw while the transition under way is not done (one transition at a
// time, design 3.3), nor of a refused transition, nor while an owner error
// holds the zone.
func TestNoThawWhileTheTransitionUnderWayIsNotDone(t *testing.T) {
	r := newThawRig(t, "notdone.thaw.example.", roleA)
	r.agree()
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		t.Fatal(err)
	}
	r.store.Note(r.zone, freezeAt(t, 43, "w", "a,b", ""), nil)
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok {
		t.Error("a serial is agreed on while the transition to 42 is not done")
	}
}

func TestNoThawOfARefusedTransition(t *testing.T) {
	r := newThawRig(t, "refused.thaw.example.", roleA)
	r.store.Note(r.zone, freezeAt(t, 42, "v", "a", ""), nil) // takes b's role: refused until S17b
	if _, ok := r.conf.thawView(r.zone, time.Now()); ok {
		t.Fatal("a refused serial is agreed on")
	}
	if len(r.conf.zoneFrozen(r.zone)) > 0 {
		t.Error("a refused newest serial freezes the zone")
	}
}

// The leader's parent work holds the thaw. At the thaw's turn, when it is
// all the thaw waits for, it is cancelled; a sync it stops is owed, not
// retried; and the next turn thaws.
func TestTheThawCancelsTheLeadersParentWork(t *testing.T) {
	r := newThawRig(t, "parent.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	runCtx, done := r.conf.delegationSyncRun(context.Background(), r.zone)
	// TestNoThawWhileTheLeaderHasParentWorkInFlight
	if v := r.view(); v.ready() || v.parent != "a sync in flight" {
		t.Fatalf("with a sync in flight: parent %q, waits %q", v.parent, v.waits)
	}
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("thawed with a sync in flight")
	}
	var pw parentWorkCancelled
	if runCtx.Err() == nil || !errors.As(context.Cause(runCtx), &pw) {
		t.Fatalf("the sync's context: %v, cause %v", runCtx.Err(), context.Cause(runCtx))
	}
	done()
	// TestACancelledZoneGetsAFreshContextForItsNextSync
	next, end := r.conf.delegationSyncRun(context.Background(), r.zone)
	if next.Err() != nil {
		t.Error("the zone's next sync starts cancelled")
	}
	end()
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatalf("no thaw once the parent work drained: %q", r.view().waits)
	}
}

// The parent work counts the leader's NOTIFY chain: a NOTIFY held, and a
// check of the parent scheduled.
func TestParentWorkCountsTheNotifyChain(t *testing.T) {
	conf := &Config{}
	const zone = "chain.parent.example."
	if w := conf.parentWorkUnderWay(zone); w != "" {
		t.Fatalf("nothing under way: %q", w)
	}
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.of(zone)
	ch.hold = &delegationNotifyHold{}
	c.mu.Unlock()
	if w := conf.parentWorkUnderWay(zone); w != "a NOTIFY held" {
		t.Errorf("a held NOTIFY: %q", w)
	}
	c.mu.Lock()
	ch.hold, ch.waiting = nil, true
	c.mu.Unlock()
	if w := conf.parentWorkUnderWay(zone); w != "a check of the parent scheduled" {
		t.Errorf("a scheduled check: %q", w)
	}
	conf.cancelParentWork(zone, "a test")
	if w := conf.parentWorkUnderWay(zone); w != "" {
		t.Errorf("after the cancel: %q", w)
	}
}

// When the group's leader is invalidated, its syncs under way stop: an
// UPDATE that tdns retries for up to 75 s goes out from nobody's lead.
func TestTheParentContextIsCancelledWhenLeadershipIsInvalidated(t *testing.T) {
	conf := &Config{}
	const zone = "invalidated.parent.example."
	runCtx, done := conf.delegationSyncRun(context.Background(), zone)
	defer done()
	conf.cancelGroupParentWork([]ZoneName{zone})
	if runCtx.Err() == nil {
		t.Error("the sync under way was not cancelled")
	}
}

// A sync stopped at the thaw's turn is no failure to retry: leaderSyncFailed
// leaves it.
func TestASyncCancelledForTheThawIsNotRetried(t *testing.T) {
	err := errors.Join(parentWorkCancelled{why: "the thaw's turn"}, context.Canceled)
	var pw parentWorkCancelled
	if !errors.As(err, &pw) {
		t.Fatal("the cause is not found")
	}
}

// A newer serial during agreeing that the judge accepts becomes the serial
// agreed on; the thaw goes to it.
func TestANewerSerialDuringAgreeingIsTheOneAgreedOn(t *testing.T) {
	r := newThawRig(t, "newer.thaw.example.", roleA)
	r.agree()
	w := freezeAt(t, 43, "w", "a,b", "")
	r.store.Note(r.zone, w, nil)
	r.hold()
	st := tells(r.n, w)
	st.Agreeing, st.AgreeingDigest, st.Hold = 43, w.Digest(), true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 43 {
		t.Fatalf("active %d, want 43", r.active())
	}
}

// A refused newer serial does not replace the serial agreed on: a record,
// and then a role taken away, published before the first is thawed. The
// first is thawed, and the second is judged again against it.
func TestARefusedNewerSerialDoesNotReplaceTheSerialAgreedOn(t *testing.T) {
	r := newThawRig(t, "record-then-role.thaw.example.", roleA)
	r.agree()
	w := freezeAt(t, 43, "v", "a", "") // b's role taken: refused until S17b
	r.store.Note(r.zone, w, nil)
	st := status(t, r.store, r.zone)
	if st.Agreeing == nil || st.Agreeing.Serial != 42 || st.Newest.Serial != 43 || len(st.Refused) == 0 {
		t.Fatalf("agreeing %s, newest %s, refused %v", serialOf(st.Agreeing), serialOf(st.Newest), st.Refused)
	}
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	st = status(t, r.store, r.zone)
	// TestARefusedNewerSerialIsJudgedAgainAfterDone
	if st.Active.Serial != 42 || st.Newest.Serial != 43 || len(st.Refused) == 0 || st.Agreeing != nil {
		t.Fatalf("after the thaw: active %s, newest %s, refused %v, agreeing %s", serialOf(st.Active), serialOf(st.Newest), st.Refused, serialOf(st.Agreeing))
	}
}

// A zone whose only voting member is this agent, in no group, is thawed by
// its own word.
func TestAZoneWithOneVotingMemberThawsItself(t *testing.T) {
	r := newThawRig(t, "alone.thaw.example.", "")
	n, v := freezeAt(t, 51, "n", "a", ""), freezeAt(t, 52, "v", "a", "")
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, r.zone, n)
	r.store.Note(r.zone, v, nil)
	r.hold()
	r.conf.thawTurn(r.zone)
	if r.active() != 52 {
		t.Fatalf("the only voting member did not thaw: %q", r.view().waits)
	}
}

// With no voting member under N, each voting member under V makes V active
// when every voting member under V tells V.
func TestAZoneWithNoVotingMemberUnderNThawsWhenTheNewVotersAgree(t *testing.T) {
	r := newThawRig(t, "novoter.thaw.example.", "")
	n, v := freezeAt(t, 61, "n", "", "x"), freezeAt(t, 62, "v", "a,b", "x")
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, r.zone, n)
	r.holdUnjudged(v, time.Now())
	if vw := r.view(); vw.ready() || len(vw.waits) != 1 || vw.waits[0] != roleB+" (not heard)" {
		t.Fatalf("before b tells: %q", vw.waits)
	}
	// heard, but telling nothing of the zone (plan S22): not "not heard"
	r.operational(roleB)
	if vw := r.view(); vw.ready() || len(vw.waits) != 1 || vw.waits[0] != roleB+" (tells nothing of the zone)" {
		t.Fatalf("b heard, telling nothing of the zone: %q", vw.waits)
	}
	st := tells(n, v)
	st.Agreeing, st.AgreeingDigest = 62, v.Digest()
	// a telling with an owner error does not count, as under N (cubic on
	// tdns-mp #311)
	bad := st
	bad.Error = "two HSYNCPARAM records"
	r.hear(roleB, bad, true)
	r.conf.thawTurn(r.zone)
	if vw := r.view(); r.active() != 61 || len(vw.waits) != 1 || vw.waits[0] != roleB+" (owner error)" {
		t.Fatalf("with b's owner error: active %d, %q", r.active(), vw.waits)
	}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 62 {
		t.Fatalf("no thaw: %q", r.view().waits)
	}
}

// The election asks its gate for the excused before it takes the
// election's lock: the gate takes the manager's lock, which allLeases holds
// while it takes the election's (cubic on tdns-mp #311).
func TestTheElectionAsksItsGateOutsideItsLock(t *testing.T) {
	const zone = "gatelock.election.example."
	lem, group, calls := arrivalLEM(t, zone)
	le := &LeaderElection{Active: true, Term: 5, startZones: []ZoneName{zone},
		Confirms: map[AgentId]AgentId{arrivalA: arrivalA, arrivalB: arrivalA}}
	lem.mu.Lock()
	lem.groupElections[group] = le
	lem.mu.Unlock()
	var asked, underLock bool
	lem.SetGateExcused(func(string) []string {
		asked = true
		if le.mu.TryLock() {
			le.mu.Unlock()
		} else {
			underLock = true
		}
		return nil
	})
	lem.finalizeGroupElection(group, 5, []string{arrivalA, arrivalB}, []ZoneName{zone})
	if !asked || underLock {
		t.Errorf("the gate asked %v, under the election's lock %v", asked, underLock)
	}
	waitUntil(t, "the winner's callback ran", func() bool { e, _ := calls.lists(); return len(e) == 1 })
}

// A leaving voting member (b votes under 41 and not under 42) that has told
// nothing that counts for leaving-timeout, counted from when this agent
// first holds 42, is excused: silent, heard without its hold, or stuck with
// its rollover flag. Before the time it holds the thaw.
func TestALeavingMemberSilentForTheTimeIsExcused(t *testing.T) {
	for _, c := range []struct {
		name string
		st   func(r *thawRig) *InstrStamp
	}{
		{"silent", func(*thawRig) *InstrStamp { return nil }},
		// TestALeavingMemberWhoseTellingDoesNotCountIsExcused
		{"no hold", func(r *thawRig) *InstrStamp { st := r.agreeing(); st.Hold = false; return &st }},
		{"a stuck rollover", func(r *thawRig) *InstrStamp { st := r.agreeing(); st.Rollover = true; return &st }},
		{"a refusal", func(r *thawRig) *InstrStamp {
			st := tells(r.n, r.v)
			st.Refused = RefusedNotBuilt
			return &st
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newThawRig(t, "leaving.thaw.example.", roleA)
			v := freezeAt(t, 42, "v", "a", "") // b's role taken (S17b's kind)
			r.v = v
			// TestTheExcusalTimeCountsFromWhenThisAgentFirstHoldsV
			r.holdUnjudged(v, time.Now())
			r.hold()
			if st := c.st(r); st != nil {
				r.hear(roleB, *st, true)
			}
			if vw := r.view(); vw.ready() || len(vw.excused) > 0 {
				t.Fatalf("excused before the time: waits %q, excused %q", vw.waits, vw.excused)
			}
			if err := r.store.update(r.zone, func(z *zoneSerials) error {
				z.Held[0].Since = time.Now().Add(-leavingTimeoutDefault - time.Minute)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if c.st(r) != nil {
				// a telling heard within the time does not count either
				r.hear(roleB, *c.st(r), true)
			}
			vw := r.view()
			if !vw.ready() || len(vw.excused) != 1 || !strings.HasPrefix(vw.excused[0], roleB+" excused (leaving, no telling that counts since ") {
				t.Fatalf("after the time: waits %q, excused %q", vw.waits, vw.excused)
			}
			r.conf.thawTurn(r.zone)
			if r.active() != 42 {
				t.Error("no thaw with the leaving member excused")
			}
		})
	}
}

// A leaving member whose telling met the conditions within the time is not
// excused: the time counts from then.
func TestALeavingMemberWhoseTellingCountedIsNotExcused(t *testing.T) {
	r := newThawRig(t, "counted.thaw.example.", roleA)
	v := freezeAt(t, 42, "v", "a", "")
	r.v = v
	r.holdUnjudged(v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.view() // it meets the conditions now
	st := r.agreeing()
	st.Hold = false
	r.hear(roleB, st, true)
	if vw := r.view(); vw.ready() || len(vw.excused) > 0 {
		t.Errorf("excused although it told what counts just now: waits %q, excused %q", vw.waits, vw.excused)
	}
}

// A leaving leader is excused only once its lease has run out in this
// agent's view. A heard one that renews it, and never tells what counts,
// stalls the zone, and the status says so.
func TestALeavingLeaderIsExcusedOnlyAfterItsLeaseInThisAgentsView(t *testing.T) {
	r := newThawRig(t, "leavingleader.thaw.example.", roleB)
	v := freezeAt(t, 42, "v", "a", "")
	r.v = v
	r.holdUnjudged(v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	r.hold()
	vw := r.view()
	if len(vw.excused) > 0 {
		t.Fatalf("the leader is excused while its lease runs: %q", vw.excused)
	}
	// its lease runs out here, and the group elects a without it
	r.lead(roleB, time.Now().Add(-time.Second))
	r.view()
	r.lead(roleA, time.Now().Add(time.Hour))
	if vw = r.view(); !vw.ready() || len(vw.excused) != 1 {
		t.Fatalf("after its lease: waits %q, excused %q", vw.waits, vw.excused)
	}
}

func TestAHeardLeavingLeaderThatRenewsItsLeaseStallsTheZone(t *testing.T) {
	r := newThawRig(t, "stuckleader.thaw.example.", roleB)
	v := freezeAt(t, 42, "v", "a", "")
	r.v = v
	r.holdUnjudged(v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	r.operational(roleB)
	vw := r.view()
	if vw.held != roleB || len(vw.excused) > 0 {
		t.Fatalf("held %q, excused %q", vw.held, vw.excused)
	}
	if line := vw.line(); !strings.Contains(line, "held by "+roleB+", the leader, which leaves and renews its lease; its operator must stop it") {
		t.Errorf("the status: %q", line)
	}
}

// A lost leader that is not leaving keeps its group without a leader: the
// zone stalls at N, and the status names it.
func TestALostLeaderThatIsNotLeavingStallsItsGroup(t *testing.T) {
	r := newThawRig(t, "lostleader.thaw.example.", roleB)
	r.agree()
	r.view() // b is seen as the leader
	r.lem.mu.Lock()
	delete(r.lem.elections, ZoneName(r.zone))
	r.lem.mu.Unlock()
	vw := r.view()
	if vw.noLeader != roleB+" not heard since never" {
		t.Fatalf("no leader: %q", vw.noLeader)
	}
	if line := vw.line(); !strings.Contains(line, "no leader ("+roleB+" not heard since never); waiting for it or for the owner to remove it") {
		t.Errorf("the status: %q", line)
	}
}

// A member makes V active on the first first-hand stamp that tells it
// active, with the thaw, from the zone's leader.
func TestAMemberActivatesOnTheLeadersActiveStamp(t *testing.T) {
	r := newThawRig(t, "leaderword.thaw.example.", roleB)
	r.agree()
	st := tells(r.v, r.v)
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("activated on a telling without the thaw")
	}
	st.Thaw, st.Reconciling = &Thaw{From: sd(r.n), To: sd(r.v)}, true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatal("not activated on the leader's thaw")
	}
	if line := r.conf.thawLine(r.zone); line != "reconciling 41->42: step 0 (the sets held), waiting for the leader's first step" {
		t.Errorf("the status: %q", line)
	}
}

// A member makes V active on a voting member's telling under V, the leader
// unknown, and a member that does not vote takes it from any voting member.
func TestAMemberActivatesOnAVotingMemberUnderV(t *testing.T) {
	for _, local := range []string{roleA, roleN} {
		t.Run(local, func(t *testing.T) {
			r := newThawRig(t, "voterword.thaw.example.", "")
			r.conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: local})
			r.agree()
			st := tells(r.v, r.v)
			st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
			r.hear(roleN, st, true) // n has no role: its telling is not taken
			r.conf.thawTurn(r.zone)
			if r.active() != 41 {
				t.Fatal("activated on the telling of a member that does not vote")
			}
			r.hear(roleB, st, true)
			r.conf.thawTurn(r.zone)
			if r.active() != 42 {
				t.Fatal("not activated on a voting member's telling")
			}
		})
	}
}

// A member behind the thaw's from-serial, holding both, moves straight to
// the target. It judges the thaw's own pair, not its own active serial
// against the target: 40 to 42 changes nsmgmt and is refused, 41 to 42 is
// not.
func TestAMemberThatMovesStraightJudgesTheThawsPairNotItsOwn(t *testing.T) {
	r := newThawRig(t, "straight.thaw.example.", roleB)
	old := jAt(t, 40, `servers="a,b" nsmgmt="owner" suffix="o"`, freezeRecords...)
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, r.zone, old)
	r.store.Note(r.zone, r.v, nil)
	if st := status(t, r.store, r.zone); len(st.Refused) == 0 {
		t.Fatal("precondition: 40 to 42 is not refused")
	}
	st := tells(r.v, r.v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	r.hear(roleB, st, true)
	// TestAMemberThatDoesNotHoldTheSerialStartsNothingAndFetches: without 41
	// it starts nothing, and asks b for it
	r.conf.thawTurn(r.zone)
	if r.active() != 40 {
		t.Fatal("moved without the from-serial")
	}
	if !r.fetchAsked(41, roleB) {
		t.Error("the from-serial was not asked for")
	}
	// TestTheFromSerialIsFetchedAndCheckedAgainstItsDigest
	if _, err := instructionsAnswered(r.zone, sd(r.n), instructionsAnswer(r.zone, r.v)); err == nil {
		t.Fatal("an answer with another serial's records was taken")
	}
	in, err := instructionsAnswered(r.zone, sd(r.n), instructionsAnswer(r.zone, r.n))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.store.Hold(r.zone, in); err != nil {
		t.Fatal(err)
	}
	// TestAMemberBehindTheThawsFromMovesStraightToTheToldSerial
	r.conf.thawTurn(r.zone)
	if got := status(t, r.store, r.zone); got.Active.Serial != 42 || got.LastThaw == nil || got.LastThaw.From != sd(r.n) {
		t.Fatalf("after the fetch: %+v", got)
	}
}

// An auditor whose transfer skipped the thaw's from-serial (active 40, the
// copy at 42, told the thaw 41 to 42) asks the member for 41, as an agent
// does, and then moves straight to 42.
func TestAnAuditorFetchesTheThawsFromSerial(t *testing.T) {
	r := newThawRig(t, "auditorfrom.thaw.example.", "")
	tdns.Globals.App.Type = AppTypeMPAuditor
	t.Cleanup(func() { tdns.Globals.App.Type = AppTypeMPAgent })
	r.conf.SetMpConfig(&MultiProviderConf{Role: "auditor", Identity: roleN})
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, r.zone, freezeAt(t, 40, "o", "a,b", ""))
	r.store.Note(r.zone, r.v, nil)
	st := tells(r.v, r.v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 40 {
		t.Fatal("moved without the from-serial")
	}
	if !r.fetchAsked(41, roleB) {
		t.Fatal("the auditor did not ask for the from-serial")
	}
	if err := r.store.Hold(r.zone, r.n); err != nil {
		t.Fatal(err)
	}
	r.conf.thawTurn(r.zone)
	if got := status(t, r.store, r.zone); got.Active.Serial != 42 || got.LastThaw == nil || got.LastThaw.From != sd(r.n) {
		t.Fatalf("after the fetch: %+v", got)
	}
}

// fetchAsked: the instructions RFI for serial was asked of member.
func (r *thawRig) fetchAsked(serial uint32, member string) bool {
	b := &r.conf.InternalMp.thaws
	b.mu.Lock()
	defer b.mu.Unlock()
	for key := range b.fetched {
		if f := strings.Fields(key); len(f) == 4 && f[1] == strconvU(serial) && f[3] == canonicalName(member) {
			return true
		}
	}
	return false
}

// A member that does not hold the serial told active starts nothing and
// asks the teller for it.
func TestAMemberThatDoesNotHoldTheSerialStartsNothingAndFetches(t *testing.T) {
	r := newThawRig(t, "nothold.thaw.example.", roleB)
	st := tells(r.v, r.v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("activated a serial it does not hold")
	}
	if !r.fetchAsked(42, roleB) {
		t.Error("the serial was not asked for")
	}
}

// An agent told first hand, by a voting member, a serial agreed on that it
// does not hold asks that member for it.
func TestAnAgentFetchesASerialAgreedOnThatItDoesNotHold(t *testing.T) {
	r := newThawRig(t, "fetchagreed.thaw.example.", roleB)
	st := r.agreeing()
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if !r.fetchAsked(42, roleB) {
		t.Error("the serial agreed on was not asked for")
	}
}

// An agent never makes active a serial it refused.
func TestAMemberNeverActivatesASerialItRefused(t *testing.T) {
	r := newThawRig(t, "neverrefused.thaw.example.", roleB)
	v := freezeAt(t, 42, "v", "a", "") // refused: b's role taken
	r.store.Note(r.zone, v, nil)
	st := tells(v, v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(v)}
	r.hear(roleB, st, true)
	var buf bytes.Buffer
	saved := lg
	lg = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lg = saved })
	r.conf.thawTurn(r.zone)
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("a refused serial was made active")
	}
	if n := strings.Count(buf.String(), "a serial a member tells active is not made active here"); n != 1 {
		t.Errorf("%d warnings, want 1:\n%s", n, buf.String())
	}
}

// The active serial is on disk before the stamp tells it, and the last
// thaw, its from-serial with it, is kept across a restart and told.
func TestTheActiveSerialIsWrittenBeforeItIsTold(t *testing.T) {
	r := newThawRig(t, "written.thaw.example.", roleA)
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	// TestTheLastThawIsToldAndKept
	st, ok := r.stamps.ownStamp(r.zone)
	if !ok || st.Active != 42 || st.Thaw == nil || st.Thaw.From != sd(r.n) || st.Thaw.To != sd(r.v) {
		t.Fatalf("the stamp: %+v", st)
	}
	reloaded := loadStore(t, r.hdb)
	got := status(t, reloaded, r.zone)
	if got.Active.Serial != 42 || !got.Enforced || got.LastThaw == nil || *got.LastThaw != *st.Thaw {
		t.Fatalf("after a restart: %+v", got)
	}
	if reloaded.readingAt(r.zone, sd(r.n)) == nil {
		t.Error("the last thaw's from-serial is not kept to answer a member behind")
	}
}

// The instructions RFI asks for a serial by serial and digest, and its
// answer is the hand-over's records.
func TestTheInstructionsRFIRoundTrip(t *testing.T) {
	r := newThawRig(t, "rfi.thaw.example.", roleA)
	asked, err := instructionsAsked(instructionsAsk(sd(r.n)))
	if err != nil || asked != sd(r.n) {
		t.Fatalf("asked %v, %v", asked, err)
	}
	if _, err := instructionsAsked(nil); err == nil {
		t.Error("a request with no serial is taken")
	}
	in := r.store.readingAt(r.zone, asked)
	if in == nil {
		t.Fatal("the active serial is not found")
	}
	got, err := instructionsAnswered(r.zone, asked, instructionsAnswer(r.zone, in))
	if err != nil || got.Digest() != r.n.Digest() {
		t.Fatalf("answered %v, %v", got, err)
	}
	if _, err := instructionsAnswered(r.zone, asked, map[string]string{configRefusedKey: "not held"}); err == nil {
		t.Error("a refusal is taken")
	}
}

func strconvU(u uint32) string { return strconv.FormatUint(uint64(u), 10) }

// operational has this agent hear id: OPERATIONAL in its peer registry.
func (r *thawRig) operational(id string) {
	r.t.Helper()
	tm := r.conf.InternalMp.MPTransport.TransportManager
	r.conf.InternalMp.AgentRegistry.TransportManager = tm
	p := tm.PeerRegistry.GetOrCreate(id)
	p.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test: heard")
	p.SetMechanismLastBeatSent(transport.MechanismDNS, time.Now())
}

// multi-provider.transitions.leaving-timeout defaults to an hour, and is
// refused when negative or not above the beat interval: no telling would
// ever be fresh.
func TestTheLeavingTimeoutIsAboveTheBeatInterval(t *testing.T) {
	var mp MultiProviderConf
	if got := leavingTimeoutFor(&mp); got != time.Hour {
		t.Errorf("the default: %s, want 1h0m0s", got)
	}
	for _, tc := range []struct {
		beat, timeout int
		ok            bool
	}{
		{0, 0, true},
		{0, 30, false}, // the beat interval's default is 30 s
		{0, 31, true},
		{60, 60, false},
		{60, 300, true},
		{0, -1, false},
	} {
		mp := MultiProviderConf{}
		mp.Remote.BeatInterval = uint32(tc.beat)
		mp.Transitions.LeavingTimeout = tc.timeout
		err := ValidateTransitions(&mp)
		if (err == nil) != tc.ok || (err != nil && !strings.Contains(err.Error(), "leaving-timeout")) {
			t.Errorf("beat %d, timeout %d: err = %v", tc.beat, tc.timeout, err)
		}
	}
}

// An excusal counts only while its zone agrees on the serial it was made
// for: the owner's newer serial, which keeps b, ends it, b unheard or not
// (CodeRabbit on tdns-mp #311).
func TestAnExcusalEndsWithTheSerialItWasMadeFor(t *testing.T) {
	r := newThawRig(t, "gateend.thaw.example.", "")
	pgm := NewProviderGroupManager(roleA)
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(ZoneName(r.zone))
	if pg == nil {
		t.Fatal("the zone is in no group")
	}
	r.conf.InternalMp.AgentRegistry.ProviderGroupManager = pgm
	r.v = freezeAt(t, 42, "v", "a", "") // b leaves
	r.holdUnjudged(r.v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	if vw := r.view(); len(vw.excused) != 1 {
		t.Fatalf("b is not excused: %q", vw.excused)
	}
	if got := r.conf.gateExcused(pg.GroupHash); len(got) != 1 {
		t.Fatalf("excused from the gate: %q", got)
	}
	r.store.Note(r.zone, freezeAt(t, 43, "w", "a,b", ""), nil) // b stays
	if st := status(t, r.store, r.zone); st.Agreeing == nil || st.Agreeing.Serial != 43 {
		t.Fatalf("the zone does not agree on 43: %+v", st)
	}
	if got := r.conf.gateExcused(pg.GroupHash); len(got) != 0 {
		t.Errorf("b is still excused from the gate after the owner kept it: %q", got)
	}
}

// A leaving member excused and not heard is left out of the gate of the
// group under N, so the group can elect without it; the excusal ends when
// it is heard again.
func TestAnUnheardExcusedMemberIsLeftOutOfTheGroupsGate(t *testing.T) {
	r := newThawRig(t, "gate.thaw.example.", "")
	pgm := NewProviderGroupManager(roleA)
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(ZoneName(r.zone))
	if pg == nil {
		t.Fatal("the zone is in no group")
	}
	r.conf.InternalMp.AgentRegistry.ProviderGroupManager = pgm
	r.v = freezeAt(t, 42, "v", "a", "")
	r.holdUnjudged(r.v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	if vw := r.view(); len(vw.excused) != 1 {
		t.Fatalf("b is not excused: %q", vw.excused)
	}
	if got := r.conf.gateExcused(pg.GroupHash); len(got) != 1 || got[0] != canonicalName(roleB) {
		t.Fatalf("excused from the gate: %q", got)
	}
	gst := NewGossipStateTable(roleA)
	gst.States[pg.GroupHash] = map[string]*MemberState{roleA: {Identity: roleA, PeerStates: map[string]string{roleB: AgentStateToString[AgentStateNeeded]}}}
	ops := 0
	gst.SetOnGroupOperational(func(string) { ops++ })
	gst.CheckGroupState(pg.GroupHash, pg.VotingMembers)
	if ops != 0 {
		t.Fatal("operational with b in the gate and not heard")
	}
	gst.SetGateExcused(r.conf.gateExcused)
	gst.CheckGroupState(pg.GroupHash, pg.VotingMembers)
	if ops != 1 {
		t.Fatal("the gate holds for b, excused and not heard")
	}
	// TestTheGateExcusalEndsWhenTheMemberIsHeard
	r.operational(roleB)
	if got := r.conf.gateExcused(pg.GroupHash); len(got) != 0 {
		t.Errorf("b is heard, and still excused from the gate: %q", got)
	}
	lem := NewLeaderElectionManager(roleA, time.Hour, nil)
	lem.SetProviderGroupManager(pgm)
	lem.SetGateExcused(func(string) []string { return []string{roleB} })
	if voters, _ := lem.groupVoters(pg.GroupHash, nil); len(voters) != 1 || voters[0] != roleA {
		t.Errorf("the election's voters: %q", voters)
	}
}

// Handed nothing, a combiner asks its agent for every zone whose copy reads
// and that it holds no hand-over for, at serial 0 as at any other (decision
// 107): from S7 a copy can hold a serial its agent refuses (tdns-mp #302).
func TestCombinerWaitsIsAskedForEveryZoneWithoutAHandOver(t *testing.T) {
	conf, zero := actingCombiner(t, "zero.waits.example.", actRecords(`serial="0" servers="alpha,beta" signers="alpha"`)...)
	_, serial := actingCombiner(t, "serial.waits.example.", actRecords(`serial="3" servers="alpha,beta" signers="alpha"`)...)
	for _, mpzd := range []*MPZoneData{zero, serial} {
		mpzd.Ready = true
		mpzd.Options[tdns.OptMultiProvider] = true
	}
	// a multi-provider zone whose copy has no instructions is handed
	// none, and does not wait
	_, none := actingCombiner(t, "none.waits.example.")
	none.Ready = true
	none.Options[tdns.OptMultiProvider] = true
	conf.InternalMp.MPZoneNames = []string{zero.ZoneName, serial.ZoneName, none.ZoneName}
	withActing(t, nil)
	if got := conf.zonesWaitingForHandover(); len(got) != 2 || slices.Contains(got, none.ZoneName) {
		t.Errorf("waiting: %q, want the two zones with instructions", got)
	}
}

// A rollover whose only missing confirmations are those of excused members
// (WaitsOn, plan S11) counts as paused, not under way: it holds the thaw no
// more, at a member and at this agent's own provider. One that waits on a
// member that is not excused holds it.
func TestAPausedRolloverDoesNotHoldTheThaw(t *testing.T) {
	r := newThawRig(t, "paused.thaw.example.", roleA)
	n, v := freezeAt(t, 41, "n", "a,b,n", ""), freezeAt(t, 42, "v", "a,n", "") // b leaves
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	knownAs(t, r.store, r.zone, n)
	r.n, r.v = n, v
	r.holdUnjudged(v, time.Now().Add(-leavingTimeoutDefault-time.Minute))
	r.hold()
	st := r.agreeing()
	st.Rollover, st.WaitsOn = true, []string{"b"}
	r.hear(roleN, st, true)
	if vw := r.view(); !vw.ready() || len(vw.excused) != 1 {
		t.Fatalf("n's rollover waits only on b, excused: waits %q, excused %q", vw.waits, vw.excused)
	}
	st.WaitsOn = []string{"a", "b"}
	r.hear(roleN, st, true)
	if vw := r.view(); vw.ready() || len(vw.waits) != 1 || vw.waits[0] != roleN+" (rollover under way)" {
		t.Fatalf("n's rollover waits on a too: waits %q", vw.waits)
	}
	st.WaitsOn = []string{"b"}
	r.hear(roleN, st, true)
	r.conf.InternalMp.MPTransport.pendingDnskeyPropagations["k"] = &PendingDnskeyPropagation{Zone: ZoneName(r.zone)}
	r.stamps.waitsOn = func(string) []string { return []string{"b"} }
	if vw := r.view(); !vw.ready() {
		t.Fatalf("this provider's rollover waits only on b: waits %q", vw.waits)
	}
	r.stamps.waitsOn = func(string) []string { return nil }
	if vw := r.view(); vw.ready() || len(vw.waits) != 1 || vw.waits[0] != roleA+" (rollover under way)" {
		t.Fatalf("this provider's rollover waits on nobody named: waits %q", vw.waits)
	}
}

// A serial a member tells active and this agent lacks is asked only of the
// zone's leader or a voting member under the active serial: a member with
// no vote is not trusted with the owner's instructions.
func TestASerialToldActiveIsAskedOnlyOfAVotingMember(t *testing.T) {
	r := newThawRig(t, "askvoter.thaw.example.", "")
	st := tells(r.v, r.v)
	st.Thaw = &Thaw{From: sd(r.n), To: sd(r.v)}
	r.hear(roleN, st, true)
	r.conf.thawTurn(r.zone)
	if r.fetchAsked(42, roleN) {
		t.Error("n, with no vote, was asked for the serial")
	}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if !r.fetchAsked(42, roleB) {
		t.Error("b, a voting member, was not asked for the serial")
	}
}

// An excusal never leaves a gate with no voter: one that would have
// nobody to wait for opens by itself, and stays open when a voter comes
// back.
func TestAnExcusalNeverEmptiesTheGate(t *testing.T) {
	if got := withoutExcused([]string{roleB}, []string{roleB}); len(got) != 1 || got[0] != roleB {
		t.Fatalf("every voter excused: %q", got)
	}
	gst := NewGossipStateTable(roleN)
	gst.SetGateExcused(func(string) []string { return []string{roleA, roleB} })
	ops := 0
	gst.SetOnGroupOperational(func(string) { ops++ })
	gst.CheckGroupState("g", []string{roleA, roleB})
	if ops != 0 {
		t.Error("a gate whose voters are all excused opened by itself")
	}
}

// A member heard that tells nothing of the zone is told apart from one not
// heard (plan S22): at rest a member lists none of its zones, until it
// hears the others' stamps of it.
func TestAHeardMemberThatTellsNothingOfTheZoneIsNotNotHeard(t *testing.T) {
	r := newThawRig(t, "nothing.thaw.example.", roleA)
	r.agree()
	r.hold()
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleB+" (not heard)" {
		t.Errorf("b not heard at all: %q", v.waits)
	}
	r.operational(roleB)
	if v := r.view(); v.ready() || len(v.waits) != 1 || v.waits[0] != roleB+" (tells nothing of the zone)" {
		t.Errorf("b heard, with no stamp of the zone: %q", v.waits)
	}
	r.hear(roleB, r.agreeing(), true)
	if v := r.view(); !v.ready() {
		t.Errorf("b telling agreement: %q", v.waits)
	}
}
