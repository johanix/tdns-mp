package tdnsmp

import (
	"errors"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// An algorithm rollover by the machine (transition table §6 O4; design §6
// S7): the driver on one provider with the fake wire and the fake clock,
// as the T3.4 scenarios run. tdns's key row invariants and P5 are checked
// after every step by the rig; the roll's own order is checked here: the
// new KSK signs only once the parent has served its DS for the DS TTL, the
// old KSK retires in that step, and the old ZSK stops signing only once no
// KSK of its algorithm does.

const algRollTo = dns.ECDSAP256SHA256

// algRolls is the driver's algorithm rollovers, a failed read fatal.
func algRolls(t *testing.T, l *ZoneKeyLifecycle) []AlgRolloverStatus {
	t.Helper()
	rolls, err := l.AlgorithmRollovers()
	if err != nil {
		t.Fatalf("the algorithm rollovers: %v", err)
	}
	return rolls
}

// keysOfAlg: the zone's own keys of the role and algorithm in the state.
func (r *driverRig) keysOfAlg(state, role string, alg uint8) []uint16 {
	r.t.Helper()
	ks, err := tdns.GetDnssecKeysByState(r.kdb, r.l.Zone, state)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []uint16
	for _, k := range ks {
		if roleOf(k.Flags) == role && k.Algorithm == alg {
			out = append(out, k.KeyTag)
		}
	}
	return out
}

func (r *driverRig) one(step, state, role string, alg uint8) uint16 {
	r.t.Helper()
	ks := r.keysOfAlg(state, role, alg)
	if len(ks) != 1 {
		r.t.Fatalf("%s: %s %s of %s: %v, want one", step, state, role, dns.AlgorithmToString[alg], ks)
	}
	return ks[0]
}

func (r *driverRig) rollOf(role string) *AlgRolloverStatus {
	for _, st := range algRolls(r.t, r.l) {
		if st.Role == role {
			s := st
			return &s
		}
	}
	return nil
}

func (r *driverRig) confirmAll(step string, keys ...uint16) {
	r.t.Helper()
	for _, k := range keys {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			r.t.Fatalf("%s: confirm %d: %v", step, k, err)
		}
	}
}

func (r *driverRig) setAlgorithms(step string, alg uint8, roles ...string) {
	r.t.Helper()
	for _, role := range roles {
		if _, err := r.l.SetAlgorithm(role, alg); err != nil {
			r.t.Fatalf("%s: set the %s algorithm: %v", step, role, err)
		}
	}
}

// The whole roll, KSK and ZSK together: ED25519 to ECDSAP256SHA256 at one
// provider with one other signer, in the conservative order.
func TestDriverRollsTheAlgorithm(t *testing.T) {
	r := newDriverRig(t, "algroll.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	if r.rollOf("KSK") != nil || r.rollOf("ZSK") != nil {
		t.Fatal("an algorithm rollover reported with the keys on the policy's algorithm")
	}

	// the trigger: the owner's algorithm changes for both roles
	r.setAlgorithms("change", algRollTo, "KSK", "ZSK")
	if r.l.Policy.KSKAlgorithm != algRollTo || r.l.Policy.ZSKAlgorithm != algRollTo {
		t.Fatalf("the policy's algorithms after the change: %d/%d", r.l.Policy.KSKAlgorithm, r.l.Policy.ZSKAlgorithm)
	}
	for _, role := range []string{"KSK", "ZSK"} {
		if st := r.rollOf(role); st == nil || st.From != dns.ED25519 || st.To != algRollTo || !strings.Contains(st.Step, "minted on the next tick") {
			t.Errorf("%s roll before the first tick: %+v", role, st)
		}
	}

	// T1 (O4): one key of the new algorithm per role, minted and on its way
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	y := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK is %s the tick the new one was minted, want active", st)
	}
	if st := r.rollOf("KSK"); st == nil || !strings.Contains(st.Step, "on its way") {
		t.Errorf("KSK roll step after the mint: %+v", st)
	}
	r.tick("nothing more minted")
	if ks := r.keysOfAlg(KeyStateMpdist, "KSK", algRollTo); len(ks) != 1 {
		t.Fatalf("a second tick minted again: %v", ks)
	}

	// T3: the other signer applies both; T8: propagated. The new ZSK signs
	// at once beside the old one (T9, P5's exception); the new KSK is
	// standby with ds=1 (its DS joins the DS set) and waits for the parent
	r.confirmAll("applied", b, y)
	if st, c := r.state(b), r.cols(b); st != KeyStatePublished || c != "100" {
		t.Fatalf("the new KSK after every signer applied: %s %s, want published 100", st, c)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	if st, c := r.state(b), r.cols(b); st != KeyStateStandby || c != "101" {
		t.Fatalf("the new KSK propagated: %s %s, want standby 101 (its DS belongs at the parent, P2)", st, c)
	}
	if st, c := r.state(y), r.cols(y); st != KeyStateActive || c != "110" {
		t.Fatalf("the new ZSK propagated: %s %s, want active 110 (it signs beside the old one)", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateActive || c != "110" {
		t.Fatalf("the old ZSK with the new one signing: %s %s, want active 110 (it leaves last: a KSK of its algorithm still signs)", st, c)
	}
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "111" {
		t.Fatalf("the old KSK with the new one standby: %s %s, want active 111", st, c)
	}
	if st := r.rollOf("ZSK"); st == nil || !strings.Contains(st.Step, "both ZSKs sign") {
		t.Errorf("ZSK roll step with both signing: %+v", st)
	}
	if st := r.rollOf("KSK"); st == nil || !strings.Contains(st.Step, "served the DS for the DS TTL") {
		t.Errorf("KSK roll step with the new KSK standby: %+v", st)
	}

	// the parent still serves only the old DS: the new KSK waits (O7)
	r.clock.Advance(2 * time.Hour)
	r.tick("the parent has only the old DS")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK promoted with its DS not at the parent: %s (O7)", st)
	}
	// the parent serves the new DS: noted (T18), and the wait is the DS TTL
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK promoted the tick its DS was first seen: %s, want standby for the DS TTL", st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK retired before the KSK side was done: %s", st)
	}
	r.clock.Advance(61 * time.Minute)
	r.tick("the DS TTL passed")
	// T9 for the new KSK; T10a for the old one: it goes on signing with
	// its DS withdrawn (the old algorithm's signatures stay as long as a
	// validator may hold the old DS, RFC 6781 §4.1.4); the old ZSK waits
	if st, c := r.state(b), r.cols(b); st != KeyStateActive || c != "111" {
		t.Errorf("the new KSK after the DS TTL: %s %s, want active 111", st, c)
	}
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Errorf("the old KSK after the DS TTL: %s %s, want active 110 (it signs on, its DS withdrawn: T10a)", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateActive || c != "110" {
		t.Errorf("the old ZSK with the old KSK still signing: %s %s, want active 110", st, c)
	}
	if st, c := r.state(y), r.cols(y); st != KeyStateActive || c != "110" {
		t.Errorf("the new ZSK: %s %s, want active 110", st, c)
	}
	if st := r.rollOf("KSK"); st == nil || !strings.Contains(st.Step, "withdrawn from the DS set") {
		t.Errorf("KSK roll step with both signing: %+v", st)
	}
	// the parent goes on serving the old DS: the old KSK signs on (T10b
	// waits for E7 and the DS TTL)
	r.clock.Advance(2 * time.Hour)
	r.tick("the parent still serves the old DS")
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Errorf("the old KSK while the parent serves its DS: %s %s, want active 110", st, c)
	}
	// the parent drops it (T11a): the DS TTL is the wait, then T10b retires
	// the old KSK and T19 the old ZSK in the same tick
	r.wire.parentDS[a] = false
	r.tick("the old DS gone")
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Errorf("the old KSK the tick its DS went: %s %s, want active 110 (a validator may hold the DS for the TTL)", st, c)
	}
	// the parent serves the old DS again (a secondary that lagged, say):
	// the note is dropped, and the wait starts afresh when it goes again
	r.wire.parentDS[a] = true
	r.tick("the old DS is back")
	r.clock.Advance(2 * time.Hour)
	r.tick("two hours with the old DS back")
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Errorf("the old KSK retired while the parent served its DS again: %s %s, want active 110", st, c)
	}
	r.wire.parentDS[a] = false
	r.tick("the old DS gone again")
	r.clock.Advance(30 * time.Minute)
	r.tick("half the DS TTL")
	if st := r.state(a); st != KeyStateActive {
		t.Errorf("the old KSK inside the DS TTL: %s, want active", st)
	}
	r.clock.Advance(31 * time.Minute)
	r.tick("the old DS TTL passed")
	if st, c := r.state(a), r.cols(a); st != KeyStateRetired || c != "100" {
		t.Errorf("the old KSK once its DS has been gone for the DS TTL: %s %s, want retired 100 (T10b)", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateRetired || c != "100" {
		t.Errorf("the old ZSK once the old KSK retired: %s %s, want retired 100 (T19)", st, c)
	}
	for _, role := range []string{"KSK", "ZSK"} {
		if st := r.rollOf(role); st == nil || !strings.Contains(st.Step, "retired") {
			t.Errorf("%s roll step with the old key retired: %+v", role, st)
		}
	}

	// the withdrawal (§5.7): the margin (the old DS is gone already), the
	// strip, the removal confirmed
	r.clock.Advance(driverPolicy.Margin + time.Second)
	r.tick("margin")
	if st, c := r.state(z), r.cols(z); st != KeyStateMpremove || c != "000" {
		t.Errorf("the old ZSK after the margin: %s %s, want mpremove 000", st, c)
	}
	if st, c := r.state(a), r.cols(a); st != KeyStateMpremove || c != "000" {
		t.Errorf("the old KSK after the margin, its DS long gone: %s %s, want mpremove 000", st, c)
	}
	stripped := map[uint16]bool{}
	for _, k := range r.wire.stripped {
		stripped[k] = true
	}
	if !stripped[a] || !stripped[z] {
		t.Errorf("stripped %v, want the old KSK %d and ZSK %d", r.wire.stripped, a, z)
	}
	for _, k := range []uint16{a, z} {
		if _, to, err := r.l.ConfirmKind(k, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
			t.Errorf("removal of %d confirmed: to=%s err=%v, want removed", k, to, err)
		}
	}
	r.check("done")
	if ks := r.keysIn(KeyStateActive, "KSK"); len(ks) != 1 || ks[0] != b {
		t.Errorf("active KSKs at the end %v, want the new one %d", ks, b)
	}
	if ks := r.keysIn(KeyStateActive, "ZSK"); len(ks) != 1 || ks[0] != y {
		t.Errorf("active ZSKs at the end %v, want the new one %d", ks, y)
	}
	if rolls := algRolls(t, r.l); len(rolls) != 0 {
		t.Errorf("rollovers still reported after the old keys left: %+v", rolls)
	}
	// a steady zone on the new algorithm: nothing more minted or moved
	r.tick("steady")
	if ks := append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...); len(ks) != 0 {
		t.Errorf("a steady zone on the new algorithm minted %v", ks)
	}
}

// The KSK side done before the new ZSK is ready: the old ZSK retires in
// the tick its successor is promoted (T19, the old KSK being retired).
func TestTheOldZSKRetiresWithItsSuccessorOnceTheKSKSideIsDone(t *testing.T) {
	r := newDriverRig(t, "algorder.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "KSK", "ZSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	y := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
	// only the KSK is confirmed; the ZSK's distribution lags
	r.confirmAll("the KSK applied", b)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the KSK propagated")
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(61 * time.Minute)
	r.tick("the DS TTL passed")
	if st := r.state(b); st != KeyStateActive {
		t.Fatalf("the new KSK: %s, want active", st)
	}
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Fatalf("the old KSK: %s %s, want active 110 (signing on, its DS withdrawn)", st, c)
	}
	// the parent drops the old DS and the DS TTL passes: the old KSK retires
	r.wire.parentDS[a] = false
	r.tick("the old DS gone")
	r.clock.Advance(61 * time.Minute)
	r.tick("the old DS TTL passed")
	if st := r.state(a); st != KeyStateRetired {
		t.Fatalf("the old KSK: %s, want retired", st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK with no successor yet: %s, want active (the zone's data must stay signed)", st)
	}
	if st := r.state(y); st != KeyStateMpdist {
		t.Fatalf("the new ZSK, unconfirmed: %s, want mpdist", st)
	}
	// now the ZSK: confirmed, propagated, promoted; the old one retires in
	// the same tick (T19: the KSK side is done, the old KSK retired)
	r.confirmAll("the ZSK applied", y)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the ZSK propagated")
	if st, c := r.state(y), r.cols(y); st != KeyStateActive || c != "110" {
		t.Errorf("the new ZSK: %s %s, want active 110", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateRetired || c != "100" {
		t.Errorf("the old ZSK with the KSK side done: %s %s, want retired 100 (T19)", st, c)
	}
	r.check("done")
}

// A ZSK-only change is gradual, as tdns's relaxed roll is: no KSK of the
// old algorithm is left to wait for, and the old ZSK keeps signing beside
// the new one for a signature lifetime before it retires (T19). And once
// the new algorithm signs the cancel is refused.
func TestAZSKOnlyAlgorithmChangeKeepsTheOldZSKForASignatureLifetimeAndCannotBeCancelledOnceItSigns(t *testing.T) {
	r := newDriverRig(t, "algzsk.owned.example.", driverPolicy, "p2")
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "ZSK")
	r.tick("minted")
	y := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
	if ks := r.keysOfAlg(KeyStateMpdist, "KSK", algRollTo); len(ks) != 0 {
		t.Fatalf("a ZSK-only change minted a KSK: %v", ks)
	}
	if st := r.rollOf("KSK"); st != nil {
		t.Errorf("a KSK roll reported for a ZSK-only change: %+v", st)
	}
	r.confirmAll("applied", y)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	if st, c := r.state(y), r.cols(y); st != KeyStateActive || c != "110" {
		t.Fatalf("the new ZSK: %s %s, want active 110", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateActive || c != "110" {
		t.Fatalf("the old ZSK of a ZSK-only change with the new one signing: %s %s, want active 110 (both sign for a signature lifetime)", st, c)
	}
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the KSK: %s, want active, untouched", st)
	}
	if st := r.rollOf("ZSK"); st == nil || !strings.Contains(st.Step, "signature lifetime") {
		t.Errorf("ZSK roll step with both signing: %+v", st)
	}
	r.clock.Advance(driverPolicy.SigLifetime / 2)
	r.tick("half a signature lifetime")
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK inside the signature lifetime: %s, want active", st)
	}
	r.clock.Advance(driverPolicy.SigLifetime/2 + time.Second)
	r.tick("a signature lifetime")
	if st, c := r.state(z), r.cols(z); st != KeyStateRetired || c != "100" {
		t.Fatalf("the old ZSK a signature lifetime after the new one began signing: %s %s, want retired 100 (T19)", st, c)
	}
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the new ZSK: %s, want active", st)
	}
	// the cancel rule: a key of the new algorithm signs, so the roll
	// completes; the way back is a change of the algorithm once it has
	if _, _, err := r.l.CancelAlgorithmRollover("ZSK"); !errors.Is(err, ErrAlgRollSigns) {
		t.Errorf("cancel with the new ZSK signing: err=%v, want ErrAlgRollSigns", err)
	}
	if r.l.Policy.ZSKAlgorithm != algRollTo {
		t.Errorf("the refused cancel changed the algorithm to %d", r.l.Policy.ZSKAlgorithm)
	}
	r.check("after the refused cancel")
}

// The withdrawal wait against a parent that answers with no DS at all
// (NOERROR and empty: the engine reports no TTL), and across a restart.
// The TTL the wait runs on is the one the parent served the successor's DS
// with (its T18 note), never the empty answer's zero and not the margin
// floor either (the parent's TTL is longer than the margin here, so the
// two are told apart); and the note is read back after a restart, so the
// wait neither starts over nor ends at once.
func TestTheWithdrawalWaitHasATTLWithAnEmptyAnswerAndSurvivesARestart(t *testing.T) {
	r := newDriverRig(t, "algwait.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = 90 * time.Minute
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	r.confirmAll("applied", b)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(91 * time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Fatalf("the old KSK after the promotion: %s %s, want active 110", st, c)
	}
	// the parent now answers with no DS at all: known, empty, no TTL
	r.wire.parentDS = map[uint16]bool{}
	r.tick("an empty answer")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK the tick of the empty answer: %s, want active (the wait is the DS TTL the parent served, not the answer's zero)", st)
	}
	r.clock.Advance(30 * time.Minute)
	r.tick("thirty minutes")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK thirty minutes into a ninety-minute wait: %s, want active", st)
	}
	// a restart in the middle of the wait: the note comes back
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	r.clock.Advance(31 * time.Minute)
	r.tick("sixty-one minutes, after a restart")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK past the margin but inside the parent's DS TTL, after a restart: %s, want active (the wait is the T18 TTL, not the margin floor, and did not end at the restart)", st)
	}
	r.clock.Advance(30 * time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(a), r.cols(a); st != KeyStateRetired || c != "100" {
		t.Errorf("the old KSK ninety minutes after the parent stopped serving its DS: %s %s, want retired 100 (the wait did not start over at the restart)", st, c)
	}
	r.check("done")
}

// A ZSK-only change in a zone that still carries a retired KSK of the old
// algorithm from an earlier KSK roll (its removal unconfirmed, say): that
// KSK is not this roll's, so the old ZSK waits the signature lifetime, not
// the KSK's leaving.
func TestAZSKOnlyChangeWithALeftoverKSKOfTheOldAlgorithmWaitsTheSignatureLifetime(t *testing.T) {
	r := newDriverRig(t, "algleft.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	// a KSK roll, through to the old KSK's removal being distributed
	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	r.confirmAll("applied", b)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(61 * time.Minute)
	r.tick("promoted")
	r.wire.parentDS[a] = false
	r.tick("the old DS gone")
	r.clock.Advance(61 * time.Minute)
	r.tick("the old DS TTL passed")
	r.clock.Advance(driverPolicy.Margin + time.Second)
	r.tick("the margin")
	if st := r.state(a); st != KeyStateMpremove {
		t.Fatalf("the old KSK after its roll: %s, want mpremove (its removal unconfirmed)", st)
	}
	// now the ZSK: the leftover KSK retired before this change began
	r.setAlgorithms("change", algRollTo, "ZSK")
	r.tick("minted")
	y := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
	r.confirmAll("applied", y)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	if st, c := r.state(y), r.cols(y); st != KeyStateActive || c != "110" {
		t.Fatalf("the new ZSK: %s %s, want active 110", st, c)
	}
	if st, c := r.state(z), r.cols(z); st != KeyStateActive || c != "110" {
		t.Fatalf("the old ZSK with a leftover KSK of its algorithm in mpremove: %s %s, want active 110 (that KSK is not this roll's: the signature lifetime applies)", st, c)
	}
	r.clock.Advance(driverPolicy.SigLifetime + time.Second)
	r.tick("a signature lifetime")
	if st, c := r.state(z), r.cols(z); st != KeyStateRetired || c != "100" {
		t.Errorf("the old ZSK after the signature lifetime: %s %s, want retired 100 (T19)", st, c)
	}
	r.check("done")
}

// Cancel while nothing of the new algorithm signs: the algorithm goes
// back, the new keys are withdrawn, and a standby of the old algorithm
// given up on at the change is minted again. Also: the change withdraws a
// standby of the old algorithm (it never signed; the policy no longer
// names its algorithm).
func TestAlgorithmRolloverCancelledBeforeTheNewAlgorithmSigns(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "algcancel.owned.example.", pol, "p2")
	r.wire.parentTTL = time.Hour
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	// the policy's standby KSK of the old algorithm, propagated
	r.tick("standby wanted")
	a2 := r.one("standby wanted", KeyStateMpdist, "KSK", dns.ED25519)
	r.confirmAll("standby applied", a2)
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	if st := r.state(a2); st != KeyStateStandby {
		t.Fatalf("the old algorithm's standby: %s", st)
	}
	r.wire.parentDS[a2] = true

	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("changed")
	// the old algorithm's standby is withdrawn (ds=0: its DS leaves the DS
	// set), the new algorithm's KSK minted in its place
	if st, c := r.state(a2), r.cols(a2); st != KeyStateMpremove || c != "000" {
		t.Fatalf("the old algorithm's standby after the change: %s %s, want mpremove 000", st, c)
	}
	b := r.one("changed", KeyStateMpdist, "KSK", algRollTo)
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK: %s, want active", st)
	}
	if _, to, err := r.l.ConfirmKind(a2, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
		t.Fatalf("the withdrawn standby's removal: to=%s err=%v", to, err)
	}
	r.confirmAll("the new KSK applied", b)
	if st := r.state(b); st != KeyStatePublished {
		t.Fatalf("the new KSK: %s, want published", st)
	}

	// cancel: nothing of the new algorithm signs, so the algorithm goes
	// back and the new KSK is withdrawn on the next tick
	from, to, err := r.l.CancelAlgorithmRollover("KSK")
	if err != nil || from != dns.ED25519 || to != algRollTo {
		t.Fatalf("cancel: from %d to %d err %v, want ED25519, ECDSAP256SHA256 and no error", from, to, err)
	}
	if r.l.Policy.KSKAlgorithm != dns.ED25519 {
		t.Fatalf("after the cancel the policy's KSK algorithm is %d, want ED25519", r.l.Policy.KSKAlgorithm)
	}
	r.tick("cancelled")
	if st, c := r.state(b), r.cols(b); st != KeyStateMpremove || c != "000" {
		t.Errorf("the new KSK after the cancel: %s %s, want mpremove 000", st, c)
	}
	if st := r.state(a); st != KeyStateActive {
		t.Errorf("the old KSK after the cancel: %s, want active, untouched", st)
	}
	// the standby count is met again with the old algorithm
	a3 := r.one("cancelled", KeyStateMpdist, "KSK", dns.ED25519)
	if a3 == a2 {
		t.Errorf("the withdrawn standby came back as itself")
	}
	if rolls := algRolls(t, r.l); len(rolls) != 0 {
		t.Errorf("rollovers reported after the cancel: %+v", rolls)
	}
	if _, to, err := r.l.ConfirmKind(b, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
		t.Errorf("the new KSK's removal: to=%s err=%v", to, err)
	}
	r.check("done")
	// with nothing to go back to, a cancel says so
	if _, _, err := r.l.CancelAlgorithmRollover("ZSK"); err == nil || !strings.Contains(err.Error(), "nothing to go back to") {
		t.Errorf("cancel with no algorithm rollover: err=%v, want a refusal naming nothing to go back to", err)
	}
}

// T15: the owner's algorithm survives a restart. A new driver over the
// same keystore, made with the bound policy's old algorithm, reads the
// change back and goes on with the roll instead of withdrawing the new key.
func TestAlgorithmRolloverSurvivesARestart(t *testing.T) {
	r := newDriverRig(t, "algrestart.owned.example.", driverPolicy, "p2")
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)

	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatal(err)
	}
	if r.l.Policy.KSKAlgorithm != algRollTo || r.l.Policy.ZSKAlgorithm != dns.ED25519 {
		t.Fatalf("after the restart the algorithms are %d/%d, want the changed KSK algorithm and the ZSK's as bound", r.l.Policy.KSKAlgorithm, r.l.Policy.ZSKAlgorithm)
	}
	if st := r.rollOf("KSK"); st == nil || st.From != dns.ED25519 || st.To != algRollTo {
		t.Errorf("the KSK roll after the restart: %+v", st)
	}
	r.tick("after the restart")
	if st := r.state(b); st != KeyStateMpdist {
		t.Errorf("the new KSK after the restart: %s, want still mpdist (not withdrawn)", st)
	}
	// a policy bound anew keeps the owner's algorithm
	r.l.SetPolicy(driverPolicy)
	if r.l.Policy.KSKAlgorithm != algRollTo {
		t.Errorf("a policy bound anew dropped the owner's KSK algorithm: %d", r.l.Policy.KSKAlgorithm)
	}
}

// The table's rows for the roll (O4), with a fake zone: T1 mints the
// policy's algorithm when no key of it is on its way or signing; a successor
// of another algorithm retires nothing on T10: the old KSK goes on signing
// with its DS withdrawn (T10a) until the parent has not served the DS for
// the DS TTL (T11a, T10b); the old ZSK waits for T19, which needs the KSK
// side done and either the old KSK retired or a signature lifetime.
func TestAlgorithmRolloverGuards(t *testing.T) {
	pending := ZoneView{AlgRollPending: true}
	if next, row := Next(KeyView{}, EvMint, pending); row == nil || row.ID != "T1" || next != KeyStateCreated {
		t.Errorf("an algorithm rollover pending with nothing of the new algorithm: row %v, want T1", row)
	}
	pending.PolicyAlgKeys = 1
	if _, row := Next(KeyView{}, EvMint, pending); row != nil {
		t.Errorf("an algorithm rollover pending with a key of the new algorithm on its way mints again (row %s)", row.ID)
	}

	oldZSK := KeyView{State: KeyStateActive, Algorithm: dns.ED25519}
	oldKSK := KeyView{State: KeyStateActive, SEP: true, Algorithm: dns.ED25519}
	// E6 on the old keys: a successor of another algorithm retires nothing
	for _, zv := range []ZoneView{{SuccessorAlgorithm: algRollTo}, {SuccessorAlgorithm: algRollTo, KSKSideDone: true}} {
		if st, row := Next(oldZSK, EvSuccessorActive, zv); st != KeyStateActive || row != nil {
			t.Errorf("the old ZSK on a successor of another algorithm (KSK side done %v): %s via %v, want active, no row", zv.KSKSideDone, st, row)
		}
	}
	if st, _ := Next(oldZSK, EvSuccessorActive, ZoneView{SuccessorAlgorithm: dns.ED25519}); st != KeyStateRetired {
		t.Errorf("a ZSK on a same-algorithm successor: %s, want retired", st)
	}
	if st, _ := Next(oldZSK, EvSuccessorActive, ZoneView{}); st != KeyStateRetired {
		t.Errorf("a ZSK on a successor of unstated algorithm: %s, want retired", st)
	}
	if st, row := Next(oldKSK, EvSuccessorActive, ZoneView{SuccessorAlgorithm: algRollTo}); st != KeyStateActive || row == nil || row.ID != "T10a" {
		t.Errorf("the old KSK on a successor of another algorithm: %s via %v, want active via T10a (it signs on with its DS withdrawn)", st, row)
	}
	if st, row := Next(oldKSK, EvSuccessorActive, ZoneView{SuccessorAlgorithm: dns.ED25519}); st != KeyStateRetired || row == nil || row.ID != "T10" {
		t.Errorf("the old KSK on a same-algorithm successor: %s via %v, want retired via T10", st, row)
	}
	// the withdrawal wait: E7 is noted on the active row (T11a), and E15
	// retires it once the DS has been gone for the DS TTL (T10b)
	now := time.Now()
	withdrawn := KeyView{State: KeyStateActive, SEP: true, Algorithm: dns.ED25519, Withdrawn: true}
	if st, row := Next(withdrawn, EvDSGone, ZoneView{}); st != KeyStateActive || row == nil || row.ID != "T11a" {
		t.Errorf("the withdrawn KSK's DS gone: %s via %v, want active via T11a", st, row)
	}
	if st, row := Next(oldKSK, EvDSGone, ZoneView{}); st != KeyStateActive || row != nil {
		t.Errorf("an active KSK whose DS is not withdrawn on E7: %s via %v, want no row", st, row)
	}
	gone := withdrawn
	gone.DSGone, gone.DSGoneAt, gone.ParentDSTTL = true, now.Add(-30*time.Minute), time.Hour
	if st, row := Next(gone, EvDSExpired, ZoneView{Now: now}); st != KeyStateActive || row != nil {
		t.Errorf("the withdrawn KSK inside the DS TTL: %s via %v, want active, no row", st, row)
	}
	if st, row := Next(gone, EvDSExpired, ZoneView{Now: now.Add(31 * time.Minute)}); st != KeyStateRetired || row == nil || row.ID != "T10b" {
		t.Errorf("the withdrawn KSK after the DS TTL: %s via %v, want retired via T10b", st, row)
	}
	notGone := withdrawn
	if st, row := Next(notGone, EvDSExpired, ZoneView{Now: now.Add(time.Hour)}); st != KeyStateActive || row != nil {
		t.Errorf("the withdrawn KSK whose DS the parent still serves on E15: %s via %v, want no row", st, row)
	}
	// T19: the KSK side done and the old KSK retired (a combined roll)
	done := ZoneView{PolicyAlgorithm: algRollTo, PolicyAlgActive: true, KSKSideDone: true, OldAlgKSKLeaving: true, Now: now}
	if st, row := Next(oldZSK, EvAlgSuperseded, done); st != KeyStateRetired || row == nil || row.ID != "T19" {
		t.Errorf("the old ZSK with the new one signing and the old KSK retired: %s via %v, want retired via T19", st, row)
	}
	notYet := done
	notYet.KSKSideDone = false
	if st, _ := Next(oldZSK, EvAlgSuperseded, notYet); st != KeyStateActive {
		t.Errorf("the old ZSK with a KSK of its algorithm still signing: %s, want active", st)
	}
	noNew := done
	noNew.PolicyAlgActive = false
	if st, _ := Next(oldZSK, EvAlgSuperseded, noNew); st != KeyStateActive {
		t.Errorf("the old ZSK with no ZSK of the policy's algorithm signing: %s, want active", st)
	}
	// T19 in a ZSK-only roll: no old KSK to wait for, a signature lifetime instead
	zskOnly := ZoneView{PolicyAlgorithm: algRollTo, PolicyAlgActive: true, KSKSideDone: true, PolicyAlgActiveSince: now.Add(-time.Hour), SigLifetime: 2 * time.Hour, Now: now}
	if st, row := Next(oldZSK, EvAlgSuperseded, zskOnly); st != KeyStateActive || row != nil {
		t.Errorf("the old ZSK of a ZSK-only roll inside the signature lifetime: %s via %v, want active, no row", st, row)
	}
	zskOnly.Now = now.Add(time.Hour + time.Second)
	if st, row := Next(oldZSK, EvAlgSuperseded, zskOnly); st != KeyStateRetired || row == nil || row.ID != "T19" {
		t.Errorf("the old ZSK of a ZSK-only roll after the signature lifetime: %s via %v, want retired via T19", st, row)
	}
	if _, row := Next(oldKSK, EvAlgSuperseded, done); row != nil {
		t.Errorf("a KSK took row %s on E14, want none (T10a and T10b are its rows)", row.ID)
	}
	if _, row := Next(KeyView{State: KeyStateActive, Algorithm: algRollTo}, EvAlgSuperseded, done); row != nil {
		t.Errorf("a ZSK of the policy's algorithm took row %s on E14, want none", row.ID)
	}
}

// The roll through the harness (T3.2): three providers, one changes its
// algorithms. The cross-provider gates hold: the new keys sign only once
// every other signing provider has applied them, the new KSK only once the
// harness's parent (which follows the DS set one tick behind) has served
// its DS for the DS TTL; the old keys leave everywhere.
func TestHarnessThreeProvidersRollTheAlgorithm(t *testing.T) {
	h := newMPHarness(t, 7, 3, harnessPolicy)
	step := func(name string) {
		h.deliver()
		h.tickAll(name)
		h.deliver()
		h.checkAll(name)
	}
	step("mint")
	h.clock.Advance(harnessPolicy.PropagationDelay + time.Hour + time.Second)
	step("propagated")
	step("standbys wanted")
	h.clock.Advance(harnessPolicy.PropagationDelay + time.Hour + time.Second)
	step("standbys propagated")
	p1, p2, p3 := h.providers[0], h.providers[1], h.providers[2]
	oldKSK, oldZSK := activeOf(h, p1, "KSK")[0], activeOf(h, p1, "ZSK")[0]
	oldStandby := standbyOf(h, p1, "KSK")
	if len(oldStandby) != 1 {
		t.Fatalf("p1 standby KSKs %v, want 1", oldStandby)
	}
	for _, role := range []string{"KSK", "ZSK"} {
		if _, err := p1.driver.SetAlgorithm(role, algRollTo); err != nil {
			t.Fatal(err)
		}
	}
	step("changed")
	// the old algorithm's standby is withdrawn, the new keys are on their
	// way: foreign at p2 and p3 once delivered
	if st := mpKeyState(t, p1.kdb, p1.zone, oldStandby[0]); st != KeyStateMpremove && st != KeyStateRemoved {
		t.Errorf("p1's standby of the old algorithm after the change: %s, want withdrawn", st)
	}
	var newKSK, newZSK uint16
	for _, it := range h.inventory(p1) {
		if it.State != DnskeyStateForeign && it.Algorithm == algRollTo {
			if it.Flags&dns.SEP != 0 {
				newKSK = it.KeyTag
			} else {
				newZSK = it.KeyTag
			}
		}
	}
	if newKSK == 0 || newZSK == 0 {
		t.Fatalf("p1 minted no keys of the new algorithm (KSK %d, ZSK %d)", newKSK, newZSK)
	}
	for _, p := range []*hProvider{p2, p3} {
		seen := map[uint16]bool{}
		for _, it := range h.inventory(p) {
			if it.State == DnskeyStateForeign {
				seen[it.KeyTag] = true
			}
		}
		if !seen[newKSK] || !seen[newZSK] {
			t.Errorf("%s does not hold p1's new keys as foreign rows: %v", p.id, seen)
		}
	}
	h.clock.Advance(harnessPolicy.PropagationDelay + time.Hour + time.Second)
	step("the new keys propagated")
	if got := activeOf(h, p1, "ZSK"); len(got) != 2 {
		t.Fatalf("p1's active ZSKs %v, want the old and the new one signing together", got)
	}
	if got := activeOf(h, p1, "KSK"); len(got) != 1 || got[0] != oldKSK {
		t.Fatalf("p1's active KSKs %v, want the old one %d only (the new one waits for the parent)", got, oldKSK)
	}
	step("the parent serves the new DS")
	if got := activeOf(h, p1, "KSK"); len(got) != 1 || got[0] != oldKSK {
		t.Fatalf("p1's new KSK promoted inside the DS TTL: active %v (O7)", got)
	}
	h.clock.Advance(h.parentTTL + time.Second)
	step("the DS TTL passed")
	// T9 and T10a: both KSKs sign, the old one's DS withdrawn; the old
	// algorithm's signatures stay while a validator may hold its DS
	if got := activeOf(h, p1, "KSK"); len(got) != 2 {
		t.Fatalf("p1's active KSKs after the DS TTL %v, want the new one %d and the old one %d signing together", got, newKSK, oldKSK)
	}
	for _, it := range h.inventory(p1) {
		if it.KeyTag == oldKSK && (!it.Sign || it.DS == nil || *it.DS) {
			t.Errorf("p1's old KSK after the new one signs: sign=%v ds=%v, want signing with its DS withdrawn (T10a)", it.Sign, it.DS)
		}
	}
	if st := mpKeyState(t, p1.kdb, p1.zone, oldZSK); st != KeyStateActive {
		t.Errorf("p1's old ZSK while the old KSK signs: %s, want active", st)
	}
	// the harness's parent follows the DS set one tick behind: the old DS
	// goes (T11a), and after the DS TTL the old KSK retires (T10b) and the
	// old ZSK with it (T19)
	step("the parent drops the old DS")
	if st := mpKeyState(t, p1.kdb, p1.zone, oldKSK); st != KeyStateActive {
		t.Errorf("p1's old KSK the tick its DS went: %s, want active for the DS TTL", st)
	}
	h.clock.Advance(h.parentTTL + time.Second)
	step("the old DS TTL passed")
	if got := activeOf(h, p1, "KSK"); len(got) != 1 || got[0] != newKSK {
		t.Fatalf("p1's active KSKs once the old DS has been gone for the DS TTL %v, want the new one %d", got, newKSK)
	}
	if st := mpKeyState(t, p1.kdb, p1.zone, oldKSK); st != KeyStateRetired {
		t.Errorf("p1's old KSK: %s, want retired (T10b)", st)
	}
	if st := mpKeyState(t, p1.kdb, p1.zone, oldZSK); st != KeyStateRetired {
		t.Errorf("p1's old ZSK once the KSK side is done: %s, want retired (T19)", st)
	}
	if left := h.drain(16); len(left) != 0 {
		t.Errorf("after the drain, still in flight: %v", left)
	}
	h.checkAll("drained")
	for _, role := range []string{"KSK", "ZSK"} {
		got := activeOf(h, p1, role)
		if len(got) != 1 || p1.keyInfo[got[0]].alg != algRollTo {
			t.Errorf("p1 ends with active %s %v, want one of the new algorithm", role, got)
		}
	}
	if rolls := algRolls(t, p1.driver); len(rolls) != 0 {
		t.Errorf("p1 still reports %+v after the drain", rolls)
	}
	for _, p := range []*hProvider{p2, p3} {
		for _, it := range h.inventory(p) {
			if it.State == DnskeyStateForeign && (it.KeyTag == oldKSK || it.KeyTag == oldZSK) {
				t.Errorf("%s still holds p1's old key %d as foreign", p.id, it.KeyTag)
			}
		}
		// the other providers' keys are untouched by p1's roll
		for _, role := range []string{"KSK", "ZSK"} {
			if got := activeOf(h, p, role); len(got) != 1 || p.keyInfo[got[0]].alg != dns.ED25519 {
				t.Errorf("%s ends with active %s %v, want one on ED25519", p.id, role, got)
			}
		}
	}
}

// The roll promotes the new algorithm once. After the new ZSK signs, the
// standby count mints the next ZSK of the new algorithm; it waits as any
// standby does while the old algorithm's ZSK signs on (T19's wait), and is
// not promoted on the old key's account. Found on the testbed: one ZSK roll
// per standby, each retiring the roll's key, until the old ZSK retired.
func TestAnAlgorithmRolloverPromotesTheNewAlgorithmOnce(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r := newDriverRig(t, "algonce.owned.example.", pol, "p2")
	r.wire.parentTTL = time.Hour
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	// the old algorithm's standby ZSK, propagated
	r.tick("standby wanted")
	z2 := r.one("standby wanted", KeyStateMpdist, "ZSK", dns.ED25519)
	r.confirmAll("standby applied", z2)
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	if st := r.state(z2); st != KeyStateStandby {
		t.Fatalf("the old algorithm's standby: %s", st)
	}

	r.setAlgorithms("change", algRollTo, "ZSK")
	r.tick("changed")
	if st := r.state(z2); st != KeyStateMpremove {
		t.Fatalf("the old algorithm's standby after the change: %s, want mpremove", st)
	}
	y := r.one("changed", KeyStateMpdist, "ZSK", algRollTo)
	if _, to, err := r.l.ConfirmKind(z2, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
		t.Fatalf("the withdrawn standby's removal: to=%s err=%v", to, err)
	}
	r.confirmAll("the new ZSK applied", y)
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new ZSK propagated")
	r.tick("the new ZSK signs")
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the new ZSK %d: %s, want active", y, st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d: %s, want active: it signs on until T19", z, st)
	}
	// the standby count mints the next ZSK of the new algorithm
	ys := r.keysOfAlg(KeyStateMpdist, "ZSK", algRollTo)
	if len(ys) == 0 {
		r.tick("standby wanted again")
		ys = r.keysOfAlg(KeyStateMpdist, "ZSK", algRollTo)
	}
	if len(ys) != 1 {
		t.Fatalf("the standby count's next ZSK of %s: %v, want one", dns.AlgorithmToString[algRollTo], ys)
	}
	y2 := ys[0]
	r.confirmAll("the next ZSK applied", y2)
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	for i := 0; i < 3; i++ {
		r.tick("the next ZSK propagated")
	}
	if st := r.state(y2); st != KeyStateStandby {
		t.Fatalf("the standby count's ZSK %d: %s, want standby: the roll promotes once", y2, st)
	}
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the roll's ZSK %d: %s, want active: it was rolled again", y, st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d: %s, want active", z, st)
	}
	if st := r.rollOf("ZSK"); st == nil || !strings.Contains(st.Step, "both ZSKs sign") {
		t.Errorf("ZSK roll step with the next standby waiting: %+v", st)
	}
	// a rollover requested still rolls the new algorithm's ZSK as any key:
	// the standby is promoted and the roll's ZSK retires (T10)
	r.l.RequestRollover("ZSK")
	r.tick("rollover requested")
	if st := r.state(y2); st != KeyStateActive {
		t.Fatalf("the standby after a rollover requested: %s, want active", st)
	}
	if st := r.state(y); st != KeyStateRetired {
		t.Fatalf("the roll's ZSK after a rollover requested: %s, want retired", st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK after the requested roll: %s, want active still", st)
	}
}

// withdrawalWait runs a KSK algorithm roll to the point where the old KSK
// signs on with its DS withdrawn, the parent has answered without the DS
// and the note is taken: the wait of T11a/T10b is on. Returns the old and
// the new KSK.
func withdrawalWait(t *testing.T, r *driverRig) (old, new uint16) {
	t.Helper()
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	r.confirmAll("applied", b)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(r.wire.parentTTL + time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(a), r.cols(a); st != KeyStateActive || c != "110" {
		t.Fatalf("the old KSK after the promotion: %s %s, want active 110", st, c)
	}
	r.wire.parentDS[a] = false
	r.tick("the old DS gone")
	if !r.l.dsGone[a] {
		t.Fatalf("the DS gone was not noted for the old KSK %d", a)
	}
	return a, b
}

// T10b fires only on a tick the parent answered without the DS: with the
// parent unknown the note's TTL passing retires nothing (the parent may
// serve the DS again, which would drop the note), as T9's wait does (O7).
func TestTheWithdrawalWaitEndsOnlyOnATickTheParentAnswered(t *testing.T) {
	r := newDriverRig(t, "algknown.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, _ := withdrawalWait(t, r)
	r.wire.parentOff = true
	r.clock.Advance(r.wire.parentTTL + time.Minute)
	r.tick("the DS TTL passed, the parent unknown")
	r.tick("still unknown")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK with the parent unknown after the DS TTL: %s, want active (no answer, no expiry)", st)
	}
	r.wire.parentOff = false
	r.tick("the parent answers without the DS")
	if st, c := r.state(a), r.cols(a); st != KeyStateRetired || c != "100" {
		t.Fatalf("the old KSK once the parent answered without the DS: %s %s, want retired 100", st, c)
	}
	r.check("done")
}

// A key inventory that cannot be read at a restart fails the reload and
// keeps the withdrawal wait's notes; the next reload reads them back.
func TestAnUnreadableInventoryAtARestartKeepsTheWithdrawalNotes(t *testing.T) {
	r := newDriverRig(t, "alginv.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, _ := withdrawalWait(t, r)
	notes := func() int {
		var n int
		if err := r.kdb.DB.QueryRow(`SELECT COUNT(*) FROM MPParentDS WHERE zonename=? AND keyid=?`, r.l.Zone, int(a)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if notes() != 1 {
		t.Fatalf("the withdrawal wait's note of %d before the restart: %d rows, want one", a, notes())
	}
	broken := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	broken.Inventory = func(*tdns.KeyDB, string) ([]tdns.KeyInventoryItem, error) {
		return nil, errors.New("the keystore is away")
	}
	if err := broken.Reload(); err == nil {
		t.Fatal("a reload with an unreadable inventory succeeded; it must fail")
	}
	if notes() != 1 {
		t.Fatalf("the withdrawal wait's note after the failed reload: %d rows, want one (nothing deleted)", notes())
	}
	// the same driver with the inventory unreadable only on a tick: the
	// wait is left alone, not ended
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !r.l.dsGone[a] {
		t.Fatalf("the DS gone note of %d did not come back at the reload", a)
	}
	r.l.Inventory = func(*tdns.KeyDB, string) ([]tdns.KeyInventoryItem, error) {
		return nil, errors.New("the keystore is away")
	}
	r.clock.Advance(r.wire.parentTTL + time.Minute)
	r.tick("the DS TTL passed, the inventory unreadable")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK on a tick with the inventory unreadable: %s, want active (the wait left alone)", st)
	}
	r.l.Inventory = nil
	r.tick("the inventory readable again")
	if st := r.state(a); st != KeyStateRetired {
		t.Fatalf("the old KSK once the inventory is readable again: %s, want retired", st)
	}
	r.check("done")
}

// A change of the owner's algorithm whose save fails leaves the policy as
// it was: no roll starts from a value the database does not hold. The
// same for a cancel whose save fails: the roll goes on.
func TestAFailedSaveOfTheAlgorithmLeavesThePolicyAsItWas(t *testing.T) {
	r := newDriverRig(t, "algsave.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	if _, err := r.kdb.DB.Exec(`ALTER TABLE MPOwnerAlgorithm RENAME TO MPOwnerAlgorithm_away`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.l.SetAlgorithm("KSK", algRollTo); err == nil {
		t.Fatal("setting the algorithm with the table away succeeded; it must fail")
	}
	if r.l.Policy.KSKAlgorithm != dns.ED25519 {
		t.Fatalf("the policy's KSK algorithm after the failed save: %s, want ED25519", dns.AlgorithmToString[r.l.Policy.KSKAlgorithm])
	}
	if st := r.rollOf("KSK"); st != nil {
		t.Fatalf("a KSK algorithm rollover reported after the failed save: %+v", st)
	}
	r.tick("nothing to mint")
	if ks := r.keysOfAlg(KeyStateMpdist, "KSK", algRollTo); len(ks) != 0 {
		t.Fatalf("a KSK of the new algorithm minted after the failed save: %v", ks)
	}
	if _, err := r.kdb.DB.Exec(`ALTER TABLE MPOwnerAlgorithm_away RENAME TO MPOwnerAlgorithm`); err != nil {
		t.Fatal(err)
	}
	// the change saved: a roll starts; a cancel whose save fails changes nothing
	r.setAlgorithms("change", algRollTo, "KSK")
	r.tick("minted")
	b := r.one("minted", KeyStateMpdist, "KSK", algRollTo)
	if _, err := r.kdb.DB.Exec(`ALTER TABLE MPOwnerAlgorithm RENAME TO MPOwnerAlgorithm_away`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.l.CancelAlgorithmRollover("KSK"); err == nil {
		t.Fatal("a cancel with the table away succeeded; it must fail")
	}
	if r.l.Policy.KSKAlgorithm != algRollTo {
		t.Fatalf("the policy's KSK algorithm after the failed cancel: %s, want %s (the roll goes on)", dns.AlgorithmToString[r.l.Policy.KSKAlgorithm], dns.AlgorithmToString[algRollTo])
	}
	if st := r.rollOf("KSK"); st == nil {
		t.Fatal("the KSK algorithm rollover vanished after the failed cancel")
	}
	if _, err := r.kdb.DB.Exec(`ALTER TABLE MPOwnerAlgorithm_away RENAME TO MPOwnerAlgorithm`); err != nil {
		t.Fatal(err)
	}
	r.tick("the roll goes on")
	if st := r.state(b); st != KeyStateMpdist {
		t.Fatalf("the new KSK after the failed cancel: %s, want mpdist (not withdrawn)", st)
	}
	r.check("done")
}

// stampWithRigClock makes a key's active_at follow the rig's clock from
// here on. tdns stamps the row with the wall clock and the rig runs on its
// own, so a key otherwise looks as old as the test in the very tick it
// begins signing: a test about the age of one key against another's needs
// the stamps a running signer has. The driver asks for a re-sign right
// after it writes a key's row to active, and the stamp is rewritten there,
// before anything else in the tick reads it.
func (r *driverRig) stampWithRigClock() {
	stamped := map[uint16]bool{}
	r.wire.onResign = func() {
		ks, err := tdns.GetDnssecKeysByState(r.kdb, r.l.Zone, KeyStateActive)
		if err != nil {
			r.t.Errorf("stamping active_at: %v", err)
			return
		}
		for _, k := range ks {
			if stamped[k.KeyTag] {
				continue
			}
			stamped[k.KeyTag] = true
			if _, err := r.kdb.DB.Exec(`UPDATE DnssecKeyStore SET active_at=? WHERE zonename=? AND keyid=?`,
				r.clock.Now().UTC().Format(time.RFC3339), r.l.Zone, int(k.KeyTag)); err != nil {
				r.t.Errorf("stamping active_at of key %d: %v", k.KeyTag, err)
			}
		}
	}
}

// zskRollWithStandby runs a ZSK-only algorithm change with a standby count
// of one and finite lifetimes to the point where the roll's ZSK signs
// beside the old one and the count's next ZSK of the new algorithm has
// propagated. With step the time a key takes from applied to standby: the
// old ZSK is three steps old, the roll's ZSK one, the ZSK lifetime two and
// the signature lifetime three. Returns the old ZSK, the roll's ZSK, the
// count's next one, and step.
func zskRollWithStandby(t *testing.T, r *driverRig) (old, rolled, next uint16, step time.Duration) {
	t.Helper()
	r.stampWithRigClock()
	step = r.l.Policy.PropagationDelay + r.wire.ttl + time.Second
	r.l.Policy.ZSKLifetime = 2 * step
	r.l.Policy.SigLifetime = 3 * step
	r.wire.parentTTL = time.Hour
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	// the old algorithm's standby ZSK, propagated
	r.tick("standby wanted")
	z2 := r.one("standby wanted", KeyStateMpdist, "ZSK", dns.ED25519)
	r.confirmAll("standby applied", z2)
	r.clock.Advance(step)
	r.tick("standby propagated")
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d one step in, half its lifetime: %s, want active", z, st)
	}

	r.setAlgorithms("change", algRollTo, "ZSK")
	r.tick("changed")
	y := r.one("changed", KeyStateMpdist, "ZSK", algRollTo)
	if _, to, err := r.l.ConfirmKind(z2, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
		t.Fatalf("the withdrawn standby's removal: to=%s err=%v", to, err)
	}
	r.confirmAll("the new ZSK applied", y)
	r.clock.Advance(step)
	r.tick("the new ZSK propagated")
	r.tick("the new ZSK signs")
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the roll's ZSK %d: %s, want active", y, st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d beside the roll's: %s, want active", z, st)
	}
	ys := r.keysOfAlg(KeyStateMpdist, "ZSK", algRollTo)
	if len(ys) == 0 {
		r.tick("standby wanted again")
		ys = r.keysOfAlg(KeyStateMpdist, "ZSK", algRollTo)
	}
	if len(ys) != 1 {
		t.Fatalf("the standby count's next ZSK of %s: %v, want one", dns.AlgorithmToString[algRollTo], ys)
	}
	r.confirmAll("the next ZSK applied", ys[0])
	r.clock.Advance(step)
	r.tick("the next ZSK propagated")
	return z, y, ys[0], step
}

// gone: retired, or already on its way out (the rig's retired_at is the
// wall clock's, so the margin of a key retired late in a test is over at
// once).
func gone(state string) bool { return state == KeyStateRetired || state == KeyStateMpremove }

// The lifetime that makes a rollover due is the policy algorithm's own
// key's. The old algorithm's key is past its lifetime for the whole of the
// wait (it is the oldest key of the role, and it is waiting out T19): that
// promotes nothing. Taking its age promoted the count's standby, which
// retired the roll's key (T10) and left the old one, tick after tick. The
// roll's key still rolls when its own lifetime has passed.
func TestAnOldKeyPastItsLifetimeDoesNotRollTheNewAlgorithm(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r := newDriverRig(t, "alglife.owned.example.", pol, "p2")
	z, y, y2, step := zskRollWithStandby(t, r)
	// the old ZSK is three steps old against a lifetime of two; the
	// roll's ZSK is one step old
	for i := 0; i < 3; i++ {
		r.tick("the old key past its lifetime")
	}
	if st := r.state(y2); st != KeyStateStandby {
		t.Fatalf("the count's ZSK %d with the old key past its lifetime: %s, want standby (the old key's age promotes nothing)", y2, st)
	}
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the roll's ZSK %d with the old key past its lifetime: %s, want active (it was rolled on the old key's account)", y, st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d: %s, want active (T19's wait is not over)", z, st)
	}
	// the roll's own lifetime: now it is due, and rolls as any key
	r.clock.Advance(step + time.Minute)
	r.tick("the roll's ZSK past its own lifetime")
	if st := r.state(y2); st != KeyStateActive {
		t.Fatalf("the count's ZSK %d once the roll's ZSK is past its lifetime: %s, want active", y2, st)
	}
	if st := r.state(y); !gone(st) {
		t.Fatalf("the roll's ZSK %d past its own lifetime: %s, want retired", y, st)
	}
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d after the new algorithm's own rollover: %s, want active still", z, st)
	}
	r.check("done")
}

// T19's signature lifetime counts from the first key of the policy's
// algorithm to sign in this roll. A rollover of that key during the wait
// (here: its own lifetime) does not start the wait over, so the old ZSK
// retires a signature lifetime after the new algorithm began signing, not
// a signature lifetime after its latest key did. With a ZSK lifetime
// shorter than the signature lifetime the wait would otherwise never end.
func TestARolloverOfTheNewKeyDoesNotRestartTheSignatureLifetime(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r := newDriverRig(t, "algsince.owned.example.", pol, "p2")
	z, y, y2, step := zskRollWithStandby(t, r)
	// the roll's ZSK began signing one step ago; its lifetime is two
	// steps, the signature lifetime three
	r.clock.Advance(step + time.Minute)
	r.tick("the roll's ZSK past its own lifetime")
	if st, st2 := r.state(y), r.state(y2); !gone(st) || st2 != KeyStateActive {
		t.Fatalf("the new algorithm's own rollover: the roll's ZSK %s, the next %s, want retired and active", st, st2)
	}
	r.tick("two steps into the signature lifetime")
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("the old ZSK %d two steps into a signature lifetime of three: %s, want active", z, st)
	}
	r.clock.Advance(step)
	r.tick("the signature lifetime passed")
	if st := r.state(z); !gone(st) {
		t.Fatalf("the old ZSK %d a signature lifetime after the new algorithm began signing: %s, want retired (the wait counts from the first key of the new algorithm, not from its latest)", z, st)
	}
	if st := r.state(y2); st != KeyStateActive {
		t.Fatalf("the new algorithm's ZSK %d: %s, want active", y2, st)
	}
	r.check("done")
}

// The signature lifetime counts keys of this roll only. After a roll to
// another algorithm and back, the keys of the first algorithm from before
// are still in the keystore with their old stamps: they are not what the
// wait counts from, or the roll back would retire the old ZSK at once.
func TestARollBackWaitsItsOwnSignatureLifetime(t *testing.T) {
	r := newDriverRig(t, "algback.owned.example.", driverPolicy, "p2")
	r.stampWithRigClock()
	r.wire.parentTTL = time.Hour
	step := driverPolicy.PropagationDelay + r.wire.ttl + time.Second
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	signs := func(what string, alg uint8) uint16 {
		t.Helper()
		r.setAlgorithms(what, alg, "ZSK")
		r.tick(what + ": minted")
		k := r.one(what+": minted", KeyStateMpdist, "ZSK", alg)
		r.confirmAll(what+": applied", k)
		r.clock.Advance(step)
		r.tick(what + ": propagated")
		r.tick(what + ": signs")
		if st := r.state(k); st != KeyStateActive {
			t.Fatalf("%s: the new ZSK %d: %s, want active", what, k, st)
		}
		return k
	}
	// there: the first algorithm's ZSK leaves a signature lifetime later
	y := signs("there", algRollTo)
	if st := r.state(z); st != KeyStateActive {
		t.Fatalf("there: the old ZSK %d the tick its successor signs: %s, want active", z, st)
	}
	r.clock.Advance(driverPolicy.SigLifetime + time.Minute)
	r.tick("there: the signature lifetime passed")
	r.clock.Advance(driverPolicy.Margin + time.Second)
	r.tick("there: the margin")
	if st := r.state(z); st != KeyStateMpremove {
		t.Fatalf("there: the old ZSK %d a signature lifetime and the margin on: %s, want mpremove", z, st)
	}
	if _, to, err := r.l.ConfirmKind(z, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
		t.Fatalf("there: the old ZSK's removal: to=%s err=%v", to, err)
	}
	// and back: a new ZSK of the first algorithm signs beside y
	x := signs("back", dns.ED25519)
	r.tick("back: both sign")
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("back: the ZSK %d of %s the tick its successor signs: %s, want active (the first algorithm's keys from before the roll there do not count)", y, dns.AlgorithmToString[algRollTo], st)
	}
	r.clock.Advance(driverPolicy.SigLifetime - time.Hour)
	r.tick("back: an hour short of the signature lifetime")
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("back: the ZSK %d an hour short of the signature lifetime: %s, want active", y, st)
	}
	r.clock.Advance(time.Hour + time.Minute)
	r.tick("back: the signature lifetime passed")
	if st := r.state(y); !gone(st) {
		t.Fatalf("back: the ZSK %d a signature lifetime after %d began signing: %s, want retired", y, x, st)
	}
	r.check("done")
}

// A rollover requested while the old algorithm's key waits to leave is
// still the operator's to withdraw. The algorithm rollover is past
// cancelling then (a key of the new algorithm signs), and that refusal used
// to come back before the request was looked at: the request stayed, and
// with no standby it minted a key and rolled once it had propagated.
func TestACancelWithdrawsARolloverRequestMadeDuringAnAlgorithmRollover(t *testing.T) {
	r := newDriverRig(t, "algcancelreq.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	withdrawalWait(t, r)
	// nothing requested: the cancel is the algorithm's, and is refused
	if msg, err := cancelRollover(r.l, "KSK"); err == nil || !strings.Contains(err.Error(), "cannot be cancelled") {
		t.Fatalf("cancel with no request and the new KSK signing: msg=%q err=%v, want the refusal", msg, err)
	}
	r.l.RequestRollover("KSK")
	if reqs := r.l.RolloverRequests(); len(reqs) != 1 || reqs[0] != "KSK" {
		t.Fatalf("the rollover requests after the request: %v, want [KSK]", reqs)
	}
	msg, err := cancelRollover(r.l, "KSK")
	if err != nil {
		t.Fatalf("cancel with a request pending during the algorithm rollover: %v, want the request withdrawn", err)
	}
	if !strings.Contains(msg, "KSK rollover request cleared") || !strings.Contains(msg, "is not cancelled") {
		t.Errorf("the answer: %q, want the request cleared and the algorithm rollover named as not cancelled", msg)
	}
	if reqs := r.l.RolloverRequests(); len(reqs) != 0 {
		t.Fatalf("the rollover requests after the cancel: %v, want none", reqs)
	}
	if r.l.Policy.KSKAlgorithm != algRollTo || r.rollOf("KSK") == nil {
		t.Fatalf("the algorithm rollover after the cancel: algorithm %s, status %+v, want it still under way", dns.AlgorithmToString[r.l.Policy.KSKAlgorithm], r.rollOf("KSK"))
	}
	// and nothing is minted for a request that is gone
	r.tick("after the cancel")
	if ks := r.keysOfAlg(KeyStateMpdist, "KSK", algRollTo); len(ks) != 0 {
		t.Fatalf("a KSK minted after the request was withdrawn: %v", ks)
	}
	// the cancel with nothing left to withdraw is the refusal again
	if _, err := cancelRollover(r.l, "KSK"); err == nil {
		t.Error("a second cancel succeeded with no request pending and the new KSK signing")
	}
	r.check("done")
}

// A cancel that cannot read the keys does nothing. Whether an algorithm
// rollover is under way decides what the cancel does, and a failed read
// used to read as none: the request was cleared and the answer said so.
func TestACancelThatCannotReadTheKeysDoesNothing(t *testing.T) {
	r := newDriverRig(t, "algcancelread.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	withdrawalWait(t, r)
	r.l.RequestRollover("KSK")
	if _, err := r.kdb.DB.Exec(`ALTER TABLE DnssecKeyStore RENAME TO DnssecKeyStore_away`); err != nil {
		t.Fatal(err)
	}
	msg, err := cancelRollover(r.l, "KSK")
	if _, rerr := r.kdb.DB.Exec(`ALTER TABLE DnssecKeyStore_away RENAME TO DnssecKeyStore`); rerr != nil {
		t.Fatal(rerr)
	}
	if err == nil {
		t.Fatalf("a cancel with the keys unreadable: %q and no error, want an error", msg)
	}
	if reqs := r.l.RolloverRequests(); len(reqs) != 1 || reqs[0] != "KSK" {
		t.Errorf("the rollover requests after the failed cancel: %v, want [KSK] (nothing done)", reqs)
	}
	if rolls := algRolls(t, r.l); len(rolls) != 1 || rolls[0].Role != "KSK" {
		t.Errorf("the algorithm rollovers once the keys read again: %+v, want the KSK one", rolls)
	}
}

// A roll back while the original key still signs: the operator changes the
// ZSK algorithm back during the first roll's signature-lifetime wait. The
// returning algorithm's key never left the DNSKEY RRset and signed every
// RRset throughout, so the wait for the key being left runs from that key's
// own stamp (signsInThisRoll counts an active key of the policy's algorithm,
// whatever its age). With the returning key younger than a signature
// lifetime, the other algorithm's ZSK waits out the rest of it; with it
// older, that ZSK retires on the next tick. Nothing is minted or promoted
// for the roll back: the returning algorithm already signs.
func TestARollBackWhileTheOriginalKeyStillSignsEndsOnThatKeysStamp(t *testing.T) {
	for _, c := range []struct {
		name    string
		aged    time.Duration // how long the original ZSK has signed before the first change
		atOnce  bool
		zoneTag string
	}{
		{"the original key younger than a signature lifetime", 0, false, "rbyoung"},
		{"the original key older than a signature lifetime", driverPolicy.SigLifetime + time.Hour, true, "rbold"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newDriverRig(t, c.zoneTag+".owned.example.", driverPolicy, "p2")
			r.stampWithRigClock()
			r.wire.parentTTL = time.Hour
			step := driverPolicy.PropagationDelay + r.wire.ttl + time.Second
			a, z := bootstrapKSK(t, r)
			r.wire.parentDS[a] = true
			r.clock.Advance(c.aged)
			// there: a ZSK of the new algorithm signs beside z
			r.setAlgorithms("there", algRollTo, "ZSK")
			r.tick("there: minted")
			y := r.one("there: minted", KeyStateMpdist, "ZSK", algRollTo)
			r.confirmAll("there: applied", y)
			r.clock.Advance(step)
			r.tick("there: propagated")
			r.tick("there: signs")
			if st, sz := r.state(y), r.state(z); st != KeyStateActive || sz != KeyStateActive {
				t.Fatalf("there: the new ZSK %d %s, the original %d %s, want both active", y, st, z, sz)
			}
			// and back, in the wait: z is the policy's algorithm again and
			// signs; y is the key being left
			r.setAlgorithms("back", dns.ED25519, "ZSK")
			r.tick("back")
			for _, state := range []string{KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby} {
				if ks := r.keysOfAlg(state, "ZSK", dns.ED25519); len(ks) != 0 {
					t.Fatalf("back: a ZSK of the returning algorithm in %s: %v, want none (z signs)", state, ks)
				}
			}
			if st := r.state(z); st != KeyStateActive {
				t.Fatalf("back: the original ZSK %d: %s, want active", z, st)
			}
			if c.atOnce {
				if st := r.state(y); !gone(st) {
					t.Fatalf("back: the ZSK %d with the original key signing for longer than a signature lifetime: %s, want retired at once", y, st)
				}
			} else {
				if st := r.state(y); st != KeyStateActive {
					t.Fatalf("back: the ZSK %d with the original key signing for less than a signature lifetime: %s, want active", y, st)
				}
				// the wait counts from z's stamp: it ends a signature
				// lifetime after z began signing, not after the roll back
				r.clock.Advance(driverPolicy.SigLifetime - step - time.Hour)
				r.tick("back: an hour short of z's signature lifetime")
				if st := r.state(y); st != KeyStateActive {
					t.Fatalf("back: the ZSK %d an hour short of a signature lifetime from z's stamp: %s, want active", y, st)
				}
				r.clock.Advance(time.Hour + time.Minute)
				r.tick("back: z's signature lifetime passed")
				if st := r.state(y); !gone(st) {
					t.Fatalf("back: the ZSK %d a signature lifetime after z began signing: %s, want retired", y, st)
				}
			}
			if st := r.state(z); st != KeyStateActive {
				t.Fatalf("the original ZSK %d at the end: %s, want active", z, st)
			}
			// the roll is reported until the other signer confirms y's
			// removal; then it is over
			r.clock.Advance(driverPolicy.Margin + time.Second)
			r.tick("the margin")
			if st := r.state(y); st != KeyStateMpremove {
				t.Fatalf("the ZSK %d a margin after it retired: %s, want mpremove", y, st)
			}
			if _, to, err := r.l.ConfirmKind(y, "p2", "applied", "", true); err != nil || to != KeyStateRemoved {
				t.Fatalf("the removal of %d: to=%s err=%v", y, to, err)
			}
			if st := r.rollOf("ZSK"); st != nil {
				t.Errorf("a ZSK algorithm rollover still reported once the key being left is removed: %+v", st)
			}
			r.check("done")
		})
	}
}
