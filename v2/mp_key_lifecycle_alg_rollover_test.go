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
	for _, st := range r.l.AlgorithmRollovers() {
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
	if rolls := r.l.AlgorithmRollovers(); len(rolls) != 0 {
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
// with (its T18 note), never the empty answer's zero; and the note is read
// back after a restart, so the wait neither starts over nor ends at once.
func TestTheWithdrawalWaitHasATTLWithAnEmptyAnswerAndSurvivesARestart(t *testing.T) {
	r := newDriverRig(t, "algwait.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
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
	r.clock.Advance(61 * time.Minute)
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
	r.clock.Advance(20 * time.Minute)
	r.tick("twenty minutes")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK twenty minutes into an hour's wait: %s, want active", st)
	}
	// a restart in the middle of the wait: the note comes back
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	r.clock.Advance(20 * time.Minute)
	r.tick("forty minutes, after a restart")
	if st := r.state(a); st != KeyStateActive {
		t.Fatalf("the old KSK forty minutes into the wait, after a restart: %s, want active (the wait did not end at the restart)", st)
	}
	r.clock.Advance(21 * time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(a), r.cols(a); st != KeyStateRetired || c != "100" {
		t.Errorf("the old KSK an hour after the parent stopped serving its DS: %s %s, want retired 100 (the wait did not start over at the restart)", st, c)
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
	if rolls := r.l.AlgorithmRollovers(); len(rolls) != 0 {
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
	if rolls := p1.driver.AlgorithmRollovers(); len(rolls) != 0 {
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
