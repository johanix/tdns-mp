package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The driver on one provider with a fake wire and a fake clock: the
// scenarios of test plan T3.4 at unit-test speed, with tdns's key row
// invariants checked after every step.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fakeWire struct {
	mu        sync.Mutex
	signers   []string
	dist      []uint16 // Distribute calls, in order
	removals  []uint16
	parentDS  map[uint16]bool // what the parent serves; absent = not served
	parentOff bool            // the parent cannot be asked
	stripped  []uint16
	resigns   int
	reports   []string
	ttl       time.Duration
	changes   int   // KeysChanged calls
	stripErr  error // what Strip returns
}

func newFakeWire(signers ...string) *fakeWire {
	return &fakeWire{signers: signers, parentDS: map[uint16]bool{}, ttl: time.Hour}
}
func (w *fakeWire) OtherSigners(zone string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.signers...)
}
func (w *fakeWire) Distribute(zone string, keyid uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dist = append(w.dist, keyid)
}
func (w *fakeWire) DistributeRemoval(zone string, keyid uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.removals = append(w.removals, keyid)
}
func (w *fakeWire) ParentServesDS(zone string, keyid uint16) (bool, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.parentOff {
		return false, false
	}
	return w.parentDS[keyid], true
}
func (w *fakeWire) Strip(zone string, keyid uint16) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stripErr != nil {
		return w.stripErr
	}
	w.stripped = append(w.stripped, keyid)
	return nil
}
func (w *fakeWire) Resign(zone string)                        { w.mu.Lock(); defer w.mu.Unlock(); w.resigns++ }
func (w *fakeWire) KeysChanged(zone string)                   { w.mu.Lock(); defer w.mu.Unlock(); w.changes++ }
func (w *fakeWire) ServedDnskeyTTL(zone string) time.Duration { return w.ttl }
func (w *fakeWire) Report(zone string, keyid uint16, what string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reports = append(w.reports, fmt.Sprintf("%d: %s", keyid, what))
}
func (w *fakeWire) distributions() []uint16 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]uint16(nil), w.dist...)
}

type driverRig struct {
	t     *testing.T
	kdb   *tdns.KeyDB
	zd    *MPZoneData
	clock *fakeClock
	wire  *fakeWire
	l     *ZoneKeyLifecycle
}

func newDriverRig(t *testing.T, name string, pol LifecyclePolicy, signers ...string) *driverRig {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	zd := signerTestZone(t, name, kdb)
	clock := &fakeClock{t: time.Now()}
	wire := newFakeWire(signers...)
	l := NewZoneKeyLifecycle(name, kdb, clock, pol, wire)
	return &driverRig{t: t, kdb: kdb, zd: zd, clock: clock, wire: wire, l: l}
}

func (r *driverRig) state(keyid uint16) string { return mpKeyState(r.t, r.kdb, r.l.Zone, keyid) }

func (r *driverRig) cols(keyid uint16) string {
	r.t.Helper()
	f, err := r.l.columnsOf(keyid)
	if err != nil {
		r.t.Fatal(err)
	}
	return flagsOf(f)
}

// check: tdns's key row invariants hold, and P5 (one sign=1 per role and
// algorithm) holds.
func (r *driverRig) check(step string) {
	r.t.Helper()
	if vs := tdns.CheckKeyRowInvariants(r.kdb, r.l.Zone); len(vs) != 0 {
		r.t.Errorf("%s: key row invariants: %v", step, vs)
	}
	inv, err := tdns.GetKeyInventory(r.kdb, r.l.Zone)
	if err != nil {
		r.t.Fatal(err)
	}
	signing := map[string]int{}
	for _, it := range inv {
		if it.Sign {
			signing[fmt.Sprintf("%s/%d", roleOf(it.Flags), it.Algorithm)]++
		}
	}
	for k, n := range signing {
		if n > 1 {
			r.t.Errorf("%s: %d signing keys of %s, want 1 (P5)", step, n, k)
		}
	}
}

func (r *driverRig) tick(step string) {
	r.t.Helper()
	if err := r.l.Tick(); err != nil {
		r.t.Fatalf("%s: tick: %v", step, err)
	}
	r.check(step)
}

func (r *driverRig) keysIn(state, role string) []uint16 {
	r.t.Helper()
	ks, err := tdns.GetDnssecKeysByState(r.kdb, r.l.Zone, state)
	if err != nil {
		r.t.Fatal(err)
	}
	var out []uint16
	for _, k := range ks {
		if roleOf(k.Flags) == role {
			out = append(out, k.KeyTag)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var driverPolicy = LifecyclePolicy{KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519, StandbyKSK: 0, StandbyZSK: 0,
	PropagationDelay: 10 * time.Minute, Margin: time.Hour}

// bootstrap: a fresh owned zone with two other signing providers gets one
// active KSK and ZSK through the machine alone, in the table's order.
func TestDriverBootstrapsAZone(t *testing.T) {
	r := newDriverRig(t, "boot.owned.example.", driverPolicy, "p2", "p3")
	r.tick("mint")
	for _, role := range []string{"KSK", "ZSK"} {
		if ks := r.keysIn(KeyStateMpdist, role); len(ks) != 1 {
			t.Fatalf("after the first tick: %s in mpdist %v, want one (minted and distributed)", role, ks)
		}
	}
	if d := r.wire.distributions(); len(d) != 2 {
		t.Fatalf("distributions %v, want the two keys", d)
	}
	ksk, zsk := r.keysIn(KeyStateMpdist, "KSK")[0], r.keysIn(KeyStateMpdist, "ZSK")[0]
	if got := r.cols(ksk); got != "100" {
		t.Errorf("mpdist KSK columns %s, want 100", got)
	}
	// one applied, one pending: still mpdist (P9)
	for _, k := range []uint16{ksk, zsk} {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.l.Confirm(k, "p3", "pending", ""); err != nil {
			t.Fatal(err)
		}
		if st := r.state(k); st != KeyStateMpdist {
			t.Errorf("one applied, one pending: %s, want mpdist", st)
		}
	}
	r.check("half confirmed")
	for _, k := range []uint16{ksk, zsk} {
		if _, to, err := r.l.Confirm(k, "p3", "applied", ""); err != nil || to != KeyStatePublished {
			t.Fatalf("every signer applied: to=%s err=%v, want published", to, err)
		}
	}
	r.check("published")
	r.tick("published, not propagated")
	if st := r.state(ksk); st != KeyStatePublished {
		t.Errorf("before the propagation wait: %s, want published", st)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	// with no active key of the role, the standby is promoted on the same tick
	if got := r.keysIn(KeyStateActive, "KSK"); len(got) != 1 || got[0] != ksk {
		t.Errorf("active KSKs %v, want %d", got, ksk)
	}
	if got := r.keysIn(KeyStateActive, "ZSK"); len(got) != 1 || got[0] != zsk {
		t.Errorf("active ZSKs %v, want %d", got, zsk)
	}
	if got := r.cols(ksk); got != "111" {
		t.Errorf("active KSK columns %s, want 111", got)
	}
	if got := r.cols(zsk); got != "110" {
		t.Errorf("active ZSK columns %s, want 110", got)
	}
	if r.wire.resigns == 0 {
		t.Error("no resign asked of tdns after the promotions")
	}
	r.tick("steady")
	if d := r.wire.distributions(); len(d) != 2 {
		t.Errorf("a steady zone distributed again: %v", d)
	}
}

// a KSK rollover: a standby KSK per the policy, its ds=1 once propagated,
// the roll on request, the old key's DS withdrawn first, the removal after
// the margin once the parent has dropped the DS, the removal confirmed.
func TestDriverRollsAKSK(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "roll.owned.example.", pol, "p2")
	bootstrap := func() (ksk, zsk uint16) {
		r.tick("mint")
		for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
			if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
				t.Fatal(err)
			}
		}
		r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
		r.tick("propagated")
		return r.keysIn(KeyStateActive, "KSK")[0], r.keysIn(KeyStateActive, "ZSK")[0]
	}
	a, _ := bootstrap()
	r.wire.parentDS[a] = true
	// the policy wants a standby KSK: minted, distributed, confirmed, propagated
	r.tick("standby wanted")
	pend := r.keysIn(KeyStateMpdist, "KSK")
	if len(pend) != 1 {
		t.Fatalf("standby KSK in mpdist: %v", pend)
	}
	b := pend[0]
	if _, _, err := r.l.Confirm(b, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	if st, c := r.state(b), r.cols(b); st != KeyStateStandby || c != "101" {
		t.Fatalf("the standby KSK: %s %s, want standby 101", st, c)
	}
	r.wire.parentDS[b] = true // the parent placed the standby's DS (D4)
	r.tick("steady with a standby")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("a standby beside an active key was promoted without a request: %s", st)
	}

	r.l.RequestRollover("KSK")
	r.tick("roll")
	if st, c := r.state(b), r.cols(b); st != KeyStateActive || c != "111" {
		t.Errorf("after the roll: new KSK %s %s, want active 111", st, c)
	}
	if st, c := r.state(a), r.cols(a); st != KeyStateRetired || c != "100" {
		t.Errorf("after the roll: old KSK %s %s, want retired 100 (its DS withdrawn on entry)", st, c)
	}
	// margin passed, but the parent still serves the old DS: the key stays
	r.clock.Advance(pol.Margin + time.Second)
	r.tick("margin, DS still at the parent")
	if st := r.state(a); st != KeyStateRetired {
		t.Errorf("removed while the parent still served the DS: %s", st)
	}
	r.wire.parentDS[a] = false
	r.tick("DS gone")
	if st, c := r.state(a), r.cols(a); st != KeyStateMpremove || c != "000" {
		t.Fatalf("after the margin with the DS gone: %s %s, want mpremove 000", st, c)
	}
	if len(r.wire.stripped) != 1 || r.wire.stripped[0] != a || len(r.wire.removals) != 1 || r.wire.removals[0] != a {
		t.Errorf("strip %v removal %v, want the old KSK in both", r.wire.stripped, r.wire.removals)
	}
	if _, to, err := r.l.Confirm(a, "p2", "applied", ""); err != nil || to != KeyStateRemoved {
		t.Errorf("removal confirmed: to=%s err=%v, want removed", to, err)
	}
	r.check("removed")
	// the policy wants a standby again: the pipeline refills
	r.tick("refill")
	if pend := r.keysIn(KeyStateMpdist, "KSK"); len(pend) != 1 {
		t.Errorf("after the roll the pipeline holds %v, want one new standby KSK", pend)
	}
}

// a rejected key stays in mpdist and is reported; retry sends it again;
// withdraw parks it for removal.
func TestDriverRejectedKeyStaysUntilTold(t *testing.T) {
	r := newDriverRig(t, "rej.owned.example.", driverPolicy, "p2", "p3")
	r.tick("mint")
	zsk := r.keysIn(KeyStateMpdist, "ZSK")[0]
	if _, to, err := r.l.Confirm(zsk, "p2", "rejected", "policy forbids"); err != nil || to != KeyStateMpdist {
		t.Fatalf("rejected: to=%s err=%v", to, err)
	}
	if len(r.wire.reports) != 1 {
		t.Errorf("reports %v, want one", r.wire.reports)
	}
	if _, _, err := r.l.Confirm(zsk, "p3", "applied", ""); err != nil {
		t.Fatal(err)
	}
	if st := r.state(zsk); st != KeyStateMpdist {
		t.Errorf("a rejected key moved to %s (P8)", st)
	}
	r.clock.Advance(24 * time.Hour)
	r.tick("time passes")
	if st := r.state(zsk); st != KeyStateMpdist {
		t.Errorf("a rejected key moved to %s on its own (P8)", st)
	}
	before := len(r.wire.distributions())
	if _, _, err := r.l.Apply(zsk, CmdRetry); err != nil {
		t.Fatal(err)
	}
	if len(r.wire.distributions()) != before+1 {
		t.Error("retry did not distribute again")
	}
	if _, _, err := r.l.Confirm(zsk, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	if _, to, err := r.l.Confirm(zsk, "p3", "applied", ""); err != nil || to != KeyStatePublished {
		t.Errorf("after the retry, every signer applied: to=%s err=%v, want published", to, err)
	}
	// withdraw a stuck one
	ksk := r.keysIn(KeyStateMpdist, "KSK")[0]
	if _, to, err := r.l.Apply(ksk, CmdWithdraw); err != nil || to != KeyStateMpremove {
		t.Errorf("withdraw: to=%s err=%v, want mpremove", to, err)
	}
	r.check("withdrawn")
}

// no other signing provider: mpdist and mpremove resolve at once (P7).
func TestDriverAloneNeedsNoConfirmation(t *testing.T) {
	r := newDriverRig(t, "alone.owned.example.", driverPolicy)
	r.tick("mint")
	if ks := r.keysIn(KeyStatePublished, "KSK"); len(ks) != 1 {
		t.Fatalf("alone: KSK in published %v, want one at once (P7)", ks)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	ksk := r.keysIn(KeyStateActive, "KSK")
	if len(ksk) != 1 {
		t.Fatalf("active KSKs %v", ksk)
	}
	if _, to, err := r.l.Apply(r.keysIn(KeyStateActive, "ZSK")[0], CmdWithdraw); err == nil && to == KeyStateMpremove {
		t.Error("withdraw of an active key was accepted; the table has no such row")
	}
}

// restart: a new driver over the same keystore sends the in-flight
// distributions again and picks the timers up from the stamps (P4).
func TestDriverRestartResendsWhatIsInFlight(t *testing.T) {
	r := newDriverRig(t, "restart.owned.example.", driverPolicy, "p2")
	r.tick("mint")
	ksk := r.keysIn(KeyStateMpdist, "KSK")[0]
	zsk := r.keysIn(KeyStateMpdist, "ZSK")[0]
	if _, _, err := r.l.Confirm(zsk, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	// a new process
	wire := newFakeWire("p2")
	l2 := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, wire)
	if err := l2.Reload(); err != nil {
		t.Fatal(err)
	}
	if d := wire.distributions(); len(d) != 1 || d[0] != ksk {
		t.Errorf("after the restart distributions %v, want the mpdist KSK %d again", d, ksk)
	}
	if _, to, err := l2.Confirm(ksk, "p2", "applied", ""); err != nil || to != KeyStatePublished {
		t.Errorf("confirmed after the restart: to=%s err=%v", to, err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + wire.ttl + time.Second)
	if err := l2.Tick(); err != nil {
		t.Fatal(err)
	}
	if got := r.keysIn(KeyStateActive, "ZSK"); len(got) != 1 || got[0] != zsk {
		t.Errorf("the published ZSK's timer after the restart: active %v, want %d", got, zsk)
	}
	r.check("after the restart")
}

// What the property runs found (T3.3): a signer that joins and rejects a
// standby key keeps it from being promoted until the operator retries or
// withdraws (P1, P8); an answer to a key's distribution that arrives after
// its removal went out is stale, not a confirmation of the removal; a retry
// on a key being removed sends the removal again.
func TestDriverLateRejectionAndStaleAnswers(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r := newDriverRig(t, "late.owned.example.", pol, "p2")
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	r.tick("standby ZSK wanted")
	sb := r.keysIn(KeyStateMpdist, "ZSK")
	if len(sb) != 1 {
		t.Fatalf("standby ZSK in mpdist: %v", sb)
	}
	if _, _, err := r.l.Confirm(sb[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	if st := r.state(sb[0]); st != KeyStateStandby {
		t.Fatalf("the standby ZSK is %s", st)
	}

	// p3 joins and rejects the standby key
	r.wire.mu.Lock()
	r.wire.signers = []string{"p2", "p3"}
	r.wire.mu.Unlock()
	if err := r.l.SignersChanged(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.l.Confirm(sb[0], "p3", "rejected", "not for me"); err != nil {
		t.Fatal(err)
	}
	r.l.RequestRollover("ZSK")
	r.tick("roll requested over a rejected standby")
	if st := r.state(sb[0]); st != KeyStateStandby {
		t.Errorf("a standby key a joiner rejected was promoted to %s (P1, P8)", st)
	}
	// the operator retries: a fresh distribution; once p3 applies, the roll goes
	before := len(r.wire.distributions())
	if _, _, err := r.l.Apply(sb[0], CmdRetry); err != nil {
		t.Fatal(err)
	}
	if len(r.wire.distributions()) != before+1 {
		t.Error("retry did not distribute the standby key again")
	}
	if _, _, err := r.l.Confirm(sb[0], "p3", "applied", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.l.Confirm(sb[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.tick("roll after the retry")
	if st := r.state(sb[0]); st != KeyStateActive {
		t.Errorf("after the retry and everyone applied, the standby is %s, want active", st)
	}

	// a key withdrawn from the pipeline: a late answer to its distribution
	// is stale; the removal's answer completes it
	r.tick("standby wanted again")
	k := r.keysIn(KeyStateMpdist, "ZSK")
	if len(k) != 1 {
		t.Fatalf("next standby ZSK in mpdist: %v", k)
	}
	if _, to, err := r.l.Apply(k[0], CmdWithdraw); err != nil || to != KeyStateMpremove {
		t.Fatalf("withdraw: to=%s err=%v", to, err)
	}
	if _, _, err := r.l.ConfirmKind(k[0], "p2", "applied", "", false); !errors.Is(err, ErrStaleConfirmation) {
		t.Errorf("an answer to the distribution after the removal went out: err=%v, want ErrStaleConfirmation", err)
	}
	if _, _, err := r.l.ConfirmKind(k[0], "p2", "rejected", "late", false); !errors.Is(err, ErrStaleConfirmation) {
		t.Errorf("a rejection of the distribution after the removal went out: err=%v, want ErrStaleConfirmation", err)
	}
	if st := r.state(k[0]); st != KeyStateMpremove {
		t.Errorf("the stale answers moved the key to %s", st)
	}
	// a retry on a key being removed sends the removal again, not the key
	dists, removals := len(r.wire.distributions()), len(r.wire.removals)
	if _, _, err := r.l.Apply(k[0], CmdRetry); err != nil {
		t.Fatal(err)
	}
	if len(r.wire.distributions()) != dists || len(r.wire.removals) != removals+1 {
		t.Errorf("retry in mpremove: distributions %d->%d removals %d->%d, want one more removal", dists, len(r.wire.distributions()), removals, len(r.wire.removals))
	}
	for _, p := range []string{"p2", "p3"} {
		if _, _, err := r.l.ConfirmKind(k[0], p, "applied", "", true); err != nil {
			t.Fatal(err)
		}
	}
	if st := r.state(k[0]); st != KeyStateRemoved {
		t.Errorf("after the removal was applied everywhere: %s, want removed", st)
	}
	r.check("done")
}

// T3.6: nothing the parent sees changes. What the parent's side reads is
// what it read before S3: the DS set tdns derives for the zone is the
// ds=1 KSK rows (S1b: standby, active and retired-not-withdrawn, the old
// key's DS leaving with its withdrawal), and the CDS the signer serves is
// still every SEP key of the served DNSKEY RRset, the pub=1 KSKs (CDS
// follows ds in S5, not before). Both follow the machine's columns at
// every step of a rollover.
func TestOwnedZoneParentViewFollowsTheColumns(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "parent.owned.example.", pol, "p2")
	// the zone is owned, as in the signer: tdns's own key paths leave it
	// alone when it signs (S2), and its DS set is the owner's answer (§4)
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return r.kdb })
	owner.Take(r.l.Zone)
	tdns.RegisterKeyLifecycleOwner(owner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	r.zd.ZoneData.InstallInitialSnapshot()
	t.Cleanup(r.zd.ZoneData.StopPublisher)
	// the rig's wire does not sign; this stands in for Wire.Resign, the
	// republish of the served DNSKEY RRset from the pub=1 rows
	resign := func(step string) {
		t.Helper()
		if _, err := r.zd.ZoneData.SignZone(context.Background(), r.kdb, false); err != nil {
			t.Fatalf("%s: sign: %v", step, err)
		}
	}
	tags := func(rrs []dns.RR) string {
		var out []uint16
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.DS:
				out = append(out, v.KeyTag)
			case *dns.CDS:
				out = append(out, v.KeyTag)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return fmt.Sprint(out)
	}
	sorted := func(ts []uint16) string {
		sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
		return fmt.Sprint(ts)
	}
	check := func(step string, ds []uint16, cds []uint16) {
		t.Helper()
		in, err := tdns.DSIntentForZone(r.kdb, r.l.Zone, dns.SHA256)
		if err != nil || !in.Known {
			t.Fatalf("%s: DS intent: known=%v err=%v", step, in.Known, err)
		}
		if got, want := tags(in.Set), sorted(ds); got != want {
			t.Errorf("%s: the DS set for the parent %v, want %v (the ds=1 KSKs)", step, got, want)
		}
		got := "[]"
		if rrs, err := r.zd.SynthesizeCdsRRs(); err == nil {
			got = tags(rrs)
		} else if len(cds) != 0 {
			t.Fatalf("%s: CDS: %v", step, err)
		}
		if want := sorted(cds); got != want {
			t.Errorf("%s: the served CDS %v, want %v (the SEP keys of the served DNSKEY RRset)", step, got, want)
		}
	}
	kskIn := func(states ...string) []uint16 {
		var out []uint16
		for _, st := range states {
			out = append(out, r.keysIn(st, "KSK")...)
		}
		return out
	}

	r.tick("mint")
	a := r.keysIn(KeyStateMpdist, "KSK")[0]
	// until the zone signs, nothing is served: no CDS, and no DS yet (P2)
	check("keys in mpdist", nil, nil)
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	check("keys published", nil, nil)
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	if r.keysIn(KeyStateActive, "KSK")[0] != a {
		t.Fatalf("active KSK %v, want %d", r.keysIn(KeyStateActive, "KSK"), a)
	}
	resign("first KSK active")
	if !r.zd.Ready {
		t.Fatal("the zone is not served after signing with the active keys")
	}
	// the same tick minted the standby the policy wants: served, no DS yet
	b := r.keysIn(KeyStateMpdist, "KSK")[0]
	check("first KSK active, a standby on its way", []uint16{a}, []uint16{a, b})
	r.wire.parentDS[a] = true
	if _, _, err := r.l.Confirm(b, "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	resign("standby published")
	check("standby published: still no DS (P2)", []uint16{a}, []uint16{a, b})
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("standby propagated")
	resign("standby propagated")
	check("standby KSK: its DS pre-published (multi-DS)", []uint16{a, b}, []uint16{a, b})
	r.wire.parentDS[b] = true
	r.l.RequestRollover("KSK")
	r.tick("roll")
	resign("roll")
	// the roll promoted b, retired a (its DS withdrawn on entry, the key
	// still served) and minted the next standby c
	c := r.keysIn(KeyStateMpdist, "KSK")[0]
	check("old KSK retired", []uint16{b}, []uint16{a, b, c})
	r.wire.parentDS[a] = false
	r.clock.Advance(pol.Margin + time.Second)
	r.tick("margin")
	if len(kskIn(KeyStateMpremove, KeyStateRemoved)) != 1 {
		t.Fatalf("after the margin the old KSK is %s", r.state(a))
	}
	resign("margin")
	check("old KSK leaving: out of the served RRset", []uint16{b}, []uint16{b, c})

	// another provider's KSK arrives with nothing said about its DS (until
	// #58, S5): the DS set is unknown, the parent left alone; the served
	// CDS is what it was
	foreign := testDnskeyRR(t, r.l.Zone, 257)
	if err := insertForeignKeyRow(r.kdb, r.l.Zone, foreign.KeyTag(), foreign, "ED25519"); err != nil {
		t.Fatal(err)
	}
	in, err := tdns.DSIntentForZone(r.kdb, r.l.Zone, dns.SHA256)
	if err != nil || in.Known {
		t.Errorf("with a foreign SEP row whose ds is unknown: known=%v err=%v, want unknown (C2)", in.Known, err)
	}
	if rrs, err := r.zd.SynthesizeCdsRRs(); err != nil || tags(rrs) != sorted([]uint16{b, c}) {
		t.Errorf("served CDS with the foreign row present: %v err=%v, want unchanged", rrs, err)
	}
}

// T3.7, the owned side of the mixed rollout: the machine on an owned zone
// consults none of the lifecycle hooks tdns's own paths ask (the staged
// and retired states, may-promote, may-generate); the state-change
// notification, which is how the peers learn a key's state today, still
// fires. (tdns's tests cover the other side: a multi-provider zone nobody
// owns keeps today's paths, hooks included.)
func TestOwnedZoneDriverUsesNoHooks(t *testing.T) {
	asked := map[string]int{}
	tdns.RegisterKeyLifecycleHooks(tdns.KeyLifecycleHooks{
		StagedState:   func(zd *tdns.ZoneData) string { asked["StagedState"]++; return DnskeyStateMpdist },
		RetiredState:  func(zd *tdns.ZoneData) string { asked["RetiredState"]++; return DnskeyStateMpremove },
		MayPromote:    func(zd *tdns.ZoneData, keyid uint16) bool { asked["MayPromote"]++; return false },
		MayGenerate:   func(zd *tdns.ZoneData, role string) bool { asked["MayGenerate"]++; return false },
		OnStateChange: func(zone string, keyid uint16, from, to string) { asked["OnStateChange"]++ },
	})
	t.Cleanup(func() { tdns.RegisterKeyLifecycleHooks(tdns.KeyLifecycleHooks{}) })
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "hooks.owned.example.", pol, "p2")
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	r.tick("standby wanted")
	if len(r.keysIn(KeyStateActive, "KSK")) != 1 || len(r.keysIn(KeyStateActive, "ZSK")) != 1 || len(r.keysIn(KeyStateMpdist, "KSK")) != 1 {
		t.Fatalf("the machine did not bootstrap: %v", r.keysIn(KeyStateActive, "KSK"))
	}
	for _, h := range []string{"StagedState", "RetiredState", "MayPromote", "MayGenerate"} {
		if asked[h] != 0 {
			t.Errorf("the machine asked the %s hook %d times (it decides itself)", h, asked[h])
		}
	}
	if asked["OnStateChange"] == 0 {
		t.Error("no state-change notification fired; the peers learn a key's state from it")
	}
}

// T5.4 (the signer's half): the machine tells its surroundings after every
// key row write, state or column, so the signer's inventory push follows
// every change; a tick that writes nothing pushes nothing.
func TestDriverPushesTheInventoryOnEveryWrite(t *testing.T) {
	r := newDriverRig(t, "push.owned.example.", driverPolicy, "p2")
	r.tick("mint") // two keys minted and distributed: created -> mpdist, twice
	if r.wire.changes != 2 {
		t.Errorf("after the mint %d changes reported, want 2 (one per key)", r.wire.changes)
	}
	r.tick("nothing to do")
	if r.wire.changes != 2 {
		t.Errorf("a tick that wrote nothing reported %d changes, want still 2", r.wire.changes)
	}
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	if r.wire.changes != 4 {
		t.Errorf("after both keys were published %d changes reported, want 4", r.wire.changes)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated") // published -> standby -> active for both: four writes
	if r.wire.changes != 8 {
		t.Errorf("after the promotion %d changes reported, want 8", r.wire.changes)
	}
}
