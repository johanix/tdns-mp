package tdnsmp

import (
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// The signer's hold (plan S6): at its agent's word the key machine starts
// nothing new for the zone. Every phase of a rollover under way runs, and so
// does the emergency rollover, the operator's.

// holdPolicy rolls each key at thirty days and keeps one standby ZSK.
var holdPolicy = func() LifecyclePolicy {
	p := driverPolicy
	p.KSKLifetime, p.ZSKLifetime = 30*24*time.Hour, 30*24*time.Hour
	return p
}()

func TestNoRolloverStartsUnderAHold(t *testing.T) {
	r := newDriverRig(t, "hold.owned.example.", holdPolicy, "p2")
	bootstrapKSK(t, r)
	r.l.SetHold(true)
	steady, sent := r.keyRows(), len(r.wire.distributions())

	// past both keys' lifetime: no lifetime rollover
	r.clock.Advance(31 * 24 * time.Hour)
	r.tick("past the lifetime, held")
	// a standby key the policy now wants: none
	pol := holdPolicy
	pol.StandbyZSK = 1
	r.l.SetPolicy(pol)
	r.tick("a standby wanted, held")
	// an algorithm rollover not begun: no key of the new algorithm
	r.setAlgorithms("held", algRollTo, "ZSK")
	r.tick("a new algorithm, held")
	if rows := r.keyRows(); rows != steady || len(r.wire.distributions()) != sent {
		t.Fatalf("a held machine started something: the key rows went from\n  %s\nto\n  %s", steady, rows)
	}

	// the hold let go: the roll starts
	r.l.SetHold(false)
	r.tick("let go")
	if len(r.keysOfAlg(KeyStateMpdist, "ZSK", algRollTo)) == 0 {
		t.Errorf("after the hold no ZSK of the new algorithm was minted: %s", r.keyRows())
	}
}

// A rollover under way runs to its end, every phase, an algorithm
// rollover's included; only what it would start besides waits.
func TestEveryPhaseOfARolloverUnderWayRunsUnderAHold(t *testing.T) {
	r := newDriverRig(t, "phases.hold.owned.example.", driverPolicy, "p2")
	a, z := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.setAlgorithms("change", algRollTo, "ZSK")
	r.tick("minted")
	y := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
	r.l.SetHold(true)

	r.confirmAll("applied", y)
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated, held")
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the new algorithm's ZSK under a hold: %s, want active", st)
	}
	r.clock.Advance(driverPolicy.SigLifetime + time.Second)
	r.tick("a signature lifetime, held")
	if st := r.state(z); st != KeyStateRetired {
		t.Fatalf("the old ZSK a signature lifetime on, under a hold: %s, want retired", st)
	}
	r.clock.Advance(driverPolicy.Margin + time.Second)
	r.tick("the margin, held")
	if st := r.state(z); st == KeyStateRetired {
		t.Errorf("the retired ZSK past its margin under a hold: still %s, want it on its way out", st)
	}
}

// The operator's rollover is the emergency one: it starts while the zone
// agrees on a newer serial, under the hold, at a provider that signs.
func TestAnEmergencyRolloverStartsDuringAgreeing(t *testing.T) {
	r := newDriverRig(t, "emergency.hold.owned.example.", driverPolicy, "p2")
	a, _ := bootstrapKSK(t, r)
	r.wire.parentDS[a] = true
	r.l.SetHold(true)
	r.l.RequestRollover("KSK")
	r.tick("requested, held")
	if ks := r.keysIn(KeyStateMpdist, "KSK"); len(ks) != 1 {
		t.Errorf("the operator's rollover under a hold minted %v, want the one KSK", ks)
	}
}

// heldEngine is the signer's key machine for a zone it owns, held at its
// agent's word.
func heldEngine(t *testing.T, zone string) (*KeyLifecycleEngine, *MPZoneData) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, zone, kdb)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.Config.Dnssec.Kasp.PropagationDelay = "5m"
	conf.SetMpConfig(&MultiProviderConf{Identity: "signer.example.", Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}})
	zoneSignedBy(t, mpzd, "agent.us.example.", "p2")
	holds, err := loadSignerHolds(nil)
	if err != nil {
		t.Fatal(err)
	}
	conf.InternalMp.SignerHolds = holds
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	tdns.RegisterKeyLifecycleOwner(owner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	e := NewKeyLifecycleEngine(conf, owner)
	conf.InternalMp.KeyLifecycleOwner, conf.InternalMp.KeyLifecycle = owner, e
	owner.Take(mpzd.ZoneName)
	if e.driver(mpzd.ZoneName) == nil {
		t.Fatal("no driver for the zone the signer owns")
	}
	if _, err := holds.set(zone, true); err != nil {
		t.Fatal(err)
	}
	return e, mpzd
}

// The emergency rollover is the operator's `signer key rollover`.
func TestTheEmergencyRolloverIsTheOperatorsRollover(t *testing.T) {
	e, mpzd := heldEngine(t, "operator.hold.owned.example.")
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreSigner: true}
	msg, err := e.RequestRollover(mpzd.ZoneName, "ksk")
	if err != nil || !strings.Contains(msg, "KSK rollover requested") {
		t.Fatalf("the operator's rollover at a signer under a hold: %q, %v", msg, err)
	}
	if got := e.driver(mpzd.ZoneName).RolloverRequests(); len(got) != 1 {
		t.Errorf("rollovers requested: %v, want the KSK's", got)
	}
}

// A provider with no role in the zone makes no emergency rollover under a
// hold: its keys go with its removal.
func TestAProviderWithNoRoleStartsNoEmergencyRollover(t *testing.T) {
	e, mpzd := heldEngine(t, "norole.hold.owned.example.")
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreSigner: false}
	if _, err := e.RequestRollover(mpzd.ZoneName, "KSK"); err == nil || !strings.Contains(err.Error(), "does not sign the zone") {
		t.Fatalf("a rollover at a provider with no role under a hold: %v, want refused", err)
	}
	if got := e.driver(mpzd.ZoneName).RolloverRequests(); len(got) != 0 {
		t.Errorf("rollovers requested: %v, want none", got)
	}
	// without the hold the request is the machine's as before
	if _, err := e.conf.InternalMp.SignerHolds.set(mpzd.ZoneName, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RequestRollover(mpzd.ZoneName, "KSK"); err != nil {
		t.Errorf("a rollover with no hold: %v", err)
	}
}

// The serial being agreed takes the provider out of signers=: the signer's
// own copy, which is never older than its agent's, says so first, and the
// emergency rollover is refused.
func TestAProviderThatTheAgreedSerialTakesAwayStartsNoEmergencyRollover(t *testing.T) {
	e, mpzd := heldEngine(t, "leaving.hold.owned.example.")
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreSigner: true}
	if _, err := e.RequestRollover(mpzd.ZoneName, "ZSK"); err != nil {
		t.Fatalf("a rollover while this provider signs: %v", err)
	}
	e.driver(mpzd.ZoneName).CancelRollover("ZSK")
	// the copy of the serial being agreed has the provider out of signers=
	mpzd.MP.MPdata = &MPdata{WeAreSigner: false}
	if _, err := e.RequestRollover(mpzd.ZoneName, "ZSK"); err == nil {
		t.Fatal("a rollover at a provider the serial being agreed takes away was taken")
	}
}

// The engine's tick holds the driver of a held zone, and lets it go with
// the hold.
func TestTheEngineHoldsTheDriverOfAHeldZone(t *testing.T) {
	e, mpzd := heldEngine(t, "tick.hold.owned.example.")
	l := e.driver(mpzd.ZoneName)
	e.tickOwned()
	if !l.hold {
		t.Error("a held zone's driver was ticked without the hold")
	}
	if _, err := e.conf.InternalMp.SignerHolds.set(mpzd.ZoneName, false); err != nil {
		t.Fatal(err)
	}
	e.tickOwned()
	if l.hold {
		t.Error("the hold stayed after the agent let it go")
	}
}

// A lifetime rollover that began before the hold, its key minted, runs to
// its end under the hold: the minted key's promotion is that rollover's
// next phase (cubic's review of ff9348d). With no standby kept, a standby
// key is always one a rollover minted.
func TestALifetimeRolloverBegunBeforeTheHoldEndsUnderIt(t *testing.T) {
	pol := driverPolicy
	pol.ZSKLifetime = 30 * 24 * time.Hour
	r := newDriverRig(t, "lifetime.hold.owned.example.", pol, "p2")
	_, z := bootstrapKSK(t, r)
	r.clock.Advance(31 * 24 * time.Hour)
	r.tick("due")
	minted := r.keysIn(KeyStateMpdist, "ZSK")
	if len(minted) != 1 {
		t.Fatalf("the lifetime rollover minted %v, want one ZSK", minted)
	}
	y := minted[0]
	r.l.SetHold(true)
	for i := 0; i < 6 && r.state(y) != KeyStateActive; i++ {
		if r.state(y) == KeyStateMpdist {
			r.confirmAll("applied", y)
		}
		r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
		r.tick("held")
	}
	if st := r.state(y); st != KeyStateActive {
		t.Fatalf("the ZSK minted for the rollover, under the hold: %s, want active", st)
	}
	if st := r.state(z); st != KeyStateRetired {
		t.Errorf("the old ZSK: %s, want retired", st)
	}
}
