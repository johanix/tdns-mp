package tdnsmp

import (
	"strings"
	"testing"
	"time"
)

// S5c (design §6; transition table O7, E13, T17): a KSK's promotion waits
// for the parent. The driver on one provider with the fake wire and the fake
// clock, as the T3.4 scenarios run.

// bootstrapKSK: a fresh owned zone gets its active KSK and ZSK through the
// machine, against a parent that serves no DS (O2: promoted at once).
func bootstrapKSK(t *testing.T, r *driverRig) (uint16, uint16) {
	t.Helper()
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	ksk, zsk := r.keysIn(KeyStateActive, "KSK"), r.keysIn(KeyStateActive, "ZSK")
	if len(ksk) != 1 || len(zsk) != 1 {
		t.Fatalf("after the bootstrap %d active KSKs and %d active ZSKs, want one each", len(ksk), len(zsk))
	}
	return ksk[0], zsk[0]
}

// rollToStandby: a KSK rollover requested, its key minted, confirmed and
// propagated to standby, with the parent serving the old key's DS only.
func rollToStandby(t *testing.T, r *driverRig, old uint16) uint16 {
	t.Helper()
	r.wire.parentDS[old] = true
	r.l.RequestRollover("KSK")
	r.tick("roll requested")
	pend := r.keysIn(KeyStateMpdist, "KSK")
	if len(pend) != 1 {
		t.Fatalf("after the request %d KSKs in mpdist, want the one minted for the roll", len(pend))
	}
	if _, _, err := r.l.Confirm(pend[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new key propagated")
	if st := r.state(pend[0]); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with its DS not at the parent, want standby (O7)", st)
	}
	return pend[0]
}

func TestAKSKIsPromotedOnceTheParentHasServedItsDSForTheTTL(t *testing.T) {
	r := newDriverRig(t, "wait.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	// the parent gets the new DS: seen on this tick and noted (E13, T17),
	// the promotion still waits for the DS TTL
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s the tick its DS was first seen, want standby for the DS TTL (O7)", st)
	}
	if _, ok := r.l.dsPresent[b]; !ok {
		t.Fatal("the parent's DS was not noted for the new KSK (T17)")
	}
	r.clock.Advance(30 * time.Minute)
	r.tick("half the DS TTL")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s after half the DS TTL, want standby", st)
	}
	r.clock.Advance(31 * time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(b), r.cols(b); st != KeyStateActive || c != "111" {
		t.Errorf("the new KSK is %s (%s) after the DS TTL, want active (111)", st, c)
	}
	if st := r.state(old); st != KeyStateRetired {
		t.Errorf("the old KSK is %s, want retired (T10 in the same step)", st)
	}
	if _, ok := r.l.dsPresent[b]; ok {
		t.Error("the parent's DS note outlived the promotion")
	}
	r.check("after the roll")
}

func TestAKSKWaitsWhileTheParentIsUnknown(t *testing.T) {
	r := newDriverRig(t, "unknown.owned.example.", driverPolicy, "p2")
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	// the parent cannot be asked: not "no DS"; the key waits (E7's rule)
	r.wire.parentOff = true
	r.clock.Advance(2 * time.Hour)
	r.tick("the resolver is down")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with the parent unknown, want standby (O7: unknown is not no DS)", st)
	}
	if _, ok := r.l.dsPresent[b]; ok {
		t.Fatal("a DS was noted as served while the parent was unknown")
	}
	r.wire.parentOff = false
	r.wire.parentDS[b] = true
	r.tick("the resolver is back and the parent serves the DS")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s once the parent serves its DS (TTL 0), want active", st)
	}
}

func TestADSThatGoesAwayAgainStartsTheWaitAfresh(t *testing.T) {
	r := newDriverRig(t, "flap.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(50 * time.Minute)
	delete(r.wire.parentDS, b)
	r.tick("the parent dropped the new DS")
	if _, ok := r.l.dsPresent[b]; ok {
		t.Fatal("the parent's DS note survived the DS going away")
	}
	r.wire.parentDS[b] = true
	r.tick("the parent serves it again")
	r.clock.Advance(20 * time.Minute)
	r.tick("70 minutes after the first sighting, 20 after the second")
	if st := r.state(b); st != KeyStateStandby {
		t.Errorf("the new KSK is %s 20 minutes after its DS came back, want standby: the wait started afresh", st)
	}
	r.clock.Advance(41 * time.Minute)
	r.tick("the DS TTL since the second sighting passed")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s after the DS TTL since the second sighting, want active", st)
	}
}

func TestTheParentWaitSurvivesARestart(t *testing.T) {
	r := newDriverRig(t, "restart.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	since := r.l.dsPresent[b].Since
	// the process restarts (T15): a new driver on the same store reads the
	// note back, and the wait runs from the first sighting, not from now
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatal(err)
	}
	// the note is kept at second precision
	if got, ok := r.l.dsPresent[b]; !ok || got.Since.Unix() != since.Unix() || got.TTL != time.Hour {
		t.Fatalf("after the restart the note is %+v (found %v), want since %s ttl 1h", got, ok, since.UTC().Format(time.RFC3339))
	}
	// the rollover request itself is not persisted (a request made before a
	// restart is forgotten; seen here, not S5c's), so the operator asks
	// again; the note makes the promotion come at once, the TTL having
	// passed since the first sighting, where without it another TTL would
	// pass first
	r.clock.Advance(61 * time.Minute)
	r.l.RequestRollover("KSK")
	r.tick("the DS TTL passed, counted from before the restart")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s after the restart and the DS TTL, want active", st)
	}
	if st := r.state(old); st != KeyStateRetired {
		t.Errorf("the old KSK is %s, want retired", st)
	}
}

func TestAKSKWaitingOnTheParentIsReportedAfterThreeMargins(t *testing.T) {
	r := newDriverRig(t, "report.owned.example.", driverPolicy, "p2")
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	before := len(r.wire.reports)
	// the parent never gets the new DS (the leader's sync is broken): the
	// operator hears once after three margins, and the key keeps waiting
	for i := 0; i < 4; i++ {
		r.clock.Advance(driverPolicy.Margin)
		r.tick("waiting")
	}
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with its DS never at the parent, want standby", st)
	}
	var waits int
	for _, rep := range r.wire.reports[before:] {
		if strings.Contains(rep, "waits for the parent to serve its DS") {
			waits++
		}
	}
	if waits != 1 {
		t.Errorf("%d reports of the KSK waiting on the parent, want exactly one: %v", waits, r.wire.reports[before:])
	}
}

func TestAZSKRollDoesNotWaitForTheParent(t *testing.T) {
	r := newDriverRig(t, "zsk.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	ksk, zsk := bootstrapKSK(t, r)
	r.wire.parentDS[ksk] = true // the parent serves the KSK's DS: not empty
	r.l.RequestRollover("ZSK")
	r.tick("ZSK roll requested")
	pend := r.keysIn(KeyStateMpdist, "ZSK")
	if len(pend) != 1 {
		t.Fatalf("after the request %d ZSKs in mpdist, want one", len(pend))
	}
	if _, _, err := r.l.Confirm(pend[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new ZSK propagated")
	if st := r.state(pend[0]); st != KeyStateActive {
		t.Errorf("the new ZSK is %s, want active: a ZSK has no DS to wait for", st)
	}
	if st := r.state(zsk); st != KeyStateRetired {
		t.Errorf("the old ZSK is %s, want retired", st)
	}
}
