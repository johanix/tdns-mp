package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// "Addition of a standby key is not the start of a key rollover" (the project
// owner, 2026-11-02). The driver on one provider with the fake wire and the
// fake clock, read as the signer's inventory reads it (inventoryMarksOf).

// underWay is rolloverUnderWay on the zone's rows and the machine's flags.
func (r *driverRig) underWay() bool {
	r.t.Helper()
	f, err := r.l.RolloverFlags()
	if err != nil {
		r.t.Fatal(err)
	}
	inv, err := tdns.GetKeyInventory(r.kdb, r.l.Zone)
	if err != nil {
		r.t.Fatal(err)
	}
	return rolloverUnderWay(inv, f)
}

// onlyKey is the one key of the role in the state.
func (r *driverRig) onlyKey(state, role string) uint16 {
	r.t.Helper()
	ks := r.keysIn(state, role)
	if len(ks) != 1 {
		r.t.Fatalf("%s %ss %v, want one: %s", state, role, ks, r.keyRows())
	}
	return ks[0]
}

// standbyInPublished: a zone with its active keys and a standby ZSK the
// policy's count asked for, in published, waiting out T8.
func standbyInPublished(t *testing.T, name string, pol LifecyclePolicy) (*driverRig, uint16) {
	t.Helper()
	r := newDriverRig(t, name, pol, "p2")
	bootstrapKSK(t, r)
	r.tick("the standby minted")
	k := r.onlyKey(KeyStateMpdist, "ZSK")
	r.confirmAll("applied", k)
	if st := r.state(k); st != KeyStatePublished {
		t.Fatalf("the standby ZSK confirmed: %s, want published", st)
	}
	return r, k
}

func TestAStandbyKeysAdditionIsNoRollover(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r := newDriverRig(t, "addition.owned.example.", pol, "p2")
	bootstrapKSK(t, r)
	r.tick("the standby minted")
	k := r.onlyKey(KeyStateMpdist, "ZSK")
	if !r.underWay() {
		t.Errorf("a key in mpdist, its distribution in flight: not counted")
	}
	r.confirmAll("applied", k)
	if st := r.state(k); st != KeyStatePublished {
		t.Fatalf("the standby ZSK confirmed: %s, want published", st)
	}
	if r.underWay() {
		t.Errorf("a standby ZSK in published, waiting out T8: a rollover under way")
	}
	r.l.SetHold(true)
	if r.underWay() {
		t.Errorf("the same under a hold: a rollover under way")
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("T8")
	if st := r.state(k); st != KeyStateStandby {
		t.Fatalf("after T8: %s, want standby", st)
	}
	if r.underWay() {
		t.Errorf("a standby ZSK: a rollover under way")
	}
}

// A role's first key is no standby key, whatever the standby count: T9
// promotes it once standby, under a hold too (Tick). It counts as before.
func TestARolesFirstKeyIsNoAddition(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK, pol.StandbyZSK = 1, 1
	r := newDriverRig(t, "first.owned.example.", pol, "p2")
	r.tick("the first keys minted")
	keys := map[string]uint16{"KSK": r.onlyKey(KeyStateMpdist, "KSK"), "ZSK": r.onlyKey(KeyStateMpdist, "ZSK")}
	r.confirmAll("applied", keys["KSK"], keys["ZSK"])
	for _, hold := range []bool{false, true} {
		r.l.SetHold(hold)
		f, err := r.l.RolloverFlags()
		if err != nil {
			t.Fatal(err)
		}
		for role, k := range keys {
			if st := r.state(k); st != KeyStatePublished {
				t.Fatalf("the first %s confirmed: %s, want published", role, st)
			}
			if f.Additions[k] {
				t.Errorf("hold %v: the first %s named a standby key's addition", hold, role)
			}
		}
		if !r.underWay() {
			t.Errorf("hold %v: the role's first keys in published: not counted", hold)
		}
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("T8 and T9, held")
	for role, k := range keys {
		if st := r.state(k); st != KeyStateActive {
			t.Errorf("the first %s under a hold: %s, want active", role, st)
		}
	}
}

// A rollover's new key in published still counts, whichever asked for it,
// and so does a key in published where only the rows can be read.
func TestARolloversNewKeyInPublishedStillCounts(t *testing.T) {
	const lifetime = 30 * 24 * time.Hour

	t.Run("the operator's, with a standby count", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyZSK = 1
		r, k := standbyInPublished(t, "asked.owned.example.", pol)
		r.l.RequestRollover("ZSK")
		if !r.underWay() {
			t.Errorf("a rollover asked for, its key %d in published: not counted", k)
		}
		r.l.SetHold(true)
		if !r.underWay() {
			t.Errorf("the same under a hold: not counted")
		}
	})

	t.Run("the operator's, with no standby count", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyKSK = 0
		r := newDriverRig(t, "asked.ksk.owned.example.", pol, "p2")
		bootstrapKSK(t, r)
		r.l.RequestRollover("KSK")
		r.tick("the KSK minted")
		k := r.onlyKey(KeyStateMpdist, "KSK")
		r.confirmAll("applied", k)
		if !r.underWay() {
			t.Errorf("a KSK rollover asked for, its key in published: not counted")
		}
	})

	t.Run("a lifetime's, with a standby count", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyZSK, pol.ZSKLifetime = 1, lifetime
		r, k := standbyInPublished(t, "due.owned.example.", pol)
		r.clock.Advance(lifetime + time.Hour)
		if !r.underWay() {
			t.Errorf("the active ZSK past its lifetime, its successor %d in published: not counted", k)
		}
		// under a hold the key is not promoted (Tick): it only becomes a
		// standby key, and the thaw that ends the hold does not wait for it
		r.l.SetHold(true)
		if r.underWay() {
			t.Errorf("the same under a hold, which holds the promotion: a rollover under way")
		}
		r.tick("T8, held")
		if st := r.state(k); st != KeyStateStandby {
			t.Fatalf("under a hold: %s, want standby and not promoted", st)
		}
	})

	t.Run("a lifetime's, with no standby count", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyKSK, pol.KSKLifetime = 0, lifetime
		r := newDriverRig(t, "due.ksk.owned.example.", pol, "p2")
		bootstrapKSK(t, r)
		r.clock.Advance(lifetime + time.Hour)
		r.tick("the KSK minted")
		k := r.onlyKey(KeyStateMpdist, "KSK")
		r.confirmAll("applied", k)
		if !r.underWay() {
			t.Errorf("a KSK past its lifetime, its successor in published: not counted")
		}
		// the hold does not stop this one: its promotion is the next phase
		r.l.SetHold(true)
		if !r.underWay() {
			t.Errorf("the same under a hold: not counted")
		}
	})

	t.Run("an algorithm's", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyZSK = 1
		r, _ := standbyInPublished(t, "alg.owned.example.", pol)
		r.setAlgorithms("change", algRollTo, "ZSK")
		r.tick("minted")
		k := r.one("minted", KeyStateMpdist, "ZSK", algRollTo)
		r.confirmAll("applied", k)
		if st := r.state(k); st != KeyStatePublished {
			t.Fatalf("the new algorithm's ZSK confirmed: %s, want published", st)
		}
		if !r.underWay() {
			t.Errorf("an algorithm rollover, its key in published: not counted")
		}
	})

	t.Run("by the rows alone", func(t *testing.T) {
		pol := driverPolicy
		pol.StandbyZSK = 1
		r, _ := standbyInPublished(t, "rows.owned.example.", pol)
		inv, err := tdns.GetKeyInventory(r.kdb, r.l.Zone)
		if err != nil {
			t.Fatal(err)
		}
		if !rolloverUnderWay(inv, rolloverFlags{}) {
			t.Errorf("a key in published with nothing known beside the rows: not counted")
		}
	})
}
