package tdnsmp

import (
	"context"
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
	f, err := r.l.RolloverFlags(r.l.hold)
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

// The same for a KSK, where the policy keeps standby KSKs.
func TestAStandbyKSKsAdditionIsNoRollover(t *testing.T) {
	pol := driverPolicy
	pol.StandbyKSK = 1
	r := newDriverRig(t, "ksk.addition.owned.example.", pol, "p2")
	bootstrapKSK(t, r)
	r.tick("the standby minted")
	k := r.onlyKey(KeyStateMpdist, "KSK")
	r.confirmAll("applied", k)
	if st := r.state(k); st != KeyStatePublished {
		t.Fatalf("the standby KSK confirmed: %s, want published", st)
	}
	if r.underWay() {
		t.Errorf("a standby KSK in published, waiting out T8: a rollover under way")
	}
	r.l.SetHold(true)
	if r.underWay() {
		t.Errorf("the same under a hold: a rollover under way")
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("T8")
	if st, c := r.state(k), r.cols(k); st != KeyStateStandby || c != "101" {
		t.Fatalf("after T8: %s %s, want standby 101", st, c)
	}
	if r.underWay() {
		t.Errorf("a standby KSK: a rollover under way")
	}
}

// An inventory reads the rows, then the flags, and T8 can come between them.
// The key is still an addition: T8's own inventory may reach the agent first,
// and this one must not leave it waiting on a rollover nobody has.
func TestAnAdditionsT8BetweenTheRowsAndTheFlags(t *testing.T) {
	pol := driverPolicy
	pol.StandbyZSK = 1
	r, k := standbyInPublished(t, "between.owned.example.", pol)
	inv, err := tdns.GetKeyInventory(r.kdb, r.l.Zone)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(pol.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("T8")
	if st := r.state(k); st != KeyStateStandby {
		t.Fatalf("after T8: %s, want standby", st)
	}
	f, err := r.l.RolloverFlags(false)
	if err != nil {
		t.Fatal(err)
	}
	if rolloverUnderWay(inv, f) {
		t.Errorf("rows from before T8, flags from after it: a rollover under way")
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
		f, err := r.l.RolloverFlags(hold)
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

// The inventory a hand-over pushes confirms the hold, and reads the keys by
// that same hold, though the machine hears of it only at its next tick: a due
// key in published is an addition under the hold, and a rollover's without it.
func TestTheInventoryReadsTheKeysByTheHoldItConfirms(t *testing.T) {
	const zone = "due.hold.signer.example."
	const lifetime = 30 * 24 * time.Hour
	records := sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)
	s := newSignerRig(t, zone, records...)
	pol := driverPolicy
	pol.StandbyZSK, pol.ZSKLifetime = 1, lifetime
	clock, wire := &fakeClock{t: time.Now()}, newFakeWire("p2")
	r := &driverRig{t: t, kdb: s.kdb, zd: s.mpzd, clock: clock, wire: wire, l: NewZoneKeyLifecycle(zone, s.kdb, clock, pol, wire)}
	s.e.zones[zone] = r.l
	bootstrapKSK(t, r)
	r.tick("the standby minted")
	r.confirmAll("applied", r.onlyKey(KeyStateMpdist, "ZSK"))
	clock.Advance(lifetime + time.Hour)
	marks := func() inventoryMarks {
		inv, err := tdns.GetKeyInventory(s.kdb, zone)
		if err != nil {
			t.Fatal(err)
		}
		return s.conf.inventoryMarksOf(zone, inv)
	}
	if m := marks(); m.hold || !m.rollover {
		t.Fatalf("a due ZSK's successor in published: hold %v, rollover %v", m.hold, m.rollover)
	}
	on := handoverFor(t, zone, records...)
	on.Sets.Hold = true
	s.hand(on, sigUs)
	if m := marks(); !m.hold || m.rollover {
		t.Errorf("handed the hold, no tick since: hold %v, rollover %v; want the hold and no rollover", m.hold, m.rollover)
	}
	off := handoverFor(t, zone, records...)
	off.Made = on.Made.Add(time.Second)
	s.hand(off, sigUs)
	if m := marks(); m.hold || !m.rollover {
		t.Errorf("handed the hold's end, no tick since: hold %v, rollover %v; want no hold and a rollover", m.hold, m.rollover)
	}
}

// The machine's hold is its tick's to set. An inventory that read the zone's
// hold before a hand-over kept a new one, and comes after the tick has set it,
// leaves it: the tick that follows starts no due rollover.
func TestAnInventoryLeavesTheMachinesHoldAlone(t *testing.T) {
	const zone = "stale.hold.signer.example."
	const lifetime = 30 * 24 * time.Hour
	s := newSignerRig(t, zone, sigRecords(`serial="5" servers="us,p2" signers="us,p2"`)...)
	pol := driverPolicy
	pol.ZSKLifetime = lifetime
	clock, wire := &fakeClock{t: time.Now()}, newFakeWire("p2")
	r := &driverRig{t: t, kdb: s.kdb, zd: s.mpzd, clock: clock, wire: wire, l: NewZoneKeyLifecycle(zone, s.kdb, clock, pol, wire)}
	s.e.zones[zone] = r.l
	bootstrapKSK(t, r)
	clock.Advance(lifetime + time.Hour)
	r.l.SetHold(true)
	inv, err := tdns.GetKeyInventory(s.kdb, zone)
	if err != nil {
		t.Fatal(err)
	}
	if m := s.conf.inventoryMarksOf(zone, inv); m.hold {
		t.Fatalf("the zone's hold, as the inventory read it: %v, want none", m.hold)
	}
	r.tick("held")
	if ks := r.keysIn(KeyStateMpdist, "ZSK"); len(ks) != 0 {
		t.Errorf("after an inventory by an older hold, a tick under the hold minted %v", ks)
	}
	r.l.SetHold(false)
	r.tick("let go")
	if ks := r.keysIn(KeyStateMpdist, "ZSK"); len(ks) != 1 {
		t.Errorf("the hold let go, the due rollover minted %v, want one ZSK", ks)
	}
}

// A signer joins a zone at rest: no key is in published, so no key row is due
// to be written. Each served key's record is done on the last answer, which
// writes no row either, and the last inventory said a rollover: the leader's
// next step and the thaw wait on that with no time-out. It must be said again.
func TestAJoinersLastAnswerIsToldWithNoKeyRowWritten(t *testing.T) {
	joined := func(t *testing.T, name string) (*driverRig, []uint16) {
		t.Helper()
		r := newDriverRig(t, name, driverPolicy, "p2")
		ksk, zsk := bootstrapKSK(t, r)
		r.wire.signers = []string{"p2", "p3"}
		if err := r.l.SignersChanged(); err != nil {
			t.Fatal(err)
		}
		if !r.underWay() {
			t.Fatalf("the served keys' records wait for the joiner: not counted")
		}
		return r, []uint16{ksk, zsk}
	}
	confirm := func(t *testing.T, r *driverRig, k uint16, provider, status string) {
		t.Helper()
		if _, _, err := r.l.Confirm(k, provider, status, "because"); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("applied, nothing due after", func(t *testing.T) {
		r, keys := joined(t, "applied.joined.owned.example.")
		changes := r.wire.changes
		for i, k := range keys {
			if r.wire.marks != 0 {
				t.Errorf("told with %d of the %d records left", len(keys)-i, len(keys))
			}
			confirm(t, r, k, "p2", "applied")
			confirm(t, r, k, "p3", "applied")
		}
		if r.wire.marks != 1 {
			t.Errorf("the last answer told %d times, want once", r.wire.marks)
		}
		if r.underWay() {
			t.Errorf("every record done: a rollover under way")
		}
		r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
		r.tick("at rest")
		if r.wire.changes != changes {
			t.Errorf("%d key rows written, want none: nothing else would say it", r.wire.changes-changes)
		}
	})

	t.Run("rejected by the joiner", func(t *testing.T) {
		r, keys := joined(t, "rejected.joined.owned.example.")
		confirm(t, r, keys[0], "p3", "rejected")
		confirm(t, r, keys[1], "p2", "applied")
		confirm(t, r, keys[1], "p3", "applied")
		if r.wire.marks != 1 {
			t.Errorf("told %d times, want once", r.wire.marks)
		}
		if r.underWay() {
			t.Errorf("no record waits: a rollover under way")
		}
	})

	t.Run("the joiner left", func(t *testing.T) {
		r, keys := joined(t, "left.joined.owned.example.")
		for _, k := range keys {
			confirm(t, r, k, "p2", "applied")
		}
		if r.wire.marks != 0 {
			t.Errorf("told %d times with the joiner's answers missing", r.wire.marks)
		}
		r.wire.signers = []string{"p2"}
		if err := r.l.SignersChanged(); err != nil {
			t.Fatal(err)
		}
		if r.wire.marks != 1 {
			t.Errorf("told %d times, want once", r.wire.marks)
		}
		if r.underWay() {
			t.Errorf("nobody left to wait for: a rollover under way")
		}
	})
}

// A rollover asked for is a flag of its own: withdrawing it writes no key row.
func TestAWithdrawnRolloverIsTold(t *testing.T) {
	r := newDriverRig(t, "withdrawn.owned.example.", driverPolicy, "p2")
	bootstrapKSK(t, r)
	r.l.CancelRollover("ZSK")
	if r.wire.marks != 0 {
		t.Errorf("nothing to withdraw: told %d times", r.wire.marks)
	}
	r.l.RequestRollover("ZSK")
	if !r.underWay() {
		t.Fatalf("a rollover asked for: not counted")
	}
	r.l.CancelRollover("ZSK")
	if r.wire.marks != 1 {
		t.Errorf("told %d times, want once", r.wire.marks)
	}
	if r.underWay() {
		t.Errorf("withdrawn: a rollover under way")
	}
}

// The signer's wire pushes the inventory, with no key marked as sent again.
func TestTheSignerPushesAnInventoryWhenTheMarksChange(t *testing.T) {
	got := make(chan []uint16, 1)
	w := &signerWire{conf: &Config{}, push: func(_ *Config, zone string, resend []uint16) {
		if zone != "marks.signer.example." {
			t.Errorf("pushed for %q", zone)
		}
		got <- resend
	}}
	w.MarksChanged("marks.signer.example")
	if r, ok := recvWithin(got, time.Second); !ok || len(r) != 0 {
		t.Errorf("pushed %v (%v), want a plain push", r, ok)
	}
}

// The agent's cover for the word that ends a rollover not arriving: its
// signer's last word is a rollover, a minute old, so it asks again.
func TestAnOldRolloverMarkIsAskedAgain(t *testing.T) {
	type rig struct {
		*freezeRig
		mpzd  *MPZoneData
		asked int
	}
	newRig := func(t *testing.T, zone string) *rig {
		t.Helper()
		r := &rig{freezeRig: newFreezeRig(t, zone)}
		r.conf.InternalMp.MPZoneNames = []string{zone}
		r.mpzd, _ = Zones.Get(zone)
		return r
	}
	told := func(r *rig, rollover bool, at time.Time) {
		r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: r.zone, Rollover: rollover, Received: at})
	}
	pass := func(r *rig, at time.Time) int {
		r.asked = 0
		r.conf.askOnOldRolloverMarks(at, func(*MPZoneData) { r.asked++ })
		return r.asked
	}
	answered := func(r *rig, rollover bool) {
		r.conf.noteKeyInventory(context.Background(), r.mpzd, &KeystateInventoryMsg{SenderID: "signer.us.example.", Zone: r.zone, Rollover: rollover})
	}
	now := time.Now()

	t.Run("the rollover's end was lost", func(t *testing.T) {
		r := newRig(t, "lost.mark.freeze.example.")
		told(r, true, now.Add(-rolloverMarkMaxAge))
		if !r.conf.InternalMp.MPTransport.rolloverAt(r.zone) {
			t.Fatalf("the signer's last word is a rollover: not read")
		}
		if n := pass(r, now); n != 1 {
			t.Errorf("asked %d times, want once", n)
		}
		answered(r, false)
		if r.conf.InternalMp.MPTransport.rolloverAt(r.zone) {
			t.Errorf("the answer says none: a rollover under way")
		}
		if n := pass(r, time.Now().Add(rolloverMarkMaxAge)); n != 0 {
			t.Errorf("no rollover told: asked %d times", n)
		}
	})

	t.Run("an older word landed after the end", func(t *testing.T) {
		r := newRig(t, "late.mark.freeze.example.")
		told(r, false, now)
		told(r, true, now)
		if n := pass(r, now); n != 0 {
			t.Errorf("the word just came: asked %d times", n)
		}
		if n := pass(r, now.Add(rolloverMarkMaxAge)); n != 1 {
			t.Errorf("a minute on: asked %d times, want once", n)
		}
	})

	t.Run("a rollover really under way", func(t *testing.T) {
		r := newRig(t, "real.mark.freeze.example.")
		told(r, true, now.Add(-rolloverMarkMaxAge))
		answered(r, true)
		fresh := time.Now()
		if n := pass(r, fresh); n != 0 {
			t.Errorf("just answered: asked %d times", n)
		}
		if n := pass(r, fresh.Add(rolloverMarkMaxAge)); n != 1 {
			t.Errorf("a minute after the answer: asked %d times, want once", n)
		}
	})

	t.Run("nothing to ask for", func(t *testing.T) {
		r := newRig(t, "none.mark.freeze.example.")
		if n := pass(r, now); n != 0 {
			t.Errorf("no inventory: asked %d times", n)
		}
		told(r, false, now.Add(-time.Hour))
		if n := pass(r, now); n != 0 {
			t.Errorf("an old word of no rollover: asked %d times", n)
		}
	})
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
