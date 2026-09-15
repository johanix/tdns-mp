package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// T3.1: the machine as data equals the transition table document, and the
// data keeps the properties the plan names structurally.

func flagsOf(f tdns.KeyRowFlags) string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	ds := "NULL"
	if f.DS.Valid {
		ds = b(f.DS.Bool)
	}
	return b(f.Pub) + b(f.Sign) + ds
}

// The document's §1, for a KSK (retired: on entry / withdrawn) and a ZSK.
func TestKeyStateColumnsFollowTheTable(t *testing.T) {
	want := map[string][3]string{ // state: KSK on entry, KSK withdrawn, ZSK
		KeyStateCreated:   {"000", "000", "000"},
		KeyStateMpdist:    {"100", "100", "100"},
		KeyStatePublished: {"100", "100", "100"},
		KeyStateStandby:   {"101", "101", "100"},
		KeyStateActive:    {"111", "111", "110"},
		KeyStateRetired:   {"101", "100", "100"},
		KeyStateMpremove:  {"000", "000", "000"},
		KeyStateRemoved:   {"000", "000", "000"},
	}
	for _, st := range KeyLifecycleStates {
		w, ok := want[st]
		if !ok {
			t.Fatalf("state %s has no expected columns in this test", st)
		}
		for i, c := range []struct {
			sep, withdrawn bool
		}{{true, false}, {true, true}, {false, false}} {
			f, ok := KeyStateColumns(st, c.sep, c.withdrawn)
			if !ok {
				t.Errorf("%s: no columns", st)
				continue
			}
			if got := flagsOf(f); got != w[i] {
				t.Errorf("%s (sep=%v withdrawn=%v): columns %s, want %s", st, c.sep, c.withdrawn, got, w[i])
			}
		}
	}
	if _, ok := KeyStateColumns("bogus", true, false); ok {
		t.Error("an unknown state has columns")
	}
}

// The document's §3, row by row: from, event, to.
func TestTransitionTableMatchesTheDocument(t *testing.T) {
	doc := []struct {
		id, from, to string
		ev           KeyEvent
	}{
		{"T1", "", KeyStateCreated, EvMint},
		{"T2", KeyStateCreated, KeyStateMpdist, EvDistributed},
		{"T3", KeyStateMpdist, KeyStatePublished, EvApplied},
		{"T3'", KeyStateMpdist, KeyStatePublished, EvDistributed},
		{"T4", KeyStateMpdist, KeyStateMpdist, EvPending},
		{"T5", KeyStateMpdist, KeyStateMpdist, EvRejected},
		{"T6", KeyStateMpdist, KeyStateMpdist, CmdRetry},
		{"T7", KeyStateMpdist, KeyStateMpremove, CmdWithdraw},
		{"T8", KeyStatePublished, KeyStateStandby, EvPropagated},
		{"T9", KeyStateStandby, KeyStateActive, EvPromote},
		{"T10", KeyStateActive, KeyStateRetired, EvSuccessorActive},
		{"T11", KeyStateRetired, KeyStateRetired, EvDSGone},
		{"T12", KeyStateRetired, KeyStateMpremove, EvMargin},
		{"T13", KeyStateMpremove, KeyStateRemoved, EvRemovalApplied},
		{"T13'", KeyStateMpremove, KeyStateRemoved, EvDistributed},
		{"T14a", KeyStateMpdist, KeyStateMpdist, EvSignersChanged},
		{"T14b", KeyStateMpremove, KeyStateMpremove, EvSignersChanged},
		{"T15", "*", "*", EvRestart},
	}
	if len(doc) != len(KeyLifecycleTable) {
		t.Errorf("the table has %d rows, the document %d", len(KeyLifecycleTable), len(doc))
	}
	for i, d := range doc {
		if i >= len(KeyLifecycleTable) {
			break
		}
		r := KeyLifecycleTable[i]
		if r.ID != d.id || r.From != d.from || r.Event != d.ev || r.To != d.to {
			t.Errorf("row %d: table %s %s --%s--> %s, document %s %s --%s--> %s", i, r.ID, r.From, r.Event, r.To, d.id, d.from, d.ev, d.to)
		}
	}
}

// P1, P2, P5, P8, P9 and P4 as properties of the data, not of a run.
func TestTransitionTableKeepsTheProperties(t *testing.T) {
	entersSign := map[string]bool{}
	entersDS := map[string]bool{}
	for _, st := range KeyLifecycleStates {
		f, _ := KeyStateColumns(st, true, false)
		if f.Sign {
			entersSign[st] = true
		}
		if f.DS.Valid && f.DS.Bool {
			entersDS[st] = true
		}
	}
	for _, r := range KeyLifecycleTable {
		if r.To == "*" {
			continue
		}
		fromF, _ := KeyStateColumns(r.From, true, false)
		toF, _ := KeyStateColumns(r.To, true, false)
		// P1: sign is gained only from standby
		if toF.Sign && !fromF.Sign && r.From != KeyStateStandby {
			t.Errorf("%s: sign gained from %s, only standby may (P1)", r.ID, r.From)
		}
		// P2: a KSK gains ds only on entering standby
		if toF.DS.Valid && toF.DS.Bool && !(fromF.DS.Valid && fromF.DS.Bool) && r.To != KeyStateStandby {
			t.Errorf("%s: ds gained on entering %s, only standby may (P2)", r.ID, r.To)
		}
		// P9: pending changes nothing; P8: rejected stays in mpdist
		if (r.Event == EvPending || r.Event == EvRejected) && r.To != r.From {
			t.Errorf("%s: %s leaves %s for %s (P8/P9)", r.ID, r.Event, r.From, r.To)
		}
	}
	// P4: every state but removed has a way out
	out := map[string]bool{}
	for _, r := range KeyLifecycleTable {
		if r.To != "*" && r.To != r.From {
			out[r.From] = true
		}
	}
	for _, st := range KeyLifecycleStates {
		if st != KeyStateRemoved && !out[st] {
			t.Errorf("%s has no transition out (P4)", st)
		}
	}
	// standby is the only state whose entry sets ds, and active the only one with sign
	if len(entersSign) != 1 || !entersSign[KeyStateActive] {
		t.Errorf("states with sign: %v, want active only", entersSign)
	}
	if len(entersDS) != 3 || !entersDS[KeyStateStandby] || !entersDS[KeyStateActive] || !entersDS[KeyStateRetired] {
		t.Errorf("KSK states with ds on entry: %v, want standby, active, retired", entersDS)
	}
}

// The guards, with a fake zone: G1 (every other signer applied, pending
// never counts), G2 (no other signer), the two timers, P5.
func TestTransitionGuards(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	two := ZoneView{OtherSigners: []string{"p2", "p3"}, Applied: map[string]bool{}, Pending: map[string]bool{}, Now: now}
	k := KeyView{State: KeyStateMpdist, SEP: true}
	if st, _ := Next(k, EvApplied, two); st != KeyStateMpdist {
		t.Errorf("applied by nobody: %s, want mpdist", st)
	}
	two.Applied["p2"] = true
	two.Pending["p3"] = true
	if st, _ := Next(k, EvApplied, two); st != KeyStateMpdist {
		t.Errorf("one applied, one pending: %s, want mpdist (P9)", st)
	}
	if st, tr := Next(k, EvPending, two); st != KeyStateMpdist || tr == nil || tr.ID != "T4" {
		t.Errorf("pending: %s via %v, want mpdist via T4", st, tr)
	}
	two.Applied["p3"] = true
	if st, tr := Next(k, EvApplied, two); st != KeyStatePublished || tr.ID != "T3" {
		t.Errorf("every other signer applied: %s via %s, want published via T3", st, tr.ID)
	}
	alone := ZoneView{Now: now}
	if st, tr := Next(k, EvDistributed, alone); st != KeyStatePublished || tr.ID != "T3'" {
		t.Errorf("no other signer: %s via %v, want published via T3'", st, tr)
	}
	if st, _ := Next(KeyView{State: KeyStateMpdist}, EvRejected, two); st != KeyStateMpdist {
		t.Errorf("rejected left mpdist for %s (P8)", st)
	}

	pub := KeyView{State: KeyStatePublished, SEP: true, PublishedAt: now.Add(-time.Hour)}
	z := ZoneView{PropagationDelay: 30 * time.Minute, ServedDnskeyTTL: time.Hour, Now: now}
	if st, _ := Next(pub, EvPropagated, z); st != KeyStatePublished {
		t.Errorf("propagated before the delay and TTL: %s, want published", st)
	}
	z.Now = now.Add(31 * time.Minute)
	if st, _ := Next(pub, EvPropagated, z); st != KeyStateStandby {
		t.Errorf("propagated after the delay and TTL: %s, want standby", st)
	}

	sb := KeyView{State: KeyStateStandby, SEP: true}
	if st, _ := Next(sb, EvPromote, ZoneView{ActiveOfRoleAndAlg: true}); st != KeyStateStandby {
		t.Errorf("promoted beside an active key of the role and algorithm: %s, want standby (P5)", st)
	}
	if st, _ := Next(sb, EvPromote, ZoneView{ActiveOfRoleAndAlg: true, AlgRollInFlight: true}); st != KeyStateActive {
		t.Errorf("promoted during an algorithm roll: %s, want active", st)
	}
	if st, _ := Next(KeyView{State: KeyStatePublished}, EvPromote, ZoneView{}); st != KeyStatePublished {
		t.Errorf("a published key promoted: %s, want published (P1)", st)
	}

	ret := KeyView{State: KeyStateRetired, SEP: true, RetiredAt: now.Add(-2 * time.Hour)}
	zm := ZoneView{Margin: time.Hour, Now: now}
	if st, _ := Next(ret, EvMargin, zm); st != KeyStateRetired {
		t.Errorf("margin passed but the DS still at the parent: %s, want retired", st)
	}
	ret.DSGone = true
	if st, _ := Next(ret, EvMargin, zm); st != KeyStateMpremove {
		t.Errorf("margin passed, DS gone: %s, want mpremove", st)
	}
	zsk := KeyView{State: KeyStateRetired, RetiredAt: now.Add(-2 * time.Hour)}
	if st, _ := Next(zsk, EvMargin, zm); st != KeyStateMpremove {
		t.Errorf("a retired ZSK after the margin: %s, want mpremove", st)
	}
	if st, tr := Next(KeyView{State: KeyStateActive}, EvRestart, ZoneView{}); st != KeyStateActive || tr == nil || tr.ID != "T15" {
		t.Errorf("restart: %s via %v, want active via T15", st, tr)
	}
	if st, tr := Next(KeyView{State: KeyStateActive}, EvApplied, two); st != KeyStateActive || tr != nil {
		t.Errorf("an event with no row: %s via %v, want unchanged, no row", st, tr)
	}
}
