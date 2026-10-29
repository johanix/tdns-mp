/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The serials an agent keeps per zone, on disk (plan S2).
 */
package tdnsmp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

const storeZone = "store.example."

// storeDB is a keystore file of its own, with the serials' tables.
func storeDB(t *testing.T) (path string, hdb *HsyncDB) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(path, nil, 0664); err != nil {
		t.Fatal(err)
	}
	return path, openStoreDB(t, path)
}

func openStoreDB(t *testing.T, path string) *HsyncDB {
	t.Helper()
	kdb, err := tdns.NewKeyDB(path, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { kdb.DB.Close() })
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitInstructionTables(); err != nil {
		t.Fatal(err)
	}
	return hdb
}

func loadStore(t *testing.T, hdb *HsyncDB) *InstructionStore {
	t.Helper()
	s, err := LoadInstructionStore(hdb)
	if err != nil {
		t.Fatalf("LoadInstructionStore: %v", err)
	}
	return s
}

func newStore(t *testing.T) *InstructionStore {
	t.Helper()
	_, hdb := storeDB(t)
	return loadStore(t, hdb)
}

// at is a reading of instrBase's instructions at serial, with auditors as
// its auditors= list: a change of auditors= has nothing to carry out, so the
// judge (S4) accepts every change between them.
func at(t *testing.T, serial uint32, auditors string) *Instructions {
	t.Helper()
	return readOf(t, withParam(fmt.Sprintf(`serial="%d" servers="alpha,beta" signers="alpha" auditors="%s"`, serial, auditors))...)
}

func sd(in *Instructions) SerialDigest { return SerialDigest{Serial: in.Serial, Digest: in.Digest()} }

// enforced has the store keep zone's active serial as the leader's, as S7's
// thaw does: with none known, the first serial noted is made known, as the
// restart rule does (S9), and the others are held above it.
func enforced(t *testing.T, s *InstructionStore, zone string) {
	t.Helper()
	if err := s.update(zone, func(z *zoneSerials) error {
		if z.Active == nil && len(z.Held) > 0 {
			a := z.Held[0]
			z.Active, z.Held = &a, slices.Clone(z.Held[1:])
			s.judged(zone, z)
		}
		z.Enforced = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// noteKnown notes a copy of the zone's instructions and, when the store
// knows no active serial for the zone, makes the copy's serial known, as the
// restart rule would (S9): the fixture of a zone whose active serial is its
// first copy's, as S7 had it.
func noteKnown(t *testing.T, s *InstructionStore, zone string, in *Instructions) {
	t.Helper()
	s.Note(zone, in, nil)
	if s.activeUnknown(zone) {
		if err := s.Know(zone, sd(in), nil, false); err != nil {
			t.Fatal(err)
		}
	}
}

// knownAs has the store keep in as the zone's copy and its active serial,
// known, in one write. Note and then Know would take the zone through a
// freeze on the way ("the active serial is not known"), which tells the
// signer a hold and lets it go again from goroutines of their own.
func knownAs(t *testing.T, s *InstructionStore, zone string, in *Instructions) {
	t.Helper()
	if err := s.update(zone, func(z *zoneSerials) error {
		z.Copy = sd(in)
		z.Active, z.Enforced = &heldSerial{SerialDigest: sd(in), Reading: in, Since: time.Now()}, true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func status(t *testing.T, s *InstructionStore, zone string) *InstructionsStatus {
	t.Helper()
	st := s.Status(zone)
	if st == nil {
		t.Fatalf("no serials kept for %s", zone)
	}
	return st
}

func serialOf(p *SerialDigest) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprint(p.Serial)
}

func TestANewerSerialIsHeldAndBecomesNewest(t *testing.T) {
	s := newStore(t)
	noteKnown(t, s, storeZone, at(t, 7, "alpha,beta"))
	enforced(t, s, storeZone)
	eight := at(t, 8, "alpha")
	noteKnown(t, s, storeZone, eight)
	st := status(t, s, storeZone)
	if st.Active.Serial != 7 || *st.Newest != sd(eight) || st.Phase != PhaseAgreeing {
		t.Errorf("active %s newest %s phase %s; want 7, 8, agreeing", serialOf(st.Active), serialOf(st.Newest), st.Phase)
	}
}

func TestALowerSerialIsNotAdopted(t *testing.T) {
	s := newStore(t)
	noteKnown(t, s, storeZone, at(t, 8, "alpha,beta"))
	noteKnown(t, s, storeZone, at(t, 7, "alpha"))
	st := status(t, s, storeZone)
	if st.Active.Serial != 8 || st.Newest.Serial != 8 || st.Copy.Serial != 7 || st.Phase != PhaseSteady {
		t.Errorf("active %s newest %s copy %d phase %s; want 8, 8, 7, steady", serialOf(st.Active), serialOf(st.Newest), st.Copy.Serial, st.Phase)
	}
	// 2^31 above is RFC 1982's undefined half: not newer either.
	noteKnown(t, s, storeZone, at(t, 8+1<<31, "alpha"))
	if st := status(t, s, storeZone); st.Active.Serial != 8 {
		t.Errorf("a serial 2^31 above was adopted: active %d", st.Active.Serial)
	}
}

func TestTheSameSerialWithAnotherDigestIsAConflict(t *testing.T) {
	s := newStore(t)
	first, second := at(t, 7, "alpha,beta"), at(t, 7, "alpha")
	noteKnown(t, s, storeZone, first)
	noteKnown(t, s, storeZone, second)
	st := status(t, s, storeZone)
	want := fmt.Sprintf("serial 7 with two digests (%s, %s)", first.Digest(), second.Digest())
	if st.Phase != PhaseOwnerError || st.OwnerError != want || st.Active.Digest != first.Digest() {
		t.Errorf("phase %s, error %q, active %s; want an owner error %q, active the first", st.Phase, st.OwnerError, st.Active, want)
	}
}

func TestAConflictLastsUntilAHigherSerial(t *testing.T) {
	s := newStore(t)
	first := at(t, 7, "alpha,beta")
	noteKnown(t, s, storeZone, first)
	noteKnown(t, s, storeZone, at(t, 7, "alpha"))
	noteKnown(t, s, storeZone, first) // reverted at the same serial
	if st := status(t, s, storeZone); st.Phase != PhaseOwnerError {
		t.Fatalf("the contents reverted at the same serial ended the owner error: phase %s", st.Phase)
	}
	noteKnown(t, s, storeZone, at(t, 8, "alpha"))
	if st := status(t, s, storeZone); st.Phase != PhaseAgreeing || st.Agreeing == nil || st.Agreeing.Serial != 8 || st.OwnerError != "" {
		t.Errorf("after serial 8: phase %s agreeing %s error %q", st.Phase, serialOf(st.Agreeing), st.OwnerError)
	}
}

func TestACopyWithoutAReadingChangesNothingHeld(t *testing.T) {
	s := newStore(t)
	seven := at(t, 7, "alpha,beta")
	noteKnown(t, s, storeZone, seven)
	s.Note(storeZone, nil, errTwoHsyncparams)
	st := status(t, s, storeZone)
	if *st.Active != sd(seven) || st.CopyError != "two HSYNCPARAM records" || st.OwnerError != "two HSYNCPARAM records" {
		t.Errorf("active %s copy error %q owner error %q", st.Active, st.CopyError, st.OwnerError)
	}
}

func TestAChangeAtSerialZeroIsAConflict(t *testing.T) {
	s := newStore(t)
	noteKnown(t, s, storeZone, readOf(t, withParam(`serial="0" servers="alpha,beta"`)...))
	noteKnown(t, s, storeZone, readOf(t, withParam(`serial="0" servers="alpha"`)...))
	st := status(t, s, storeZone)
	if st.Phase != PhaseOwnerError || !strings.HasPrefix(st.OwnerError, "serial 0 with two digests") {
		t.Errorf("phase %s error %q; want the serial-0 change an owner error", st.Phase, st.OwnerError)
	}
}

// A copy with no reading (#306, #308) is an owner error the store notes:
// after a held serial the zone holds at it; at a first load nothing is
// held, and no instructions are acted on, until a copy that reads.
func TestACopyWithNoReadingIsAnOwnerError(t *testing.T) {
	noParam := apexOf(t, instrBase[:3]...)
	noSerial := apexOf(t, append(slices.Clone(instrBase[:3]), `3600 IN HSYNCPARAM servers="alpha,beta"`)...)
	for _, c := range []struct {
		name string
		apex *tdns.OwnerData
		want string
	}{
		{"HSYNC3 without HSYNCPARAM", noParam, "HSYNC3 without HSYNCPARAM"},
		{"HSYNCPARAM without serial=", noSerial, "HSYNCPARAM without serial="},
	} {
		in, err := ReadInstructions(c.apex)
		s := newStore(t)
		noteKnown(t, s, storeZone, at(t, 7, "alpha,beta"))
		s.Note(storeZone, in, err)
		if st := status(t, s, storeZone); st.Phase != PhaseOwnerError || st.Active.Serial != 7 || st.OwnerError != c.want {
			t.Errorf("%s after serial 7: phase %s active %s error %q", c.name, st.Phase, serialOf(st.Active), st.OwnerError)
		}
		first := newStore(t)
		first.Note(storeZone, in, err)
		if st := status(t, first, storeZone); st.Phase != PhaseOwnerError || st.Active != nil || st.OwnerError != c.want {
			t.Errorf("%s at a first load: phase %s active %s error %q", c.name, st.Phase, serialOf(st.Active), st.OwnerError)
		}
		// The first copy that reads ends it.
		noteKnown(t, first, storeZone, at(t, 1, "beta"))
		if st := status(t, first, storeZone); st.Phase != PhaseSteady || st.Active == nil || st.Active.Serial != 1 {
			t.Errorf("%s, then serial 1: phase %s active %s error %q", c.name, st.Phase, serialOf(st.Active), st.OwnerError)
		}
	}
}

func TestBothRecordsDroppedWithTwoProvidersIsAnOwnerError(t *testing.T) {
	s := newStore(t)
	noteKnown(t, s, storeZone, at(t, 7, "alpha,beta"))
	noteKnown(t, s, storeZone, nil)
	st := status(t, s, storeZone)
	if st.Phase != PhaseOwnerError || !strings.Contains(st.OwnerError, "lists 2 providers") || st.Active.Serial != 7 {
		t.Errorf("phase %s error %q active %s", st.Phase, st.OwnerError, serialOf(st.Active))
	}
}

func TestTheEndOfMultiProviderServiceEndsTheSerials(t *testing.T) {
	_, hdb := storeDB(t)
	s := loadStore(t, hdb)
	noteKnown(t, s, storeZone, readOf(t, instrBase[0], `3600 IN HSYNCPARAM serial="7" servers="alpha" signers="alpha"`))
	noteKnown(t, s, storeZone, nil)
	if st := s.Status(storeZone); st != nil {
		t.Errorf("one provider, both records dropped: still kept, %s", st.Line())
	}
	if st := loadStore(t, hdb).Status(storeZone); st != nil {
		t.Errorf("the serials are still on disk: %s", st.Line())
	}
}

// heldStore is a zone whose active serial is enforced at 7, with 8, 9 and
// 10 held above it.
func heldStore(t *testing.T) (*InstructionStore, []*Instructions) {
	t.Helper()
	s := newStore(t)
	var ins []*Instructions
	for i, auditors := range []string{"alpha,beta", "alpha", "beta", "alpha,beta,gamma"} {
		in := at(t, uint32(7+i), auditors)
		ins = append(ins, in)
		noteKnown(t, s, storeZone, in)
		if i == 0 {
			enforced(t, s, storeZone)
		}
	}
	return s, ins
}

func TestActivateNeedsAHeldSerialAboveTheActive(t *testing.T) {
	s, ins := heldStore(t)
	for name, thaw := range map[string]Thaw{
		"a serial not held":        {From: sd(ins[0]), To: sd(at(t, 11, "alpha"))},
		"another digest":           {From: sd(ins[0]), To: SerialDigest{Serial: 8, Digest: ins[2].Digest()}},
		"the active serial itself": {From: sd(ins[0]), To: sd(ins[0])},
		"a from-serial not held":   {From: sd(at(t, 6, "alpha")), To: sd(ins[1])},
	} {
		if err := s.Activate(storeZone, thaw); err == nil {
			t.Errorf("%s: activated", name)
		}
	}
	if st := status(t, s, storeZone); st.Active.Serial != 7 || st.Newest.Serial != 10 {
		t.Errorf("a refused activation changed the serials: active %s newest %s", serialOf(st.Active), serialOf(st.Newest))
	}
}

func TestActivateRefusesARefusedSerial(t *testing.T) {
	s, ins := heldStore(t)
	if err := s.update(storeZone, func(z *zoneSerials) error {
		z.held(8).Refused = []Refusal{{Code: RefusedRecordWithRoleRemoved, Reason: "removes the record of agent.beta.example., which has a role under 7"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a refused serial: %v", err)
	}
}

func TestActivateKeepsTheFromSerialUntilDone(t *testing.T) {
	s, ins := heldStore(t)
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err != nil {
		t.Fatal(err)
	}
	st := status(t, s, storeZone)
	if st.Active.Serial != 8 || st.From == nil || *st.From != sd(ins[0]) || st.Phase != PhaseReconciling || !st.Enforced {
		t.Fatalf("after the thaw: active %s from %s phase %s enforced %v", serialOf(st.Active), serialOf(st.From), st.Phase, st.Enforced)
	}
	if err := s.Done(storeZone); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, storeZone); st.From != nil || st.Phase != PhaseAgreeing {
		t.Errorf("after done: from %s phase %s; want none, agreeing on the serials still held", serialOf(st.From), st.Phase)
	}
}

func TestAtTheThawTheStepsSetsAreTheFromSerials(t *testing.T) {
	s, ins := heldStore(t)
	sets := json.RawMessage(`{"servers":[["alpha","agent.alpha.example."],["beta","agent.beta.example."]]}`)
	if err := s.update(storeZone, func(z *zoneSerials) error { z.Step, z.Sets = 3, sets; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	z := s.zones[storeZone]
	step, got := z.Step, string(z.Sets)
	s.mu.Unlock()
	if step != 0 || got != string(sets) {
		t.Errorf("step %d sets %s; want step 0 and the sets held", step, got)
	}
}

func TestANewerSerialDuringReconcilingIsHeldAsNewest(t *testing.T) {
	s := newStore(t)
	seven, eight, nine := at(t, 7, "alpha,beta"), at(t, 8, "alpha"), at(t, 9, "beta")
	noteKnown(t, s, storeZone, seven)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, eight)
	if err := s.Activate(storeZone, Thaw{From: sd(seven), To: sd(eight)}); err != nil {
		t.Fatal(err)
	}
	noteKnown(t, s, storeZone, nine)
	st := status(t, s, storeZone)
	if st.Active.Serial != 8 || *st.Newest != sd(nine) || st.Phase != PhaseReconciling {
		t.Errorf("active %s newest %s phase %s; want 8, 9, reconciling", serialOf(st.Active), serialOf(st.Newest), st.Phase)
	}
}

func withRemoval(t *testing.T, s *InstructionStore, step int) {
	t.Helper()
	if err := s.update(storeZone, func(z *zoneSerials) error {
		z.Step = step
		z.Removals = []Removal{{Label: "beta", Identity: "agent.beta.example.", Step: step, NSNames: []string{"ns1.beta.example."}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDoneOnTheLeadersStampDropsTheRemovalsHeld(t *testing.T) {
	path, hdb := storeDB(t)
	s := loadStore(t, hdb)
	noteKnown(t, s, storeZone, at(t, 7, "alpha,beta"))
	withRemoval(t, s, 2)
	if st := status(t, loadStore(t, openStoreDB(t, path)), storeZone); len(st.Removals) != 1 || st.Removals[0].NSNames[0] != "ns1.beta.example." {
		t.Fatalf("the removal is not on disk: %v", st.Removals)
	}
	if err := s.Done(storeZone); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, storeZone); len(st.Removals) != 0 || st.Phase != PhaseSteady {
		t.Errorf("after done: removals %v phase %s", st.Removals, st.Phase)
	}
	if st := status(t, loadStore(t, openStoreDB(t, path)), storeZone); len(st.Removals) != 0 {
		t.Errorf("after done, on disk: removals %v", st.Removals)
	}
}

func TestAThawDropsWhatAnAgentThatMissedTheEndHolds(t *testing.T) {
	s, ins := heldStore(t)
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err != nil {
		t.Fatal(err)
	}
	withRemoval(t, s, 4) // the end of 7 -> 8 never reached this agent
	if err := s.Activate(storeZone, Thaw{From: sd(ins[1]), To: sd(ins[2])}); err != nil {
		t.Fatal(err)
	}
	st := status(t, s, storeZone)
	if st.Active.Serial != 9 || *st.From != sd(ins[1]) || len(st.Removals) != 0 {
		t.Errorf("active %s from %s removals %v; want 9, from 8, none", serialOf(st.Active), serialOf(st.From), st.Removals)
	}
}

func TestAMemberBehindTheFromMovesStraightToTheTarget(t *testing.T) {
	s, ins := heldStore(t) // active 7; the thaw is from 8 to 9
	if err := s.Activate(storeZone, Thaw{From: sd(ins[1]), To: sd(ins[2])}); err != nil {
		t.Fatal(err)
	}
	st := status(t, s, storeZone)
	if st.Active.Serial != 9 || *st.From != sd(ins[1]) || st.Newest.Serial != 10 {
		t.Errorf("active %s from %s newest %s; want 9, the thaw's from 8, 10", serialOf(st.Active), serialOf(st.From), serialOf(st.Newest))
	}
}

func TestASerialHeldAboveActiveIsKeptWhenANewerOneArrives(t *testing.T) {
	s, ins := heldStore(t)
	s.mu.Lock()
	held := len(s.zones[storeZone].Held)
	s.mu.Unlock()
	if held != 3 {
		t.Fatalf("held %d serials above the active one, want 8, 9 and 10", held)
	}
	// a thaw to 8 that comes after 9 and 10 were loaded still finds 8
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err != nil {
		t.Errorf("a thaw to 8 with 10 loaded: %v", err)
	}
}

func TestSerialsAtOrBelowTheNewActiveAreDropped(t *testing.T) {
	s, ins := heldStore(t)
	if err := s.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[2])}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	var held []uint32
	for _, h := range s.zones[storeZone].Held {
		held = append(held, h.Serial)
	}
	s.mu.Unlock()
	if !slices.Equal(held, []uint32{10}) {
		t.Errorf("held %v after a thaw to 9, want [10]", held)
	}
}

func TestTheLastThawIsKept(t *testing.T) {
	path, hdb := storeDB(t)
	s := loadStore(t, hdb)
	seven, eight := at(t, 7, "alpha,beta"), at(t, 8, "alpha")
	noteKnown(t, s, storeZone, seven)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, eight)
	thaw := Thaw{From: sd(seven), To: sd(eight)}
	if err := s.Activate(storeZone, thaw); err != nil {
		t.Fatal(err)
	}
	if err := s.Done(storeZone); err != nil {
		t.Fatal(err)
	}
	if st := status(t, loadStore(t, openStoreDB(t, path)), storeZone); st.LastThaw == nil || *st.LastThaw != thaw {
		t.Errorf("last thaw %v, want %v", st.LastThaw, thaw)
	}
}

func TestTheStoreSurvivesARestart(t *testing.T) {
	path, hdb := storeDB(t)
	s := loadStore(t, hdb)
	seven, eight, nine := at(t, 7, "alpha,beta"), at(t, 8, "alpha"), at(t, 9, "beta")
	noteKnown(t, s, storeZone, seven)
	enforced(t, s, storeZone)
	noteKnown(t, s, storeZone, eight)
	noteKnown(t, s, storeZone, nine)
	if err := s.Activate(storeZone, Thaw{From: sd(seven), To: sd(eight)}); err != nil {
		t.Fatal(err)
	}
	withRemoval(t, s, 1)
	before := status(t, s, storeZone)
	after := status(t, loadStore(t, openStoreDB(t, path)), storeZone)
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Errorf("after a restart:\n%s\nbefore it:\n%s", a, b)
	}
	// and what is held is still held: the next thaw finds 9
	if err := loadStore(t, openStoreDB(t, path)).Activate(storeZone, Thaw{From: sd(eight), To: sd(nine)}); err != nil {
		t.Errorf("a thaw to the serial held before the restart: %v", err)
	}
}

// The agent's and the auditor's initialisation read the stored serials:
// a zone's status shows them before its first load, and the first load of
// the same copy changes nothing.
func TestTheStoreIsReadBeforeTheFirstLoad(t *testing.T) {
	for _, c := range []struct {
		role string
		init func(*Config, *MultiProviderConf) error
	}{
		{"agent", (*Config).initMPAgent},
		{"auditor", (*Config).initMPAuditor},
	} {
		t.Run(c.role, func(t *testing.T) {
			path, hdb := storeDB(t)
			seven := at(t, 7, "alpha,beta")
			noteKnown(t, loadStore(t, hdb), storeZone, seven)

			conf := &Config{Config: &tdns.Config{}}
			conf.Config.Internal.KeyDB = openStoreDB(t, path).KeyDB
			conf.Config.Internal.StopCh = make(chan struct{})
			t.Cleanup(func() { close(conf.Config.Internal.StopCh) })
			mp := &MultiProviderConf{Role: c.role, Identity: c.role + ".store.example."}
			conf.SetMpConfig(mp)
			if err := c.init(conf, mp); err != nil {
				t.Fatalf("init: %v", err)
			}
			st := status(t, conf.InternalMp.Instructions, storeZone)
			if *st.Active != sd(seven) {
				t.Fatalf("before the first load: active %s, want %s", st.Active, sd(seven))
			}
			noteKnown(t, conf.InternalMp.Instructions, storeZone, seven)
			if again := status(t, conf.InternalMp.Instructions, storeZone); *again.Active != *st.Active || again.Phase != PhaseSteady {
				t.Errorf("the first load of the same copy: %s", again.Line())
			}
		})
	}
}

func TestAZoneThatLeavesTheConfigLosesItsSerials(t *testing.T) {
	path, hdb := storeDB(t)
	s := loadStore(t, hdb)
	kept := instrTestZone(t, "kept.example.", instrBase...)
	noteKnown(t, s, kept.ZoneName, at(t, 7, "alpha,beta"))
	noteKnown(t, s, "gone.example.", at(t, 7, "alpha,beta"))

	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.Instructions = s
	conf.RegisterMPRefreshCallbacks() // at the start, and after a zone reload

	if s.Status(kept.ZoneName) == nil {
		t.Error("a configured zone lost its serials")
	}
	if s.Status("gone.example.") != nil || loadStore(t, openStoreDB(t, path)).Status("gone.example.") != nil {
		t.Error("a zone that left the configuration kept its serials")
	}
}

func TestForgetClearsASteadyZonesSerials(t *testing.T) {
	path, hdb := storeDB(t)
	s := loadStore(t, hdb)
	noteKnown(t, s, storeZone, at(t, 9, "alpha,beta"))
	if err := s.Forget(storeZone); err != nil {
		t.Fatal(err)
	}
	if s.Status(storeZone) != nil || loadStore(t, openStoreDB(t, path)).Status(storeZone) != nil {
		t.Fatal("the serials are still kept")
	}
	// The owner re-created the zone at a lower serial: it is adopted now.
	noteKnown(t, s, storeZone, at(t, 1, "alpha"))
	if st := status(t, s, storeZone); st.Active.Serial != 1 {
		t.Errorf("after forget, a lower serial: active %s", serialOf(st.Active))
	}
}

func TestForgetIsRefusedForAZoneThatIsNotSteady(t *testing.T) {
	agreeing, _ := heldStore(t)
	reconciling, ins := heldStore(t)
	if err := reconciling.Activate(storeZone, Thaw{From: sd(ins[0]), To: sd(ins[1])}); err != nil {
		t.Fatal(err)
	}
	removal := newStore(t)
	noteKnown(t, removal, storeZone, at(t, 7, "alpha,beta"))
	withRemoval(t, removal, 2)
	ownerError := newStore(t)
	noteKnown(t, ownerError, storeZone, at(t, 7, "alpha,beta"))
	noteKnown(t, ownerError, storeZone, at(t, 7, "alpha"))
	for name, s := range map[string]*InstructionStore{
		"agreeing": agreeing, "reconciling": reconciling, "a removal under way": removal, "an owner error": ownerError,
	} {
		if err := s.Forget(storeZone); !errors.Is(err, errNotSteady) {
			t.Errorf("%s: forget %v, want refused", name, err)
		}
		if s.Status(storeZone) == nil {
			t.Errorf("%s: the serials are gone", name)
		}
	}
}

// A zone's first copy is held, and no active serial is known until the
// restart rule makes one known (S9): a newer copy is held too, and the
// serials above the one made known are held above it.
func TestAFirstCopyIsHeldWithNoActiveSerialKnown(t *testing.T) {
	s := newStore(t)
	seven, eight := at(t, 7, "alpha,beta"), at(t, 8, "alpha")
	s.Note(storeZone, seven, nil)
	if st := status(t, s, storeZone); st.Active != nil || st.Newest == nil || st.Newest.Serial != 7 || st.Phase != PhaseNotKnown {
		t.Fatalf("the first copy: active %s newest %s phase %q; want none, 7, %q", serialOf(st.Active), serialOf(st.Newest), st.Phase, PhaseNotKnown)
	}
	s.Note(storeZone, eight, nil)
	if err := s.Know(storeZone, sd(seven), nil, false); err != nil {
		t.Fatal(err)
	}
	if st := status(t, s, storeZone); st.Active.Serial != 7 || st.Newest.Serial != 8 || !st.Enforced || st.Agreeing == nil {
		t.Errorf("made known: active %s newest %s enforced %v agreeing %s; want 7, 8, enforced, agreeing on 8", serialOf(st.Active), serialOf(st.Newest), st.Enforced, serialOf(st.Agreeing))
	}
	if err := s.Know(storeZone, sd(eight), nil, false); err == nil {
		t.Error("a second Know moved a known active serial")
	}
}

// A record kept before S7 followed the copy, and counts as none when the
// store loads: its serial is held, none active, and the status says so.
func TestARecordKeptBeforeTheThawCountsAsNone(t *testing.T) {
	_, hdb := storeDB(t)
	s := loadStore(t, hdb)
	seven, eight := at(t, 7, "alpha,beta"), at(t, 8, "alpha")
	if err := s.update(storeZone, func(z *zoneSerials) error {
		z.Active = &heldSerial{SerialDigest: sd(seven), Reading: seven, Since: time.Now()}
		z.Held = []heldSerial{{SerialDigest: sd(eight), Reading: eight, Since: time.Now(), Refused: []Refusal{{Code: "x"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s = loadStore(t, hdb)
	st := status(t, s, storeZone)
	if st.Active != nil || st.Phase != PhaseNotKnown || st.Newest.Serial != 8 || len(st.Refused) != 0 {
		t.Fatalf("after the load: active %s newest %s phase %q refused %v", serialOf(st.Active), serialOf(st.Newest), st.Phase, st.Refused)
	}
	if s.readingAt(storeZone, sd(seven)) == nil {
		t.Error("the record's serial is not held")
	}
	if line := st.Line(); !strings.HasSuffix(line, "; "+PhaseNotKnown) {
		t.Errorf("status %q does not say the active serial is not known", line)
	}
}

// A serial fetched from a member is held in order among the newer serials,
// judged against the active serial; one held already is not kept twice, one
// held with another digest is refused, and one at or below the active
// serial is not kept.
func TestAFetchedSerialIsHeldInOrder(t *testing.T) {
	s := newStore(t)
	seven, eight, nine := at(t, 7, "alpha,beta"), at(t, 8, "alpha"), at(t, 9, "beta")
	noteKnown(t, s, storeZone, seven)
	noteKnown(t, s, storeZone, nine)
	if err := s.Hold(storeZone, eight); err != nil {
		t.Fatal(err)
	}
	st := status(t, s, storeZone)
	if st.Newest.Serial != 9 || st.Agreeing == nil || st.Agreeing.Serial != 9 || s.readingAt(storeZone, sd(eight)) == nil {
		t.Fatalf("after holding 8: %+v", st)
	}
	if err := s.Hold(storeZone, eight); !errors.Is(err, errHeldAlready) {
		t.Errorf("8 again: %v", err)
	}
	if err := s.Hold(storeZone, at(t, 8, "beta")); err == nil {
		t.Error("8 with another digest is kept")
	}
	if err := s.Hold(storeZone, at(t, 6, "alpha")); err == nil {
		t.Error("6, below the active serial, is kept")
	}
	// a member at 7 that holds the thaw's pair, 8 to 9, moves straight
	if err := s.Activate(storeZone, Thaw{From: sd(eight), To: sd(nine)}); err != nil {
		t.Errorf("moving straight from 7 by the thaw 8 to 9: %v", err)
	}
}

func TestStatusShowsActiveNewestCopyAndOwnerError(t *testing.T) {
	s := newStore(t)
	seven, eight := at(t, 7, "alpha,beta"), at(t, 8, "alpha")
	if got := s.Status(storeZone).Line(); got != "none kept" {
		t.Errorf("nothing kept: %q", got)
	}
	noteKnown(t, s, storeZone, seven)
	if got, want := status(t, s, storeZone).Line(), fmt.Sprintf("active 7 (%s), copy 7", seven.Digest()); got != want {
		t.Errorf("steady:\n got %q\nwant %q", got, want)
	}
	noteKnown(t, s, storeZone, eight)
	if got, want := status(t, s, storeZone).Line(), fmt.Sprintf("active 7 (%s), newest 8 (%s), copy 8; agreeing", seven.Digest(), eight.Digest()); got != want {
		t.Errorf("a newer serial held:\n got %q\nwant %q", got, want)
	}
	other := at(t, 8, "beta")
	noteKnown(t, s, storeZone, other)
	if got, want := status(t, s, storeZone).Line(), fmt.Sprintf("held: owner error: serial 8 with two digests (%s, %s)", eight.Digest(), other.Digest()); got != want {
		t.Errorf("an owner error:\n got %q\nwant %q", got, want)
	}

	// mplist: the active serial, ->newest, or ERR
	var info MPZoneInfo
	s.fillMPZoneInfo(storeZone, &info)
	if info.Active.Serial != 7 || info.Newest.Serial != 8 || !strings.HasPrefix(info.OwnerError, "serial 8 with two digests") {
		t.Errorf("mplist: active %s newest %s owner error %q", serialOf(info.Active), serialOf(info.Newest), info.OwnerError)
	}
}

// The auditor keeps serials as an agent does: its refresh callback notes
// every copy, and its mplist shows them.
func TestTheAuditorKeepsSerialsToo(t *testing.T) {
	_, hdb := storeDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = hdb.KeyDB
	conf.Config.Internal.StopCh = make(chan struct{})
	t.Cleanup(func() { close(conf.Config.Internal.StopCh) })
	mp := &MultiProviderConf{Role: "auditor", Identity: "auditor.store.example."}
	conf.SetMpConfig(mp)
	if err := conf.initMPAuditor(mp); err != nil {
		t.Fatalf("initMPAuditor: %v", err)
	}
	mpzd := instrTestZone(t, "audited.example.", instrBase...)
	conf.noteInstructions(mpzd)
	st := status(t, conf.InternalMp.Instructions, mpzd.ZoneName)
	if st.Newest == nil || st.Newest.Serial != 7 || st.Newest.Digest != digestOf(t, instrBase...) || st.Active != nil {
		t.Errorf("the auditor keeps %s", st.Line()) // its first copy, no active serial known yet (S9)
	}
	if loadStore(t, hdb).Status(mpzd.ZoneName) == nil {
		t.Error("the auditor's serials are not on disk")
	}
}
