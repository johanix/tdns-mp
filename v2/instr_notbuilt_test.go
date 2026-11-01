package tdnsmp

import (
	"strings"
	"testing"
)

// notBuiltFrom is the zone's active serial 7 in these tests: alpha and
// beta serve, alpha signs.
func notBuiltFrom(t *testing.T, s *InstructionStore) {
	t.Helper()
	noteKnown(t, s, storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="7" servers="alpha,beta" signers="alpha"`))
}

// A serial refused only for kinds whose steps are not built is followed, as
// before S7: it becomes the active serial, nothing is frozen for it, and the
// status says why.
func TestANotBuiltChangeIsFollowed(t *testing.T) {
	for _, c := range []struct{ name, to, why string }{
		{"a move into signers=", `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha,beta"`, "moves"},                      // S18b
		{"a change of parentsync", `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha" parentsync="agent"`, "parentsync"}, // S20
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			notBuiltFrom(t, s)
			s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], c.to), nil)
			st := status(t, s, storeZone)
			if st.Active == nil || st.Active.Serial != 8 || st.Agreeing != nil || len(st.Refused) != 0 || len(s.frozen(storeZone)) != 0 {
				t.Fatalf("not followed: %s", st.Line())
			}
			if line := st.Line(); !strings.HasPrefix(line, "follows the copy: ") || !strings.Contains(line, c.why) {
				t.Errorf("status: %s", line)
			}
		})
	}
}

// The status says the zone follows the copy only while it does: a newer copy
// that is not followed, accepted or refused, ends the line (CodeRabbit on
// tdns-mp #350).
func TestAFollowedSerialIsNotReportedOnceTheCopyMoves(t *testing.T) {
	for _, c := range []struct{ name, to string }{
		{"accepted", `3600 IN HSYNCPARAM serial="9" servers="alpha,beta" signers="alpha,beta" suffix="x"`},
		{"refused", `3600 IN HSYNCPARAM serial="9" servers="alpha,beta,zulu" signers="alpha,beta"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			notBuiltFrom(t, s)
			s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha,beta"`), nil)
			if st := status(t, s, storeZone); st.Follows == "" {
				t.Fatalf("8 is not followed: %s", st.Line())
			}
			s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], c.to), nil)
			st := status(t, s, storeZone)
			if st.Active == nil || st.Active.Serial != 8 || st.Copy.Serial != 9 {
				t.Fatalf("active %s, copy %d", serialOf(st.Active), st.Copy.Serial)
			}
			if st.Follows != "" || strings.Contains(st.Line(), "follows the copy") {
				t.Errorf("active 8, copy 9, and the status says: %s", st.Line())
			}
		})
	}
}

// An owner error is still held: after the zone followed a not-built change
// to 8, the owner's edit of 8 without a raised serial is not acted on.
func TestAnOwnerErrorIsHeldAfterTheNotBuiltFallback(t *testing.T) {
	s := newStore(t)
	notBuiltFrom(t, s)
	followed := readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha,beta"`)
	s.Note(storeZone, followed, nil)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`), nil)
	st := status(t, s, storeZone)
	if st.OwnerError == "" || !strings.HasPrefix(st.Line(), "held: owner error: serial 8 with two digests") {
		t.Fatalf("the edit at 8 is no owner error: %s", st.Line())
	}
	if st.Active == nil || st.Active.Serial != 8 || st.Active.Digest != followed.Digest() {
		t.Errorf("the active serial moved with the edit: %+v", st.Active)
	}
}

// A removal has its steps (S17b): it leaves the fallback. It is agreed on,
// the zone frozen and the active serial where it was, and nothing says the
// zone follows its copy.
func TestARemovalLeavesTheNotBuiltFallback(t *testing.T) {
	s := newStore(t)
	notBuiltFrom(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 7 || st.Follows != "" || strings.Contains(st.Line(), "follows the copy") {
		t.Fatalf("a removal followed unenforced: %s", st.Line())
	}
	if st.Agreeing == nil || st.Agreeing.Serial != 8 || len(st.Refused) != 0 || len(s.frozen(storeZone)) == 0 {
		t.Errorf("a removal not agreed on: %s", st.Line())
	}
}

// The fallback's rule is by the whole change: a serial that also holds a kind
// still not built has no step for that kind, so it is followed as a whole,
// its removal too, unenforced as before S7. The first serial that is only a
// removal runs the steps.
func TestARemovalWithAKindNotBuiltIsFollowedAsAWhole(t *testing.T) {
	s := newStore(t)
	notBuiltFrom(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha,beta"`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 8 || st.Agreeing != nil || !strings.HasPrefix(st.Line(), "follows the copy: ") {
		t.Fatalf("a removal with a move into signers=: %s", st.Line())
	}
	if refs := judgeTransition(readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="7" servers="alpha,beta" signers="alpha"`),
		readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha,beta"`)); notBuiltOnly(refs) == "" || strings.Contains(notBuiltOnly(refs), "takes a role") {
		t.Errorf("the refusals: %v", refs)
	}
}

// Removing a record that still has a role is a rule of the design, not a step
// missing (S17b leaves it so): refused, and never followed.
func TestRemovingARecordThatStillHasARoleStaysRefused(t *testing.T) {
	s := newStore(t)
	notBuiltFrom(t, s)
	s.Note(storeZone, readOf(t, instrBase[0], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`), nil)
	st := status(t, s, storeZone)
	if st.Active == nil || st.Active.Serial != 7 || st.Agreeing != nil || st.Follows != "" {
		t.Fatalf("a record with a role removed: %s", st.Line())
	}
	if len(st.Refused) == 0 || st.Refused[0].Code != RefusedRecordWithRoleRemoved {
		t.Errorf("the refusal: %v", st.Refused)
	}
}

// The owner's order: the roles first, the record later. With the roles gone,
// removing the record has nothing to carry out, and is agreed on.
func TestARecordRemovedAfterItsRolesIsAgreed(t *testing.T) {
	noRole := readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`)
	gone := readOf(t, instrBase[0], `3600 IN HSYNCPARAM serial="9" servers="alpha" signers="alpha"`)
	if refs := judgeTransition(noRole, gone); len(refs) != 0 {
		t.Errorf("the record of a provider with no role: %v", refs)
	}
}
