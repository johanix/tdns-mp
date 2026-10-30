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
		{"a move into signers=", `3600 IN HSYNCPARAM serial="8" servers="alpha,beta" signers="alpha,beta"`, "moves"}, // S18b
		{"a role taken away", `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`, "takes a role"},       // S17b
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

// An owner error is still held: after the zone followed a not-built change
// to 8, the owner's edit of 8 without a raised serial is not acted on.
func TestAnOwnerErrorIsHeldAfterTheNotBuiltFallback(t *testing.T) {
	s := newStore(t)
	notBuiltFrom(t, s)
	followed := readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha"`)
	s.Note(storeZone, followed, nil)
	s.Note(storeZone, readOf(t, instrBase[0], instrBase[1], `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha" parentsync="agent"`), nil)
	st := status(t, s, storeZone)
	if st.OwnerError == "" || !strings.HasPrefix(st.Line(), "held: owner error: serial 8 with two digests") {
		t.Fatalf("the edit at 8 is no owner error: %s", st.Line())
	}
	if st.Active == nil || st.Active.Serial != 8 || st.Active.Digest != followed.Digest() {
		t.Errorf("the active serial moved with the edit: %+v", st.Active)
	}
}
