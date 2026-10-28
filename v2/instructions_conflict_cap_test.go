package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// sevens is n readings at serial 7 with n digests: what an owner who edits
// in place without raising the serial leaves, one copy after another.
func sevens(t *testing.T, n int) (ins []*Instructions, digests []string) {
	t.Helper()
	for _, signers := range []string{"alpha", "beta", "alpha,beta"} {
		for _, auditors := range []string{"alpha", "beta", "alpha,beta"} {
			in := readOf(t, withParam(fmt.Sprintf(`serial="7" servers="alpha,beta" signers="%s" auditors="%s"`, signers, auditors))...)
			if slices.Contains(digests, in.Digest()) {
				t.Fatalf("two readings with digest %s", in.Digest())
			}
			ins, digests = append(ins, in), append(digests, in.Digest())
			if len(ins) == n {
				return ins, digests
			}
		}
	}
	t.Fatalf("fewer than %d readings", n)
	return nil, nil
}

// A conflict mark keeps the last four digests seen at its serial. A fifth
// drops the oldest and counts it, the owner error says "… and N more", and
// the count is kept on disk. A digest the mark holds adds nothing (#307).
func TestAFifthDigestDropsTheOldestAndCountsIt(t *testing.T) {
	_, hdb := storeDB(t)
	s := loadStore(t, hdb)
	ins, d := sevens(t, 7)
	for _, in := range ins[:4] {
		s.Note(storeZone, in, nil)
	}
	want := fmt.Sprintf("serial 7 with 4 digests (%s)", strings.Join(d[:4], ", "))
	if got := status(t, s, storeZone).OwnerError; got != want {
		t.Fatalf("four digests: %q, want %q", got, want)
	}

	s.Note(storeZone, ins[4], nil)
	want = fmt.Sprintf("serial 7 with 5 digests (%s, … and 1 more)", strings.Join(d[1:5], ", "))
	if got := status(t, s, storeZone).OwnerError; got != want {
		t.Errorf("a fifth digest: %q, want %q", got, want)
	}
	s.Note(storeZone, ins[3], nil) // one the mark holds
	if got := status(t, s, storeZone).OwnerError; got != want {
		t.Errorf("a digest the mark holds, again: %q, want %q", got, want)
	}

	s.Note(storeZone, ins[5], nil)
	s = loadStore(t, hdb) // the mark as the disk keeps it
	s.Note(storeZone, ins[6], nil)
	want = fmt.Sprintf("serial 7 with 7 digests (%s, … and 3 more)", strings.Join(d[3:7], ", "))
	if got := status(t, s, storeZone).OwnerError; got != want {
		t.Errorf("after a reload and a seventh digest: %q, want %q", got, want)
	}
	if line := status(t, s, storeZone).Line(); !strings.HasSuffix(line, "… and 3 more); not enforced") {
		t.Errorf("the status line %q does not end with the count", line)
	}

	s.Note(storeZone, at(t, 8, "alpha"), nil)
	z := s.zones[storeZone]
	if z.OwnerError != "" || len(z.Conflict) > 0 || z.ConflictMore != 0 {
		t.Errorf("serial 8 left the mark: error %q, conflict %v, %d more", z.OwnerError, z.Conflict, z.ConflictMore)
	}
}

// The mark the agents tell each other keeps four digests too, and telling
// the same ones again changes nothing.
func TestAToldConflictKeepsFourDigestsAndCountsTheRest(t *testing.T) {
	s := newStore(t)
	s.Note(storeZone, at(t, 7, "alpha"), nil)
	told := []string{"d1", "d2", "d3", "d4", "d5", "d6"}
	if !s.noteToldConflict(storeZone, 7, told) {
		t.Fatal("six digests told at the active serial changed nothing")
	}
	want := "serial 7 told with 6 digests (d3, d4, d5, d6, … and 2 more)"
	if got := status(t, s, storeZone).OwnerError; got != want {
		t.Errorf("six digests told: %q, want %q", got, want)
	}
	if s.noteToldConflict(storeZone, 7, told[2:]) {
		t.Error("the same digests told again changed the mark")
	}
}
