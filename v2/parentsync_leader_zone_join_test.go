/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"
)

// zoneJoiner is a member of a three-member zone that has never called an
// election itself, with the election it will join.
func zoneJoiner(t *testing.T) (*LeaderElectionManager, *LeaderElection, ZoneName) {
	t.Helper()
	const zone = ZoneName("zone.example.")
	lem := NewLeaderElectionManager("c.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.SetConfiguredPeersFunc(func(ZoneName) int { return 2 })
	le := lem.getOrCreate(zone)
	t.Cleanup(func() {
		le.mu.Lock()
		for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer} {
			if tm != nil {
				tm.Stop()
			}
		}
		le.mu.Unlock()
	})
	return lem, le, zone
}

// confirmed reports whether the member has determined a winner: it then holds
// a confirm of its own.
func confirmed(le *LeaderElection, id AgentId) bool {
	le.mu.Lock()
	defer le.mu.Unlock()
	_, ok := le.Confirms[id]
	return ok
}

func waitConfirmed(t *testing.T, le *LeaderElection, id AgentId) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !confirmed(le, id) {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not determine a winner with every vote in", id)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A member that joins a per-zone election counts against the zone's peers,
// though it has never called an election itself. It used to count against
// none, and determined the winner at the first vote it received (#129).
func TestAZoneMemberThatJoinsWaitsForEveryVote(t *testing.T) {
	lem, le, zone := zoneJoiner(t)

	lem.handleCall(zone, "a.example.", map[string][]string{"_term": {"1"}})
	le.mu.Lock()
	expected := le.ExpectedPeers
	le.mu.Unlock()
	if expected != 2 {
		t.Fatalf("after joining, the member counts against %d peers, want the zone's 2", expected)
	}

	lem.handleVote(zone, "a.example.", map[string][]string{"_term": {"1"}, "_vote": {"7"}})
	time.Sleep(50 * time.Millisecond)
	if confirmed(le, "c.example.") {
		t.Fatalf("the member determined a winner with two votes of three")
	}

	lem.handleVote(zone, "b.example.", map[string][]string{"_term": {"1"}, "_vote": {"9"}})
	waitConfirmed(t, le, "c.example.")
}

// The same when a vote was kept from before the CALL: the kept vote and the
// member's own are two of three, and joining does not settle it.
func TestAZoneMemberThatJoinsWithAnEarlyVoteWaitsForEveryVote(t *testing.T) {
	lem, le, zone := zoneJoiner(t)

	lem.handleVote(zone, "b.example.", map[string][]string{"_term": {"1"}, "_vote": {"9"}})
	lem.handleCall(zone, "a.example.", map[string][]string{"_term": {"1"}})
	time.Sleep(50 * time.Millisecond)
	if confirmed(le, "c.example.") {
		t.Fatalf("the member determined a winner on joining, with two votes of three")
	}

	lem.handleVote(zone, "a.example.", map[string][]string{"_term": {"1"}, "_vote": {"7"}})
	waitConfirmed(t, le, "c.example.")
}
