/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// waitLeader polls get until it names want, for at most d.
func waitLeader(t *testing.T, get func() (AgentId, bool), want AgentId, d time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		if leader, ok := get(); ok && leader == want {
			return time.Since(start)
		}
		if time.Since(start) > d {
			t.Fatalf("no leader %s within %v (the confirm timer is 5 s)", want, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A two-member group election, seen from the initiator. The peer confirms the
// moment it holds both votes, so its CONFIRM can be handled before its VOTE.
// The initiator's own confirm then completes the set, and the election must
// finalize there, not when the confirm timer fires five seconds later; and it
// must finalize once.
func TestGroupElectionFinalizesWhenOwnConfirmCompletesTheSet(t *testing.T) {
	const group = "0123456789abcdef"
	members := []string{"a.example.", "b.example."}
	zones := []ZoneName{"zone.example."}
	var elected atomic.Int32
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.SetOnLeaderElected(func(ZoneName) error { elected.Add(1); return nil })

	lem.StartGroupElection(group, members, zones)
	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()
	le.mu.Lock()
	term := strconv.FormatUint(le.Term, 10)
	myVote := le.MyVote
	le.mu.Unlock()

	const peerVote = 0
	winner := determineWinner(map[AgentId]uint32{"a.example.": myVote, "b.example.": peerVote})

	// The peer's CONFIRM first, then its VOTE: the order seen on a live run.
	lem.handleGroupConfirm(le, group, "b.example.",
		map[string][]string{"_term": {term}, "_winner": {string(winner)}, "_group": {group}}, members, zones)
	lem.handleGroupVote(le, group, "b.example.",
		map[string][]string{"_term": {term}, "_vote": {strconv.Itoa(peerVote)}, "_group": {group}}, members, zones)

	took := waitLeader(t, func() (AgentId, bool) { return lem.GetGroupLeader(group) }, winner, 2*time.Second)
	t.Logf("elected %s after %v", winner, took)

	time.Sleep(100 * time.Millisecond)
	if got := elected.Load(); winner == "a.example." && got != int32(len(zones)) {
		t.Errorf("onLeaderElected ran %d times, want once per zone (%d)", got, len(zones))
	}
}

// The per-zone election has the same order and the same fix.
func TestZoneElectionFinalizesWhenOwnConfirmCompletesTheSet(t *testing.T) {
	const zone = ZoneName("zone.example.")
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })

	lem.StartElection(zone, 1)
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	term := strconv.FormatUint(le.Term, 10)
	myVote := le.MyVote
	le.mu.Unlock()

	const peerVote = 0
	winner := determineWinner(map[AgentId]uint32{"a.example.": myVote, "b.example.": peerVote})

	lem.handleConfirm(zone, "b.example.", map[string][]string{"_term": {term}, "_winner": {string(winner)}})
	lem.handleVote(zone, "b.example.", map[string][]string{"_term": {term}, "_vote": {strconv.Itoa(peerVote)}})

	took := waitLeader(t, func() (AgentId, bool) { return lem.GetLeader(zone) }, winner, 2*time.Second)
	t.Logf("elected %s after %v", winner, took)
}

// Finalization happens once per term, however many of the paths that can
// reach it do: the last confirm, the own confirm, the confirm timer.
func TestGroupElectionFinalizesOncePerTerm(t *testing.T) {
	const group = "fedcba9876543210"
	members := []string{"a.example.", "b.example."}
	zones := []ZoneName{"zone.example."}
	var elected atomic.Int32
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.SetOnLeaderElected(func(ZoneName) error { elected.Add(1); return nil })

	lem.StartGroupElection(group, members, zones)
	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()
	le.mu.Lock()
	term := le.Term
	le.Confirms["a.example."] = "a.example."
	le.Confirms["b.example."] = "a.example."
	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	le.mu.Unlock()

	lem.finalizeGroupElection(group, term, members, zones)
	lem.finalizeGroupElection(group, term, members, zones)
	time.Sleep(100 * time.Millisecond)
	if got := elected.Load(); got != 1 {
		t.Errorf("onLeaderElected ran %d times for one term, want 1", got)
	}
}
