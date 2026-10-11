/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"
)

// A member's VOTE can reach another member before the initiator's CALL does:
// the two come from different senders. The vote used to be dropped, the late
// member then never held every vote, and the election waited out the 5 s
// timeout and ran again (#125). It is kept and counted when the CALL comes.
func TestAVoteThatOvertakesTheCallIsCounted(t *testing.T) {
	const group = "0123456789abcdef"
	members := []string{"a.example.", "b.example.", "c.example."}
	zones := []ZoneName{"zone.example."}
	lem := NewLeaderElectionManager("c.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	pgm := NewProviderGroupManager("c.example.")
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: members, VotingMembers: members, Zones: zones}
	lem.SetProviderGroupManager(pgm)

	// At c: b's VOTE for term 1, then a's CALL for it.
	lem.HandleGroupMessage(group, "b.example.", "ELECT-VOTE",
		map[string][]string{"_term": {"1"}, "_vote": {"5"}, "_group": {group}})
	lem.HandleGroupMessage(group, "a.example.", "ELECT-CALL",
		map[string][]string{"_term": {"1"}, "_vote": {"9"}, "_group": {group}})

	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()
	t.Cleanup(func() {
		le.mu.Lock()
		for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer} {
			if tm != nil {
				tm.Stop()
			}
		}
		le.mu.Unlock()
	})
	le.mu.Lock()
	votes := len(le.Votes)
	winner := determineWinner(map[AgentId]uint32{"a.example.": 9, "b.example.": 5, "c.example.": le.MyVote})
	le.mu.Unlock()
	if votes != 3 {
		t.Fatalf("after the CALL c holds %d votes, want all 3: b's came before the CALL", votes)
	}

	// The others confirm; c, holding every vote, has confirmed too.
	for _, peer := range []AgentId{"a.example.", "b.example."} {
		lem.HandleGroupMessage(group, peer, "ELECT-CONFIRM",
			map[string][]string{"_term": {"1"}, "_winner": {string(winner)}, "_group": {group}})
	}
	waitLeader(t, func() (AgentId, bool) { return lem.GetGroupLeader(group) }, winner, 2*time.Second)
}

// The same through three managers wired together, with the CALL reaching the
// last member after another member's VOTE: the election completes at once, in
// its first term.
func TestAnElectionSurvivesALateCall(t *testing.T) {
	n := newElectionNet(t, time.Hour, "a.example.", "b.example.", "c.example.")
	n.lateCalls = true
	n.mgrs["a.example."].StartGroupElection(n.group, n.members, n.zones)
	n.waitSettled(t, 1, 1500*time.Millisecond)
	if got := n.electedCount(); got != 1 {
		t.Errorf("onLeaderElected ran %d times, want 1", got)
	}
}

// Only the newest term's early votes are kept; a vote for a term at or below
// the current one is late; and a member that starts a term of its own forgets
// what it kept for it.
func TestEarlyVotesAreKeptForTheNewestTermOnly(t *testing.T) {
	le := &LeaderElection{Term: 3, Votes: map[AgentId]uint32{}}

	if le.keepEarlyVote(3, "b.example.", 1) || le.keepEarlyVote(2, "b.example.", 1) {
		t.Fatal("a vote for the current term or an older one was kept as early")
	}
	if !le.keepEarlyVote(5, "b.example.", 50) || !le.keepEarlyVote(5, "c.example.", 51) {
		t.Fatal("votes for a newer term were not kept")
	}
	if le.keepEarlyVote(4, "d.example.", 40) {
		t.Fatal("a vote for a term older than the one kept was kept")
	}
	if !le.keepEarlyVote(7, "b.example.", 70) {
		t.Fatal("a vote for a still newer term was not kept")
	}
	if le.earlyTerm != 7 || len(le.earlyVotes) != 1 {
		t.Fatalf("kept term %d with %d vote(s), want term 7 with 1: the newest term replaces the one before", le.earlyTerm, len(le.earlyVotes))
	}

	// Joining term 6: nothing of term 7 applies, and it stays kept.
	le.Term = 6
	le.takeEarlyVotes(6, true)
	if len(le.Votes) != 0 || le.earlyTerm != 7 {
		t.Fatalf("joining term 6 took votes kept for term 7: votes %v, kept term %d", le.Votes, le.earlyTerm)
	}
	// Starting term 7 ourselves: forgotten, not applied.
	le.Term = 7
	le.takeEarlyVotes(7, false)
	if len(le.Votes) != 0 || le.earlyTerm != 0 || le.earlyVotes != nil {
		t.Fatalf("a start of our own applied or kept the early votes: votes %v, kept term %d", le.Votes, le.earlyTerm)
	}
	// Joining a term whose votes were kept: applied, then forgotten.
	le.keepEarlyVote(9, "b.example.", 90)
	le.Term = 9
	le.takeEarlyVotes(9, true)
	if le.Votes["b.example."] != 90 || le.earlyTerm != 0 {
		t.Fatalf("joining term 9 did not apply its early vote: votes %v, kept term %d", le.Votes, le.earlyTerm)
	}
}

// The per-zone election keeps an early vote the same way.
func TestZoneElectionCountsAVoteThatOvertakesTheCall(t *testing.T) {
	const zone = ZoneName("zone.example.")
	lem := NewLeaderElectionManager("c.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
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

	lem.handleVote(zone, "b.example.", map[string][]string{"_term": {"1"}, "_vote": {"5"}})
	lem.handleCall(zone, "a.example.", map[string][]string{"_term": {"1"}})

	le.mu.Lock()
	defer le.mu.Unlock()
	if got, ok := le.Votes["b.example."]; !ok || got != 5 {
		t.Errorf("after the CALL the votes are %v, want b's early vote of 5 among them", le.Votes)
	}
}
