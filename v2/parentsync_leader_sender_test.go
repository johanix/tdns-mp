/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"
)

// senderTestGroup is a member's election manager for a group of three voting
// members and an auditor. The auditor is a member of the group and a peer the
// transport admits, and it does not vote.
func senderTestGroup(t *testing.T) (*LeaderElectionManager, string) {
	t.Helper()
	const group = "0123456789abcdef"
	voting := []string{"a.example.", "b.example.", "c.example."}
	members := append([]string{"auditor.example."}, voting...)
	lem := NewLeaderElectionManager("c.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	pgm := NewProviderGroupManager("c.example.")
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: members, VotingMembers: voting, Zones: []ZoneName{"zone.example."}}
	lem.SetProviderGroupManager(pgm)
	t.Cleanup(func() {
		lem.mu.RLock()
		le := lem.groupElections[group]
		lem.mu.RUnlock()
		if le == nil {
			return
		}
		le.mu.Lock()
		for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
			if tm != nil {
				tm.Stop()
			}
		}
		le.mu.Unlock()
	})
	return lem, group
}

func groupElectionOf(lem *LeaderElectionManager, group string) *LeaderElection {
	lem.mu.RLock()
	defer lem.mu.RUnlock()
	return lem.groupElections[group]
}

// A VOTE from a sender that is not a voting member used to be stored like any
// other, and the votes were complete when the map held as many entries as the
// group has voting members: the auditor's vote stood in for a member's, and
// took part in the choice of the winner (#143).
func TestAGroupVoteCountsOnlyFromAVotingMember(t *testing.T) {
	lem, group := senderTestGroup(t)
	msg := func(vote string) map[string][]string {
		return map[string][]string{"_term": {"1"}, "_vote": {vote}, "_group": {group}}
	}

	lem.HandleGroupMessage(group, "a.example.", "ELECT-CALL", msg("9"))
	lem.HandleGroupMessage(group, "auditor.example.", "ELECT-VOTE", msg("4000000000"))

	le := groupElectionOf(lem, group)
	le.mu.Lock()
	votes := len(le.Votes)
	_, counted := le.Votes["auditor.example."]
	le.mu.Unlock()
	if counted || votes != 2 {
		t.Fatalf("after the auditor's VOTE c holds %d votes (the auditor's among them: %v), want 2: a's and its own", votes, counted)
	}

	lem.HandleGroupMessage(group, "b.example.", "ELECT-VOTE", msg("5"))
	le.mu.Lock()
	votes = len(le.Votes)
	le.mu.Unlock()
	if votes != 3 {
		t.Fatalf("after b's VOTE c holds %d votes, want all 3", votes)
	}
}

// A vote that comes ahead of its CALL is kept and counted when the CALL comes
// (#125). One from a sender that is not a voting member is not kept.
func TestAnEarlyGroupVoteIsKeptOnlyFromAVotingMember(t *testing.T) {
	lem, group := senderTestGroup(t)
	lem.HandleGroupMessage(group, "auditor.example.", "ELECT-VOTE",
		map[string][]string{"_term": {"1"}, "_vote": {"4000000000"}, "_group": {group}})
	lem.HandleGroupMessage(group, "a.example.", "ELECT-CALL",
		map[string][]string{"_term": {"1"}, "_vote": {"9"}, "_group": {group}})

	le := groupElectionOf(lem, group)
	le.mu.Lock()
	defer le.mu.Unlock()
	if _, counted := le.Votes["auditor.example."]; counted || len(le.Votes) != 2 {
		t.Fatalf("after the CALL c holds %d votes (the auditor's among them: %v), want 2: a's and its own", len(le.Votes), counted)
	}
}

// A CALL from such a sender starts no term.
func TestAGroupCallCountsOnlyFromAVotingMember(t *testing.T) {
	lem, group := senderTestGroup(t)
	lem.HandleGroupMessage(group, "auditor.example.", "ELECT-CALL",
		map[string][]string{"_term": {"1"}, "_vote": {"7"}, "_group": {group}})

	// No election entry at all is no term: the refused CALL created nothing.
	le := groupElectionOf(lem, group)
	if le == nil {
		return
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Active || le.Term != 0 {
		t.Fatalf("the auditor's CALL started an election: active=%v term=%d", le.Active, le.Term)
	}
}

// A CONFIRM from such a sender is not one of the confirms the election waits
// for: with a's and the auditor's, c would hold three and elect without b.
func TestAGroupConfirmCountsOnlyFromAVotingMember(t *testing.T) {
	lem, group := senderTestGroup(t)
	lem.HandleGroupMessage(group, "a.example.", "ELECT-CALL",
		map[string][]string{"_term": {"1"}, "_vote": {"9"}, "_group": {group}})
	lem.HandleGroupMessage(group, "b.example.", "ELECT-VOTE",
		map[string][]string{"_term": {"1"}, "_vote": {"5"}, "_group": {group}})

	le := groupElectionOf(lem, group)
	le.mu.Lock()
	winner := determineWinner(map[AgentId]uint32{"a.example.": 9, "b.example.": 5, "c.example.": le.MyVote})
	le.mu.Unlock()
	confirm := map[string][]string{"_term": {"1"}, "_winner": {string(winner)}, "_group": {group}}

	// c confirms on its own once it holds every vote; wait for that, so that
	// the two confirms below would make three.
	deadline := time.Now().Add(2 * time.Second)
	for {
		le.mu.Lock()
		_, own := le.Confirms["c.example."]
		le.mu.Unlock()
		if own {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("c did not confirm after holding every vote")
		}
		time.Sleep(10 * time.Millisecond)
	}

	lem.HandleGroupMessage(group, "a.example.", "ELECT-CONFIRM", confirm)
	lem.HandleGroupMessage(group, "auditor.example.", "ELECT-CONFIRM", confirm)
	time.Sleep(100 * time.Millisecond)
	if leader, ok := lem.GetGroupLeader(group); ok {
		t.Fatalf("leader %s elected with b's confirm missing: the auditor's was counted in its place", leader)
	}

	lem.HandleGroupMessage(group, "b.example.", "ELECT-CONFIRM", confirm)
	waitLeader(t, func() (AgentId, bool) { return lem.GetGroupLeader(group) }, winner, 2*time.Second)
}

// This agent's own membership is read the way a sender's is. The members of
// a group come from zone data, with the trailing dot; an identity from the
// config need not have it. Compared as plain strings, such an agent took
// itself for an observer and never voted, while its peers counted it as a
// member and waited for its vote.
func TestAnAgentIsAVotingMemberWhateverTheDotOnItsConfiguredName(t *testing.T) {
	const group = "0123456789abcdef"
	voting := []string{"a.example.", "b.example.", "c.example."}
	lem := NewLeaderElectionManager("c.example", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	pgm := NewProviderGroupManager("c.example")
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: voting, VotingMembers: voting, Zones: []ZoneName{"zone.example."}}
	lem.SetProviderGroupManager(pgm)
	t.Cleanup(func() {
		if le := groupElectionOf(lem, group); le != nil {
			le.mu.Lock()
			for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
				if tm != nil {
					tm.Stop()
				}
			}
			le.mu.Unlock()
		}
	})

	lem.HandleGroupMessage(group, "a.example.", "ELECT-CALL",
		map[string][]string{"_term": {"1"}, "_vote": {"9"}, "_group": {group}})

	le := groupElectionOf(lem, group)
	le.mu.Lock()
	defer le.mu.Unlock()
	if !le.Active || len(le.Votes) != 2 {
		t.Fatalf("after a's CALL: active=%v, %d votes; want the election joined with a's vote and this agent's own", le.Active, len(le.Votes))
	}
}
