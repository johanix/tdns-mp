/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// statusGroup is a two-member provider group, for the tests of what the
// election tells in gossip and in the gossip API.
const statusGroup = "0123456789abcdef"

func statusGroupManager(local string) *ProviderGroupManager {
	members := []string{"a.example.", "b.example."}
	pgm := NewProviderGroupManager(local)
	pgm.Groups[statusGroup] = &ProviderGroup{
		GroupHash: statusGroup, Members: members, VotingMembers: members,
		Zones: []ZoneName{"zone.example."},
	}
	return pgm
}

// A record without a leader is no election's result, and is not stored.
// Stored, it stood for its term: the result that followed was of the same
// term, not a higher one, and was dropped (#154).
func TestAnElectionRecordWithoutALeaderIsNotStored(t *testing.T) {
	gst := NewGossipStateTable("b.example.")
	var told []GroupElectionState
	gst.SetOnElectionUpdate(func(_ string, state GroupElectionState) { told = append(told, state) })

	// a's gossip from inside its election: the term is set, the leader is not.
	gst.MergeGossip(&GossipMessage{GroupHash: statusGroup, Election: GroupElectionState{Term: 1}})
	if _, election, _ := gst.GetGroupState(statusGroup); election != nil {
		t.Fatalf("a record without a leader was stored: %+v", *election)
	}
	if len(told) != 0 {
		t.Fatalf("a record without a leader was passed on: %+v", told)
	}

	// a's gossip once the election is decided, of the same term.
	expiry := time.Now().Add(time.Hour)
	gst.MergeGossip(&GossipMessage{GroupHash: statusGroup,
		Election: GroupElectionState{Leader: "a.example.", Term: 1, LeaderExpiry: expiry}})
	_, election, _ := gst.GetGroupState(statusGroup)
	if election == nil || election.Leader != "a.example." || election.Term != 1 {
		t.Fatalf("the election's result was not stored: %+v", election)
	}
	if len(told) != 1 || told[0].Leader != "a.example." {
		t.Fatalf("the election's result was passed on %d times (%+v), want once", len(told), told)
	}
}

// A member tells its peers of a term only once the term is decided. Inside an
// election the term is already the new one and the leader is not decided: none
// in a first election, the leader of the term before in a renewal. After an
// aborted election it stays so, and a member that has invalidated its leader
// has a term without one.
func TestAnUndecidedTermIsNotGossiped(t *testing.T) {
	members := []string{"a.example.", "b.example."}
	zones := []ZoneName{"zone.example."}
	pgm := statusGroupManager("a.example.")
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.SetProviderGroupManager(pgm)
	gst := NewGossipStateTable("a.example.")

	told := func() GroupElectionState {
		t.Helper()
		msgs := gst.BuildGossipForPeer("b.example.", pgm, lem)
		if len(msgs) != 1 {
			t.Fatalf("%d gossip messages for the peer, want 1", len(msgs))
		}
		return msgs[0].Election
	}
	vote := func(term string) {
		lem.HandleGroupMessage(statusGroup, "b.example.", "ELECT-VOTE",
			map[string][]string{"_term": {term}, "_vote": {"7"}, "_group": {statusGroup}})
	}
	confirm := func(term string, winner AgentId) {
		lem.HandleGroupMessage(statusGroup, "b.example.", "ELECT-CONFIRM",
			map[string][]string{"_term": {term}, "_winner": {string(winner)}, "_group": {statusGroup}})
	}

	// The first election, running.
	lem.StartGroupElection(statusGroup, members, zones)
	lem.mu.RLock()
	le := lem.groupElections[statusGroup]
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
	if got := told(); got.Term != 0 {
		t.Fatalf("inside the first election the member told its peer %+v, want nothing", got)
	}

	// Decided: term 1 and its leader.
	le.mu.Lock()
	winner := determineWinner(map[AgentId]uint32{"a.example.": le.MyVote, "b.example.": 7})
	le.mu.Unlock()
	vote("1")
	confirm("1", winner)
	waitLeader(t, func() (AgentId, bool) { return lem.GetGroupLeader(statusGroup) }, winner, 2*time.Second)
	if got := told(); got.Term != 1 || AgentId(got.Leader) != winner {
		t.Fatalf("after the election the member told its peer %+v, want term 1 and leader %s", got, winner)
	}

	// The renewal, running: the term is 2, and the leader is still term 1's.
	lem.StartGroupElection(statusGroup, members, zones)
	if got := told(); got.Term != 0 {
		t.Fatalf("inside the renewal the member told its peer %+v, want nothing of term 2", got)
	}

	// The renewal, aborted: no vote came.
	lem.onGroupVoteTimeout(statusGroup, 2, members, zones)
	if got := told(); got.Term != 0 {
		t.Fatalf("after an aborted renewal the member told its peer %+v, want nothing of term 2", got)
	}

	// What the member heard from its peer before stands in for its own word.
	gst.MergeGossip(&GossipMessage{GroupHash: statusGroup,
		Election: GroupElectionState{Leader: string(winner), Term: 1, LeaderExpiry: time.Now().Add(time.Hour)}})
	if got := told(); got.Term != 1 || AgentId(got.Leader) != winner {
		t.Fatalf("with a decided term heard from the peer, the member told %+v, want term 1 and leader %s", got, winner)
	}

	// A leader invalidated: a term without a leader.
	lem.InvalidateGroupLeader(statusGroup)
	if _, ok := lem.GroupElectionForGossip(statusGroup); ok {
		t.Fatalf("a member that has invalidated its leader has an election to tell")
	}
}

// The /gossip handler asks the election manager that exists when a request
// comes in. The routes are set up before the role is started, and the manager
// is created at that start: the handler used to keep the nil it was given, and
// answered from the gossip table alone.
func TestTheGossipAPIAsksTheElectionManagerOfTheMoment(t *testing.T) {
	pgm := statusGroupManager("b.example.")
	gst := NewGossipStateTable("b.example.")
	conf := &Config{}
	conf.InternalMp.AgentRegistry = &AgentRegistry{GossipStateTable: gst, ProviderGroupManager: pgm}

	// The route is registered: there is no election manager yet.
	handler := APIgossip(conf)

	// The role starts, and elects. The gossip table has nothing of it.
	lem := NewLeaderElectionManager("b.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.SetProviderGroupManager(pgm)
	lem.ApplyGossipElection(statusGroup, GroupElectionState{
		Leader: "a.example.", Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	lem.mu.RLock()
	le := lem.groupElections[statusGroup]
	lem.mu.RUnlock()
	t.Cleanup(func() {
		le.mu.Lock()
		if le.ReelectTimer != nil {
			le.ReelectTimer.Stop()
		}
		le.mu.Unlock()
	})
	conf.InternalMp.LeaderElectionManager = lem

	body, _ := json.Marshal(GossipPost{Command: "gossip-zone-state", Zone: "zone.example."})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/gossip", bytes.NewReader(body)))

	var resp struct {
		Error    bool   `json:"error"`
		ErrorMsg string `json:"error_msg"`
		Data     struct {
			Election struct {
				Status string `json:"status"`
				Leader string `json:"leader"`
				Term   int    `json:"term"`
			} `json:"election"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("the answer does not parse: %v: %s", err, rec.Body.String())
	}
	if resp.Error {
		t.Fatalf("the handler answered with an error: %s", resp.ErrorMsg)
	}
	el := resp.Data.Election
	if el.Status != "active" || el.Leader != "a.example." || el.Term != 1 {
		t.Fatalf("the handler reports the election as %+v, want active, leader a.example., term 1", el)
	}
}
