/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strconv"
	"testing"
	"time"
)

// Step 8, design 4.6: a voting member never takes a lower term, from a call
// either. A call at or below the term a member holds is not joined, whether
// or not an election runs there; a call above it is.

const (
	termA AgentId = "a.term.example."
	termB AgentId = "b.term.example."
	termC AgentId = "c.term.example."
)

// holdLead gives a member of the net a decided election: term, its leader,
// and the lease's end, with no election running.
func (n *electionNet) holdLead(id AgentId, term uint64, leader AgentId, expiry time.Time) {
	lem := n.mgrs[id]
	lem.mu.Lock()
	le, ok := lem.groupElections[n.group]
	if !ok {
		le = &LeaderElection{Zone: ZoneName(n.group), Votes: map[AgentId]uint32{}, Confirms: map[AgentId]AgentId{}}
		lem.groupElections[n.group] = le
	}
	lem.mu.Unlock()
	le.mu.Lock()
	le.Term, le.Leader, le.leaderTerm, le.LeaderExpiry, le.Active = term, leader, term, expiry, false
	le.mu.Unlock()
}

// call is an ELECT-CALL of from's, at term, as it reaches to.
func (n *electionNet) call(to, from AgentId, term uint64) {
	n.mgrs[to].HandleGroupMessage(n.group, from, "ELECT-CALL",
		map[string][]string{"_term": {strconv.FormatUint(term, 10)}, "_vote": {"7"}, "_group": {n.group}})
}

// drained waits until every message sent so far has been handled.
func (n *electionNet) drained(t *testing.T) {
	t.Helper()
	waitUntil(t, "the election messages were handled", func() bool {
		n.qmu.Lock()
		defer n.qmu.Unlock()
		return len(n.queue) == 0
	})
	time.Sleep(50 * time.Millisecond) // the last one handed over
}

// A member with a decided leader joins no call at its term or below it,
// whether the lease runs or has run out, and joins a call above it.
func TestAVoterJoinsNoCallAtOrBelowItsTerm(t *testing.T) {
	for _, lease := range []struct {
		name string
		end  time.Duration
	}{{"the lease runs", time.Hour}, {"the lease has run out", -time.Second}} {
		t.Run(lease.name, func(t *testing.T) {
			n := newElectionNet(t, time.Hour, string(termA), string(termB), string(termC))
			n.holdLead(termB, 2, termA, time.Now().Add(lease.end))
			for _, below := range []uint64{1, 2} {
				n.call(termB, termC, below)
				if term, active, leader := n.state(termB); term != 2 || active || leader != termA {
					t.Fatalf("after a call at term %d B holds term %d (running %v, leader %s), want term 2, A, no election", below, term, active, leader)
				}
			}
			n.call(termB, termC, 3)
			if term, active, _ := n.state(termB); term != 3 || !active {
				t.Errorf("a call above B's term was not joined: B holds term %d (running %v)", term, active)
			}
		})
	}
}

// The zone's own election keeps the same rule.
func TestAVoterJoinsNoZoneCallAtOrBelowItsTerm(t *testing.T) {
	const zone ZoneName = "own.term.example."
	lem := NewLeaderElectionManager(termB, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	le.Term, le.Leader, le.LeaderExpiry = 2, termA, time.Now().Add(time.Hour)
	le.mu.Unlock()
	state := func() (uint64, bool) {
		le.mu.Lock()
		defer le.mu.Unlock()
		return le.Term, le.Active
	}
	for _, below := range []uint64{1, 2} {
		lem.HandleMessage(zone, termC, "ELECT-CALL", map[string][]string{"_term": {strconv.FormatUint(below, 10)}})
		if term, active := state(); term != 2 || active {
			t.Fatalf("after a call at term %d the zone's election is at term %d (running %v), want 2", below, term, active)
		}
	}
	lem.HandleMessage(zone, termC, "ELECT-CALL", map[string][]string{"_term": {"3"}})
	if term, active := state(); term != 3 || !active {
		t.Errorf("a call above the zone's term was not joined: term %d (running %v)", term, active)
	}
}

// A leader that restarted inside its lease calls from term 0. Its peers do
// not join; it learns from their gossip that it leads at the group's term,
// and its retry starts nothing. The group stays at that term and leader.
func TestARestartedLeaderLeadsOnAtItsTerm(t *testing.T) {
	n := newElectionNet(t, time.Hour, string(termA), string(termB), string(termC))
	lease := time.Now().Add(time.Hour)
	n.holdLead(termB, 2, termA, lease)
	n.holdLead(termC, 2, termA, lease)

	a := n.mgrs[termA]
	a.StartGroupElection(n.group, n.members, n.zones) // term 1, from nothing
	n.drained(t)
	for _, id := range []AgentId{termB, termC} {
		if term, active, leader := n.state(id); term != 2 || active || leader != termA {
			t.Fatalf("%s joined the restarted leader's call: term %d (running %v, leader %s)", id, term, active, leader)
		}
	}

	a.ApplyGossipElection(n.group, GroupElectionState{Leader: string(termA), Term: 2, LeaderExpiry: lease})
	if term, active, leader := n.state(termA); term != 2 || active || leader != termA {
		t.Fatalf("the restarted leader holds term %d (running %v, leader %s), want term 2 and itself", term, active, leader)
	}
	waitUntil(t, "the restarted leader runs its set-up", func() bool { return n.electedCount() == 1 })

	one := uint64(1)
	a.startGroupElection(n.group, n.members, n.zones, &one) // its retry after term 1
	a.onGroupVoteTimeout(n.group, 1, n.members, n.zones)
	n.drained(t)
	if calls := n.callers(); len(calls) != 1 {
		t.Errorf("calls after the gossip: %v, want only the first", calls)
	}
	if !n.settledAt(2) {
		t.Error("the group did not stay at term 2")
	}
}

// A former leader that restarted after its group elected another leader at
// a higher term learns that from gossip, and leads nothing.
func TestARestartedFormerLeaderFollowsTheNewLeader(t *testing.T) {
	n := newElectionNet(t, time.Hour, string(termA), string(termB), string(termC))
	lease := time.Now().Add(time.Hour)
	n.holdLead(termB, 5, termB, lease)
	n.holdLead(termC, 5, termB, lease)

	a := n.mgrs[termA]
	a.StartGroupElection(n.group, n.members, n.zones)
	n.drained(t)
	a.ApplyGossipElection(n.group, GroupElectionState{Leader: string(termB), Term: 5, LeaderExpiry: lease})
	one := uint64(1)
	a.startGroupElection(n.group, n.members, n.zones, &one)
	n.drained(t)

	if leader, ok := a.GetGroupLeader(n.group); !ok || leader != termB {
		t.Errorf("the restarted former leader takes %q (%v) as the leader, want B", leader, ok)
	}
	if !n.settledAt(5) {
		t.Error("the group did not stay at term 5")
	}
	time.Sleep(50 * time.Millisecond)
	if got := n.electedCount(); got != 0 {
		t.Errorf("a leader's set-up ran %d time(s), want none", got)
	}
	if calls := n.callers(); len(calls) != 1 {
		t.Errorf("calls: %v, want only the first", calls)
	}
}

// A group whose leader's lease has run out elects at the next term: the
// rule refuses only calls at or below a member's term. Here the old leader
// is back with nothing (restarted), another member holds the old term, and
// a third calls; all join, and the group elects.
func TestAGroupWhoseLeaseRanOutElectsAtTheNextTerm(t *testing.T) {
	n := newElectionNet(t, time.Hour, string(termA), string(termB), string(termC))
	gone := time.Now().Add(-time.Second)
	n.holdLead(termB, 2, termA, gone)
	n.holdLead(termC, 2, termA, gone)
	n.mgrs[termC].StartGroupElection(n.group, n.members, n.zones)
	n.waitSettled(t, 3, 3*time.Second)
}

// Every voting member restarted: all are at nothing, and the group elects
// at term 1 (M3's voters).
func TestVotersThatAllRestartedElectAtTermOne(t *testing.T) {
	n := newElectionNet(t, time.Hour, string(termA), string(termB), string(termC))
	n.mgrs[termA].StartGroupElection(n.group, n.members, n.zones)
	n.waitSettled(t, 1, 3*time.Second)
}

// An agent that restarted inside its group's lease has the group's term and
// leader from its peers' gossip before the beats find the group mutually
// OPERATIONAL. As the group's initiator it then starts no election, and the
// group stays at its term and leader. A lease that has run out elects, as a
// group with no leader does (#253, the operational start).
func TestARestartedInitiatorElectsNothingWhileTheLeaseRuns(t *testing.T) {
	members := []string{arrivalA, arrivalB}
	for _, c := range []struct {
		name  string
		lease time.Duration
		term  uint64 // the term the group settles at
	}{{"the lease runs", time.Hour, 2}, {"the lease has run out", -time.Second, 3}} {
		t.Run(c.name, func(t *testing.T) {
			r := newGroupRig(t, members, arrivalA, arrivalB)
			zone := providerZone(t, "restart."+strconv.Itoa(int(c.term))+".lease.example.", members...)
			r.refresh()
			inGroup(t, r.pgms[arrivalA], zone, members...)
			// B holds A's lead at term 2; A, restarted, has it from B's gossip
			word := GroupElectionState{Leader: arrivalA, Term: 2, LeaderExpiry: time.Now().Add(c.lease)}
			for _, m := range members {
				r.gsts[AgentId(m)].mergeGossip(&GossipMessage{GroupHash: r.net.group, Election: word})
			}
			r.operational()
			r.net.waitSettled(t, c.term, 3*time.Second)
			time.Sleep(100 * time.Millisecond)
			calls := r.net.callers()
			if c.term == 2 && len(calls) != 0 {
				t.Errorf("the restarted initiator called an election inside the lease: %v", calls)
			}
			if c.term == 3 && len(calls) != 1 {
				t.Errorf("calls after the lease ran out: %v, want one", calls)
			}
		})
	}
}
