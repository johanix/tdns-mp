/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// Step 8, design 4.1: a zone that arrives while its group's election runs.

type arrivalCalls struct {
	mu      sync.Mutex
	elected []ZoneName
	joined  []ZoneName
}

func (a *arrivalCalls) lists() ([]ZoneName, []ZoneName) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, j := slices.Clone(a.elected), slices.Clone(a.joined)
	slices.Sort(e)
	slices.Sort(j)
	return e, j
}

// arrivalLEM is this agent (A) in a group with B, whose zones are these,
// with its callbacks recorded.
func arrivalLEM(t *testing.T, zones ...string) (*LeaderElectionManager, string, *arrivalCalls) {
	t.Helper()
	for _, z := range zones {
		providerZone(t, z, arrivalA, arrivalB)
	}
	pgm := NewProviderGroupManager(arrivalA)
	pgm.RecomputeGroups()
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	lem.SetProviderGroupManager(pgm)
	calls := &arrivalCalls{}
	lem.SetOnLeaderElected(func(z ZoneName) error {
		calls.mu.Lock()
		calls.elected = append(calls.elected, z)
		calls.mu.Unlock()
		return nil
	})
	lem.SetOnZoneJoined(func(z ZoneName) error {
		calls.mu.Lock()
		calls.joined = append(calls.joined, z)
		calls.mu.Unlock()
		return nil
	})
	return lem, ComputeGroupHash([]string{arrivalA, arrivalB}, nil, nil), calls
}

// The election keeps the group's zones as they were when it started, both
// where this agent calls it and where it joins another's call.
func TestAnElectionKeepsTheZonesItStartedWith(t *testing.T) {
	lem, group, _ := arrivalLEM(t, "start1.arrival.election.example.")
	lem.StartGroupElection(group, []string{arrivalA, arrivalB}, []ZoneName{"start1.arrival.election.example."})
	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()
	le.mu.Lock()
	got := slices.Clone(le.startZones)
	le.mu.Unlock()
	if !slices.Equal(got, []ZoneName{"start1.arrival.election.example."}) {
		t.Errorf("the election called here started with %v", got)
	}

	other, group2, _ := arrivalLEM(t, "start2.arrival.election.example.")
	other.HandleGroupMessage(group2, arrivalB, "ELECT-CALL", map[string][]string{"_term": {"1"}})
	other.mu.RLock()
	le2 := other.groupElections[group2]
	other.mu.RUnlock()
	le2.mu.Lock()
	got2 := slices.Clone(le2.startZones)
	le2.mu.Unlock()
	// both zones are of one make-up, so of one group: the group's zones
	// when the call was handled
	if !slices.Equal(got2, []ZoneName{"start1.arrival.election.example.", "start2.arrival.election.example."}) {
		t.Errorf("the election joined here started with %v, want the group's two zones", got2)
	}
}

// A zone that arrives during the election is one of its zones: when this
// agent wins, it is taken up as an arrival (onZoneJoined), not as one of the
// zones the election was held for; a zone that left during it is not asked.
func TestAZoneThatArrivesDuringAnElectionIsOneOfItsZones(t *testing.T) {
	const kept, arrived, left = "kept.arrival.election.example.", "arrived.arrival.election.example.", "left.arrival.election.example."
	lem, group, calls := arrivalLEM(t, kept, arrived)
	lem.mu.Lock()
	lem.groupElections[group] = &LeaderElection{Active: true, Term: 3, startZones: []ZoneName{kept, left},
		Confirms: map[AgentId]AgentId{arrivalA: arrivalA, arrivalB: arrivalA}}
	lem.mu.Unlock()
	lem.finalizeGroupElection(group, 3, []string{arrivalA, arrivalB}, []ZoneName{kept, left})
	waitUntil(t, "the winner's callbacks ran", func() bool { e, j := calls.lists(); return len(e)+len(j) >= 2 })
	time.Sleep(50 * time.Millisecond)
	e, j := calls.lists()
	if !slices.Equal(e, []ZoneName{kept}) || !slices.Equal(j, []ZoneName{arrived}) {
		t.Errorf("the election's callback ran for %v and the arrival's for %v; want %s and %s, and nothing for %s", e, j, kept, arrived, left)
	}
}

// A zone that arrives during an election makes no key, wherever between the
// election's start and its end it arrives: it is taken up through the
// arrival's set-up, which since step 7b neither asks for nor makes a key
// (the key rounds do, and make none while the zone publishes one).
func TestAZoneThatArrivesDuringAnElectionMakesNoKey(t *testing.T) {
	const kept, arrived = "kept.nokey.election.example.", "arrived.nokey.election.example."
	lem, group, calls := arrivalLEM(t, kept, arrived)
	for _, started := range [][]ZoneName{{kept}, {}} {
		calls.mu.Lock()
		calls.elected, calls.joined = nil, nil
		calls.mu.Unlock()
		lem.mu.Lock()
		lem.groupElections[group] = &LeaderElection{Active: true, Term: 4, startZones: started,
			Confirms: map[AgentId]AgentId{arrivalA: arrivalA, arrivalB: arrivalA}}
		lem.mu.Unlock()
		lem.finalizeGroupElection(group, 4, []string{arrivalA, arrivalB}, started)
		waitUntil(t, "the winner's callbacks ran", func() bool { e, j := calls.lists(); return len(e)+len(j) >= 2 })
		time.Sleep(50 * time.Millisecond)
		if _, j := calls.lists(); !slices.Contains(j, ZoneName(arrived)) {
			t.Errorf("started with %v: %s was not taken up as an arrival (%v)", started, arrived, j)
		}
	}
}

// A zone that arrives in a group with a leader forces no election: the
// leader takes it up as an arrival (zoneJoinedGroup), and nobody calls one.
func TestAZoneThatArrivesInAGroupWithALeaderForcesNoElection(t *testing.T) {
	const kept, arrived = "kept.leader.arrival.example.", "arrived.leader.arrival.example."
	lem, group, calls := arrivalLEM(t, kept)
	sent := 0
	lem.broadcastFunc = func(ZoneName, string, map[string][]string) error { sent++; return nil }
	lem.ApplyGossipElection(group, GroupElectionState{Leader: arrivalA, Term: 2, LeaderExpiry: time.Now().Add(time.Hour)})
	providerZone(t, arrived, arrivalA, arrivalB)
	lem.zoneJoinedGroup(arrived, "", group)
	waitUntil(t, "the arrival was taken up", func() bool { _, j := calls.lists(); return len(j) == 1 })
	if sent != 0 {
		t.Errorf("%d election message(s) were sent for an arrival in a group with a leader", sent)
	}
	if es := lem.GetGroupElectionState(group); es.Term != 2 {
		t.Errorf("the group's term moved to %d", es.Term)
	}
}
