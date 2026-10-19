/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The agent's heartbeat round and a recompute of the provider groups: the
 * round calls out of the provider group manager with none of its locks held
 * (tdns-mp #180).
 */
package tdnsmp

import (
	"testing"
	"time"
)

// beatRig is an agent as its start has it, with one zone that it serves
// together with a peer, and the heartbeat round that its hsync engine runs.
type beatRig struct {
	conf  *Config
	pgm   *ProviderGroupManager
	gst   *GossipStateTable
	lem   *LeaderElectionManager
	group string
	round func() // the engine's BeforeHeartbeats
}

func newBeatRig(t *testing.T, zoneName string) *beatRig {
	t.Helper()
	zone := providerZone(t, zoneName, arrivalA, arrivalB)
	conf := roleConf(t, AppTypeMPAgent, "agent", arrivalA, zone)
	ar := conf.InternalMp.AgentRegistry
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem
	lem.SetProviderGroupManager(ar.ProviderGroupManager)
	wireAgentGossipCallbacks(conf, ar)
	deps, _ := buildHsyncEngineDeps(conf)
	ar.ProviderGroupManager.RecomputeGroups()
	return &beatRig{
		conf:  conf,
		pgm:   ar.ProviderGroupManager,
		gst:   ar.GossipStateTable,
		lem:   lem,
		group: ComputeGroupHash([]string{arrivalA, arrivalB}),
		round: deps.Host.BeforeHeartbeats,
	}
}

// within runs f and fails the test when it has not returned after d: a
// deadlock fails the test, and does not hang the suite.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// A heartbeat round checks every provider group, and a group that has just
// reached mutual OPERATIONAL has its election called from there, by a
// callback that looks the group up. The round held the group manager's read
// lock across that call. A zone refresh that ended in a recompute of the
// groups at that moment asked for the write lock, and waited for the round;
// the callback's own read then waited for the recompute, and the agent
// neither beat nor recomputed again.
func TestAHeartbeatRoundIsNotStoppedByARecomputeOfTheGroups(t *testing.T) {
	r := newBeatRig(t, "round.beatlock.example.")

	// The agent has just started. Its first row of the group is held back
	// until it has good news, and the row it wrote before the restart comes
	// back in its peer's beat: with the peer's own row, the group is
	// mutually OPERATIONAL at the next round.
	holdFirstLocalRows(r.conf.InternalMp.AgentRegistry, time.Minute)
	op := AgentStateToString[AgentStateOperational]
	r.gst.MergeGossip(&GossipMessage{GroupHash: r.group, Members: map[string]*MemberState{
		arrivalA: {Identity: arrivalA, PeerStates: map[string]string{arrivalB: op}, Timestamp: time.Now()},
		arrivalB: {Identity: arrivalB, PeerStates: map[string]string{arrivalA: op}, Timestamp: time.Now()},
	}})

	// A recompute starts once the round is on its way into the callback, and
	// is either done or waiting for the manager's lock when the callback
	// goes on to look the group up.
	r.gst.mu.Lock()
	wired := r.gst.onGroupOperational
	r.gst.mu.Unlock()
	recomputed := make(chan struct{})
	r.gst.SetOnGroupOperational(func(groupHash string) {
		go func() {
			r.pgm.RecomputeGroups()
			close(recomputed)
		}()
		select {
		case <-recomputed:
		case <-time.After(100 * time.Millisecond):
		}
		wired(groupHash)
	})

	within(t, 3*time.Second, "the heartbeat round, with a recompute of the provider groups arriving in the middle of it,", r.round)
	select {
	case <-recomputed:
	case <-time.After(3 * time.Second):
		t.Fatalf("the recompute that arrived in the middle of a heartbeat round did not finish")
	}

	// The callback ran to its end: this agent, first in the order of the
	// identities, has called the group's election.
	if es := r.lem.GetGroupElectionState(r.group); es.Term != 1 {
		t.Errorf("after the round the group's election is at term %d, want the election called (term 1)", es.Term)
	}
}

// The round also writes this agent's rows into the gossip table, and held
// the group manager's read lock while it did. With the table busy (a beat's
// gossip being built reads it), a recompute then waited for the table, and
// every reader of the groups behind the recompute. The election manager is
// such a reader, while it holds an election's lock that the building of the
// gossip waits for: four parties that wait for each other.
func TestARecomputeOfTheGroupsDoesNotWaitForTheGossipTable(t *testing.T) {
	r := newBeatRig(t, "table.beatlock.example.")

	// A reader of the gossip table, and a round that has to write a row.
	r.gst.mu.RLock()
	round := make(chan struct{})
	go func() {
		r.round()
		close(round)
	}()
	time.Sleep(50 * time.Millisecond) // the round is at the table by now

	stuck := false
	recomputed := make(chan struct{})
	go func() {
		r.pgm.RecomputeGroups()
		close(recomputed)
	}()
	select {
	case <-recomputed:
	case <-time.After(2 * time.Second):
		stuck = true
	}
	r.gst.mu.RUnlock()

	select {
	case <-round:
	case <-time.After(3 * time.Second):
		t.Fatalf("the heartbeat round did not finish once the gossip table was free")
	}
	if stuck {
		t.Fatalf("a recompute of the provider groups waited for a heartbeat round that was waiting for the gossip table")
	}
	if row := localRow(r.gst, r.group); row == nil {
		t.Errorf("the round wrote no row for the group")
	}
}
