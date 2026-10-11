/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strconv"
	"testing"
	"time"
)

// newZoneElectionNet is newElectionNet for a zone that no provider group
// covers: the members run the per-zone election, where each knows how many
// peers the zone has and not who they are.
func newZoneElectionNet(t *testing.T, ttl time.Duration, members ...string) *electionNet {
	t.Helper()
	n := &electionNet{
		zone:    "zone.example.",
		members: members,
		mgrs:    map[AgentId]*LeaderElectionManager{},
		wake:    make(chan struct{}, 1),
	}
	peers := func(ZoneName) int { return len(members) - 1 }
	for _, m := range members {
		id := AgentId(m)
		lem := NewLeaderElectionManager(id, ttl, func(_ ZoneName, rfiType string, records map[string][]string) error {
			return n.broadcast(id, rfiType, records)
		})
		lem.SetConfiguredPeersFunc(peers)
		lem.SetOperationalPeersFunc(peers)
		lem.SetOnLeaderElected(func(ZoneName) error {
			n.mu.Lock()
			n.elected = append(n.elected, id)
			n.mu.Unlock()
			return nil
		})
		n.mgrs[id] = lem
	}
	n.start(t)
	return n
}

// firstZoneElection runs the zone's first election, called by its first
// member, and returns the leader.
func (n *electionNet) firstZoneElection(t *testing.T) AgentId {
	t.Helper()
	first := AgentId(n.members[0])
	n.mgrs[first].StartElection(n.zone, len(n.members)-1)
	n.waitSettled(t, 1, 2*time.Second)
	_, _, leader := n.state(first)
	return leader
}

// A per-zone lease renewal is the leader's call, and nobody else's: the leader
// calls at 90% of the lease, and the other member's fallback, a step later,
// finds the term renewed. Before, every member called at the same delay: one
// term when the calls crossed, and one more when a member's timer fired after
// it had joined the other's call.
func TestZoneLeaseRenewalIsTheLeadersCall(t *testing.T) {
	const ttl = 3 * time.Second
	for _, members := range [][]string{
		{"a.example.", "b.example."},
		{"a.example.", "b.example.", "c.example."},
	} {
		t.Run(strconv.Itoa(len(members))+" members", func(t *testing.T) {
			n := newZoneElectionNet(t, ttl, members...)
			start := time.Now()
			leader := n.firstZoneElection(t)

			n.waitSettled(t, 2, ttl*9/10+900*time.Millisecond)
			if took := time.Since(start); took < ttl*8/10 {
				t.Errorf("term 2 was elected %v after the first election, before the renewal was due", took)
			}

			// Past the fallbacks, and before the next renewal.
			time.Sleep(ttl / 10)
			if !n.settledAt(2) {
				t.Errorf("after the renewal the zone moved on from term 2")
			}
			if calls := n.callers(); len(calls) != 2 || calls[1] != leader {
				t.Errorf("elections were called by %v, want two: the first, and the renewal by the leader %s", calls, leader)
			}
			if got := n.electedCount(); got != 2 {
				t.Errorf("onLeaderElected ran %d times over the first election and one renewal, want 2", got)
			}
		})
	}
}

// With the leader's timer gone, the other member renews, a step after the
// leader would have, once.
func TestZoneLeaseRenewalFallsBackWhenTheLeaderHasNoTimer(t *testing.T) {
	const ttl = 3 * time.Second
	n := newZoneElectionNet(t, ttl, "a.example.", "b.example.")
	leader := n.firstZoneElection(t)

	le := n.election(n.mgrs[leader])
	le.mu.Lock()
	le.ReelectTimer.Stop()
	le.mu.Unlock()

	n.waitSettled(t, 2, ttl*9/10+900*time.Millisecond)
	time.Sleep(ttl / 10)
	if !n.settledAt(2) {
		t.Errorf("after the fallback renewal the zone moved on from term 2")
	}
	if calls := n.callers(); len(calls) != 2 || calls[1] == leader {
		t.Errorf("elections were called by %v, want two: the first, and the renewal by the member that does not lead (the leader is %s)", calls, leader)
	}
	if got := n.electedCount(); got != 2 {
		t.Errorf("onLeaderElected ran %d times over the first election and one renewal, want 2", got)
	}
}
