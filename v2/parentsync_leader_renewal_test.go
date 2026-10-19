/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// electionNet is a provider group's election managers wired to each other in
// process: what one broadcasts, every other one handles.
//
// Delivery is in the order of sending, through one queue. A broadcast queues
// its copies for every member before anything a member sends in answer, so a
// VOTE does not overtake the CALL it answers, unless lateCalls is set: then
// the CALL's copy for the last member is held back until the next VOTE has
// been queued, which is the order a network can give (#125).
type electionNet struct {
	group   string
	zone    ZoneName // set: the election of a zone that no group covers
	members []string
	zones   []ZoneName
	mgrs    map[AgentId]*LeaderElectionManager
	closed  atomic.Bool

	qmu   sync.Mutex
	queue []electionMsg
	held  *electionMsg // a CALL held back for its last member (lateCalls)
	wake  chan struct{}

	// lateCalls: a CALL reaches the last member after another member's VOTE.
	lateCalls bool

	mu      sync.Mutex
	elected []AgentId // one entry per onLeaderElected call, the winner
	calls   []AgentId // one entry per ELECT-CALL broadcast, its sender
}

type electionMsg struct {
	to, from AgentId
	rfiType  string
	records  map[string][]string
}

// broadcast is a member's broadcastFunc: it notes who calls an election and
// queues the message.
func (n *electionNet) broadcast(from AgentId, rfiType string, records map[string][]string) error {
	if rfiType == "ELECT-CALL" {
		n.mu.Lock()
		n.calls = append(n.calls, from)
		n.mu.Unlock()
	}
	n.send(from, rfiType, records)
	return nil
}

// send queues one broadcast for every member but its sender.
func (n *electionNet) send(from AgentId, rfiType string, records map[string][]string) {
	if n.closed.Load() {
		return
	}
	n.qmu.Lock()
	var copies []electionMsg
	for _, m := range n.members {
		if to := AgentId(m); to != from {
			copies = append(copies, electionMsg{to: to, from: from, rfiType: rfiType, records: records})
		}
	}
	if n.lateCalls && rfiType == "ELECT-CALL" && len(copies) > 1 {
		last := copies[len(copies)-1]
		n.held = &last
		copies = copies[:len(copies)-1]
	}
	n.queue = append(n.queue, copies...)
	if n.held != nil && rfiType == "ELECT-VOTE" {
		n.queue = append(n.queue, *n.held)
		n.held = nil
	}
	n.qmu.Unlock()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// deliver hands the queued messages to their members, one at a time, until
// the net is closed.
func (n *electionNet) deliver() {
	for range n.wake {
		for {
			n.qmu.Lock()
			if len(n.queue) == 0 || n.closed.Load() {
				n.qmu.Unlock()
				break
			}
			msg := n.queue[0]
			n.queue = n.queue[1:]
			n.qmu.Unlock()
			n.handle(msg)
		}
		if n.closed.Load() {
			return
		}
	}
}

// handle gives one message to its member: the group's election, or the zone's.
func (n *electionNet) handle(msg electionMsg) {
	if n.zone != "" {
		n.mgrs[msg.to].HandleMessage(n.zone, msg.from, msg.rfiType, msg.records)
		return
	}
	n.mgrs[msg.to].HandleGroupMessage(n.group, msg.from, msg.rfiType, msg.records)
}

func newElectionNet(t *testing.T, ttl time.Duration, members ...string) *electionNet {
	t.Helper()
	n := &electionNet{
		group:   "0123456789abcdef",
		members: members,
		zones:   []ZoneName{"zone.example."},
		mgrs:    map[AgentId]*LeaderElectionManager{},
		wake:    make(chan struct{}, 1),
	}
	for _, m := range members {
		id := AgentId(m)
		lem := NewLeaderElectionManager(id, ttl, func(_ ZoneName, rfiType string, records map[string][]string) error {
			return n.broadcast(id, rfiType, records)
		})
		pgm := NewProviderGroupManager(m)
		pgm.Groups[n.group] = &ProviderGroup{GroupHash: n.group, Members: members, VotingMembers: members, Zones: n.zones}
		lem.SetProviderGroupManager(pgm)
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

// start begins the delivery, and stops it and every member's timers when the
// test ends.
func (n *electionNet) start(t *testing.T) {
	go n.deliver()
	t.Cleanup(func() {
		n.closed.Store(true)
		select {
		case n.wake <- struct{}{}:
		default:
		}
		for _, lem := range n.mgrs {
			if le := n.election(lem); le != nil {
				le.mu.Lock()
				for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
					if tm != nil {
						tm.Stop()
					}
				}
				le.mu.Unlock()
			}
		}
	})
}

func (n *electionNet) election(lem *LeaderElectionManager) *LeaderElection {
	lem.mu.RLock()
	defer lem.mu.RUnlock()
	if n.zone != "" {
		return lem.elections[n.zone]
	}
	return lem.groupElections[n.group]
}

// state returns one member's term, whether an election is running there, and
// its leader.
func (n *electionNet) state(id AgentId) (term uint64, active bool, leader AgentId) {
	le := n.election(n.mgrs[id])
	if le == nil {
		return 0, false, ""
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.Term, le.Active, le.Leader
}

func (n *electionNet) electedCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.elected)
}

// callers returns who has called an election, in order.
func (n *electionNet) callers() []AgentId {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]AgentId(nil), n.calls...)
}

// settledAt reports whether every member has finalized exactly term.
func (n *electionNet) settledAt(term uint64) bool {
	for id := range n.mgrs {
		got, active, leader := n.state(id)
		if got != term || active || leader == "" {
			return false
		}
	}
	return true
}

func (n *electionNet) waitSettled(t *testing.T, term uint64, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !n.settledAt(term) {
		if time.Now().After(deadline) {
			for id := range n.mgrs {
				got, active, leader := n.state(id)
				t.Logf("%s: term %d, active %v, leader %q", id, got, active, leader)
			}
			t.Fatalf("the group did not settle on term %d within %v", term, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// firstElection runs the group's first election and returns its leader.
func (n *electionNet) firstElection(t *testing.T) AgentId {
	t.Helper()
	n.mgrs[AgentId(n.members[0])].StartGroupElection(n.group, n.members, n.zones)
	n.waitSettled(t, 1, 2*time.Second)
	_, _, leader := n.state(AgentId(n.members[0]))
	return leader
}

// A lease renewal is one election: the leader renews, the others' fallbacks
// find the term renewed and start nothing. Before, every member renewed at the
// same instant with a term of its own, nobody joined anybody, all aborted
// after the 5 s vote timeout, and each member's retry then minted one more
// term: two or three elected terms per renewal (#120).
func TestGroupLeaseRenewalIsOneElection(t *testing.T) {
	const ttl = 3 * time.Second
	for _, members := range [][]string{
		{"a.example.", "b.example."},
		{"a.example.", "b.example.", "c.example."},
	} {
		t.Run(strconv.Itoa(len(members))+" members", func(t *testing.T) {
			n := newElectionNet(t, ttl, members...)
			start := time.Now()
			n.firstElection(t)

			// The renewal comes at 90% of the lease and takes milliseconds.
			n.waitSettled(t, 2, ttl*9/10+900*time.Millisecond)
			if took := time.Since(start); took < ttl*8/10 {
				t.Errorf("term 2 was elected %v after the first election, before the renewal was due", took)
			}

			// Past every fallback, and before the next renewal: still term 2,
			// and one more leader elected, not one per member.
			time.Sleep(ttl / 10)
			if !n.settledAt(2) {
				t.Errorf("after the renewal the group moved on from term 2")
			}
			if got := n.electedCount(); got != 2 {
				t.Errorf("onLeaderElected ran %d times over the first election and one renewal, want 2", got)
			}
		})
	}
}

// A leader that restarted inside its term has no renewal timer: it learnt from
// gossip that it leads. The next member in line renews, a step after the
// leader would have, and the one after it finds the term renewed.
func TestGroupLeaseRenewalFallsBackWhenTheLeaderHasNoTimer(t *testing.T) {
	const ttl = 3 * time.Second
	n := newElectionNet(t, ttl, "a.example.", "b.example.", "c.example.")
	leader := n.firstElection(t)

	le := n.election(n.mgrs[leader])
	le.mu.Lock()
	le.ReelectTimer.Stop()
	le.mu.Unlock()

	n.waitSettled(t, 2, ttl*9/10+900*time.Millisecond)
	time.Sleep(ttl / 10)
	if !n.settledAt(2) {
		t.Errorf("after the fallback renewal the group moved on from term 2")
	}
	if got := n.electedCount(); got != 2 {
		t.Errorf("onLeaderElected ran %d times over the first election and one renewal, want 2", got)
	}
}

// The retry after an aborted election acts only on the term that was aborted.
// When another member's retry has produced a newer term by the time it fires,
// it starts nothing.
func TestAnElectionRetryYieldsToANewerTerm(t *testing.T) {
	const group = "fedcba9876543210"
	members := []string{"a.example.", "b.example."}
	zones := []ZoneName{"zone.example."}
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	// The retry reads the group from the provider group manager when it
	// fires, and starts nothing for a group that is not there.
	pgm := NewProviderGroupManager("a.example.")
	pgm.Groups[group] = &ProviderGroup{GroupHash: group, Members: members, VotingMembers: members, Zones: zones}
	lem.SetProviderGroupManager(pgm)

	lem.StartGroupElection(group, members, zones)
	lem.mu.RLock()
	le := lem.groupElections[group]
	lem.mu.RUnlock()

	// Term 1 gets no vote from b and is aborted; the retry is armed.
	lem.onGroupVoteTimeout(group, 1, members, zones)

	// b's retry gets here first: term 2, which a joins and both confirm.
	lem.handleGroupCall(le, group, "b.example.",
		map[string][]string{"_term": {"2"}, "_vote": {"7"}, "_group": {group}}, members, zones)
	le.mu.Lock()
	winner := determineWinner(map[AgentId]uint32{"a.example.": le.MyVote, "b.example.": 7})
	le.mu.Unlock()
	lem.handleGroupConfirm(le, group, "b.example.",
		map[string][]string{"_term": {"2"}, "_winner": {string(winner)}, "_group": {group}}, members, zones)
	waitLeader(t, func() (AgentId, bool) { return lem.GetGroupLeader(group) }, winner, 2*time.Second)

	// a's own retry fires within 1.5 s of the abort.
	time.Sleep(1700 * time.Millisecond)
	le.mu.Lock()
	term, active := le.Term, le.Active
	le.mu.Unlock()
	if term != 2 || active {
		t.Errorf("after a's retry fired the election is at term %d (active %v), want term 2 left alone", term, active)
	}
}

// The leader renews at 90% of the lease; every other member a step later for
// each member before it, in the order of their identities, with the steps
// inside the lease's last tenth.
func TestRenewalDelay(t *testing.T) {
	members := []string{"c.example.", "a.example.", "b.example."}
	for _, tc := range []struct {
		ttl           time.Duration
		local, leader AgentId
		members       []string
		want          time.Duration
	}{
		// 1000 s: a tenth is 100 s, a step would be 20 s and is capped at 10 s.
		{1000 * time.Second, "a.example.", "a.example.", members, 900 * time.Second},
		{1000 * time.Second, "b.example.", "a.example.", members, 910 * time.Second},
		{1000 * time.Second, "c.example.", "a.example.", members, 920 * time.Second},
		{1000 * time.Second, "a.example.", "c.example.", members, 910 * time.Second},
		{1000 * time.Second, "b.example.", "c.example.", members, 920 * time.Second},
		// 5 s: a tenth is 500 ms, a step 100 ms.
		{5 * time.Second, "c.example.", "a.example.", members, 4700 * time.Millisecond},
		// A per-zone election does not know its members.
		{1000 * time.Second, "a.example.", "a.example.", nil, 900 * time.Second},
		{1000 * time.Second, "b.example.", "a.example.", nil, 910 * time.Second},
	} {
		lem := NewLeaderElectionManager(tc.local, tc.ttl, nil)
		if got := lem.renewalDelay(tc.leader, tc.members); got != tc.want {
			t.Errorf("ttl %v, %s with leader %s, %d members: delay %v, want %v",
				tc.ttl, tc.local, tc.leader, len(tc.members), got, tc.want)
		}
	}
}

// The per-zone election's timers follow the same rule: a start that was armed
// in a term does nothing once the election has moved on from it.
func TestZoneElectionTimerActsOnlyOnItsTerm(t *testing.T) {
	const zone = ZoneName("zone.example.")
	lem := NewLeaderElectionManager("a.example.", time.Hour,
		func(ZoneName, string, map[string][]string) error { return nil })
	lem.StartElection(zone, 1)
	le := lem.getOrCreate(zone)
	t.Cleanup(func() {
		le.mu.Lock()
		if le.VoteTimer != nil {
			le.VoteTimer.Stop()
		}
		le.mu.Unlock()
	})
	term := func() uint64 {
		le.mu.Lock()
		defer le.mu.Unlock()
		return le.Term
	}

	// Armed in term 0, and term 1 is running: nothing.
	armed := uint64(0)
	lem.startElection(zone, 1, &armed)
	if got := term(); got != 1 {
		t.Fatalf("a timer armed in term 0 started an election: term %d, want 1", got)
	}
	// Armed in term 1, and term 1 is still running: nothing.
	armed = 1
	lem.startElection(zone, 1, &armed)
	if got := term(); got != 1 {
		t.Fatalf("a timer started an election over a running one: term %d, want 1", got)
	}
	// Armed in term 1, which ended without a successor: it starts term 2.
	le.mu.Lock()
	le.Active = false
	le.mu.Unlock()
	lem.startElection(zone, 1, &armed)
	if got := term(); got != 2 {
		t.Fatalf("a timer whose term still stands started nothing: term %d, want 2", got)
	}
}
