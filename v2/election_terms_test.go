/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"sync/atomic"
	"testing"
	"time"
)

// Step 8, design 4.6 and 4.7: a self-election takes the next term, and a
// member that does not vote (an observer) follows the lease.

// termRig is a zone voted by A and audited by X, with the group manager,
// gossip table and election manager of each, and a count of the election
// messages each election manager sent.
type termRig struct {
	group string
	zone  ZoneName
	pgm   map[string]*ProviderGroupManager
	gst   map[string]*GossipStateTable
	lem   map[string]*LeaderElectionManager
	sent  map[string]*atomic.Int32
}

func newTermRig(t *testing.T, name string, ttl time.Duration) *termRig {
	t.Helper()
	zd := providerZone(t, name, arrivalA)
	voteless(t, zd, serve(arrivalA), arrivalX)
	r := &termRig{group: ComputeGroupHash([]string{arrivalA}, []string{arrivalX}, nil), zone: ZoneName(zd.ZoneName),
		pgm: map[string]*ProviderGroupManager{}, gst: map[string]*GossipStateTable{}, lem: map[string]*LeaderElectionManager{},
		sent: map[string]*atomic.Int32{}}
	for _, id := range []string{arrivalA, arrivalX} {
		n := &atomic.Int32{}
		r.sent[id] = n
		lem := NewLeaderElectionManager(AgentId(id), ttl, func(ZoneName, string, map[string][]string) error { n.Add(1); return nil })
		t.Cleanup(func() { stopElectionTimers(lem) })
		pgm := NewProviderGroupManager(id)
		lem.SetProviderGroupManager(pgm)
		gst := NewGossipStateTable(id)
		gst.SetOnElectionUpdate(lem.ApplyGossipElection)
		pgm.RecomputeGroups()
		if pg := pgm.GetGroup(r.group); pg == nil {
			t.Fatalf("%s has no group of A voting and X auditing", id)
		}
		r.pgm[id], r.gst[id], r.lem[id] = pgm, gst, lem
	}
	return r
}

// tell is a beat of from's that carries this election record of the group.
func (r *termRig) tell(to, from string, rec GroupElectionState) {
	r.gst[to].MergeGossip(&GossipMessage{GroupHash: r.group, Election: rec}, from, r.pgm[to].GetGroup(r.group), false)
}

func (r *termRig) held(id string) (table, manager GroupElectionState) {
	r.gst[id].mu.Lock()
	if e := r.gst[id].Elections[r.group]; e != nil {
		table = *e
	}
	r.gst[id].mu.Unlock()
	return table, r.lem[id].GetGroupElectionState(r.group)
}

// A group's one voting member elects itself at a term above zero, so the
// record goes into its gossip, and its auditor learns who leads.
func TestALoneVoterLeadsAtATermAboveZeroAndItsObserverLearnsIt(t *testing.T) {
	r := newTermRig(t, "lone.term.example.", time.Hour)
	r.lem[arrivalA].StartGroupElection(r.group, []string{arrivalA}, []ZoneName{r.zone})
	state, decided, known := r.lem[arrivalA].GroupElectionForGossip(r.group)
	if !known || !decided || state.Term == 0 || state.Leader != arrivalA {
		t.Fatalf("the lone voter's election as gossip: %+v (decided %v, known %v), want A at a term above zero", state, decided, known)
	}
	r.tell(arrivalX, arrivalA, state)
	if table, manager := r.held(arrivalX); table.Leader != arrivalA || manager.Leader != arrivalA {
		t.Errorf("the auditor holds %+v in its gossip table and %+v in its election manager, want A", table, manager)
	}
}

// Every renewal of a lone voter's lease is a new term, and keeps its lead
// (step 7b's renewal keeps the zone's key).
func TestEveryRenewalOfALoneVoterIsANewTerm(t *testing.T) {
	const ttl = 400 * time.Millisecond
	zd := providerZone(t, "renewed.term.example.", arrivalA)
	zone := ZoneName(zd.ZoneName)
	lem := NewLeaderElectionManager(arrivalA, ttl, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	lem.SetConfiguredPeersFunc(func(ZoneName) int { return 0 })
	lem.StartElection(zone, 0)
	term := func() (uint64, uint64) {
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		defer le.mu.Unlock()
		return le.Term, le.leadStart
	}
	t1, lead1 := term()
	if t1 == 0 {
		t.Fatal("a lone voter elected itself at term 0")
	}
	waitUntil(t, "the lease was renewed", func() bool { t2, _ := term(); return t2 > t1 })
	if _, lead2 := term(); lead2 != lead1 {
		t.Errorf("a renewal started the lead anew (%d, was %d)", lead2, lead1)
	}
}

// An observer, in its gossip table and its election manager alike: takes a
// higher term at once; keeps its leader while the lease runs; once the lease
// has run out takes a lower term, or the same term from voters that have all
// restarted (another leader, or a later end of the lease).
func TestAnObserverFollowsTheLease(t *testing.T) {
	now := time.Now()
	run, gone := now.Add(time.Hour), now.Add(-time.Second)
	cases := []struct {
		name       string
		held, told GroupElectionState
		takes      bool
	}{
		{"TestAnObserverTakesAHigherTermAtOnce", GroupElectionState{Leader: arrivalA, Term: 5, LeaderExpiry: run},
			GroupElectionState{Leader: arrivalA, Term: 6, LeaderExpiry: run.Add(time.Minute)}, true},
		{"TestAnObserverKeepsItsLeaderWhileTheLeaseRuns", GroupElectionState{Leader: arrivalA, Term: 5, LeaderExpiry: run},
			GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: run.Add(time.Minute)}, false},
		{"TestAnObserverTakesALowerTermWhenTheLeaseHasRunOut", GroupElectionState{Leader: arrivalA, Term: 5, LeaderExpiry: gone},
			GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: run}, true},
		{"TestAnObserverTakesTheSameTermFromRestartedVotersWhenTheLeaseHasRunOut", GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: gone},
			GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: run}, true},
		{"the same term and lease, after the lease has run out", GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: gone},
			GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: gone}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newTermRig(t, "case.observer.term.example.", time.Hour)
			// what the observer holds, as both places keep it
			r.gst[arrivalX].mergeGossip(&GossipMessage{GroupHash: r.group, Election: c.held})
			r.tell(arrivalX, arrivalA, c.told)
			table, manager := r.held(arrivalX)
			want := c.held
			if c.takes {
				want = c.told
			}
			if table.Term != want.Term || !table.LeaderExpiry.Equal(want.LeaderExpiry) {
				t.Errorf("the gossip table holds term %d until %v, want term %d until %v", table.Term, table.LeaderExpiry, want.Term, want.LeaderExpiry)
			}
			if manager.Term != want.Term || !manager.LeaderExpiry.Equal(want.LeaderExpiry) {
				t.Errorf("the election manager holds term %d until %v, want term %d until %v", manager.Term, manager.LeaderExpiry, want.Term, want.LeaderExpiry)
			}
		})
	}
}

// A voting member never takes a lower term, also after the lease it holds
// has run out.
func TestAVotingMemberNeverTakesALowerTerm(t *testing.T) {
	r := newTermRig(t, "voter.term.example.", time.Hour)
	held := GroupElectionState{Leader: arrivalA, Term: 5, LeaderExpiry: time.Now().Add(-time.Second)}
	r.gst[arrivalA].mergeGossip(&GossipMessage{GroupHash: r.group, Election: held})
	lower := GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)}
	r.tell(arrivalA, arrivalA, lower)
	r.lem[arrivalA].ApplyGossipElection(r.group, lower) // the election manager's own rule too
	if table, manager := r.held(arrivalA); table.Term != 5 || manager.Term != 5 {
		t.Errorf("the voter took a lower term: gossip table %d, election manager %d, want 5", table.Term, manager.Term)
	}
}

// What an observer takes starts no election there, and nothing it tells
// makes one elsewhere: it sends no election message.
func TestNoElectionIsCausedByAMemberThatDoesNotVote(t *testing.T) {
	r := newTermRig(t, "noelect.term.example.", 300*time.Millisecond)
	r.gst[arrivalX].mergeGossip(&GossipMessage{GroupHash: r.group,
		Election: GroupElectionState{Leader: arrivalA, Term: 5, LeaderExpiry: time.Now().Add(-time.Second)}})
	r.tell(arrivalX, arrivalA, GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: time.Now().Add(400 * time.Millisecond)})
	time.Sleep(time.Second) // past the lease it took
	if n := r.sent[arrivalX].Load(); n != 0 {
		t.Errorf("the observer sent %d election message(s)", n)
	}
	// and a record an observer sends is not taken by a voter
	r.tell(arrivalA, arrivalX, GroupElectionState{Leader: arrivalX, Term: 9, LeaderExpiry: time.Now().Add(time.Hour)})
	if table, manager := r.held(arrivalA); table.Leader == arrivalX || manager.Leader == AgentId(arrivalX).String() {
		t.Errorf("a voter took an election record from a member that does not vote: %+v, %+v", table, manager)
	}
}
