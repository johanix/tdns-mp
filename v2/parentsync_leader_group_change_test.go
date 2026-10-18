/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The election manager and a provider group that changes under it: a group
 * that loses its last zone, and a lease renewal after the group's zones or
 * votes have changed (tdns-mp #182).
 */
package tdnsmp

import (
	"slices"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// arrivalX is a provider that is a member of a group without a vote in it.
const arrivalX = "x.agent.example."

// leases gives every agent of the rig a lease of ttl. Before any election.
func (r *groupRig) leases(ttl time.Duration) {
	for _, lem := range r.lems {
		lem.leaderTTL = ttl
	}
}

// calledThrough notes the zone that each ELECT-CALL of the rig's agents is
// sent through: a group's election messages go to the agents of one of its
// zones. It returns the zones noted so far. Before any election.
func (r *groupRig) calledThrough() func() []ZoneName {
	var mu sync.Mutex
	var through []ZoneName
	for _, lem := range r.lems {
		send := lem.broadcastFunc
		lem.broadcastFunc = func(zone ZoneName, rfiType string, records map[string][]string) error {
			if rfiType == "ELECT-CALL" {
				mu.Lock()
				through = append(through, zone)
				mu.Unlock()
			}
			return send(zone, rfiType, records)
		}
	}
	return func() []ZoneName {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(through)
	}
}

// holdNothing fails the test when an agent of the rig holds election state
// for the rig's group.
func (r *groupRig) holdNothing(t *testing.T, when string) {
	t.Helper()
	for id, lem := range r.lems {
		if r.net.election(lem) != nil {
			t.Errorf("%s: %s holds election state for the group", when, id)
		}
	}
}

// voteless is the edit e with one more provider, which serves nothing and
// audits: a member of the zone's provider group that has no vote in it.
func voteless(t *testing.T, zd *tdns.ZoneData, e zoneEdit, auditor string) {
	t.Helper()
	e.listed = append(slices.Clone(e.listed), auditor)
	apex := e.apex(t, zd)
	rrset, _ := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	hp := rrset.RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
	hp.Value = append(hp.Value, &core.HSYNCPARAMAuditors{Auditors: []string{shortLabel(auditor)}})
	zd.Data.Set(zd.ZoneName, *apex)
	zd.InstallInitialSnapshot()
}

// alone makes the group of one agent and a member that is not in the rig
// mutually OPERATIONAL at that agent, as the beats between the two do.
func (r *groupRig) alone(agent, peer string) {
	op := AgentStateToString[AgentStateOperational]
	gst := r.gsts[AgentId(agent)]
	gst.MergeGossip(&GossipMessage{GroupHash: r.net.group, Members: map[string]*MemberState{
		agent: {Identity: agent, PeerStates: map[string]string{peer: op}, Timestamp: time.Now()},
		peer:  {Identity: peer, PeerStates: map[string]string{agent: op}, Timestamp: time.Now()},
	}})
	gst.CheckGroupState(r.net.group, []string{agent, peer})
}

// A group's last zone moves to another group: the owner added a provider to
// it. The group is gone, and its election with it: no member holds state for
// it, and nobody renews its lease. Each former member used to call the
// group's election at 90% of the lease, with the members it had; nobody
// answered, each of them having lost the group, and the election was aborted
// and retried until the lease ran out and after.
func TestAGroupThatLosesItsLastZoneHoldsNoElection(t *testing.T) {
	const ttl = 2 * time.Second
	members := []string{arrivalA, arrivalB}
	r := newGroupRig(t, members, arrivalA, arrivalB, arrivalC)
	r.leases(ttl)
	zone := providerZone(t, "last.gone.example.", members...)
	r.refresh()
	r.operational()
	r.leader(t, 1)
	r.take(1)

	serve(arrivalA, arrivalB, arrivalC).apply(t, zone)
	r.refresh()
	if pg := r.pgms[arrivalA].GetGroup(r.net.group); pg != nil {
		t.Fatalf("the group still has zones after its last one left: %+v", pg)
	}
	r.holdNothing(t, "after the group's last zone left it")

	// A message of the group's election that was still on its way, from a
	// member that had not lost the group yet, brings nothing back.
	r.lems[arrivalA].HandleGroupMessage(r.net.group, arrivalB, "ELECT-CALL",
		map[string][]string{"_term": {"2"}, "_vote": {"7"}, "_group": {r.net.group}})
	r.holdNothing(t, "after a late message for the group that is gone")

	// Past the end of the lease: the renewal is at 90% of it, and the
	// fallbacks of the other members follow within the last tenth.
	time.Sleep(ttl)
	if calls := r.net.callers(); len(calls) != 1 {
		t.Errorf("elections were called by %v, want the group's first election only: a group without a zone elects nobody", calls)
	}
	r.holdNothing(t, "after the lease of the group that is gone ran out")
}

// The same for the retry of an election that was aborted: its timer is
// armed, and the group's last zone leaves before it fires. It starts no
// election, and puts no state back.
//
// And for an election that was called in the moment the group went, by a
// caller that had read the group just before: the word that the group is
// gone came before the election and found nothing to drop. The election gets
// no answer, and its retry drops what it left.
func TestTheRetryOfAnElectionStartsNothingOnceTheGroupIsGone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		goneBefore bool // the group goes before the election is called, not after it was aborted
	}{
		{"the group goes while the retry is armed", false},
		{"the group went as the election was called", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := []string{arrivalA, arrivalB}
			r := newGroupRig(t, members, arrivalA)
			calls := r.calledThrough()
			zone := providerZone(t, "retry.gone.example.", members...)
			r.refresh()
			lem := r.lems[arrivalA]
			pg := r.pgms[arrivalA].GetGroup(r.net.group)
			if pg == nil {
				t.Fatalf("no group of %v", members)
			}
			gone := func() {
				serve(arrivalA, arrivalB, arrivalC).apply(t, zone)
				r.refresh()
			}

			// The election gets no vote from the peer, is aborted when the
			// vote timeout fires, and its retry is armed.
			if tc.goneBefore {
				gone()
			}
			lem.StartGroupElection(pg.GroupHash, pg.VotingMembers, pg.Zones)
			lem.onGroupVoteTimeout(pg.GroupHash, 1, pg.VotingMembers, pg.Zones)
			if !tc.goneBefore {
				gone()
				r.holdNothing(t, "after the group's last zone left it")
			}

			// The retry fires within 1.5 s of the abort.
			time.Sleep(1700 * time.Millisecond)
			if through := calls(); len(through) != 1 {
				t.Errorf("elections were called through %v, want the first one only: the retry is for a group that is gone", through)
			}
			r.holdNothing(t, "after the retry fired for the group that is gone")
		})
	}
}

// A group that is gone and comes back, here because the owner added a
// provider to its only zone and took it out again, is a new group: it has no
// leader when it is back, and it elects one when the beats find it mutually
// OPERATIONAL, as a new group does. Its members never stopped being
// OPERATIONAL to each other, so the gossip table has to forget that the
// group was, or the election would not be called.
func TestAGroupThatComesBackElectsAgain(t *testing.T) {
	members := []string{arrivalA, arrivalB}
	r := newGroupRig(t, members, arrivalA, arrivalB, arrivalC)
	zone := providerZone(t, "back.gone.example.", members...)
	r.refresh()
	r.operational()
	r.leader(t, 1)
	r.take(1)

	serve(arrivalA, arrivalB, arrivalC).apply(t, zone)
	r.refresh()
	serve(arrivalA, arrivalB).apply(t, zone)
	r.refresh()
	inGroup(t, r.pgms[arrivalA], zone, members...)
	for _, m := range members {
		if leader, ok := r.lems[AgentId(m)].GetGroupLeader(r.net.group); ok {
			t.Errorf("%s has %s as the leader of the group that came back, from before it was gone", m, leader)
		}
	}
	if got := r.take(0); len(got) != 0 {
		t.Fatalf("the group that came back has no leader yet, and somebody was asked: %+v", got)
	}

	r.operational()
	leader := r.leader(t, 1)
	got := r.take(1)
	if len(got) != 1 || got[0].agent != leader || got[0].zone != ZoneName(zone.ZoneName) || !got[0].leads {
		t.Fatalf("after the group that came back elected %s: asked %+v, want the leader asked once, for %s", leader, got, zone.ZoneName)
	}
}

// What the peers say of the election of a group that came back is news,
// whatever the term: the same leader in the same term, when only this agent
// lost the group for a moment, or a leader in a term that starts again from
// one, when every member lost it and they have elected anew. The gossip
// table hands a term on once, and a higher term wins: with the record from
// before the group was gone still in it, neither was handed on.
func TestAGroupThatComesBackHearsOfItsElectionAnew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		leader string
		term   uint32
		asks   int
	}{
		{"the same leader in the same term", arrivalB, 7, 0},
		{"this agent, in a term that starts again", arrivalA, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			members := []string{arrivalA, arrivalB}
			r := newGroupRig(t, members, arrivalA)
			zone := providerZone(t, "heard.gone.example.", members...)
			r.refresh()
			lem := r.lems[arrivalA]
			r.gossipLeader(arrivalA, arrivalB, 7)
			if leader, ok := lem.GetGroupLeader(r.net.group); !ok || leader != arrivalB {
				t.Fatalf("before the group was gone its leader is %q, want %s", leader, arrivalB)
			}

			serve(arrivalA, arrivalB, arrivalC).apply(t, zone)
			r.refresh()
			serve(arrivalA, arrivalB).apply(t, zone)
			r.refresh()
			r.take(0)

			r.gossipLeader(arrivalA, tc.leader, tc.term)
			if leader, ok := lem.GetGroupLeader(r.net.group); !ok || leader != AgentId(tc.leader) {
				t.Fatalf("after a peer told of the election of the group that came back, its leader is %q, want %s", leader, tc.leader)
			}
			got := r.take(tc.asks)
			if len(got) != tc.asks {
				t.Fatalf("asked %+v, want %d asked", got, tc.asks)
			}
			for _, c := range got {
				if c.zone != ZoneName(zone.ZoneName) || !c.leads {
					t.Errorf("asked %+v, want this agent asked as the leader of %s", c, zone.ZoneName)
				}
			}
		})
	}
}

// A lease renewal is called for the group as it is when the renewal is due.
// Between the election and its renewal one zone has left the group and
// another has joined it. The renewal is called through a zone the group has,
// not through the one that left, and its winner asks for the zones the group
// has. The call used to go through the first zone of the list from when the
// timer was armed, and so to the agents of a zone of another group.
func TestALeaseRenewalIsForTheGroupAsItIsThen(t *testing.T) {
	const ttl = 3 * time.Second
	members := []string{arrivalA, arrivalB}
	r := newGroupRig(t, members, arrivalA, arrivalB, arrivalC)
	r.leases(ttl)
	calls := r.calledThrough()
	// The first of the group's zones in the order of their names is the one
	// its election messages are sent through.
	leaves := providerZone(t, "a-leaves.renewal.example.", members...)
	stays := providerZone(t, "b-stays.renewal.example.", members...)
	joins := providerZone(t, "c-joins.renewal.example.", arrivalA, arrivalB, arrivalC)
	r.refresh()
	r.operational()
	leader := r.leader(t, 1)
	if got := r.take(2); len(got) != 2 {
		t.Fatalf("the election of %s asked %+v, want it asked for the group's two zones", leader, got)
	}

	serve(arrivalA, arrivalB, arrivalC).apply(t, leaves)
	serve(arrivalA, arrivalB).apply(t, joins)
	r.refresh()
	if got := r.take(1); len(got) != 1 || got[0].zone != ZoneName(joins.ZoneName) {
		t.Fatalf("after %s joined the group: asked %+v, want the leader asked for it", joins.ZoneName, got)
	}

	// The renewal, at 90% of the lease.
	r.net.waitSettled(t, 2, ttl)
	renewed := r.leader(t, 2)
	through := calls()
	if len(through) != 2 {
		t.Fatalf("elections were called through %v, want two calls: the first election and its renewal", through)
	}
	if through[1] != ZoneName(stays.ZoneName) {
		t.Errorf("the renewal was called through %s, want %s: %s has left the group", through[1], stays.ZoneName, leaves.ZoneName)
	}
	asked := map[ZoneName]int{}
	for _, c := range r.take(2) {
		if c.agent != renewed || !c.leads {
			t.Errorf("after the renewal: asked %+v, want only the leader %s asked", c, renewed)
		}
		asked[c.zone]++
	}
	if len(asked) != 2 || asked[ZoneName(stays.ZoneName)] != 1 || asked[ZoneName(joins.ZoneName)] != 1 {
		t.Errorf("the renewal's winner was asked for %v, want once for each zone the group has: %s and %s",
			asked, stays.ZoneName, joins.ZoneName)
	}
}

// A group with one voting member renews its lease by electing itself, and
// asks for the zones the group has then. A zone that joined the group after
// the election before was not asked for at the renewal: the list was the one
// from when the timer was armed.
func TestAOneVoterGroupRenewsForAZoneAddedSince(t *testing.T) {
	const ttl = 2 * time.Second
	r := newGroupRig(t, []string{arrivalA, arrivalX}, arrivalA)
	r.leases(ttl)
	first := providerZone(t, "first.onevoter.example.", arrivalA)
	voteless(t, first, serve(arrivalA), arrivalX)
	r.refresh()
	if pg := r.pgms[arrivalA].GetGroup(r.net.group); pg == nil || !slices.Equal(pg.VotingMembers, []string{arrivalA}) {
		t.Fatalf("the group of %s and %s is %+v, want it with one voting member", arrivalA, arrivalX, pg)
	}

	r.alone(arrivalA, arrivalX)
	if got := r.take(1); len(got) != 1 || got[0].zone != ZoneName(first.ZoneName) || !got[0].leads {
		t.Fatalf("the one voter elected itself and asked %+v, want it asked for %s", got, first.ZoneName)
	}

	added := providerZone(t, "added.onevoter.example.", arrivalA)
	voteless(t, added, serve(arrivalA), arrivalX)
	r.refresh()
	if got := r.take(1); len(got) != 1 || got[0].zone != ZoneName(added.ZoneName) {
		t.Fatalf("after %s joined the group: asked %+v, want the leader asked for it", added.ZoneName, got)
	}

	// The renewal, at 90% of the lease.
	asked := map[ZoneName]int{}
	for _, c := range r.take(2) {
		asked[c.zone]++
	}
	if len(asked) != 2 || asked[ZoneName(first.ZoneName)] != 1 || asked[ZoneName(added.ZoneName)] != 1 {
		t.Errorf("at the renewal the one voter asked for %v, want once for each zone the group has: %s and %s",
			asked, first.ZoneName, added.ZoneName)
	}
}

// A member whose vote the owner has taken away renews nothing. Here the
// group's one voter and its member without a vote change places: the group
// is the same, and this agent, which led it, is no longer among its voting
// members when its renewal is due. It used to elect itself once more, from
// the list of voting members it had when the timer was armed.
func TestAGroupMemberWithoutAVoteRenewsNothing(t *testing.T) {
	const ttl = 2 * time.Second
	r := newGroupRig(t, []string{arrivalA, arrivalX}, arrivalA)
	r.leases(ttl)
	zone := providerZone(t, "roles.onevoter.example.", arrivalA)
	voteless(t, zone, serve(arrivalA), arrivalX)
	r.refresh()
	r.alone(arrivalA, arrivalX)
	if got := r.take(1); len(got) != 1 {
		t.Fatalf("the one voter elected itself and asked %+v, want it asked for its zone", got)
	}

	voteless(t, zone, serve(arrivalX), arrivalA)
	r.refresh()
	if pg := r.pgms[arrivalA].GetGroup(r.net.group); pg == nil || !slices.Equal(pg.VotingMembers, []string{arrivalX}) {
		t.Fatalf("after the roles changed the group is %+v, want it with %s as its one voting member", pg, arrivalX)
	}

	// Past the end of the lease.
	time.Sleep(ttl)
	if got := r.take(0); len(got) != 0 {
		t.Errorf("the member without a vote renewed the lease and asked %+v", got)
	}
	if leader, ok := r.lems[arrivalA].GetGroupLeader(r.net.group); ok {
		t.Errorf("past the lease the group's leader here is %s, want none: the member without a vote elected nobody", leader)
	}
}

// A timer of the group's election reads this agent's vote as a sender's is
// read: the voting members come from zone data and carry the trailing dot,
// a configured identity need not. An agent configured without the dot is a
// voter, and its renewal starts; one that is not a member is not.
func TestARenewalCountsTheVoteOfAnIdentityWithoutTheTrailingDot(t *testing.T) {
	const group = "0123456789abcdef"
	pgm := NewProviderGroupManager("a.timer.example")
	pgm.Groups[group] = &ProviderGroup{
		GroupHash:     group,
		Members:       []string{"a.timer.example.", "b.timer.example."},
		VotingMembers: []string{"a.timer.example.", "b.timer.example."},
		Zones:         []ZoneName{"zone.timer.example."},
	}
	for _, tc := range []struct {
		id    AgentId
		voter bool
	}{
		{"a.timer.example", true},
		{"a.timer.example.", true},
		{"c.timer.example", false},
	} {
		lem := NewLeaderElectionManager(tc.id, time.Hour, nil)
		lem.providerGroupMgr = pgm
		if got := lem.groupForTimer(group, "lease renewal") != nil; got != tc.voter {
			t.Errorf("%s: the timer starts an election: %v, want %v", tc.id, got, tc.voter)
		}
	}
}
