/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"slices"
	"testing"
	"time"
)

// Step 8: the group is its make-up, and its election gate counts the voting
// members only.

// The hash is of the three lists, each under its label: a member moved from
// one list to another, or two lists that write the same identities run
// together, is another group. Order and repeats within a list do not count.
func TestTheGroupHashTellsTheMakeUpsApart(t *testing.T) {
	a, b, c := "a.example.", "b.example.", "c.example."
	hashes := map[string]string{
		"all vote":      ComputeGroupHash([]string{a, b, c}, nil, nil),
		"c audits":      ComputeGroupHash([]string{a, b}, []string{c}, nil),
		"b audits":      ComputeGroupHash([]string{a, c}, []string{b}, nil),
		"c has no role": ComputeGroupHash([]string{a, b}, nil, []string{c}),
		"two audit":     ComputeGroupHash([]string{a}, []string{b, c}, nil),
		"split names":   ComputeGroupHash([]string{"a", "bb"}, nil, nil),
		"joined names":  ComputeGroupHash([]string{"ab", "b"}, nil, nil),
	}
	seen := map[string]string{}
	for name, h := range hashes {
		if other, ok := seen[h]; ok {
			t.Errorf("%q and %q have the same hash %s", name, other, h)
		}
		seen[h] = name
	}
	if ComputeGroupHash([]string{b, a, a}, []string{c}, nil) != hashes["c audits"] {
		t.Error("the order or a repeat within a list changed the hash")
	}
}

// Zones with the same providers and another make-up are two groups, and the
// zones of one group agree on who votes: no union of voting members, and no
// warning about one.
func TestTwoZonesWithTheSameProvidersAndAnotherMakeUpAreTwoGroups(t *testing.T) {
	one := providerZone(t, "one.makeup.example.", arrivalA, arrivalB)
	voteless(t, one, serve(arrivalA, arrivalB), arrivalX)
	same := providerZone(t, "same.makeup.example.", arrivalA, arrivalB)
	voteless(t, same, serve(arrivalA, arrivalB), arrivalX)
	other := providerZone(t, "other.makeup.example.", arrivalA, arrivalX)
	voteless(t, other, serve(arrivalA, arrivalX), arrivalB)

	pgm := NewProviderGroupManager(arrivalA)
	pgm.RecomputeGroups()
	g1 := pgm.GetGroupForZone(ZoneName(one.ZoneName))
	g2 := pgm.GetGroupForZone(ZoneName(same.ZoneName))
	g3 := pgm.GetGroupForZone(ZoneName(other.ZoneName))
	if g1 == nil || g2 == nil || g3 == nil {
		t.Fatalf("the zones' groups: %+v %+v %+v", g1, g2, g3)
	}
	if g1.GroupHash != g2.GroupHash {
		t.Errorf("two zones of one make-up are in two groups: %s and %s", g1.GroupHash, g2.GroupHash)
	}
	if g1.GroupHash == g3.GroupHash {
		t.Errorf("zones of the same providers and another make-up share group %s", g1.GroupHash)
	}
	want := func(name string, pg *ProviderGroup, voting, auditors []string) {
		t.Helper()
		if !slices.Equal(pg.VotingMembers, voting) || !slices.Equal(pg.Auditors, auditors) ||
			!slices.Equal(pg.Members, []string{arrivalA, arrivalB, arrivalX}) {
			t.Errorf("%s: voting %v, auditors %v, members %v; want voting %v, auditors %v and all three as members",
				name, pg.VotingMembers, pg.Auditors, pg.Members, voting, auditors)
		}
		if pg.GroupHash != ComputeGroupHash(voting, auditors, nil) {
			t.Errorf("%s: hash %s is not the hash of its make-up", name, pg.GroupHash)
		}
	}
	want("the group of A and B, X auditing", g1, []string{arrivalA, arrivalB}, []string{arrivalX})
	want("the group of A and X, B auditing", g3, []string{arrivalA, arrivalX}, []string{arrivalB})
}

// TestAGroupsZonesAgreeOnWhoVotes: every zone of a group has the group's
// voting members as its own.
func TestAGroupsZonesAgreeOnWhoVotes(t *testing.T) {
	for i, e := range []zoneEdit{serve(arrivalA, arrivalB), serve(arrivalA), serve(arrivalB)} {
		zd := providerZone(t, fmtZone(i)+"agree.example.", arrivalA, arrivalB)
		voteless(t, zd, e, arrivalX)
	}
	pgm := NewProviderGroupManager(arrivalA)
	pgm.RecomputeGroups()
	for _, pg := range pgm.GetGroups() {
		for _, z := range pg.Zones {
			if _, voting := participantsOf(instructionsFor(z)); !slices.Equal(voting, pg.VotingMembers) {
				t.Errorf("zone %s votes %v in group %s, whose voting members are %v", z, voting, pg.GroupHash, pg.VotingMembers)
			}
		}
	}
}

// newAuditedBeatRig is newBeatRig for a zone served by A and B and audited by
// X: the group's gate counts A and B.
func newAuditedBeatRig(t *testing.T, zoneName string) *beatRig {
	t.Helper()
	zone := providerZone(t, zoneName, arrivalA, arrivalB)
	voteless(t, zone, serve(arrivalA, arrivalB), arrivalX)
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
	return &beatRig{conf: conf, pgm: ar.ProviderGroupManager, gst: ar.GossipStateTable, lem: lem,
		group: ComputeGroupHash([]string{arrivalA, arrivalB}, []string{arrivalX}, nil), round: deps.Host.BeforeHeartbeats}
}

// rows writes the members' rows of the group, as a beat brings them.
func (r *beatRig) rows(rows map[string]map[string]string) {
	msg := &GossipMessage{GroupHash: r.group, Members: map[string]*MemberState{}}
	for id, peers := range rows {
		msg.Members[id] = &MemberState{Identity: id, PeerStates: peers, Timestamp: time.Now()}
	}
	r.gst.mergeGossip(msg)
}

// The voting members are mutually OPERATIONAL and the auditor is down: the
// heartbeat round calls the group's election all the same.
func TestAnAuditorThatIsDownDoesNotHoldTheElectionBack(t *testing.T) {
	r := newAuditedBeatRig(t, "down.auditor.example.")
	holdFirstLocalRows(r.conf.InternalMp.AgentRegistry, time.Minute)
	op := AgentStateToString[AgentStateOperational]
	r.rows(map[string]map[string]string{
		arrivalA: {arrivalB: op},
		arrivalB: {arrivalA: op},
	})
	within(t, 3*time.Second, "the heartbeat round", r.round)
	if es := r.lem.GetGroupElectionState(r.group); es.Term != 1 {
		t.Errorf("with the auditor down the group's election is at term %d, want it called (term 1)", es.Term)
	}
}

// The group is mutually OPERATIONAL, the auditor too; then the auditor goes
// down. The group stays OPERATIONAL: its leader is not invalidated.
func TestAnAuditorThatGoesDownDoesNotInvalidateTheLeader(t *testing.T) {
	r := newAuditedBeatRig(t, "goes.down.auditor.example.")
	holdFirstLocalRows(r.conf.InternalMp.AgentRegistry, time.Minute)
	degraded := 0
	r.gst.mu.Lock()
	wired := r.gst.onGroupDegraded
	r.gst.mu.Unlock()
	r.gst.SetOnGroupDegraded(func(h string) {
		degraded++
		if wired != nil {
			wired(h)
		}
	})
	op, down := AgentStateToString[AgentStateOperational], "DOWN"
	r.rows(map[string]map[string]string{
		arrivalA: {arrivalB: op, arrivalX: op},
		arrivalB: {arrivalA: op, arrivalX: op},
		arrivalX: {arrivalA: op, arrivalB: op},
	})
	within(t, 3*time.Second, "the heartbeat round", r.round)
	r.rows(map[string]map[string]string{
		arrivalA: {arrivalB: op, arrivalX: down},
		arrivalB: {arrivalA: op, arrivalX: down},
	})
	within(t, 3*time.Second, "the heartbeat round after the auditor went down", r.round)
	if degraded != 0 {
		t.Errorf("the auditor going down took the group out of mutual OPERATIONAL %d time(s)", degraded)
	}
}
