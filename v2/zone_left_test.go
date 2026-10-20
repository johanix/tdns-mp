/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Step 8, design 4.1: a zone that leaves its group. When this agent does not
// lead the zone now, what it scheduled for the zone's parent ends: the
// chain, the owed sync, and a sync under way, which is cancelled.

// zonesThatLeft reports each zone taken out of its group, to another group
// or to none, and zonesThatJoined only a zone that lands in one.
func TestARecomputeReportsTheZonesThatLeft(t *testing.T) {
	g1, g2 := "1111111111111111", "2222222222222222"
	before := map[string]*ProviderGroup{g1: {GroupHash: g1, Zones: []ZoneName{"a.example.", "b.example.", "c.example."}}}
	after := map[string]*ProviderGroup{g1: {GroupHash: g1, Zones: []ZoneName{"a.example."}}, g2: {GroupHash: g2, Zones: []ZoneName{"b.example."}}}
	left := zonesThatLeft(before, after)
	want := []zoneGroupChange{{zone: "b.example.", from: g1, to: g2}, {zone: "c.example.", from: g1, to: ""}}
	if !slices.Equal(left, want) {
		t.Errorf("left: %+v, want %+v", left, want)
	}
	if joined := zonesThatJoined(before, after); !slices.Equal(joined, []zoneGroupChange{{zone: "b.example.", from: g1, to: g2}}) {
		t.Errorf("joined: %+v", joined)
	}
}

// The leader of a zone's group has a sync of the zone in tdns's UPDATE retry
// loop when the owner's edit moves the zone out of the group: to a group this
// agent does not lead, or to no group (the owner took this agent's role).
// The sync under way is cancelled, and the UPDATE is not sent again; the
// chain and the owed sync end, and the plan's line says so.
func TestAnAgentThatLedTheGroupAZoneLeftDropsItsSync(t *testing.T) {
	for _, tc := range []struct{ name, zone string }{
		{"to another group", "another.left.group.example."},
		{"to no group", "nogroup.left.group.example."},
	} {
		t.Run(tc.name, func(t *testing.T) { zoneLeftDropsItsSync(t, tc.zone, tc.name == "to no group") })
	}
}

func zoneLeftDropsItsSync(t *testing.T, zone string, toNoGroup bool) {
	elog := &lockedBuffer{}
	saved := lgElect
	lgElect = slog.New(slog.NewTextHandler(elog, nil))
	t.Cleanup(func() { lgElect = saved })
	r := newNotifyRig(t, zone, "UPDATE", repeat(30*time.Millisecond, 400)...)
	us, peer := r.us.Identity, r.peer.Identity
	servedMembers(t, r.mpzd, []h3rec{{us, true}, {peer, true}}, []string{us, peer})
	refreshed(t, r.conf, r.mpzd)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName

	// the zone's group, which this agent leads; no per-zone result (zoneChanged
	// drops it once a group covers the zone)
	pgm := NewProviderGroupManager(us)
	r.lem.SetProviderGroupManager(pgm)
	r.lem.SetOnZoneLeft(func(zn ZoneName) bool { return r.conf.delegationSyncZoneLeft(string(zn)) })
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(ZoneName(z))
	if pg == nil {
		t.Fatal("the zone of two providers is in no group")
	}
	r.lem.dropZoneElection(ZoneName(z))
	r.lem.ApplyGossipElection(pg.GroupHash, GroupElectionState{Leader: us, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	if !r.lem.IsLeader(ZoneName(z)) {
		t.Fatal("this agent does not lead the zone's group")
	}

	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	r.parent.refuses()
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	underWay := func() int {
		c := &r.conf.InternalMp.delegationSyncChains
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.runs[z])
	}
	waitUntil(t, "an UPDATE reached the parent", func() bool { return r.parent.updatesSeen() > 0 })
	if underWay() != 1 {
		t.Fatal("the refused UPDATE is not being retried")
	}

	// The owner's edit, and the recompute it brings.
	if toNoGroup {
		servedMembers(t, r.mpzd, []h3rec{{us, true}, {peer, true}}, []string{peer})
	} else {
		servedMembers(t, r.mpzd, []h3rec{{us, true}, {peer, true}, {"c.third.example.", true}}, []string{us, peer, "c.third.example."})
	}
	pgm.RecomputeGroups()
	waitUntil(t, "the sync under way was stopped", func() bool { return underWay() == 0 })
	sent := r.parent.updatesSeen()
	time.Sleep(300 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != sent {
		t.Errorf("the UPDATE was sent again after the zone left the group: %d, then %d", sent, n)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left for a zone this agent does not lead", n)
	}
	if owed, _ := r.conf.InternalMp.CatchUp.owedState(ZoneName(z)); owed {
		t.Error("the sync is still owed")
	}
	if !strings.Contains(elog.String(), "zone left a group this agent leads, dropping its delegation sync") {
		t.Errorf("no line says the zone left a group this agent leads:\n%s", elog)
	}
}

// A zone that leaves a group this agent does not lead, and holds nothing for
// its parent here, is no news: no line.
func TestAZoneThatLeftAGroupThisAgentDidNotLeadSaysNothing(t *testing.T) {
	elog := &lockedBuffer{}
	saved := lgElect
	lgElect = slog.New(slog.NewTextHandler(elog, nil))
	t.Cleanup(func() { lgElect = saved })
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	conf := &Config{Config: &tdns.Config{}}
	lem.SetOnZoneLeft(func(zn ZoneName) bool { return conf.delegationSyncZoneLeft(string(zn)) })
	lem.zoneLeftGroup("quiet.left.example.", "1111111111111111", "")
	if strings.Contains(elog.String(), "zone left a group") {
		t.Errorf("a zone with nothing scheduled here was logged:\n%s", elog)
	}
}

// A zone that moves to another group this agent leads keeps its sync: it is
// decided by the state now, and this agent leads the zone.
func TestAZoneThatMovesToAGroupThisAgentLeadsKeepsItsSync(t *testing.T) {
	const zone = "moves.led.group.example."
	providerZone(t, zone, arrivalA, arrivalB)
	pgm := NewProviderGroupManager(arrivalA)
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(zone)
	if pg == nil {
		t.Fatal("the zone is in no group")
	}
	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	lem.SetProviderGroupManager(pgm)
	lem.ApplyGossipElection(pg.GroupHash, GroupElectionState{Leader: arrivalA, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.LeaderElectionManager = lem
	lem.SetOnZoneLeft(func(zn ZoneName) bool { return conf.delegationSyncZoneLeft(string(zn)) })
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	c.of(zone)
	c.mu.Unlock()

	lem.zoneLeftGroup(zone, "1111111111111111", pg.GroupHash)
	c.mu.Lock()
	_, kept := c.zones[zone]
	c.mu.Unlock()
	if !kept {
		t.Error("the sync chain of a zone this agent leads in its new group was dropped")
	}
}
