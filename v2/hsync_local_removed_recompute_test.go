/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * An agent that the owner takes out of a zone recomputes its provider groups
 * (tdns-mp #183).
 */
package tdnsmp

import (
	"testing"
	"time"
)

// The owner takes a provider out of a zone in one edit: its role and its
// HSYNC3 record go together. That provider's agent finds itself gone from
// the zone's HSYNC3 RRset when the refresh comes, and has nothing more to do
// with the zone's other providers. Its provider groups are recomputed all
// the same: the zone is in the group of the providers that are left, and
// this agent does not lead it. The agent used to keep the zone in the group
// it had been in, and went on answering that it led the zone.
func TestAnAgentTakenOutOfAZoneInOneEditLeavesTheZonesGroup(t *testing.T) {
	stays := providerZone(t, "stays.removed.example.", arrivalA, arrivalB, arrivalC)
	leaves := providerZone(t, "leaves.removed.example.", arrivalA, arrivalB, arrivalC)
	conf := roleConf(t, AppTypeMPAgent, "agent", arrivalA, stays, leaves)
	ar := conf.InternalMp.AgentRegistry
	pgm := ar.ProviderGroupManager
	NewHsyncDataEngine(conf)

	lem := NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	conf.InternalMp.LeaderElectionManager = lem
	ar.LeaderElectionManager = lem
	lem.SetProviderGroupManager(pgm)

	// The zones are loaded, and a peer's beat says that this agent leads the
	// group of the three.
	pgm.RecomputeGroups()
	ar.GossipStateTable.mergeGossip(&GossipMessage{GroupHash: ComputeGroupHash([]string{arrivalA, arrivalB, arrivalC}, nil, nil),
		Election: GroupElectionState{Leader: arrivalA, Term: 3, LeaderExpiry: time.Now().Add(time.Hour)}})
	if !lem.IsLeader(ZoneName(leaves.ZoneName)) || !lem.IsLeader(ZoneName(stays.ZoneName)) {
		t.Fatalf("before the edit this agent does not lead both zones of its group")
	}

	refreshWith(t, leaves, serve(arrivalB, arrivalC))

	inGroup(t, pgm, leaves, arrivalB, arrivalC)
	if lem.IsLeader(ZoneName(leaves.ZoneName)) {
		t.Errorf("the agent still answers that it leads %s, a zone it has been taken out of", leaves.ZoneName)
	}
	inGroup(t, pgm, stays, arrivalA, arrivalB, arrivalC)
	if !lem.IsLeader(ZoneName(stays.ZoneName)) {
		t.Errorf("the agent no longer leads %s, a zone nothing changed for", stays.ZoneName)
	}
}
