/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
)

// ReconcileHsync periodically walks every multi-provider zone's
// HSYNC3 RRset and reconciles the AgentRegistry with that RRset:
// missing peers are added via MarkAgentAsNeeded (discovery → HELLO →
// BEAT), and peers no longer listed are removed for that zone.
//
// This is a safety-net pass that catches:
//   - Incremental HSYNC3 updates that bypass or fail UpdateAgents'
//     diff path.
//   - Auditors that have no UpdateAgents flow at all.
//   - Stale registry entries after HSYNC3 removals or migrations.
//
// MarkAgentAsNeeded is idempotent for already-registered peers
// (it returns early after adding the zone association), so this
// loop is safe to run on a short interval.
func (ar *AgentRegistry) ReconcileHsync(ctx context.Context) {
	interval := configureInterval("multi-provider.syncengine.intervals.reconcile", 60, 3600)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	lgAgent.Info("HsyncReconcile started", "interval_sec", interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ar.reconcileAllZones()
		}
	}
}

// reconcileAllZones iterates every known MP zone and reconciles its
// HSYNC3 RRset against the registry.
func (ar *AgentRegistry) reconcileAllZones() {
	added := 0
	removed := 0
	scanned := 0

	for zoneName, mpzd := range Zones.Items() {
		if mpzd == nil {
			continue
		}
		if !mpzd.Options[tdns.OptMultiProvider] {
			continue
		}
		a, r, err := ar.reconcileZone(mpzd)
		if err != nil {
			lgAgent.Debug("HsyncReconcile: skipping zone", "zone", zoneName, "err", err)
			continue
		}
		scanned++
		added += a
		removed += r
	}

	if added > 0 || removed > 0 {
		lgAgent.Info("HsyncReconcile pass complete",
			"zones_scanned", scanned, "peers_added", added, "peers_removed", removed)
	}
}

// reconcileZone reads the current HSYNC3 RRset for one zone, removes
// registry entries for identities no longer listed, and adds missing
// ones. Returns counts of peers newly added and removed in this pass.
func (ar *AgentRegistry) reconcileZone(mpzd *MPZoneData) (added int, removed int, err error) {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return 0, 0, fmt.Errorf("get apex: %w", err)
	}
	if apex == nil {
		return 0, 0, nil
	}

	localIdentity := ""
	if ar.LocalAgent != nil {
		localIdentity = ar.LocalAgent.Identity
	}

	zoneName := ZoneName(mpzd.ZoneName)
	expected := make(map[AgentId]struct{})

	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if exists && len(hsync3RRset.RRs) > 0 {
		for id := range hsync3IdentitiesFromRRset(hsync3RRset.RRs, localIdentity) {
			expected[id] = struct{}{}
		}
	}

	var toRemove []AgentId
	for _, agent := range ar.GetAgentsForZone(zoneName) {
		if localIdentity != "" && string(agent.Identity) == localIdentity {
			continue
		}
		if _, ok := expected[agent.Identity]; !ok {
			toRemove = append(toRemove, agent.Identity)
		}
	}

	for _, remoteID := range toRemove {
		lgAgent.Info("HsyncReconcile: removing peer no longer in HSYNC3",
			"zone", zoneName, "identity", remoteID)
		ar.RemoveRemoteAgent(zoneName, remoteID)
		if agent, ok := ar.S.Get(remoteID); ok {
			ar.RecomputeSharedZonesAndSyncState(agent)
		}
		removed++
	}

	for remoteID := range expected {
		if _, already := ar.S.Get(remoteID); already {
			ar.MarkAgentAsNeeded(remoteID, zoneName, nil)
			continue
		}

		lgAgent.Info("HsyncReconcile: registering missing peer",
			"zone", zoneName, "identity", remoteID)
		ar.MarkAgentAsNeeded(remoteID, zoneName, nil)
		added++
	}

	return added, removed, nil
}

// hsync3IdentitiesFromRRset returns remote HSYNC3 identities in rrset,
// excluding localIdentity when non-empty.
func hsync3IdentitiesFromRRset(rrs []dns.RR, localIdentity string) map[AgentId]struct{} {
	out := make(map[AgentId]struct{})
	for _, rr := range rrs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.Identity == "" {
			continue
		}
		if localIdentity != "" && h3.Identity == localIdentity {
			continue
		}
		out[AgentId(h3.Identity)] = struct{}{}
	}
	return out
}
