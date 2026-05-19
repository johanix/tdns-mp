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
// HSYNC3 RRset and ensures every listed identity is present in the
// AgentRegistry. Missing peers are added via MarkAgentAsNeeded,
// which triggers the normal discovery → HELLO → BEAT chain.
//
// This is a safety-net pass that catches:
//   - Incremental HSYNC3 updates that bypass or fail UpdateAgents'
//     diff path.
//   - Auditors that have no UpdateAgents flow at all and would
//     otherwise only learn peers via inbound message receipt.
//   - Stale registry entries from zone-format migrations.
//
// The pass is purely additive: it never removes peers from the
// registry. Removal continues to be handled by HsyncRemoves in
// UpdateAgents on the agent side, where it belongs.
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

// reconcileAllZones iterates every known MP zone, reads its HSYNC3
// RRset, and ensures every listed identity is in the registry.
func (ar *AgentRegistry) reconcileAllZones() {
	added := 0
	scanned := 0

	for zoneName, mpzd := range Zones.Items() {
		if mpzd == nil {
			continue
		}
		if !mpzd.Options[tdns.OptMultiProvider] {
			continue
		}
		n, err := ar.reconcileZone(mpzd)
		if err != nil {
			lgAgent.Debug("HsyncReconcile: skipping zone", "zone", zoneName, "err", err)
			continue
		}
		scanned++
		added += n
	}

	if added > 0 {
		lgAgent.Info("HsyncReconcile pass complete",
			"zones_scanned", scanned, "peers_added", added)
	}
}

// reconcileZone reads the current HSYNC3 RRset for one zone and
// calls MarkAgentAsNeeded for each listed identity. Returns the
// number of peers newly added in this pass (peers already present
// are a no-op).
func (ar *AgentRegistry) reconcileZone(mpzd *MPZoneData) (int, error) {
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil {
		return 0, fmt.Errorf("get apex: %w", err)
	}

	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists || len(hsync3RRset.RRs) == 0 {
		return 0, nil
	}

	localIdentity := ""
	if ar.LocalAgent != nil {
		localIdentity = ar.LocalAgent.Identity
	}

	added := 0
	zoneName := ZoneName(mpzd.ZoneName)

	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		if h3.Identity == "" {
			continue
		}
		if h3.Identity == localIdentity {
			continue
		}

		remoteID := AgentId(h3.Identity)
		if _, already := ar.S.Get(remoteID); already {
			// Idempotent: still call MarkAgentAsNeeded so the
			// zone association is refreshed if needed.
			ar.MarkAgentAsNeeded(remoteID, zoneName, nil)
			continue
		}

		lgAgent.Info("HsyncReconcile: registering missing peer",
			"zone", zoneName, "identity", remoteID)
		ar.MarkAgentAsNeeded(remoteID, zoneName, nil)
		added++
	}

	return added, nil
}
