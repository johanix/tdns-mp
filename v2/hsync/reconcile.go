/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"time"
)

// ReconcileZone reads HSYNC3 for zone and symmetrically adds/removes registry peers.
func (e *Engine) ReconcileZone(zone ZoneName) (added, removed int, err error) {
	if e == nil || e.deps.Zones == nil || e.registry == nil {
		return 0, 0, nil
	}
	zv, ok := e.deps.Zones.Get(string(zone))
	if !ok || zv == nil {
		return 0, 0, nil
	}
	localIdentity := string(e.deps.LocalID)
	expected := IdentitiesFromRRset(zv.HSYNC3(), localIdentity)

	var toRemove []PeerID
	for _, peer := range e.registry.GetPeersForZone(zone) {
		if localIdentity != "" && string(peer.ID) == localIdentity {
			continue
		}
		if _, ok := expected[peer.ID]; !ok {
			toRemove = append(toRemove, peer.ID)
		}
	}

	for _, id := range toRemove {
		e.registry.RemovePeerFromZone(zone, id)
		if peer, ok := e.registry.S.Get(id); ok {
			e.registry.RecomputeSharedZones(peer)
		}
		removed++
	}

	for id := range expected {
		if _, already := e.registry.S.Get(id); already {
			e.MarkNeeded(id, zone, nil)
			continue
		}
		e.MarkNeeded(id, zone, nil)
		added++
	}
	return added, removed, nil
}

func (e *Engine) reconcileAllZones() {
	if e.deps.Zones == nil {
		return
	}
	added, removed, scanned := 0, 0, 0
	for name, zv := range e.deps.Zones.Items() {
		if zv == nil || !zv.IsMultiProvider() {
			continue
		}
		a, r, err := e.ReconcileZone(ZoneName(name))
		if err != nil {
			continue
		}
		scanned++
		added += a
		removed += r
	}
	_ = scanned
	_ = added
	_ = removed
}

func (e *Engine) runReconcile(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.reconcileAllZones()
		}
	}
}
