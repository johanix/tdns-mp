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
	expected := e.expectedPeers(zv)

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

// expectedPeers returns the peers this agent expects in the zone: the zone's
// participants other than itself, and none at all where it has no standing
// (participates). Membership is HSYNCPARAM-derived (resolved by the host via
// ZoneView.Participants); HSYNC3 alone is just an identity↔label mapping and
// does not confer membership. An agent whose own record has left the zone,
// or whose role was taken, sends no hellos there that would be refused, and
// its comms with the zone's providers end (#178 step 7). With no local
// identity (harnesses) there is nothing to test.
func (e *Engine) expectedPeers(zv ZoneView) map[PeerID]struct{} {
	local := e.deps.LocalID
	expected := make(map[PeerID]struct{})
	if local != "" && !participates(zv, local) {
		return expected
	}
	for _, id := range zv.Participants() {
		if id != local {
			expected[id] = struct{}{}
		}
	}
	return expected
}

// ZoneNamesPeer reports whether a multi-provider zone this agent holds names
// id as a peer, by the test ReconcileZone makes. A discovery of an identity
// that no zone names puts nothing in the registry (design 3.3). An engine
// with no zones to ask (harnesses) counts every identity as named.
func (e *Engine) ZoneNamesPeer(id PeerID) bool {
	if e == nil || e.deps.Zones == nil {
		return true
	}
	for _, zv := range e.deps.Zones.Items() {
		if zv == nil || !zv.IsMultiProvider() {
			continue
		}
		if _, ok := e.expectedPeers(zv)[id]; ok {
			return true
		}
	}
	return false
}

// reconcileAllZones reconciles every multi-provider zone the agent holds,
// takes off its peers every zone it no longer holds, and then prunes the
// peers that no zone names. With that the engine's set of zones per peer holds
// the shared zones and no others (2.11), and "no zone shared" reads as: that
// set is empty.
func (e *Engine) reconcileAllZones() {
	if e.deps.Zones == nil {
		return
	}
	held := make(map[ZoneName]bool)
	for name, zv := range e.deps.Zones.Items() {
		if zv == nil || !zv.IsMultiProvider() {
			continue
		}
		held[ZoneName(name)] = true
		if _, _, err := e.ReconcileZone(ZoneName(name)); err != nil {
			continue
		}
	}
	e.dropZonesNotHeld(held)
	e.pruneUnsharedPeers(time.Now())
}

// dropZonesNotHeld takes off every peer the zones that are not in held: zones
// that left the agent's config, or are no longer multi-provider. The pass over
// the zones visits only the zones the agent has, so nothing else would.
func (e *Engine) dropZonesNotHeld(held map[ZoneName]bool) {
	for id, peer := range e.registry.S.Items() {
		var gone []ZoneName
		peer.Mu.RLock()
		for z := range peer.Zones {
			if !held[z] {
				gone = append(gone, z)
			}
		}
		peer.Mu.RUnlock()
		if len(gone) == 0 {
			continue
		}
		for _, z := range gone {
			e.registry.RemovePeerFromZone(z, id)
		}
		if stored, ok := e.registry.S.Get(id); ok {
			e.registry.RecomputeSharedZones(stored)
		}
	}
}

// pruneUnsharedPeers ends the comms with a peer that no zone has named for
// the hold time (design 3.1, decision 11). For every peer that is not an
// infrastructure peer:
//
//  1. a zone names it: Unshared is cleared, and a peer named again within the
//     hold time is kept;
//  2. no zone names it and Unshared is zero: Unshared is set to now;
//  3. no zone names it and Unshared is older than the hold time: the peer is
//     removed. The test is made again under the lock of the peer's shard, so
//     a zone that a refresh adds before the removal keeps the peer, and one
//     added after it finds no peer and MarkNeeded makes a new one.
//
// Until it is removed the peer is beaten whatever its state.
func (e *Engine) pruneUnsharedPeers(now time.Time) {
	hold := e.cfg.PeerHold
	if hold <= 0 {
		hold = DefaultConfig().PeerHold
	}
	for id, peer := range e.registry.S.Items() {
		if peer.IsInfraPeer {
			continue
		}
		peer.Mu.Lock()
		named := len(peer.Zones) > 0
		since := peer.Unshared
		switch {
		case named && !since.IsZero():
			peer.Unshared = time.Time{}
		case !named && since.IsZero():
			peer.Unshared = now
		}
		peer.Mu.Unlock()

		switch {
		case named && !since.IsZero():
			e.peerUnshared(peer, false)
		case !named && since.IsZero():
			e.peerUnshared(peer, true)
		case !named && now.Sub(since) >= hold:
			if e.beforePruneRemoval != nil {
				e.beforePruneRemoval(id)
			}
			removed := e.registry.S.RemoveCb(id, func(_ PeerID, stored *Peer, ok bool) bool {
				if !ok || stored != peer {
					return false
				}
				stored.Mu.RLock()
				defer stored.Mu.RUnlock()
				return len(stored.Zones) == 0 && !stored.Unshared.IsZero() && now.Sub(stored.Unshared) >= hold
			})
			if removed {
				e.afterRemoval(peer)
			}
		}
	}
}

func (e *Engine) peerUnshared(peer *Peer, unshared bool) {
	if e.deps.PeerHooks.OnPeerUnshared != nil {
		e.deps.PeerHooks.OnPeerUnshared(peer, unshared)
	}
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
