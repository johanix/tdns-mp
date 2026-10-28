/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"fmt"
	"time"
)

// MarkNeeded creates or updates a peer in NEEDED state and kicks discovery.
func (e *Engine) MarkNeeded(id PeerID, zone ZoneName, task *DeferredTask) {
	if e == nil || e.registry == nil {
		return
	}
	r := e.registry
	if isLocal(r.LocalID, id) {
		return
	}

	// A known peer takes the zone and the task in place. A new peer is stored
	// only where none is: if another caller stored one first, this one adds to
	// it and leaves the discovery to that caller. Neither stores a peer that
	// was removed again (#132). Each pass of the loop that does not return
	// found a peer stored or removed by another caller in between.
	var peer *Peer
	for {
		if e.addToStoredPeer(id, zone, task) {
			return
		}
		peer = NewPeer(id)
		if e.deps.Transport != nil {
			peer.DnsMethod = e.deps.Transport.MechanismSupported("dns")
			peer.ApiMethod = e.deps.Transport.MechanismSupported("api")
		}
		if zone != "" {
			peer.Zones[zone] = true
		}
		if task != nil {
			peer.Deferred = append(peer.Deferred, *task)
		}
		if r.S.SetIfAbsent(id, peer) {
			break
		}
	}
	e.storeHook(peer)
	// Same concurrency limit as retryPendingDiscoveries, acquired inside
	// the goroutine so MarkNeeded itself never blocks (ReconcileZone calls
	// it once per expected identity).
	sem := e.discoverySem()
	go func(p *Peer, api, dns bool) {
		sem <- struct{}{}
		defer func() { <-sem }()
		e.attemptDiscovery(p, api, dns)
	}(peer, peer.ApiMethod, peer.DnsMethod)
}

// addToStoredPeer adds the zone and the task to the peer the registry holds,
// under the lock of its shard, and reports whether it held one.
func (e *Engine) addToStoredPeer(id PeerID, zone ZoneName, task *DeferredTask) bool {
	var stored *Peer
	ok := e.registry.S.UpdateIf(id, func(peer *Peer) (*Peer, bool) {
		peer.Mu.Lock()
		if zone != "" {
			if peer.Zones == nil {
				peer.Zones = make(map[ZoneName]bool)
			}
			peer.Zones[zone] = true
		}
		if task != nil {
			peer.Deferred = append(peer.Deferred, *task)
		}
		peer.Mu.Unlock()
		stored = peer
		return peer, true
	})
	if ok {
		e.storeHook(stored)
	}
	return ok
}

// Rediscover forces a fresh discovery pass for an already-known peer (the
// `peer reset` path). MarkNeeded short-circuits known peers, so it cannot
// re-drive discovery; Rediscover re-runs attemptDiscovery, which re-resolves
// the address and registers the result on transport.Peer, the sole
// connection-state store (a mechanism is promoted there only while it is
// still NEEDED; an established mechanism keeps its state). hsync.Peer.State
// is not written: nothing reads it (v4 D0). Falls back to MarkNeeded for an
// unknown peer.
func (e *Engine) Rediscover(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, exists := e.registry.S.Get(id)
	if !exists {
		e.MarkNeeded(id, "", nil)
		return
	}
	// The peer is not stored back: the object is the stored one, or the peer
	// is gone and the discovery starts no hello for it (#132).
	peer.Mu.Lock()
	peer.LastState = time.Now() // the reset is a state event for the display
	peer.Mu.Unlock()
	e.storeHook(peer)
	go e.attemptDiscovery(peer, peer.ApiMethod, peer.DnsMethod)
}

func (e *Engine) storeHook(peer *Peer) {
	if e.deps.PeerHooks.OnPeerStored != nil {
		e.deps.PeerHooks.OnPeerStored(peer)
	}
}

// RemovePeer removes a peer object from the registry and fires the
// OnPeerRemoved hook (Phase 3c: prunes are events, not reconcile-only —
// the application drops its view of the peer promptly instead of waiting
// for a scan). The reconcile loop removes a peer that no zone has named for
// the hold time (pruneUnsharedPeers); a provider that a zone names again
// later is a new peer to MarkNeeded, and is discovered afresh.
func (e *Engine) RemovePeer(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, ok := e.registry.S.Pop(id)
	if !ok {
		return
	}
	e.afterRemoval(peer)
}

// afterRemoval runs once the registry no longer holds peer: it stops the
// peer's hello retrier, drops the engine's notes of its beats, and fires the
// hook. It runs outside the map's locks. The notes are kept by identity: when
// a new peer under the same identity was stored in the moment since the
// removal, they may be the new peer's, and are left to it.
func (e *Engine) afterRemoval(peer *Peer) {
	e.registry.cancelHello(peer)
	if _, successor := e.registry.S.Get(peer.ID); !successor {
		e.forgetBeats(peer.ID)
	}
	if e.deps.PeerHooks.OnPeerRemoved != nil {
		e.deps.PeerHooks.OnPeerRemoved(peer)
	}
}

func (e *Engine) runDiscoveryRetry(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.RetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.retryPendingDiscoveries()
		}
	}
}

func (e *Engine) retryPendingDiscoveries() {
	if e.deps.Transport == nil {
		return
	}
	for _, peer := range e.registry.S.Items() {
		// A peer removed since the pass began has no transport entry either,
		// and would read NEEDED below: discovering it would make the transport
		// peer again that its removal had just dropped.
		if !e.holds(peer) {
			continue
		}
		// State reads the canonical transport.Peer (END.0). A peer with no
		// transport entry maps to NEEDED — exactly the peers needing discovery.
		peer.Mu.RLock()
		apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
		id := peer.ID
		peer.Mu.RUnlock()
		apiState := mechPeerState(e, id, TransportAPI)
		dnsState := mechPeerState(e, id, TransportDNS)
		// A mechanism with no address needs discovery whatever its state:
		// nothing can be sent to it, and nothing else looks the peer up
		// again (mechHasAddress).
		apiNeeded := apiMethod && (needsDiscovery(apiState) || !mechHasAddress(e, id, TransportAPI))
		dnsNeeded := dnsMethod && (needsDiscovery(dnsState) || !mechHasAddress(e, id, TransportDNS))

		if apiNeeded || dnsNeeded {
			sem := e.discoverySem()
			sem <- struct{}{}
			go func(p *Peer, api, dns bool) {
				defer func() { <-sem }()
				e.attemptDiscovery(p, api, dns)
			}(peer, apiNeeded, dnsNeeded)
			continue
		}

		// A peer that reached KNOWN without going through the engine's
		// attemptDiscovery (e.g. discovered via the chunk-notify kick) needs its
		// Hello started here — attemptDiscovery is the only other launcher, and
		// it didn't run for this peer. startHelloRetrier is idempotent (no-op if
		// a retrier is already running, so engine-discovered peers don't restart).
		apiNeedsHello := apiMethod && needsHello(apiState)
		dnsNeedsHello := dnsMethod && needsHello(dnsState)
		if apiNeedsHello || dnsNeedsHello {
			e.startHelloRetrier(peer)
		}
	}
}

func (e *Engine) discoverySem() chan struct{} {
	e.discSemOnce.Do(func() {
		limit := e.cfg.DiscoverySemLimit
		if limit < 1 {
			limit = 8
		}
		e.discSem = make(chan struct{}, limit)
	})
	return e.discSem
}

// holds reports whether the registry still holds this very peer object: not
// removed, and not replaced by a new peer under the same identity.
func (e *Engine) holds(peer *Peer) bool {
	cur, ok := e.registry.S.Get(peer.ID)
	return ok && cur == peer
}

func (e *Engine) attemptDiscovery(peer *Peer, discoverAPI, discoverDNS bool) {
	if e.deps.Transport == nil {
		return
	}
	// The pass that launched this may have seen the peer before its
	// removal: comms with it have ended, and a discovery now would make its
	// transport peer again (W1, a peer no zone names any more).
	if !e.holds(peer) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := e.deps.Transport.DiscoverPeer(ctx, string(peer.ID))
	// A removal while the lookup ran dropped the transport peer, and the
	// lookup may have made it again: the application drops what the lookup
	// left, as the removal would have done had it come after (W1).
	if !e.holds(peer) {
		if e.deps.PeerHooks.OnRemovedPeerDiscovered != nil {
			e.deps.PeerHooks.OnRemovedPeerDiscovered(peer)
		}
		return
	}
	if err == nil {
		e.deps.Transport.AfterDiscoverPeer(peer)
	}
	if err != nil {
		// The failure itself is recorded on transport.Peer by the
		// application's OnDiscoveryFailed (D0: the NG sidecar's failure
		// counters are gone).
		e.deps.Transport.FireDiscoveryFailed(peer.ID, fmt.Errorf("discover peer: %w", err))
		return
	}

	// Post-discovery usability + needs-hello read the canonical transport.Peer
	// (END.0). "Useful" = mechanism advanced past NEEDED; "needsHello" = at KNOWN.
	peer.Mu.RLock()
	apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
	id := peer.ID
	peer.Mu.RUnlock()
	apiState := mechPeerState(e, id, TransportAPI)
	dnsState := mechPeerState(e, id, TransportDNS)
	apiUseful := apiMethod && pastDiscovery(apiState)
	dnsUseful := dnsMethod && pastDiscovery(dnsState)
	apiNeedsHello := apiMethod && needsHello(apiState)
	dnsNeedsHello := dnsMethod && needsHello(dnsState)

	if !apiUseful && !dnsUseful {
		return
	}
	if !apiNeedsHello && !dnsNeedsHello {
		return
	}
	// A peer removed while it was looked up gets no hello (#132).
	if !e.stillStored(peer) {
		return
	}

	e.startHelloRetrier(peer)
}

// startHelloRetrier launches the Hello retrier for a peer, unless one is already
// running. Idempotent: safe to call from both attemptDiscovery (engine-driven
// discovery) and retryPendingDiscoveries (for peers discovered out-of-band that
// reached KNOWN without going through attemptDiscovery — e.g. the chunk-notify
// kick). The hello-launch is thus state-driven (KNOWN ⇒ hello), not tied to who
// discovered the peer.
func (e *Engine) startHelloRetrier(peer *Peer) {
	helloCtx, ok := e.registry.registerHello(peer)
	if !ok {
		return
	}
	go e.helloRetrierNG(helloCtx, peer)
}
