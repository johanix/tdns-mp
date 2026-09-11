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
	local := string(r.LocalID)
	if local != "" && string(id) == local {
		return
	}

	peer, exists := r.S.Get(id)
	if exists {
		if zone != "" {
			r.AddZoneToPeer(id, zone)
		}
		if task != nil {
			peer.Mu.Lock()
			peer.Deferred = append(peer.Deferred, *task)
			peer.Mu.Unlock()
			r.S.Set(id, peer)
		}
		e.storeHook(peer)
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
	r.S.Set(id, peer)
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

// Rediscover forces a fresh discovery pass for an already-known peer (the
// `peer reset` path). MarkNeeded short-circuits known peers, so it cannot
// re-drive discovery; Rediscover resets the peer's per-mechanism state to
// NEEDED and re-runs attemptDiscovery, which re-resolves the address and
// drives hello -> operational. Discovery promotes NEEDED->KNOWN only when the
// state is <= NEEDED, so the reset is required for the hello kick to fire.
// Falls back to MarkNeeded for an unknown peer.
func (e *Engine) Rediscover(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, exists := e.registry.S.Get(id)
	if !exists {
		e.MarkNeeded(id, "", nil)
		return
	}
	peer.Mu.Lock()
	peer.State = PeerStateNeeded
	peer.LastState = time.Now()
	forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
		td.State = PeerStateNeeded
		td.DiscoveryFailures = 0
		td.LatestError = ""
	})
	peer.Mu.Unlock()
	e.registry.S.Set(id, peer)
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
// for a scan). The removal PRIMITIVE lives here; the pruning POLICY (who
// decides a peer is gone for good) is the caller's — today that is an
// explicit operator/API action, never automatic: peers that merely leave
// their last shared zone stay as LEGACY by design.
func (e *Engine) RemovePeer(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, ok := e.registry.S.Get(id)
	if !ok {
		return
	}
	// Stop any hello retrier running for this peer before dropping it.
	e.registry.cancelHello(id)
	e.registry.S.Remove(id)
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
		// State reads the canonical transport.Peer (END.0). A peer with no
		// transport entry maps to NEEDED — exactly the peers needing discovery.
		peer.Mu.RLock()
		apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
		id := peer.ID
		peer.Mu.RUnlock()
		apiState := mechPeerState(e, id, TransportAPI)
		dnsState := mechPeerState(e, id, TransportDNS)
		apiNeeded := apiMethod && apiState == PeerStateNeeded
		dnsNeeded := dnsMethod && dnsState == PeerStateNeeded

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
		apiNeedsHello := apiMethod && apiState == PeerStateKnown
		dnsNeedsHello := dnsMethod && dnsState == PeerStateKnown
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

func (e *Engine) attemptDiscovery(peer *Peer, discoverAPI, discoverDNS bool) {
	if e.deps.Transport == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := e.deps.Transport.DiscoverPeer(ctx, string(peer.ID))
	if err == nil {
		e.deps.Transport.AfterDiscoverPeer(peer)
	}
	if err != nil {
		peer.Mu.Lock()
		var failures uint32
		forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
			td.DiscoveryFailures++
			td.LatestError = err.Error()
			td.LatestErrorTime = time.Now()
			if td.DiscoveryFailures > failures {
				failures = td.DiscoveryFailures
			}
		})
		peer.Mu.Unlock()
		e.deps.Transport.FireDiscoveryFailed(peer.ID, fmt.Errorf("discover peer: %w (failures=%d)", err, failures))
		return
	}

	peer.Mu.Lock()
	forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
		td.DiscoveryFailures = 0
	})
	peer.Mu.Unlock()

	// Post-discovery usability + needs-hello read the canonical transport.Peer
	// (END.0). "Useful" = mechanism advanced past NEEDED; "needsHello" = at KNOWN.
	peer.Mu.RLock()
	apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
	id := peer.ID
	peer.Mu.RUnlock()
	apiState := mechPeerState(e, id, TransportAPI)
	dnsState := mechPeerState(e, id, TransportDNS)
	apiUseful := apiMethod && apiState >= PeerStateKnown
	dnsUseful := dnsMethod && dnsState >= PeerStateKnown
	apiNeedsHello := apiMethod && apiState == PeerStateKnown
	dnsNeedsHello := dnsMethod && dnsState == PeerStateKnown

	if !apiUseful && !dnsUseful {
		return
	}
	if !apiNeedsHello && !dnsNeedsHello {
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
	if e.registry.hasHelloCancel(peer.ID) {
		return
	}
	helloCtx, helloCancel := context.WithCancel(context.Background())
	e.registry.setHelloCancel(peer.ID, helloCancel)
	go e.helloRetrierNG(helloCtx, peer)
}
