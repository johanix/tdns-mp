/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"fmt"
	"time"
)

const discoveryFailureFlushThreshold = 3

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
	if zone != "" {
		r.addRemoteAgent(zone, peer)
	}
	e.storeHook(peer)
	go e.attemptDiscovery(peer, peer.ApiMethod, peer.DnsMethod)
}

func (e *Engine) storeHook(peer *Peer) {
	if e.deps.PeerHooks.OnPeerStored != nil {
		e.deps.PeerHooks.OnPeerStored(peer)
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
		peer.Mu.RLock()
		apiNeeded := peer.ApiMethod && peer.ApiDetails.State == PeerStateNeeded
		dnsNeeded := peer.DnsMethod && peer.DnsDetails.State == PeerStateNeeded
		peer.Mu.RUnlock()
		if !apiNeeded && !dnsNeeded {
			continue
		}
		sem := e.discoverySem()
		sem <- struct{}{}
		go func(p *Peer, api, dns bool) {
			defer func() { <-sem }()
			e.attemptDiscovery(p, api, dns)
		}(peer, apiNeeded, dnsNeeded)
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
		peer.ApiDetails.DiscoveryFailures++
		failures := peer.ApiDetails.DiscoveryFailures
		peer.ApiDetails.LatestError = err.Error()
		peer.ApiDetails.LatestErrorTime = time.Now()
		peer.Mu.Unlock()
		e.deps.Transport.FireDiscoveryFailed(peer.ID, fmt.Errorf("discover peer: %w (failures=%d)", err, failures))
		return
	}

	peer.Mu.Lock()
	peer.ApiDetails.DiscoveryFailures = 0
	peer.Mu.Unlock()

	peer.Mu.RLock()
	apiUseful := peer.ApiMethod && peer.ApiDetails.State >= PeerStateKnown
	dnsUseful := peer.DnsMethod && peer.DnsDetails.State >= PeerStateKnown
	apiNeedsHello := peer.ApiMethod && peer.ApiDetails.State == PeerStateKnown
	dnsNeedsHello := peer.DnsMethod && peer.DnsDetails.State == PeerStateKnown
	peer.Mu.RUnlock()

	if !apiUseful && !dnsUseful {
		return
	}
	if !apiNeedsHello && !dnsNeedsHello {
		return
	}

	helloCtx, helloCancel := context.WithCancel(context.Background())
	e.registry.setHelloCancel(peer.ID, helloCancel)
	go e.helloRetrierNG(helloCtx, peer)
}
