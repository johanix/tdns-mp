/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"time"
)

func (e *Engine) helloHandler(report *InboundReport) {
	if report == nil || report.MessageType != MsgHello {
		return
	}
}

func (e *Engine) agentNeedsHello(peer *Peer) bool {
	// Connection state reads the canonical transport.Peer (END.0); capability
	// flags (ApiMethod/DnsMethod) stay on the hsync.Peer.
	peer.Mu.RLock()
	apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
	id := peer.ID
	peer.Mu.RUnlock()
	apiNeeds := apiMethod && mechPeerState(e, id, TransportAPI) == PeerStateKnown
	dnsNeeds := dnsMethod && mechPeerState(e, id, TransportDNS) == PeerStateKnown
	return apiNeeds || dnsNeeds
}

func (e *Engine) helloRetrierNG(ctx context.Context, peer *Peer) {
	if !e.agentNeedsHello(peer) {
		return
	}
	fastAttempts := e.cfg.HelloFastAttempts
	fastInterval := e.cfg.HelloFastSpacing

	for attempt := 1; attempt <= fastAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(fastInterval):
			}
		}
		if !e.agentNeedsHello(peer) {
			e.fastBeatAttempts(ctx, peer)
			return
		}
		e.sendHelloToPeer(peer)
	}

	if !e.agentNeedsHello(peer) {
		e.fastBeatAttempts(ctx, peer)
		return
	}

	ticker := time.NewTicker(e.cfg.HelloRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !e.agentNeedsHello(peer) {
			e.fastBeatAttempts(ctx, peer)
			return
		}
		e.sendHelloToPeer(peer)
	}
}

func (e *Engine) sendHelloToPeer(peer *Peer) {
	if e.deps.Transport == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	zones := e.registry.sharedZones(peer)
	_ = e.deps.Transport.SendHello(ctx, peer, zones)
	e.registry.S.Set(peer.ID, peer)
}

func (e *Engine) fastBeatAttempts(ctx context.Context, peer *Peer) {
	const fastAttempts = 3
	const fastInterval = 5 * time.Second

	needsBeat := func() bool {
		// Connection state reads the canonical transport.Peer (END.0).
		peer.Mu.RLock()
		apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
		id := peer.ID
		peer.Mu.RUnlock()
		apiIntro := apiMethod && mechPeerState(e, id, TransportAPI) == PeerStateIntroduced
		dnsIntro := dnsMethod && mechPeerState(e, id, TransportDNS) == PeerStateIntroduced
		return apiIntro || dnsIntro
	}
	if !needsBeat() {
		return
	}
	for attempt := 1; attempt <= fastAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(fastInterval):
			}
		}
		if !needsBeat() {
			return
		}
		e.sendBeatToPeer(ctx, peer)
		if !needsBeat() {
			e.runDeferredTasks(peer)
			return
		}
	}
}
