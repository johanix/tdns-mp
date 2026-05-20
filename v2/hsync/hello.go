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
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	apiNeeds := peer.ApiMethod && peer.ApiDetails.State == PeerStateKnown
	dnsNeeds := peer.DnsMethod && peer.DnsDetails.State == PeerStateKnown
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
		peer.Mu.RLock()
		defer peer.Mu.RUnlock()
		apiIntro := peer.ApiMethod && peer.ApiDetails.State == PeerStateIntroduced
		dnsIntro := peer.DnsMethod && peer.DnsDetails.State == PeerStateIntroduced
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
