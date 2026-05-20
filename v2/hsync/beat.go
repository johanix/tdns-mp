/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"time"
)

func (e *Engine) heartbeatHandler(report *InboundReport) {
	if report == nil || report.MessageType != MsgBeat {
		return
	}
	peer, exists := e.registry.S.Get(report.Identity)
	if !exists {
		return
	}
	now := time.Now()
	peer.Mu.Lock()
	switch report.Transport {
	case TransportDNS:
		applyInboundBeat(peer, TransportDNS, report.BeatInterval, now)
	case TransportAPI:
		applyInboundBeat(peer, TransportAPI, report.BeatInterval, now)
	}
	peer.Mu.Unlock()

	e.mergeGossipFromBeat(report)
}

func (e *Engine) mergeGossipFromBeat(report *InboundReport) {
	if e == nil || e.deps.Gossip == nil || report == nil {
		return
	}
	abp, ok := report.Msg.(*BeatPost)
	if !ok || len(abp.Gossip) == 0 {
		return
	}
	for i := range abp.Gossip {
		e.deps.Gossip.MergeGossip(&abp.Gossip[i])
	}
	if e.deps.ProviderGroups != nil {
		for i := range abp.Gossip {
			pg := e.deps.ProviderGroups.GetGroup(abp.Gossip[i].GroupHash)
			if pg != nil {
				e.deps.Gossip.CheckGroupState(pg.GroupHash, pg.Members)
			}
		}
	}
}

func (e *Engine) sendHeartbeats() {
	if e.deps.Host.BeforeHeartbeats != nil {
		e.deps.Host.BeforeHeartbeats()
	}
	if e.deps.Gossip != nil && e.deps.ProviderGroups != nil {
		e.deps.Gossip.RefreshLocalStates(e.registry, e.deps.ProviderGroups, e.deps.LocalBeatInterval)
		for _, pg := range e.deps.ProviderGroups.Groups() {
			e.deps.Gossip.CheckGroupState(pg.GroupHash, pg.Members)
		}
	}

	for _, peer := range e.registry.S.Items() {
		if peer.IsInfraPeer {
			continue
		}
		peer.Mu.RLock()
		apiState := peer.ApiDetails.State
		dnsState := peer.DnsDetails.State
		peer.Mu.RUnlock()

		if !transportReady(apiState) && !transportReady(dnsState) {
			continue
		}
		go func(p *Peer) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			e.sendBeatToPeer(ctx, p)
			e.checkPeerState(p, e.deps.LocalBeatInterval)
			e.runDeferredTasks(p)
		}(peer)
	}
}

func transportReady(s PeerState) bool {
	switch s {
	case PeerStateIntroduced, PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
		return true
	}
	return false
}

func (e *Engine) sendBeatToPeer(ctx context.Context, peer *Peer) {
	if e.deps.Transport == nil {
		return
	}
	peer.Mu.RLock()
	seq := beatOutboundSequence(peer)
	peer.Mu.RUnlock()

	ack, used, err := e.deps.Transport.SendBeat(ctx, peer, seq)
	peer.Mu.Lock()
	if used != "" {
		td := peerDetailsFor(peer, used)
		if td != nil {
			switch {
			case err != nil:
				td.LatestError = err.Error()
				td.LatestErrorTime = time.Now()
			case !ack:
				if td.LatestError == "" {
					td.LatestError = "beat not acknowledged"
					td.LatestErrorTime = time.Now()
				}
			default:
				td.LatestError = ""
				if td.State == PeerStateNeeded || td.State == PeerStateKnown || td.State == PeerStateIntroduced {
					td.State = PeerStateOperational
				}
				if peer.State == PeerStateNeeded || peer.State == PeerStateKnown || peer.State == PeerStateIntroduced {
					peer.State = PeerStateOperational
				}
			}
		}
	} else if err != nil {
		forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
			if transportReady(td.State) {
				td.LatestError = err.Error()
				td.LatestErrorTime = time.Now()
			}
		})
	}
	peer.Mu.Unlock()
	e.registry.S.Set(peer.ID, peer)
	e.storeHook(peer)
}

func (e *Engine) checkPeerState(peer *Peer, ourBeatInterval uint32) {
	peer.Mu.Lock()
	defer peer.Mu.Unlock()

	latestRBeat := peer.ApiDetails.LatestRBeat
	if peer.DnsDetails.LatestRBeat.After(latestRBeat) {
		latestRBeat = peer.DnsDetails.LatestRBeat
	}
	latestSBeat := peer.ApiDetails.LatestSBeat
	if peer.DnsDetails.LatestSBeat.After(latestSBeat) {
		latestSBeat = peer.DnsDetails.LatestSBeat
	}

	remoteBeatInterval := time.Duration(peer.ApiDetails.BeatInterval) * time.Second
	if dnsInterval := time.Duration(peer.DnsDetails.BeatInterval) * time.Second; dnsInterval > remoteBeatInterval {
		remoteBeatInterval = dnsInterval
	}
	if remoteBeatInterval == 0 {
		remoteBeatInterval = 30 * time.Second
	}
	localBeatInterval := time.Duration(ourBeatInterval) * time.Second
	if localBeatInterval == 0 {
		localBeatInterval = 30 * time.Second
	}

	apiActive, dnsActive := false, false
	switch peer.ApiDetails.State {
	case PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
		apiActive = true
	}
	switch peer.DnsDetails.State {
	case PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
		dnsActive = true
	}
	if !apiActive && !dnsActive {
		return
	}

	timeSinceLastReceivedBeat := time.Since(latestRBeat)
	timeSinceLastSentBeat := time.Since(latestSBeat)
	if timeSinceLastReceivedBeat > 10*remoteBeatInterval || timeSinceLastSentBeat > 10*localBeatInterval {
		peer.ApiDetails.State = PeerStateInterrupted
		peer.DnsDetails.State = PeerStateInterrupted
	} else if timeSinceLastReceivedBeat > 2*remoteBeatInterval || timeSinceLastSentBeat > 2*localBeatInterval {
		peer.ApiDetails.State = PeerStateDegraded
		peer.DnsDetails.State = PeerStateDegraded
	} else if peer.State == PeerStateNeeded || peer.State == PeerStateKnown || peer.State == PeerStateIntroduced {
		peer.State = PeerStateOperational
	}
}

func (e *Engine) runDeferredTasks(peer *Peer) {
	peer.Mu.Lock()
	tasks := peer.Deferred
	peer.Deferred = nil
	peer.Mu.Unlock()
	if len(tasks) == 0 {
		return
	}
	var remaining []DeferredTask
	for _, task := range tasks {
		if task.Precondition != nil && !task.Precondition() {
			remaining = append(remaining, task)
			continue
		}
		if task.Action == nil {
			continue
		}
		ok, err := task.Action()
		if err != nil || !ok {
			remaining = append(remaining, task)
		}
	}
	if len(remaining) > 0 {
		peer.Mu.Lock()
		peer.Deferred = append(peer.Deferred, remaining...)
		peer.Mu.Unlock()
	}
}
