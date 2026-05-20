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
		if !peerAnyTransportReady(peer) {
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

	localInterval := time.Duration(ourBeatInterval) * time.Second
	if localInterval == 0 {
		localInterval = 30 * time.Second
	}

	anyActive := false
	anyHealthy := false

	evaluate := func(td *PeerDetails) {
		if td == nil || !transportParticipating(td.State) {
			return
		}
		switch td.State {
		case PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
			anyActive = true
		default:
			return
		}
		remoteInterval := time.Duration(td.BeatInterval) * time.Second
		if remoteInterval == 0 {
			remoteInterval = 30 * time.Second
		}
		sinceR := time.Since(td.LatestRBeat)
		sinceS := time.Since(td.LatestSBeat)
		if sinceR > 10*remoteInterval || sinceS > 10*localInterval {
			td.State = PeerStateInterrupted
		} else if sinceR > 2*remoteInterval || sinceS > 2*localInterval {
			td.State = PeerStateDegraded
		} else {
			anyHealthy = true
		}
	}

	if peer.DnsMethod {
		evaluate(peer.DnsDetails)
	}
	if peer.ApiMethod {
		evaluate(peer.ApiDetails)
	}

	if !anyActive {
		return
	}
	if anyHealthy {
		if peer.State == PeerStateNeeded || peer.State == PeerStateKnown || peer.State == PeerStateIntroduced {
			peer.State = PeerStateOperational
		}
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
