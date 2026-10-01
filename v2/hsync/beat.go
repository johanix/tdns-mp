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
	// END.3 (Phase 3a): ONE writer per inbound message type — the producer
	// (DNS router / API handler) records inbound-liveness evidence on
	// transport.Peer. The former applyInboundBeat wrote only the retired
	// hsync.PeerDetails beat fields (zero readers post-D2.5) and is gone.
	// The engine keeps only its gossip side-effect.
	e.mergeGossipFromBeat(report)
}

// sendHeartbeats runs one beat round: the host refreshes its gossip rows, and
// every peer past the hello gets a beat. It returns the engine's view of its
// peers as the round found it (peersView), which paces the next round.
func (e *Engine) sendHeartbeats() string {
	view := e.peersView()
	if e.deps.Host.BeforeHeartbeats != nil {
		e.deps.Host.BeforeHeartbeats()
	} else if e.deps.Gossip != nil && e.deps.ProviderGroups != nil {
		e.deps.Gossip.RefreshLocalStates(e.registry, e.deps.ProviderGroups, e.deps.LocalBeatInterval)
		for _, pg := range e.deps.ProviderGroups.Groups() {
			e.deps.Gossip.CheckGroupState(pg.GroupHash, pg.Members)
		}
	}

	for _, peer := range e.registry.S.Items() {
		if peer.IsInfraPeer {
			continue
		}
		if !e.peerAnyTransportReady(peer) {
			continue
		}
		go func(p *Peer) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			e.sendBeatToPeer(ctx, p)
			// D2.5: the NG checkPeerState decay is retired — liveness decay now
			// lives on transport.Peer (EffectiveState decay-on-read), read by the
			// MP-side gossip path. No hsync.PeerDetails.State to decay here.
			e.runDeferredTasks(p)
		}(peer)
	}
	return view
}

func (e *Engine) sendBeatToPeer(ctx context.Context, peer *Peer) {
	if e.deps.Transport == nil {
		return
	}
	seq := e.beatOutboundSequence(peer.ID)
	before := e.peerView(peer.ID)

	// SendBeat (the MP bridge) writes the canonical transport.Peer mechanism
	// state OPERATIONAL on a successful round-trip — that is now the SOLE
	// connection-state store (D2.5). The former hsync.PeerDetails.State /
	// LatestError bookkeeping here was write-only (no live reader) and is
	// removed; outcome/error telemetry lives on transport.Peer.Stats.
	_, _, _ = e.deps.Transport.SendBeat(ctx, peer, seq)
	e.registry.S.Set(peer.ID, peer)
	e.storeHook(peer)
	// A beat that moved the peer (to OPERATIONAL, or back from a decay) is
	// news the other peers should get soon, in this agent's gossip row.
	if e.peerView(peer.ID) != before {
		e.kickBeats()
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
