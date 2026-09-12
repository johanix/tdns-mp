/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"github.com/johanix/tdns-transport/v2/transport"
)

const (
	TransportAPI = "API"
	TransportDNS = "DNS"
)

// mechPeerState reads the RAW (non-decayed) per-mechanism connection state of
// the peer from the canonical transport.Peer store; the engine's send-decision
// gates speak transport's vocabulary through the predicates below.
//
// transport.Peer is the SOLE functional connection-state store (END.0). The
// engine's Hello/Beat/discovery gates read it through here instead of the
// retired hsync.PeerDetails.State sidecar — so the END.0 dual-write that fed
// that sidecar is gone.
//
// RAW, not decayed: the gates ask "where are we in the handshake" (NEEDED →
// discover; KNOWN → Hello; INTRODUCED+ → Beat), which must not flip on liveness
// decay — a DEGRADED/INTERRUPTED mechanism stays beat-eligible (beats are how
// we recover). Same choice as mechStateForGate on the MP side.
//
// Absence (peer or mechanism not yet in the transport registry) maps to NEEDED:
// a peer with no transport entry is exactly one that still needs discovery, so
// the "needs discovery" gate stays correct.
func mechPeerState(e *Engine, peerID PeerID, mech string) transport.PeerState {
	if e == nil || e.deps.Transport == nil {
		return transport.PeerStateNeeded
	}
	reg := e.deps.Transport.PeerRegistry()
	if reg == nil {
		return transport.PeerStateNeeded
	}
	p, ok := reg.Get(string(peerID))
	if !ok || p == nil {
		return transport.PeerStateNeeded
	}
	st, ok := p.MechanismRawState(mech)
	if !ok {
		return transport.PeerStateNeeded
	}
	return st
}

// The gates, in transport's vocabulary. The retired hsync enum folded
// transport's transient DISCOVERING into NEEDED and INTRODUCING into
// INTRODUCED; these predicates keep those folds so no gate changes its
// answer.

// needsDiscovery: the mechanism has not been discovered (NEEDED, or a
// discovery that never completed).
func needsDiscovery(s transport.PeerState) bool {
	return s == transport.PeerStateNeeded || s == transport.PeerStateDiscovering
}

// pastDiscovery: the mechanism is usable, discovery is behind it.
func pastDiscovery(s transport.PeerState) bool {
	return !needsDiscovery(s)
}

// needsHello: discovered, not yet introduced.
func needsHello(s transport.PeerState) bool {
	return s == transport.PeerStateKnown
}

// introduced: the hello handshake is in progress and not yet confirmed by
// a beat round trip.
func introduced(s transport.PeerState) bool {
	return s == transport.PeerStateIntroducing
}

// beatOutboundSequence returns the outbound beat sequence for the peer from
// the canonical transport.Peer per-mechanism counters (max across mechanisms
// — the same shape the retired PeerDetails.SentBeats read had). The retired
// store lost its last SentBeats writer in Phase 2, which froze the wire
// sequence at 0 (2026-08-25 review, finding 2); the transport counters are
// maintained by the transport's own Beat() success path, the same source the
// infra beat loop already reads.
func (e *Engine) beatOutboundSequence(peerID PeerID) uint64 {
	if e == nil || e.deps.Transport == nil {
		return 0
	}
	reg := e.deps.Transport.PeerRegistry()
	if reg == nil {
		return 0
	}
	p, ok := reg.Get(string(peerID))
	if !ok || p == nil {
		return 0
	}
	seq := p.MechanismBeatSequence(TransportAPI)
	if d := p.MechanismBeatSequence(TransportDNS); d > seq {
		seq = d
	}
	return seq
}

// transportReady reports whether a mechanism state is past the Hello handshake
// (INTRODUCING or any active state) — i.e. beat-eligible.
func transportReady(state transport.PeerState) bool {
	switch state {
	case transport.PeerStateIntroducing, transport.PeerStateOperational,
		transport.PeerStateDegraded, transport.PeerStateInterrupted:
		return true
	}
	return false
}

// peerAnyTransportReady reports whether any enabled mechanism is beat-eligible,
// reading the canonical transport.Peer store (D2.5) via mechPeerState — not the
// retired hsync.PeerDetails.State sidecar.
func (e *Engine) peerAnyTransportReady(peer *Peer) bool {
	peer.Mu.RLock()
	apiMethod, dnsMethod := peer.ApiMethod, peer.DnsMethod
	id := peer.ID
	peer.Mu.RUnlock()
	if apiMethod && transportReady(mechPeerState(e, id, TransportAPI)) {
		return true
	}
	if dnsMethod && transportReady(mechPeerState(e, id, TransportDNS)) {
		return true
	}
	return false
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
