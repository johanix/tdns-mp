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
// the peer from the canonical transport.Peer store and maps it into the hsync
// PeerState vocabulary the engine's send-decision gates speak.
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
func mechPeerState(e *Engine, peerID PeerID, mech string) PeerState {
	if e == nil || e.deps.Transport == nil {
		return PeerStateNeeded
	}
	reg := e.deps.Transport.PeerRegistry()
	if reg == nil {
		return PeerStateNeeded
	}
	p, ok := reg.Get(string(peerID))
	if !ok || p == nil {
		return PeerStateNeeded
	}
	st, ok := p.MechanismRawState(mech)
	if !ok {
		return PeerStateNeeded
	}
	return transportToHsyncState(st)
}

// transportToHsyncState maps a transport.PeerState to the hsync PeerState enum.
// transport has transient DISCOVERING/INTRODUCING and no LEGACY (an MP overlay
// concept); the engine has no transient equivalents, so DISCOVERING folds to
// NEEDED and INTRODUCING to INTRODUCED.
func transportToHsyncState(s transport.PeerState) PeerState {
	switch s {
	case transport.PeerStateNeeded, transport.PeerStateDiscovering:
		return PeerStateNeeded
	case transport.PeerStateKnown:
		return PeerStateKnown
	case transport.PeerStateIntroducing:
		return PeerStateIntroduced
	case transport.PeerStateOperational:
		return PeerStateOperational
	case transport.PeerStateDegraded:
		return PeerStateDegraded
	case transport.PeerStateInterrupted:
		return PeerStateInterrupted
	case transport.PeerStateError:
		return PeerStateError
	default:
		return PeerStateNeeded
	}
}

func forEachEnabledTransport(peer *Peer, fn func(name string, td *PeerDetails)) {
	if peer.DnsMethod && peer.DnsDetails != nil {
		fn(TransportDNS, peer.DnsDetails)
	}
	if peer.ApiMethod && peer.ApiDetails != nil {
		fn(TransportAPI, peer.ApiDetails)
	}
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

// transportParticipating is true once discovery or protocol has advanced past
// NEEDED. Used only by the dead-in-production hsync GossipStateTable's
// EffectiveState (see types.go) — removed with it in a later cleanup.
func transportParticipating(state PeerState) bool {
	return state >= PeerStateKnown
}

// transportReady reports whether a mechanism state is past the Hello handshake
// (INTRODUCED or any active state) — i.e. beat-eligible.
func transportReady(state PeerState) bool {
	switch state {
	case PeerStateIntroduced, PeerStateOperational, PeerStateLegacy,
		PeerStateDegraded, PeerStateInterrupted:
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
