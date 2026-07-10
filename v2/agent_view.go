/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// A3d peer-element type-merge: transitional types and the canonical
// state-overlay accessor. transport.Peer is the SOLE connection-state store;
// these definitions stage the Agent-as-view migration without changing
// behavior. Design pinned in docs/2026-06-01-a3d-field-ownership.md.
//
// A3d.0 lands these additively (no live struct swap). The Agent-view embed
// (struct { *hsync.Peer; *agentMeta }) and the ~300-site read redirects to
// transport.Peer arrive in A3d.1–A3d.3.
package tdnsmp

import (
	"github.com/johanix/tdns-transport/v2/transport"
)

// The agentMeta/mechCrypto sidecar is GONE (Phase 2.5): per-mechanism crypto
// lives on transport.Peer's crypto slots (SetMechanismTLSA/JWK/KeyRR +
// MechanismTLSA/JWK/KeyRR accessors). Its InitialZone/Api fields were dead
// duplicates of the Agent-level fields and were folded out with it.

// transportToAgentState maps the canonical transport PeerState back to MP's
// AgentState (the read direction; transport.Peer is the source of truth).
// LEGACY is never produced here — it is the MP overlay applied by
// effectiveAgentState.
//
// transport.PeerState has the transient DISCOVERING/INTRODUCING and no LEGACY;
// MP has no transient equivalents, so DISCOVERING folds to NEEDED and
// INTRODUCING to INTRODUCED.
func transportToAgentState(s transport.PeerState) AgentState {
	switch s {
	case transport.PeerStateNeeded, transport.PeerStateDiscovering:
		return AgentStateNeeded
	case transport.PeerStateKnown:
		return AgentStateKnown
	case transport.PeerStateIntroducing:
		return AgentStateIntroduced
	case transport.PeerStateOperational:
		return AgentStateOperational
	case transport.PeerStateDegraded:
		return AgentStateDegraded
	case transport.PeerStateInterrupted:
		return AgentStateInterrupted
	case transport.PeerStateError:
		return AgentStateError
	default:
		return AgentStateNeeded
	}
}

// effectiveAgentState reads the canonical connection state from transport.Peer
// (the sole store) and applies the MP LEGACY overlay: an *established* peer with
// zero derived zone-participations is LEGACY. This is the one place the LEGACY
// concept (a zones concept transport knows nothing of) is reintroduced MP-side.
//
// The overlay fires only for OPERATIONAL/INTRODUCED, mirroring today's
// RecomputeSharedZonesAndSyncState transition exactly (DEGRADED/INTERRUPTED are
// liveness states and are not overlaid).
// isAgentOperational reports whether the agent has an operational transport,
// reading the canonical transport.Peer store. Replaces the former
// Agent.IsAnyTransportOperational. No LEGACY overlay (LEGACY is a display
// concept): a LEGACY peer's mechanism is still OPERATIONAL on transport.Peer,
// so it counts as operational for send-gating — matching prior behavior.
func (ar *AgentRegistry) isAgentOperational(id AgentId) bool {
	if ar.TransportManager == nil {
		return false
	}
	peer, ok := ar.TransportManager.PeerRegistry.Get(string(id))
	if !ok {
		return false
	}
	return peer.EffectiveState() == transport.PeerStateOperational
}

// mechStateForGate returns the RAW (non-decayed) per-mechanism state of the
// peer, mapped into MP's AgentState, for use by the Hello/Beat send gates.
// Raw — not decayed — because the gates ask "where are we in the handshake"
// (KNOWN → send Hello; INTRODUCED/OPERATIONAL/… → send Beat), which must not
// flip on liveness decay: a DEGRADED/INTERRUPTED mechanism is still
// beat-eligible (beats are how we recover), and that is exactly what the raw
// OPERATIONAL→…→INTERRUPTED ladder preserves. ok is false when the peer or the
// named mechanism is not (yet) in the registry — the caller then has no peer to
// gate on (treated as not-ready by the send paths).
func mechStateForGate(peer *transport.Peer, mech string) (AgentState, bool) {
	if peer == nil {
		return AgentStateNeeded, false
	}
	st, ok := peer.MechanismRawState(mech)
	if !ok {
		return AgentStateNeeded, false
	}
	return transportToAgentState(st), true
}

func (ar *AgentRegistry) effectiveAgentState(id AgentId) AgentState {
	if ar.TransportManager == nil {
		return AgentStateNeeded
	}
	peer, ok := ar.TransportManager.PeerRegistry.Get(string(id))
	if !ok {
		return AgentStateNeeded
	}
	st := transportToAgentState(peer.EffectiveState())
	if st == AgentStateOperational || st == AgentStateIntroduced {
		if len(ar.sharedParticipantZones(id)) == 0 {
			return AgentStateLegacy
		}
	}
	return st
}
