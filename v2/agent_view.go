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
	"github.com/miekg/dns"
)

// agentMeta is the TRANSITIONAL MP-side sidecar for per-peer fields whose final
// home is transport but whose migration is deferred. Keyed by PeerID in the
// AgentRegistry. Every field is tagged with its end-state destination — this is
// a holding pen, not a permanent store. See the field-ownership table in
// docs/2026-06-01-a3d-field-ownership.md §3–§4.
type agentMeta struct {
	InitialZone ZoneName               // → MP (or drop); 2 uses
	Api         *AgentApi              // → transport (mechanism client), at/after E1
	Crypto      map[string]*mechCrypto // keys "API","DNS"; → transport.Peer crypto slots @ E1
}

// mechCrypto is the per-mechanism MP-side crypto material that moves into
// transport.Peer's crypto slots at E1 (decision: identity crypto stays MP-side
// until E1). Holding pen only.
type mechCrypto struct {
	KeyRR        *dns.KEY
	TlsaRR       *dns.TLSA
	JWKData      string
	KeyAlgorithm string
}

// ensureCrypto returns the per-mechanism crypto holding pen for mech on this
// agent's transitional agentMeta sidecar, allocating the sidecar + entry
// lazily. Write path; the caller's locking contract matches the surrounding
// AgentDetails writes.
func (a *Agent) ensureCrypto(mech string) *mechCrypto {
	if a.meta == nil {
		a.meta = &agentMeta{}
	}
	if a.meta.Crypto == nil {
		a.meta.Crypto = make(map[string]*mechCrypto)
	}
	mc := a.meta.Crypto[mech]
	if mc == nil {
		mc = &mechCrypto{}
		a.meta.Crypto[mech] = mc
	}
	return mc
}

// cryptoFor returns the per-mechanism crypto for mech, or nil if none was
// recorded. Read-only; does not allocate.
func (a *Agent) cryptoFor(mech string) *mechCrypto {
	if a.meta == nil || a.meta.Crypto == nil {
		return nil
	}
	return a.meta.Crypto[mech]
}

// transportToAgentState maps the canonical transport PeerState back to MP's
// AgentState. Inverse of agentStateToTransportStateFn. LEGACY is never produced
// here — it is the MP overlay applied by effectiveAgentState.
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
