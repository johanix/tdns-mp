/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
)

// d25Transport is a TransportBridge whose PeerRegistry is STABLE (the base
// mockTransport returns a throwaway registry per call). D2.5 made the engine's
// Hello/Beat/discovery gates read connection state from transport.Peer via this
// registry, so the test must be able to seed a peer's mechanism state and have
// the gates observe it.
type d25Transport struct {
	reg *transport.PeerRegistry
}

func newD25Transport() *d25Transport {
	return &d25Transport{reg: transport.NewPeerRegistry()}
}

func (m *d25Transport) PeerRegistry() *transport.PeerRegistry { return m.reg }

// seed sets the raw per-mechanism state of a peer in the transport registry.
func (m *d25Transport) seed(id, mech string, st transport.PeerState) {
	p := m.reg.GetOrCreate(id)
	p.SetMechanismState(mech, st, "test seed")
}

func (m *d25Transport) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	return transport.NewPeer(identity), nil
}

// The remaining TransportBridge methods are unused by these gate tests.
func (m *d25Transport) RegisterDiscovered(peer *Peer, result *DiscoveryResult) error { return nil }
func (m *d25Transport) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	return nil
}
func (m *d25Transport) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, string, error) {
	return true, TransportDNS, nil
}
func (m *d25Transport) MechanismSupported(name string) bool          { return true }
func (m *d25Transport) FireDiscoveryFailed(peerID PeerID, err error) {}
func (m *d25Transport) SyncPeerZones(peer *Peer)                     {}
func (m *d25Transport) AfterDiscoverPeer(peer *Peer)                 {}

// engineWithTransport builds an Engine and registers a DNS-only hsync peer whose
// hsync.PeerDetails.State is left at the NEEDED init — proving the gates read
// transport.Peer, NOT the NG sidecar.
func engineWithD25(tb TransportBridge) (*Engine, *Peer) {
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())
	peer := NewPeer("remote.example.")
	peer.DnsMethod = true
	peer.ApiMethod = false
	// Deliberately leave peer.DnsDetails.State == NEEDED (the retired sidecar).
	e.registry.S.Set(peer.ID, peer)
	return e, peer
}

// TestD25_agentNeedsHello_readsTransport asserts the engine's Hello gate fires
// based on transport.Peer mechanism state (KNOWN), not hsync.PeerDetails.State.
// This is the regression guard for the END.0 dual-write removal: with the NG
// sidecar left at NEEDED, the gate must still fire once transport says KNOWN.
func TestD25_agentNeedsHello_readsTransport(t *testing.T) {
	tb := newD25Transport()
	e, peer := engineWithD25(tb)

	// transport says NEEDED (absent) -> no hello.
	if e.agentNeedsHello(peer) {
		t.Fatal("agentNeedsHello: want false when transport DNS state is NEEDED/absent")
	}

	// transport says KNOWN -> hello must fire, even though the NG sidecar is NEEDED.
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateKnown)
	if !e.agentNeedsHello(peer) {
		t.Fatalf("agentNeedsHello: want true when transport DNS state is KNOWN (NG sidecar=%s)",
			StateToString[peer.DnsDetails.State])
	}

	// transport advanced past KNOWN -> hello no longer needed.
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateIntroducing)
	if e.agentNeedsHello(peer) {
		t.Fatal("agentNeedsHello: want false when transport DNS state is INTRODUCING")
	}
}

// TestD25_peerAnyTransportReady_readsTransport asserts the steady-state beat
// readiness gate reads transport.Peer (INTRODUCED+ = beat-eligible), not the NG
// sidecar.
func TestD25_peerAnyTransportReady_readsTransport(t *testing.T) {
	tb := newD25Transport()
	e, peer := engineWithD25(tb)

	// NEEDED/absent and KNOWN are not beat-eligible.
	if e.peerAnyTransportReady(peer) {
		t.Fatal("peerAnyTransportReady: want false at NEEDED/absent")
	}
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateKnown)
	if e.peerAnyTransportReady(peer) {
		t.Fatal("peerAnyTransportReady: want false at KNOWN (pre-hello)")
	}

	// INTRODUCING (maps to INTRODUCED) and OPERATIONAL are beat-eligible.
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateIntroducing)
	if !e.peerAnyTransportReady(peer) {
		t.Fatal("peerAnyTransportReady: want true at INTRODUCING")
	}
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateOperational)
	if !e.peerAnyTransportReady(peer) {
		t.Fatal("peerAnyTransportReady: want true at OPERATIONAL")
	}
}
