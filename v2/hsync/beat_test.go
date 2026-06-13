/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"
	"time"
)

func TestEffectiveState_dnsOnlyOperational(t *testing.T) {
	peer := NewPeer("peer.example.")
	peer.DnsMethod = true
	peer.ApiMethod = false
	peer.DnsDetails.State = PeerStateOperational
	peer.DnsDetails.LatestRBeat = time.Now()
	peer.DnsDetails.LatestSBeat = time.Now()

	if got := peer.EffectiveState(); got != PeerStateOperational {
		t.Fatalf("EffectiveState() = %v, want OPERATIONAL", StateToString[got])
	}
}

// D2.5: TestCheckPeerState_dnsOnlyDoesNotInterruptApi removed — the NG
// checkPeerState decay it exercised is retired (liveness decay now lives on
// transport.Peer via decayedMechanismState, where per-mechanism independence
// is covered by the transport boundary suite).

func TestHeartbeatHandler_dnsBeatMergesGossip(t *testing.T) {
	gst := NewGossipStateTable("local.example.")
	e := NewEngine(Deps{
		LocalID: "local.example.",
		Gossip:  gst,
	}, DefaultConfig())
	e.registry.S.Set("peer.example.", NewPeer("peer.example."))

	e.heartbeatHandler(&InboundReport{
		Transport:   TransportDNS,
		MessageType: MsgBeat,
		Identity:    "peer.example.",
		Msg: &BeatPost{
			Gossip: []GossipMessage{{
				GroupHash: "hash1",
				Members: map[string]*MemberState{
					"peer.example.": {Identity: "peer.example."},
				},
			}},
		},
	})

	gst.mu.RLock()
	_, ok := gst.States["hash1"]
	gst.mu.RUnlock()
	if !ok {
		t.Fatal("expected gossip merge from DNS beat")
	}
}
