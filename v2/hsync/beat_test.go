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

func TestCheckPeerState_dnsOnlyDoesNotInterruptApi(t *testing.T) {
	peer := NewPeer("peer.example.")
	peer.DnsMethod = true
	peer.ApiMethod = false
	now := time.Now()
	peer.DnsDetails.State = PeerStateOperational
	peer.DnsDetails.LatestRBeat = now
	peer.DnsDetails.LatestSBeat = now
	peer.DnsDetails.BeatInterval = 30
	peer.ApiDetails.State = PeerStateNeeded

	e := NewEngine(Deps{LocalBeatInterval: 30}, DefaultConfig())
	e.checkPeerState(peer, 30)

	if peer.ApiDetails.State != PeerStateNeeded {
		t.Fatalf("ApiDetails.State = %v, want NEEDED", StateToString[peer.ApiDetails.State])
	}
	if peer.DnsDetails.State != PeerStateOperational {
		t.Fatalf("DnsDetails.State = %v, want OPERATIONAL", StateToString[peer.DnsDetails.State])
	}
}

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
