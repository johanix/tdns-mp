/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"
)

// D2.5: TestCheckPeerState_dnsOnlyDoesNotInterruptApi removed — the NG
// checkPeerState decay it exercised is retired (liveness decay now lives on
// transport.Peer via decayedMechanismState, where per-mechanism independence
// is covered by the transport boundary suite).

func TestHeartbeatHandler_dnsBeatMergesGossip(t *testing.T) {
	gst := &stubGossipPort{}
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

	if len(gst.merged) != 1 || gst.merged[0].GroupHash != "hash1" {
		t.Fatalf("expected gossip merge from DNS beat, got %+v", gst.merged)
	}
}

// stubGossipPort records merges; the engine has no gossip table of its own
// since D0 (the application wires its port).
type stubGossipPort struct{ merged []*GossipMessage }

func (s *stubGossipPort) MergeGossip(m *GossipMessage)                              { s.merged = append(s.merged, m) }
func (s *stubGossipPort) CheckGroupState(string, []string)                          {}
func (s *stubGossipPort) RefreshLocalStates(*Registry, ProviderGroupLookup, uint32) {}
func (s *stubGossipPort) SetOnGroupOperational(func(string))                        {}
func (s *stubGossipPort) SetOnGroupDegraded(func(string))                           {}
func (s *stubGossipPort) SetOnElectionUpdate(func(string, GroupElectionState))      {}
