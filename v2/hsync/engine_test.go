/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

type mockTransport struct {
	discoverCalls int
}

func (m *mockTransport) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	m.discoverCalls++
	return transport.NewPeer(identity), nil
}
func (m *mockTransport) RegisterDiscovered(peer *Peer, result *DiscoveryResult) error {
	return nil
}
func (m *mockTransport) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	return nil
}
func (m *mockTransport) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, error) {
	peer.Mu.Lock()
	peer.ApiDetails.State = PeerStateOperational
	peer.Mu.Unlock()
	return true, nil
}
func (m *mockTransport) MechanismSupported(name string) bool          { return true }
func (m *mockTransport) FireDiscoveryFailed(peerID PeerID, err error) {}
func (m *mockTransport) SyncPeerZones(peer *Peer)                     {}
func (m *mockTransport) AfterDiscoverPeer(peer *Peer)                 {}
func (m *mockTransport) PeerRegistry() *transport.PeerRegistry {
	return transport.NewPeerRegistry()
}

type mockZone struct {
	zone string
	rrs  []dns.RR
	mp   bool
}

func (z *mockZone) ZoneName() string      { return z.zone }
func (z *mockZone) HSYNC3() []dns.RR      { return z.rrs }
func (z *mockZone) IsMultiProvider() bool { return z.mp }

type mapZoneLookup map[string]*mockZone

func (m mapZoneLookup) Get(zone string) (ZoneView, bool) {
	z, ok := m[zone]
	return z, ok
}
func (m mapZoneLookup) Items() map[string]ZoneView {
	out := make(map[string]ZoneView, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestMarkNeeded_triggersDiscovery(t *testing.T) {
	tb := &mockTransport{}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())
	e.MarkNeeded("remote.example.", "z.test.", nil)
	deadline := time.Now().Add(2 * time.Second)
	for tb.discoverCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if tb.discoverCalls == 0 {
		t.Fatal("expected DiscoverPeer to be called")
	}
}

func TestEngine_dispatchRoutesSyncHandler(t *testing.T) {
	var got bool
	e := NewEngine(Deps{LocalID: "local.example.", Transport: &mockTransport{}}, DefaultConfig())
	e.SetSyncHandler(func(msg *InboundMsg) {
		if msg != nil && msg.Originator == "peer.example." {
			got = true
		}
	})
	e.dispatchByType(&InboundMsg{Originator: "peer.example.", MessageType: MsgNotify})
	if !got {
		t.Fatal("sync handler not invoked")
	}
}

func TestCheckGroupState_operational(t *testing.T) {
	gst := NewGossipStateTable("a.example.")
	members := []string{"a.example.", "b.example."}
	gst.UpdateLocalState("hash", map[string]string{
		"b.example.": StateToString[PeerStateOperational],
	}, nil, 30)
	gst.States["hash"]["b.example."] = &MemberState{
		Identity: "b.example.",
		PeerStates: map[string]string{
			"a.example.": StateToString[PeerStateOperational],
		},
		Timestamp: time.Now(),
	}
	var fired bool
	gst.SetOnGroupOperational(func(string) { fired = true })
	gst.CheckGroupState("hash", members)
	if !fired {
		t.Fatal("expected operational callback")
	}
}
