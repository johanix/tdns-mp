/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

type mockTransport struct {
	discoverCalls atomic.Int32
}

func (m *mockTransport) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	m.discoverCalls.Add(1)
	return transport.NewPeer(identity), nil
}
func (m *mockTransport) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	return nil
}
func (m *mockTransport) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, string, error) {
	peer.Mu.RLock()
	dns, api := peer.DnsMethod, peer.ApiMethod
	peer.Mu.RUnlock()
	if dns {
		return true, TransportDNS, nil
	}
	if api {
		return true, TransportAPI, nil
	}
	return true, "", nil
}
func (m *mockTransport) MechanismSupported(name string) bool          { return true }
func (m *mockTransport) FireDiscoveryFailed(peerID PeerID, err error) {}
func (m *mockTransport) SyncPeerZones(peer *Peer)                     {}
func (m *mockTransport) AfterDiscoverPeer(peer *Peer)                 {}
func (m *mockTransport) PeerRegistry() *transport.PeerRegistry {
	return transport.NewPeerRegistry()
}

type mockZone struct {
	zone       string
	rrs        []dns.RR
	hsyncparam *core.HSYNCPARAM
	mp         bool
}

func (z *mockZone) ZoneName() string      { return z.zone }
func (z *mockZone) HSYNC3() []dns.RR      { return z.rrs }
func (z *mockZone) IsMultiProvider() bool { return z.mp }

func (z *mockZone) Participants() []PeerID {
	return testParticipantsFromHSYNC3(z.rrs, z.hsyncparam)
}

// testParticipantsFromHSYNC3 mirrors tdnsmp.zoneParticipants for mock RRs.
// Test-only — production derives participants via mpZoneView.Participants().
func testParticipantsFromHSYNC3(hsyncRRs []dns.RR, hsyncparam *core.HSYNCPARAM) []PeerID {
	if len(hsyncRRs) == 0 {
		return nil
	}

	labelToIdentity := map[string]string{}
	var allIdentities []PeerID
	for _, rr := range hsyncRRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.State == 0 { // skip OFF (decommissioned)
			continue
		}
		labelToIdentity[strings.TrimSuffix(h3.Label, ".")] = h3.Identity
		allIdentities = append(allIdentities, PeerID(h3.Identity))
	}

	if hsyncparam == nil {
		slices.SortFunc(allIdentities, func(a, b PeerID) int {
			return strings.Compare(string(a), string(b))
		})
		return slices.Compact(allIdentities)
	}

	seen := map[PeerID]bool{}
	var participants []PeerID
	addRole := func(labels []string) {
		for _, label := range labels {
			id, ok := labelToIdentity[strings.TrimSuffix(label, ".")]
			if !ok {
				continue
			}
			pid := PeerID(id)
			if !seen[pid] {
				participants = append(participants, pid)
				seen[pid] = true
			}
		}
	}
	addRole(hsyncparam.GetServers())
	addRole(hsyncparam.GetSigners())
	addRole(hsyncparam.GetAuditors())

	slices.SortFunc(participants, func(a, b PeerID) int {
		return strings.Compare(string(a), string(b))
	})
	return participants
}

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
	for tb.discoverCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if tb.discoverCalls.Load() == 0 {
		t.Fatal("expected DiscoverPeer to be called")
	}
}

// TestRediscover_triggersDiscoveryForExistingPeer is a regression test for the
// peer-reset bug: MarkNeeded short-circuits an already-known peer (so it cannot
// re-drive discovery), while Rediscover must force a fresh discovery pass.
func TestRediscover_triggersDiscoveryForExistingPeer(t *testing.T) {
	tb := &mockTransport{}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())

	waitFor := func(want int32) {
		deadline := time.Now().Add(2 * time.Second)
		for tb.discoverCalls.Load() < want && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Initial mark: creates the peer and runs discovery once.
	e.MarkNeeded("remote.example.", "z.test.", nil)
	waitFor(1)
	if got := tb.discoverCalls.Load(); got != 1 {
		t.Fatalf("expected 1 discovery after MarkNeeded, got %d", got)
	}

	// MarkNeeded on the now-known peer must NOT re-discover.
	e.MarkNeeded("remote.example.", "", nil)
	time.Sleep(100 * time.Millisecond)
	if got := tb.discoverCalls.Load(); got != 1 {
		t.Fatalf("MarkNeeded must not re-discover a known peer; discoverCalls=%d", got)
	}

	// Rediscover must force a fresh discovery pass for the existing peer.
	e.Rediscover("remote.example.")
	waitFor(2)
	if got := tb.discoverCalls.Load(); got < 2 {
		t.Fatalf("Rediscover must re-trigger discovery for a known peer; discoverCalls=%d", got)
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

func TestMockZoneParticipants_offExcluded(t *testing.T) {
	on := mustHSYNC3RR(t, "fox", "fox.example.")
	off := mustHSYNC3RR(t, "hare", "hare.example.")
	off.Data.(*core.HSYNC3).State = 0

	got := testParticipantsFromHSYNC3([]dns.RR{on, off}, nil)
	if len(got) != 1 || got[0] != PeerID("fox.example.") {
		t.Fatalf("got %v, want [fox.example.]", got)
	}
}

func TestMockZoneParticipants_hsyncparamRoles(t *testing.T) {
	fox := mustHSYNC3RR(t, "fox", "fox.example.")
	hare := mustHSYNC3RR(t, "hare", "hare.example.")
	param := &core.HSYNCPARAM{
		Value: []core.HSYNCPARAMKeyValue{
			&core.HSYNCPARAMServers{Servers: []string{"fox"}},
		},
	}

	got := testParticipantsFromHSYNC3([]dns.RR{fox, hare}, param)
	if len(got) != 1 || got[0] != PeerID("fox.example.") {
		t.Fatalf("got %v, want [fox.example.]", got)
	}
}
