/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/miekg/dns"
)

func TestReconcileZone_removesStalePeer(t *testing.T) {
	const zone = "customer.test."
	rrs := []dns.RR{mustHSYNC3RR(t, "fox", "fox.agent.example.")}
	zl := mapZoneLookup{
		zone: &mockZone{zone: zone, rrs: rrs, mp: true},
	}
	e := NewEngine(Deps{
		LocalID:   "self.agent.example.",
		Transport: &mockTransport{},
		Zones:     zl,
	}, DefaultConfig())

	stale := NewPeer("stale.agent.example.")
	stale.Zones[ZoneName(zone)] = true
	e.registry.S.Set(stale.ID, stale)
	e.registry.addRemoteAgent(ZoneName(zone), stale)

	added, removed, err := e.ReconcileZone(ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("added=%d, want 1", added)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
	staleAfter, exists := e.registry.S.Get(stale.ID)
	if !exists {
		t.Fatal("stale peer should remain in registry")
	}
	staleAfter.Mu.RLock()
	_, inZone := staleAfter.Zones[ZoneName(zone)]
	staleAfter.Mu.RUnlock()
	if inZone {
		t.Fatal("stale peer should no longer be in zone")
	}
}

func TestReconcileZone_emptyHSYNC3RemovesAllRemote(t *testing.T) {
	const zone = "customer.test."
	zl := mapZoneLookup{
		zone: &mockZone{zone: zone, mp: true},
	}
	e := NewEngine(Deps{
		LocalID:   "self.agent.example.",
		Transport: &mockTransport{},
		Zones:     zl,
	}, DefaultConfig())

	peer := NewPeer("gone.agent.example.")
	peer.Zones[ZoneName(zone)] = true
	e.registry.S.Set(peer.ID, peer)
	e.registry.addRemoteAgent(ZoneName(zone), peer)

	_, removed, err := e.ReconcileZone(ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
}
