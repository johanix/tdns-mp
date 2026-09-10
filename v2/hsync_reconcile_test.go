/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
)

func TestHsync3IdentitiesFromRRset(t *testing.T) {
	zd := seedZoneWithHSYNC3(t, "customer.test.", "fox.example.", "hare.example.")
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		t.Fatal(err)
	}
	rrset, ok := apex.RRtypes.Get(core.TypeHSYNC3)
	if !ok {
		t.Fatal("expected HSYNC3 rrset")
	}

	got := hsync3IdentitiesFromRRset(rrset.RRs, "fox.example.")
	if len(got) != 1 {
		t.Fatalf("got %d identities, want 1", len(got))
	}
	if _, ok := got[AgentId("hare.example.")]; !ok {
		t.Fatalf("missing hare.example., got %v", got)
	}
}

func TestReconcileZone_removesStalePeer(t *testing.T) {
	const zone = "customer.test."
	const local = "self.agent.example."

	seedZoneWithHSYNC3(t, zone, "fox.agent.example.")
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("zone not in Zones")
	}
	zd.Options[tdns.OptMultiProvider] = true

	ar := &AgentRegistry{
		S:            core.NewStringer[AgentId, *Agent](),
		RemoteAgents: make(map[ZoneName][]AgentId),
		LocalAgent:   &tdns.MultiProviderConf{Identity: local},
	}

	stale := &Agent{
		Identity:   AgentId("stale.agent.example."),
		PeerID:     "stale.agent.example.",
		ApiDetails: &AgentDetails{State: AgentStateOperational},
		DnsDetails: &AgentDetails{State: AgentStateOperational},
		Zones:      make(map[ZoneName]bool),
	}
	ar.S.Set(stale.Identity, stale)
	ar.AddZoneToAgent(stale.Identity, ZoneName(zone))

	added, removed, err := ar.reconcileZone(zd)
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("added=%d, want 1 (fox)", added)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1 (stale)", removed)
	}

	staleAfter, exists := ar.S.Get(stale.Identity)
	if !exists {
		t.Fatal("stale agent entry should remain in registry")
	}
	staleAfter.Mu.RLock()
	_, inZone := staleAfter.Zones[ZoneName(zone)]
	staleAfter.Mu.RUnlock()
	if inZone {
		t.Fatal("stale agent should no longer be associated with zone")
	}
}

func TestReconcileZone_emptyHSYNC3RemovesAllRemote(t *testing.T) {
	const zone = "customer.test."
	const local = "self.agent.example."

	seedZoneWithHSYNC3(t, zone) // no HSYNC3 RRs
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("zone not in Zones")
	}
	zd.Options[tdns.OptMultiProvider] = true

	ar := &AgentRegistry{
		S:            core.NewStringer[AgentId, *Agent](),
		RemoteAgents: make(map[ZoneName][]AgentId),
		LocalAgent:   &tdns.MultiProviderConf{Identity: local},
	}

	peer := &Agent{
		Identity:   AgentId("gone.agent.example."),
		PeerID:     "gone.agent.example.",
		ApiDetails: &AgentDetails{State: AgentStateOperational},
		DnsDetails: &AgentDetails{State: AgentStateOperational},
		Zones:      make(map[ZoneName]bool),
	}
	ar.S.Set(peer.Identity, peer)
	ar.AddZoneToAgent(peer.Identity, ZoneName(zone))

	_, removed, err := ar.reconcileZone(zd)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
}
