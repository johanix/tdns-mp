/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestReconcileZone_removesStalePeer(t *testing.T) {
	const zone = "customer.test."
	rrs := []dns.RR{
		mustHSYNC3RR(t, "self", "self.agent.example."),
		mustHSYNC3RR(t, "fox", "fox.agent.example."),
	}
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

	_, removed, err := e.ReconcileZone(ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
}

// standingZone is a multi-provider zone with an ON record for each of the
// given labels, as label.agent.example., and, when servers is not nil, an
// HSYNCPARAM listing those labels in servers=.
func standingZone(t *testing.T, zone string, labels []string, servers []string) *mockZone {
	t.Helper()
	z := &mockZone{zone: zone, mp: true}
	for _, l := range labels {
		z.rrs = append(z.rrs, mustHSYNC3RR(t, l, l+".agent.example."))
	}
	if servers != nil {
		z.hsyncparam = &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: servers}}}
	}
	return z
}

func peerZones(t *testing.T, e *Engine, id PeerID) map[ZoneName]bool {
	t.Helper()
	peer, ok := e.registry.S.Get(id)
	if !ok {
		return nil
	}
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	out := make(map[ZoneName]bool, len(peer.Zones))
	for z := range peer.Zones {
		out[z] = true
	}
	return out
}

// A zone with no record of this agent expects no peers: none is added, and a
// peer already in the zone has it taken off. The auditor runs the same
// engine.
func TestReconcileExpectsNoPeersInAZoneThatDoesNotListThisAgent(t *testing.T) {
	const zone = "customer.test."
	zl := mapZoneLookup{zone: standingZone(t, zone, []string{"fox", "hare"}, nil)}
	e := NewEngine(Deps{LocalID: "self.agent.example.", Transport: &mockTransport{}, Zones: zl}, DefaultConfig())
	hare := NewPeer("hare.agent.example.")
	hare.Zones[zone] = true
	e.registry.S.Set(hare.ID, hare)

	added, removed, _ := e.ReconcileZone(zone)
	if added != 0 || removed != 1 {
		t.Fatalf("added %d, removed %d; want 0 and 1", added, removed)
	}
	if _, ok := e.registry.S.Get("fox.agent.example."); ok {
		t.Error("a peer was added in a zone that does not list this agent")
	}
	if peerZones(t, e, hare.ID)[zone] {
		t.Error("the zone was not taken off a peer")
	}
}

// From the switch (plan S15) an ON record is a member, with a role or
// without: an agent whose label HSYNCPARAM does not list expects the zone's
// peers as a voting member does.
func TestReconcileAMemberWithNoRoleExpectsThePeers(t *testing.T) {
	const zone = "customer.test."
	zl := mapZoneLookup{zone: standingZone(t, zone, []string{"self", "fox"}, []string{"fox"})}
	e := NewEngine(Deps{LocalID: "self.agent.example.", Transport: &mockTransport{}, Zones: zl}, DefaultConfig())
	if added, _, _ := e.ReconcileZone(zone); added != 1 {
		t.Fatalf("%d peer(s) added where this agent is a member with no role, want 1", added)
	}
}

// The gate of ApplyHsyncDiff and ReconcileZone make one test. When this
// agent's record turns OFF, or its role is taken, a diff registers no peer in
// the zone, the groups are recomputed, and the next pass takes the zone off
// the peers.
func TestTheZoneLeavesItsGroupWhenThisAgentsRecordTurnsOFF(t *testing.T) {
	const zone = "customer.test."
	z := standingZone(t, zone, []string{"self", "fox"}, nil)
	zl := mapZoneLookup{zone: z}
	e, h := newDiffEngine("self.agent.example.", true, zl)
	e.ReconcileZone(zone)
	if !peerZones(t, e, "fox.agent.example.")[zone] {
		t.Fatal("setup: fox is not in the zone")
	}

	z.rrs[0].(*dns.PrivateRR).Data.(*core.HSYNC3).State = 0
	hare := mustHSYNC3RR(t, "hare", "hare.agent.example.")
	z.rrs = append(z.rrs, hare)
	_ = e.ApplyHsyncDiff(zone, HsyncDiff{Entered: idsOf(hare)})
	if _, ok := e.registry.S.Get("hare.agent.example."); ok {
		t.Error("a diff registered a peer in a zone where this agent's record is OFF")
	}
	if h.hsync3Changed != 1 {
		t.Errorf("the groups were recomputed %d times, want 1", h.hsync3Changed)
	}
	e.ReconcileZone(zone)
	if peerZones(t, e, "fox.agent.example.")[zone] {
		t.Error("the zone stayed on fox after this agent's record turned OFF")
	}
}

// An agent whose role is taken and whose record stays is a member with no
// role (plan S15): a diff registers peers in the zone, and the zone stays
// on them.
func TestTheZoneStaysWhenThisAgentLosesItsRoleAndKeepsItsRecord(t *testing.T) {
	const zone = "customer.test."
	z := standingZone(t, zone, []string{"self", "fox", "hare"}, []string{"self", "fox"})
	zl := mapZoneLookup{zone: z}
	e, h := newDiffEngine("self.agent.example.", true, zl)
	e.ReconcileZone(zone)
	if !peerZones(t, e, "fox.agent.example.")[zone] {
		t.Fatal("setup: fox is not in the zone")
	}

	z.hsyncparam.Value = []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: []string{"fox", "hare"}}}
	_ = e.ApplyHsyncDiff(zone, HsyncDiff{Entered: idsOf(z.rrs[2])})
	if _, ok := e.registry.S.Get("hare.agent.example."); !ok {
		t.Error("a diff registered no peer in a zone where this agent is a member with no role")
	}
	if h.hsync3Changed != 1 {
		t.Errorf("the groups were recomputed %d times, want 1", h.hsync3Changed)
	}
	e.ReconcileZone(zone)
	if !peerZones(t, e, "fox.agent.example.")[zone] {
		t.Error("the zone left fox when this agent lost its role and kept its record")
	}
}
