/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestIdentitiesFromRRset(t *testing.T) {
	rrs := []dns.RR{
		mustHSYNC3RR(t, "fox", "fox.example."),
		mustHSYNC3RR(t, "hare", "hare.example."),
	}
	got := IdentitiesFromRRset(rrs, "fox.example.")
	if len(got) != 1 {
		t.Fatalf("got %d identities, want 1", len(got))
	}
	if _, ok := got[PeerID("hare.example.")]; !ok {
		t.Fatalf("missing hare.example., got %v", got)
	}
}

func TestApplyHsyncDiff_addAndRemove(t *testing.T) {
	tb := &mockTransport{}
	zone := ZoneName("customer.test.")
	// fox must be a participant for the add to register (adds fail closed without
	// a zone view, and exclude non-participants).
	zoneRR := mustHSYNC3RR(t, "fox", "fox.agent.example.")
	e := NewEngine(Deps{
		LocalID:   "self.example.",
		Transport: tb,
		Zones:     mapZoneLookup{string(zone): {zone: string(zone), rrs: []dns.RR{zoneRR}}},
	}, DefaultConfig())

	addRR := mustHSYNC3RR(t, "fox", "fox.agent.example.")
	e.ApplyHsyncDiff(zone, HsyncDiff{Adds: []dns.RR{addRR}})
	if _, ok := e.registry.S.Get(PeerID("fox.agent.example.")); !ok {
		t.Fatal("expected fox.agent.example. registered")
	}

	remRR := mustHSYNC3RR(t, "fox", "fox.agent.example.")
	e.ApplyHsyncDiff(zone, HsyncDiff{Removes: []dns.RR{remRR}})
	peer, ok := e.registry.S.Get(PeerID("fox.agent.example."))
	if !ok {
		t.Fatal("peer entry should remain")
	}
	peer.Mu.RLock()
	_, inZone := peer.Zones[zone]
	peer.Mu.RUnlock()
	if inZone {
		t.Fatal("peer should no longer be associated with zone")
	}
}

func mustHSYNC3RR(t *testing.T, label, identity string) *dns.PrivateRR {
	t.Helper()
	return &dns.PrivateRR{
		Hdr: dns.RR_Header{Name: "customer.test.", Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 300},
		Data: &core.HSYNC3{
			State:    1, // ON
			Label:    label,
			Identity: identity,
			Upstream: ".",
		},
	}
}
