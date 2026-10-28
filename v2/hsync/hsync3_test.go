/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// idsOf is the identities of HSYNC3 records, as the hook at activation hands
// them to ApplyHsyncDiff.
func idsOf(rrs ...dns.RR) []PeerID {
	var out []PeerID
	for _, rr := range rrs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				out = append(out, PeerID(h3.Identity))
			}
		}
	}
	return out
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
	e.ApplyHsyncDiff(zone, HsyncDiff{Entered: idsOf(addRR)})
	if _, ok := e.registry.S.Get(PeerID("fox.agent.example.")); !ok {
		t.Fatal("expected fox.agent.example. registered")
	}

	remRR := mustHSYNC3RR(t, "fox", "fox.agent.example.")
	e.ApplyHsyncDiff(zone, HsyncDiff{Left: idsOf(remRR)})
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
