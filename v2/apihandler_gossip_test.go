package tdnsmp

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProviderGroupForGossipZone_fromGossipStateTable(t *testing.T) {
	ar := &AgentRegistry{
		GossipStateTable: NewGossipStateTable("auditor.example."),
	}
	hash := "abc123"
	ar.GossipStateTable.mu.Lock()
	ar.GossipStateTable.States[hash] = map[string]*MemberState{
		"agent.hare.mp.axfr.net.": {
			Identity:   "agent.hare.mp.axfr.net.",
			Timestamp:  time.Now(),
			Zones:      []string{"customer.mptest."},
			PeerStates: map[string]string{"agent.fox.mp.axfr.net.": "OPERATIONAL"},
		},
		"agent.fox.mp.axfr.net.": {
			Identity:  "agent.fox.mp.axfr.net.",
			Timestamp: time.Now(),
			Zones:     []string{"customer.mptest."},
		},
	}
	ar.GossipStateTable.mu.Unlock()

	pg, gotHash, err := providerGroupForGossipZone(ar, "customer.mptest.")
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != hash {
		t.Fatalf("hash = %q, want %q", gotHash, hash)
	}
	if len(pg.Members) != 2 {
		t.Fatalf("members = %v, want 2", pg.Members)
	}
	if dns.Fqdn(string(pg.Zones[0])) != "customer.mptest." {
		t.Fatalf("zones = %v", pg.Zones)
	}
}
