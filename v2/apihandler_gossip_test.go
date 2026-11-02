package tdnsmp

import (
	"testing"
	"time"
)

// A zone's group is the group manager's alone (plan S22): a row of gossip
// lists no zone, and a row that lists one, from an agent before S22, finds
// no group for it.
func TestTheGroupOfAZoneComesFromTheGroupManagerOnly(t *testing.T) {
	const hash, zone = "abc123", "customer.example."
	ar := &AgentRegistry{
		ProviderGroupManager: NewProviderGroupManager("auditor.example."),
		GossipStateTable:     NewGossipStateTable("auditor.example."),
	}
	ar.GossipStateTable.mu.Lock()
	ar.GossipStateTable.States[hash] = map[string]*MemberState{
		"agent.a.example.": {Identity: "agent.a.example.", Timestamp: time.Now(), Zones: []string{zone}},
	}
	ar.GossipStateTable.mu.Unlock()
	if pg, _, err := providerGroupForGossipZone(ar, zone); err == nil {
		t.Fatalf("a group found from the rows: %+v", pg)
	}

	ar.ProviderGroupManager.mu.Lock()
	ar.ProviderGroupManager.Groups[hash] = &ProviderGroup{GroupHash: hash,
		Members: []string{"agent.a.example.", "agent.b.example."}, Zones: []ZoneName{zone}}
	ar.ProviderGroupManager.mu.Unlock()
	pg, got, err := providerGroupForGossipZone(ar, "customer.example")
	if err != nil || got != hash || len(pg.Members) != 2 {
		t.Fatalf("the group: %+v %q %v, want %s with both members", pg, got, err, hash)
	}
}
