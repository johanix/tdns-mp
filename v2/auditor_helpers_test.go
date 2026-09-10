package tdnsmp

import "testing"

func TestIsProviderIdentity_noZoneData(t *testing.T) {
	if !IsProviderIdentity("unknown.zone.", "agent.foo.example.") {
		t.Fatal("expected true when zone not loaded")
	}
}

func TestIsProviderIdentity_empty(t *testing.T) {
	if IsProviderIdentity("", "agent.foo.example.") {
		t.Fatal("expected false for empty zone")
	}
	if IsProviderIdentity("z.", "") {
		t.Fatal("expected false for empty identity")
	}
}
