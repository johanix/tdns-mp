package tdnsmp

import "testing"

func TestParentDomain(t *testing.T) {
	for in, want := range map[string]string{
		"agent.fox.mp.example.": "fox.mp.example.",
		"auditor.x.example":     "x.example.",
		"example.":              "",
		".":                     "",
	} {
		if got := parentDomain(in); got != want {
			t.Errorf("parentDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if flushDiscoveryCache(nil, "a.b.example.") != 0 || flushDiscoveryCache(&Imr{}, "a.b.example.") != 0 {
		t.Error("nil IMR must flush nothing")
	}
}
