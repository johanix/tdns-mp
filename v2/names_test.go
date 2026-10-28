package tdnsmp

import (
	"testing"

	"github.com/miekg/dns"
)

// Every identity in the multi-provider block is folded once, at config load
// (#287): a daemon whose own identity, or a peer's, is configured in capitals
// announces and keys it as the canonical name. The control zone and the
// protected namespaces are zone names; they keep their case.
func TestAnIdentityInCapitalsIsFoldedAtConfigLoad(t *testing.T) {
	block := map[string]interface{}{
		"role":             "agent",
		"identity":         "Agent.Alice.Example",
		"combiner":         map[string]interface{}{"identity": "Combiner.Alice.Example."},
		"signer":           map[string]interface{}{"identity": "SIGNER.alice.example."},
		"agents":           []interface{}{map[string]interface{}{"identity": "Agent.Bob.Example"}},
		"authorized_peers": []interface{}{"Agent.Carol.Example."},
		"dns":              map[string]interface{}{"control_zone": "Control.Alice.Example"},
	}
	mp, err := parseMultiProvider(map[string]interface{}{"multi-provider": block})
	if err != nil {
		t.Fatalf("parseMultiProvider: %v", err)
	}
	for _, c := range []struct{ what, got, want string }{
		{"identity", mp.Identity, "agent.alice.example."},
		{"combiner", mp.Combiner.Identity, "combiner.alice.example."},
		{"signer", mp.Signer.Identity, "signer.alice.example."},
		{"agents[0]", mp.Agents[0].Identity, "agent.bob.example."},
		{"authorized_peers[0]", mp.AuthorizedPeers[0], "agent.carol.example."},
		{"dns.control_zone", mp.Dns.ControlZone, "Control.Alice.Example."},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
		}
	}
	if a := mp.FindAgent("AGENT.bob.example."); a == nil {
		t.Errorf("FindAgent in another case found nothing")
	}
}

// sameName is the DNS rule: US-ASCII case only, each name with its trailing
// dot. strings.EqualFold folds by Unicode, so it takes U+212A KELVIN SIGN
// for "k"; sameName does not.
func TestSameNameFoldsUSASCIIOnly(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"Agent.Example.", "agent.example.", true},
		{"agent.example", "AGENT.EXAMPLE.", true},
		{"agent.example.", "agent.example.org.", false},
		{"Key.example.", "key.example.", false},
	} {
		if got := sameName(c.a, c.b); got != c.want {
			t.Errorf("sameName(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A protected namespace takes an NS target at or below it, in any case, and
// only on a label boundary.
func TestAProtectedNamespaceIsMatchedByLabelInAnyCase(t *testing.T) {
	ns := func(target string) *dns.NS {
		return &dns.NS{Hdr: dns.RR_Header{Name: "zone.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: target}
	}
	protected := []string{"provider.example."}
	for _, c := range []struct {
		target   string
		intrudes bool
	}{
		{"NS1.Provider.Example.", true},
		{"provider.example.", true},
		{"ns1.otherprovider.example.", false},
		{"ns1.example.", false},
	} {
		got := checkNSNamespacePolicy(ns(c.target), protected) != ""
		if got != c.intrudes {
			t.Errorf("NS %s: intrudes = %v, want %v", c.target, got, c.intrudes)
		}
	}
}
