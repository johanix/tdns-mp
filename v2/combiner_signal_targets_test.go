package tdnsmp

import (
	"fmt"
	"io"
	"log"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// plainTestZone: a primary map zone in tdns.Zones with the given apex NS
// names, wrapped as the combiner sees it. Not a provider zone unless the
// caller registers it as one.
func plainTestZone(t *testing.T, name string, nsNames ...string) *MPZoneData {
	t.Helper()
	zone := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n", name, name, name)
	for _, ns := range nsNames {
		zone += fmt.Sprintf("%s 3600 IN NS %s\n", name, ns)
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData(%s): %v", name, err)
	}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatalf("no MPZoneData for %s", name)
	}
	return mpzd
}

// The at-ns targets are the nameservers of the zone as served, the owner's
// and the sender's, that fall in a provider zone this combiner holds: the
// parent asks at every NS in the delegation, whoever put it there.
func TestSignalTargetsAreTheServedNameserversWithAProviderZone(t *testing.T) {
	const cell = "cell.cust.example."
	// this provider's zone, where its signal names live
	plainTestZone(t, "p1.example.", "ns.p1.example.")
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: "p1.example.", AllowedRRtypes: []string{"KEY"}})
	t.Cleanup(func() { delete(providerZoneRRtypes, "p1.example.") })
	// the customer's zone: the owner lists both providers' nameservers
	mpzd := plainTestZone(t, cell, "ns.p1.example.", "ns.p2.example.")

	got := mpzd.signalNSTargets("agent.p1.example.", cell)
	if len(got) != 1 || got[0] != "ns.p1.example." {
		t.Fatalf("owner's NS only: got %v, want [ns.p1.example.]", got)
	}

	// the sender contributes a second nameserver of its own, and the
	// owner's one again: one more target, nothing twice
	ns := func(target string) dns.RR {
		return &dns.NS{Hdr: dns.RR_Header{Name: cell, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: target}
	}
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		"agent.p1.example.": {cell: {dns.TypeNS: {Name: cell, RRtype: dns.TypeNS, RRs: []dns.RR{ns("ns2.p1.example."), ns("ns.p1.example.")}}}},
	}
	got = mpzd.signalNSTargets("agent.p1.example.", cell)
	if len(got) != 2 || got[0] != "ns.p1.example." || got[1] != "ns2.p1.example." {
		t.Fatalf("owner's and sender's NS: got %v, want [ns.p1.example. ns2.p1.example.]", got)
	}
	// another sender's contributions are not this sender's targets
	got = mpzd.signalNSTargets("agent.p2.example.", cell)
	if len(got) != 1 || got[0] != "ns.p1.example." {
		t.Fatalf("another sender: got %v, want [ns.p1.example.]", got)
	}
}
