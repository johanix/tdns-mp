package tdnsmp

import (
	"fmt"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The leader's KEY goes to the apex always, and to the signal names under
// the zone's nameservers only when the customer's HSYNCPARAM says pubkey and
// the zone has HSYNC3: without it tdns's use-hsyncparam publishes there, each
// provider on its own (the project owner, 2026-11-06).
func TestTheKeyGoesToTheSignalNamesOnlyWhenTheCustomerSaysPubkey(t *testing.T) {
	mpzd := signerTestZone(t, "loc.owned.example.", newMPTestKeyDB(t))
	setParams := func(params string) {
		t.Helper()
		apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN HSYNCPARAM %s", mpzd.ZoneName, numberedText(params)))
		if err != nil {
			t.Fatalf("HSYNCPARAM %q: %v", params, err)
		}
		apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{rr}})
		mpzd.Data.Set(mpzd.ZoneName, *apex)
	}
	want := func(locs []string, atNS bool) {
		t.Helper()
		if len(locs) == 0 || locs[0] != "at-apex" {
			t.Fatalf("locations %v: the apex comes first, always", locs)
		}
		has := len(locs) == 2 && locs[1] == "at-ns"
		if has != atNS || len(locs) > 2 {
			t.Errorf("locations %v, want at-ns=%v", locs, atNS)
		}
	}
	// no HSYNCPARAM at all: the apex only
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	setParams(`servers="us,p2" signers="us" parentsync="agent"`)
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	setParams(`servers="us,p2" signers="us" parentsync="agent" pubkey`)
	want(publishLocations(ZoneName(mpzd.ZoneName)), false)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var records []dns.RR
	for _, r := range []string{"us agent.us.example.", "p2 agent.p2.example."} {
		rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN HSYNC3 ON %s .", mpzd.ZoneName, r))
		if err != nil {
			t.Fatalf("HSYNC3 %q: %v", r, err)
		}
		records = append(records, rr)
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: records})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	want(publishLocations(ZoneName(mpzd.ZoneName)), true)
	// a zone this agent does not hold: the apex only
	want(publishLocations("nowhere.example."), false)
}
