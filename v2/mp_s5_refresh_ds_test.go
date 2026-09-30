package tdnsmp

import (
	"fmt"
	"io"
	"log"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// refreshedZone is the zone as a refresh would bring it: the same zone
// text with extra apex records.
func refreshedZone(t *testing.T, mpzd *MPZoneData, extra ...string) *tdns.ZoneData {
	t.Helper()
	name := mpzd.ZoneName
	zone := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 2 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\nwww.%s 3600 IN A 192.0.2.2\n", name, name, name, name, name, name, name)
	for _, rr := range extra {
		zone += rr + "\n"
	}
	zd := &tdns.ZoneData{ZoneName: name, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: log.New(io.Discard, "", 0),
		Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true, tdns.OptParentSync: true}}
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	return zd
}

// tdns-mp #112: a refresh that brings another provider's new KSK must not
// send its DS to the parent. The DS set of a multi-provider zone is the
// owner's intent, and the implicit sync carries NS and glue only.
func TestARefreshThatBringsAnotherProvidersKSKSendsNoDS(t *testing.T) {
	mpzd := signerTestZone(t, "refresh.owned.example.", newMPTestKeyDB(t))
	mpzd.Options[tdns.OptParentSync] = true
	mpzd.InstallInitialSnapshot() // the served zone: what a refresh compares the incoming one with
	mpzd.Ready = true
	ksk := testDnskey(t, mpzd.ZoneName, 257)

	// tdns's own diff would send the key's DS
	changed, dss, err := mpzd.DelegationDataChangedNG(refreshedZone(t, mpzd, ksk.String()))
	if err != nil || !changed || len(dss.DSAdds) != 1 {
		t.Fatalf("tdns's diff: changed=%v ds adds %d err=%v; the test needs it to see the new KSK", changed, len(dss.DSAdds), err)
	}

	// the multi-provider zone's refresh does not
	changed, dss, err = implicitDelegationChange(mpzd, refreshedZone(t, mpzd, ksk.String()))
	if err != nil {
		t.Fatal(err)
	}
	if changed || !dss.InSync || len(dss.DSAdds) != 0 || len(dss.DSRemoves) != 0 || dss.NewDS != nil || dss.NewDSKnown {
		t.Errorf("a new KSK by refresh: changed=%v insync=%v ds adds %d removes %d newds %v known %v; want no delegation change and no DS", changed, dss.InSync, len(dss.DSAdds), len(dss.DSRemoves), dss.NewDS, dss.NewDSKnown)
	}

	// an NS change is still a change, and still carries no DS
	ns := fmt.Sprintf("%s 3600 IN NS ns2.%s", mpzd.ZoneName, mpzd.ZoneName)
	changed, dss, err = implicitDelegationChange(mpzd, refreshedZone(t, mpzd, ksk.String(), ns))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || dss.InSync || len(dss.NsAdds) != 1 || len(dss.DSAdds) != 0 || dss.NewDSKnown {
		t.Errorf("a new NS and a new KSK by refresh: changed=%v insync=%v ns adds %d ds adds %d known %v; want the NS change alone", changed, dss.InSync, len(dss.NsAdds), len(dss.DSAdds), dss.NewDSKnown)
	}

	// a zone tdns runs alone keeps tdns's DS diff
	mpzd.Options[tdns.OptMultiProvider] = false
	changed, dss, err = implicitDelegationChange(mpzd, refreshedZone(t, mpzd, ksk.String()))
	if err != nil || !changed || len(dss.DSAdds) != 1 {
		t.Errorf("a zone tdns runs alone: changed=%v ds adds %d err=%v; want tdns's DS diff as before", changed, len(dss.DSAdds), err)
	}
}
