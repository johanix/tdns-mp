package tdnsmp

import (
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #151: the CSYNC the combiner publishes after an NS change is what
// a parent that takes only the generalized NOTIFY scheme copies the NS set
// from, and a parent acts on a CSYNC only when it carries the immediate flag
// (RFC 7477 section 3; tdns's scanner implements nothing else).

// combinerCustomerZone is a Ready customer zone as a signing provider's
// combiner holds it: signed by "us", with the NS set and the parent sync in
// the agents' hands (nsmgmt=agent, parentsync=agent), its MP state computed
// from the zone the way a refresh does.
func combinerCustomerZone(t *testing.T, name string) *MPZoneData {
	t.Helper()
	zone := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n", name, name, name, name, name, name)
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatal("MPZoneData wrapper not found")
	}
	apex, err := mpzd.OwnerForAnalysis(name)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{
		&core.HSYNCPARAMSigners{Signers: []string{"us"}},
		&core.HSYNCPARAMNSmgmt{Value: core.HsyncNSmgmtAGENT},
		&core.HSYNCPARAMParentSync{Value: core.HsyncParentSyncAgent},
	}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{
		&dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: "us", Identity: "agent.us.example.", Upstream: "."}},
	}})
	mpzd.Data.Set(name, *apex)
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if !zd.Ready {
		t.Fatal("test zone did not become Ready")
	}
	mpzd.populateMPdata(&MultiProviderConf{Role: "combiner", Agents: []*PeerConf{{Identity: "agent.us.example."}}})
	if mpzd.MP.MPdata == nil || !mpzd.MP.MPdata.ZoneSigned || !mpzd.MP.MPdata.WeAreSigner {
		t.Fatalf("the zone's MP state: %+v, want a signed zone that we sign", mpzd.MP.MPdata)
	}
	mpzd.snapshotUpstreamData(zd)
	return mpzd
}

// servedCsync is the one CSYNC the zone serves at its apex, nil for none.
func servedCsync(t *testing.T, zd *tdns.ZoneData) *dns.CSYNC {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	rrs := apex.RRtypes.GetOnlyRRSet(dns.TypeCSYNC).RRs
	if len(rrs) == 0 {
		return nil
	}
	if len(rrs) != 1 {
		t.Fatalf("the zone serves %d CSYNC records, want one: %v", len(rrs), rrs)
	}
	return rrs[0].(*dns.CSYNC)
}

// An NS add and an NS delete, each through the combiner's update path as an
// agent's SYNC arrives there: both end with a served CSYNC that a parent
// processes (immediate set, no other flag) and that covers NS, and the
// second replaces the first with a later serial.
func TestCombinerCsyncAfterAnNSChangeIsImmediate(t *testing.T) {
	const zone = "csync.combiner.example."
	const agent = "agent.us.example."
	mpzd := combinerCustomerZone(t, zone)
	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{LocalID: "combiner.us.example."}}
	ns := fmt.Sprintf("%s 3600 IN NS ns2.%s", zone, zone)

	// waitCsync returns the served CSYNC once it is one other than prev: the
	// combiner publishes it from a goroutine of its own, after the NS change.
	waitCsync := func(step string, prev *dns.CSYNC) *dns.CSYNC {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			got := servedCsync(t, mpzd.ZoneData)
			if got != nil && (prev == nil || got.Serial != prev.Serial) {
				return got
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no new CSYNC was published (served: %v)", step, got)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	check := func(step string, c *dns.CSYNC) {
		t.Helper()
		// RFC 7477 section 2.1.1.2: immediate is 0x0001, soaminimum 0x0002
		if c.Flags != 0x0001 {
			t.Errorf("%s: the CSYNC's flags are 0x%04x, want 0x0001 (immediate, and soaminimum unset): %s", step, c.Flags, c)
		}
		hasNS := false
		for _, typ := range c.TypeBitMap {
			hasNS = hasNS || typ == dns.TypeNS
		}
		if !hasNS {
			t.Errorf("%s: the CSYNC's type bitmap %v lacks NS", step, c.TypeBitMap)
		}
	}
	update := func(step, operation string) {
		t.Helper()
		resp := CombinerProcessUpdate(&CombinerSyncRequest{
			SenderID:       agent,
			DeliveredBy:    agent,
			Zone:           zone,
			Operations:     []core.RROperation{{Operation: operation, RRtype: "NS", Records: []string{ns}}},
			DistributionID: step,
			Timestamp:      time.Now(),
		}, nil, map[string]bool{agent: true}, nil, tm)
		if resp.Status != "ok" || !resp.DataChanged {
			t.Fatalf("%s: status %q, changed %v: %s", step, resp.Status, resp.DataChanged, resp.Message)
		}
	}

	update("ns-add", "add")
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); !hasName(got, "ns2."+zone) {
		t.Fatalf("the added NS is not served: %v", got)
	}
	added := waitCsync("ns-add", nil)
	check("ns-add", added)

	update("ns-delete", "delete")
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); hasName(got, "ns2."+zone) {
		t.Fatalf("the deleted NS is still served: %v", got)
	}
	deleted := waitCsync("ns-delete", added)
	check("ns-delete", deleted)
	// tdns's scanner skips a CSYNC whose serial is below the last it processed
	if int32(deleted.Serial-added.Serial) <= 0 {
		t.Errorf("the CSYNC after the delete has serial %d, not later than the add's %d", deleted.Serial, added.Serial)
	}
}
