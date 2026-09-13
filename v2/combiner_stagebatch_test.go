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

// B-MP M-1: the combiner's writes go through one tdns StageBatch per logical
// change (CombineWithLocalChanges), on a live zone and on the draft the
// pre-refresh callback receives; and the pre-refresh analysis reads an
// incoming zone that has published nothing.

// combinerTestZone is a Ready provider zone with an upstream NS RRset,
// registered so the MPZoneData wrapper resolves, with its upstream apex
// snapshotted the way MPPreRefresh does before a combine.
func combinerTestZone(t *testing.T, name string) *MPZoneData {
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
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if !zd.Ready {
		t.Fatal("test zone did not become Ready")
	}
	// A provider zone: any owner in the zone, the configured RRtypes.
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: name, AllowedRRtypes: []string{"NS", "TXT", "KEY"}})
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatal("MPZoneData wrapper not found")
	}
	mpzd.snapshotUpstreamData(zd)
	return mpzd
}

func servedNames(t *testing.T, zd *tdns.ZoneData, owner string, rrtype uint16) []string {
	t.Helper()
	od, err := zd.GetOwner(owner)
	if err != nil {
		t.Fatalf("GetOwner(%s): %v", owner, err)
	}
	if od == nil {
		return nil
	}
	rs, ok := od.RRtypes.Get(rrtype)
	if !ok {
		return nil
	}
	var out []string
	for _, rr := range rs.RRs {
		switch v := rr.(type) {
		case *dns.NS:
			out = append(out, v.Ns)
		case *dns.TXT:
			out = append(out, v.Txt[0])
		default:
			out = append(out, rr.String())
		}
	}
	return out
}

func nsContribution(zone, target string) map[string][]core.RRset {
	rr := &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: target}
	return map[string][]core.RRset{zone: {{Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{rr}}}}
}

func withMPNotifyQ(t *testing.T) chan tdns.NotifyRequest {
	t.Helper()
	prev := tdns.Conf.Internal.NotifyQ
	q := make(chan tdns.NotifyRequest, 8)
	tdns.Conf.Internal.NotifyQ = q
	t.Cleanup(func() { tdns.Conf.Internal.NotifyQ = prev })
	return q
}

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestCombineIsOneBatchOneSerial(t *testing.T) {
	const zone = "combine.example."
	q := withMPNotifyQ(t)
	mpzd := combinerTestZone(t, zone)
	mpzd.Notify = []tdns.PeerConf{{Addr: "127.0.0.1:5399"}}
	serial := mpzd.CurrentSerial

	// Two agents contribute one NS each: state only, nothing served yet.
	for _, c := range []struct{ agent, ns string }{{"agent-a", "ns2." + zone}, {"agent-b", "ns3." + zone}} {
		changed, err := mpzd.AddCombinerData(c.agent, nsContribution(zone, c.ns))
		if err != nil || !changed {
			t.Fatalf("AddCombinerData(%s): changed=%v err=%v", c.agent, changed, err)
		}
	}
	if got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS); len(got) != 1 {
		t.Fatalf("contributions reached the served zone before the batch: %v", got)
	}
	if mpzd.CurrentSerial != serial {
		t.Fatal("a contribution alone moved the serial")
	}

	// The one batch: merged NS served, serial +1, one NOTIFY.
	changed, err := mpzd.CombineWithLocalChanges()
	if err != nil || !changed {
		t.Fatalf("CombineWithLocalChanges: changed=%v err=%v", changed, err)
	}
	got := servedNames(t, mpzd.ZoneData, zone, dns.TypeNS)
	for _, want := range []string{"ns1." + zone, "ns2." + zone, "ns3." + zone} {
		if !hasName(got, want) {
			t.Errorf("served NS %v lacks %s", got, want)
		}
	}
	if len(got) != 3 {
		t.Errorf("served NS %v, want exactly the upstream plus two contributions", got)
	}
	if mpzd.CurrentSerial != serial+1 {
		t.Fatalf("serial %d after one batch, want %d", mpzd.CurrentSerial, serial+1)
	}
	if n := len(q); n != 1 {
		t.Fatalf("%d NOTIFYs for one batch, want 1", n)
	}
	<-q

	// An identical second batch reports no change and publishes nothing.
	changed, err = mpzd.CombineWithLocalChanges()
	if err != nil || changed {
		t.Fatalf("second identical batch: changed=%v err=%v", changed, err)
	}
	if mpzd.CurrentSerial != serial+1 || len(q) != 0 {
		t.Fatalf("an unchanged batch published: serial %d, %d NOTIFYs", mpzd.CurrentSerial, len(q))
	}

	// Removing one agent's NS: the merge drops it, one serial.
	rrStr := (&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns3." + zone}).String()
	removed, err := mpzd.RemoveCombinerDataNG("agent-b", map[string][]string{zone: {rrStr}})
	if err != nil || len(removed) != 1 {
		t.Fatalf("RemoveCombinerDataNG: removed=%v err=%v", removed, err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("batch after removal: changed=%v err=%v", changed, err)
	}
	got = servedNames(t, mpzd.ZoneData, zone, dns.TypeNS)
	if hasName(got, "ns3."+zone) || !hasName(got, "ns2."+zone) || len(got) != 2 {
		t.Fatalf("served NS after removing ns3: %v", got)
	}
	if mpzd.CurrentSerial != serial+2 {
		t.Fatalf("serial %d, want %d", mpzd.CurrentSerial, serial+2)
	}

	// Removing the last NS contribution restores the upstream set.
	rrStr = (&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns2." + zone}).String()
	if _, err := mpzd.RemoveCombinerDataNG("agent-a", map[string][]string{zone: {rrStr}}); err != nil {
		t.Fatalf("RemoveCombinerDataNG: %v", err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("batch after the last removal: changed=%v err=%v", changed, err)
	}
	got = servedNames(t, mpzd.ZoneData, zone, dns.TypeNS)
	if len(got) != 1 || got[0] != "ns1."+zone {
		t.Fatalf("the upstream NS was not restored: %v", got)
	}
	if mpzd.CurrentSerial != serial+3 {
		t.Fatalf("serial %d, want %d", mpzd.CurrentSerial, serial+3)
	}
}

func TestCombineDropsAnOwnerWithItsLastType(t *testing.T) {
	const zone = "combine-owner.example."
	mpzd := combinerTestZone(t, zone)
	owner := "_signal.ns1." + zone
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"hello"}}
	if _, err := mpzd.AddCombinerData("agent-a", map[string][]core.RRset{owner: {{Name: owner, RRtype: dns.TypeTXT, RRs: []dns.RR{txt}}}}); err != nil {
		t.Fatalf("AddCombinerData: %v", err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("batch: changed=%v err=%v", changed, err)
	}
	if got := servedNames(t, mpzd.ZoneData, owner, dns.TypeTXT); len(got) != 1 || got[0] != "hello" {
		t.Fatalf("contribution not served: %v", got)
	}

	if _, err := mpzd.RemoveCombinerDataNG("agent-a", map[string][]string{owner: {txt.String()}}); err != nil {
		t.Fatalf("RemoveCombinerDataNG: %v", err)
	}
	if changed, err := mpzd.CombineWithLocalChanges(); err != nil || !changed {
		t.Fatalf("batch after removal: changed=%v err=%v", changed, err)
	}
	if mpzd.ZoneData.NameExists(owner) {
		t.Fatal("the owner is still in the zone after its last RRset was removed")
	}
}

func TestCombineServesTheSignatureTXTOnce(t *testing.T) {
	const zone = "combine-sig.example."
	mpzd := combinerTestZone(t, zone)
	conf := &MultiProviderConf{
		Identity:        "combiner.example.",
		Signature:       "combined by {identity} for {zone}",
		CombinerOptions: map[CombinerOption]bool{CombinerOptAddSignature: true},
	}
	serial := mpzd.CurrentSerial
	changed, _, err := mpzd.combineAndPublish(conf)
	if err != nil || !changed {
		t.Fatalf("combineAndPublish: changed=%v err=%v", changed, err)
	}
	got := servedNames(t, mpzd.ZoneData, "hsync-signature."+zone, dns.TypeTXT)
	if len(got) != 1 || got[0] != "combined by combiner.example. for "+zone {
		t.Fatalf("signature TXT: %v", got)
	}
	if mpzd.CurrentSerial != serial+1 {
		t.Fatalf("serial %d, want %d", mpzd.CurrentSerial, serial+1)
	}
	changed, _, err = mpzd.combineAndPublish(conf)
	if err != nil || changed {
		t.Fatalf("second signature batch: changed=%v err=%v", changed, err)
	}
	if mpzd.CurrentSerial != serial+1 {
		t.Fatal("the signature was published twice")
	}
}

// The pre-refresh combine runs the same code on the incoming zone, which has
// published nothing: the batch writes Data and publishes nothing, and the
// refresh publish that consumes Data serves it.
func TestCombineOnADraftWritesDataAndPublishesNothing(t *testing.T) {
	const zone = "combine-draft.example."
	mpzd := combinerTestZone(t, zone)
	if _, err := mpzd.AddCombinerData("agent-a", nsContribution(zone, "ns2."+zone)); err != nil {
		t.Fatalf("AddCombinerData: %v", err)
	}

	incoming := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 2 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n", zone, zone, zone, zone, zone, zone)
	draft := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary,
		Logger: log.New(io.Discard, "", 0), Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	if _, _, err := draft.ReadZoneData(incoming, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	// What MPPreRefresh does: the persistent MP state wrapped around new_zd.
	tmp := &MPZoneData{ZoneData: draft, MP: mpzd.MP, MPOptions: mpzd.MPOptions}
	tmp.snapshotUpstreamData(draft)

	changed, resp, err := tmp.combineAndPublish(nil)
	if err != nil || !changed {
		t.Fatalf("combineAndPublish on a draft: changed=%v err=%v", changed, err)
	}
	if draft.HasPublishedData() || resp.NewSerial != resp.OldSerial {
		t.Fatal("a batch on a draft published")
	}
	rs, err := draft.RRsetForAnalysis(zone, dns.TypeNS)
	if err != nil || rs == nil {
		t.Fatalf("RRsetForAnalysis on the draft: rs=%v err=%v", rs, err)
	}
	var names []string
	for _, rr := range rs.RRs {
		names = append(names, rr.(*dns.NS).Ns)
	}
	if !hasName(names, "ns1."+zone) || !hasName(names, "ns2."+zone) || len(names) != 2 {
		t.Fatalf("draft NS after the combine: %v", names)
	}

	// The refresh publish, stood in for by InstallInitialSnapshot.
	tdns.Zones.Set(zone+"draft", draft)
	t.Cleanup(func() { tdns.Zones.Remove(zone + "draft") })
	draft.InstallInitialSnapshot()
	t.Cleanup(draft.StopPublisher)
	got := servedNames(t, draft, zone, dns.TypeNS)
	if !hasName(got, "ns2."+zone) || len(got) != 2 {
		t.Fatalf("served NS after the draft was published: %v", got)
	}
}

// The readers behind the pre-refresh analysis see an incoming zone that has
// no published snapshot: what the deleted GetOwner/GetRRset shadow did, done
// by tdns's OwnerForAnalysis/RRsetForAnalysis.
func TestPreRefreshReadersSeeTheIncomingZone(t *testing.T) {
	const zone = "readers.example."
	const identity = "alice.agent.example."
	incoming := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary,
		Logger: log.New(io.Discard, "", 0), Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}
	if _, _, err := incoming.ReadZoneData(fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns1.%s\n", zone, zone, zone, zone, zone), true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	apex, ok := incoming.Data.Get(zone)
	if !ok {
		t.Fatal("no apex")
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{&dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNC3{State: 1, Label: "alice", Identity: identity, Upstream: "."},
	}}})
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: []string{"alice"}}}},
	}}})
	incoming.Data.Set(zone, apex)
	if incoming.HasPublishedData() {
		t.Fatal("the incoming zone must not have a snapshot")
	}

	// The live zone, as it is before its first load: nothing at all.
	live := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, Logger: log.New(io.Discard, "", 0),
		Data: core.NewNameMap[tdns.OwnerData]()}
	changed, hss, err := HsyncChanged(live, incoming)
	if err != nil || !changed || hss == nil || len(hss.HsyncAdds) != 1 {
		t.Fatalf("HsyncChanged on the first load: changed=%v hss=%+v err=%v", changed, hss, err)
	}

	mp := &MultiProviderConf{Role: "agent", Identity: identity}
	newMpzd := &MPZoneData{ZoneData: incoming, MP: &MPState{}, MPOptions: map[tdns.ZoneOption]bool{}}
	newMpzd.populateMPdata(mp)
	if newMpzd.MP.MPdata == nil {
		t.Fatal("populateMPdata found nothing in an incoming zone with HSYNC3 and HSYNCPARAM")
	}
	if newMpzd.MP.MPdata.OurLabel != "alice" || !newMpzd.MP.MPdata.WeAreProvider {
		t.Fatalf("MPdata from the incoming zone: %+v", newMpzd.MP.MPdata)
	}
	if hp := newMpzd.getHSYNCPARAM(); hp == nil {
		t.Fatal("getHSYNCPARAM read nothing from the incoming zone")
	}
	// And the same readers on a zone with no apex at all answer nil, not a
	// panic.
	empty := &MPZoneData{ZoneData: live, MP: &MPState{}, MPOptions: map[tdns.ZoneOption]bool{}}
	if hp := empty.getHSYNCPARAM(); hp != nil {
		t.Fatal("getHSYNCPARAM on an empty zone returned something")
	}
	if matched, _, err := empty.matchHsyncIdentity([]string{identity}); matched || err != nil {
		t.Fatalf("matchHsyncIdentity on an empty zone: matched=%v err=%v", matched, err)
	}
}
