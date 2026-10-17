/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp #175: a zone has one CSYNC. The combiner makes none; it serves
 * the newest of those the agents contribute, refuses an older one that
 * arrives late, and drops the older ones when a newer one arrives.
 */
package tdnsmp

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	csyncCombinerID = "combiner.us.example."
	csyncOurAgent   = "agent.us.example."
	csyncLeaderA    = "agent.alpha.example."
	csyncLeaderB    = "agent.beta.example."
)

// csyncCombinerZone is a combiner's copy of a multi-provider zone whose
// providers manage the NS set and sync with the parent through their
// agents. signed: a provider signs the zone; signer: this combiner's
// provider does. The combiner stores in a real database.
func csyncCombinerZone(t *testing.T, name string, signed, signer bool) (*MPZoneData, *HsyncDB) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("the combiner's tables: %v", err)
	}
	mpzd := signerTestZone(t, name, kdb)
	mpzd.ZoneData.Options = map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}
	apex, err := mpzd.OwnerForAnalysis(name)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	values := []core.HSYNCPARAMKeyValue{
		&core.HSYNCPARAMNSmgmt{Value: core.HsyncNSmgmtAGENT},
		&core.HSYNCPARAMParentSync{Value: core.HsyncParentSyncAgent},
		&core.HSYNCPARAMServers{Servers: []string{"us", "alpha", "beta"}},
	}
	if signed {
		values = append(values, &core.HSYNCPARAMSigners{Signers: []string{"us", "alpha"}})
	}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core_RRset(&dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: name, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNCPARAM{Value: values}}))
	mpzd.Data.Set(name, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	t.Cleanup(mpzd.ZoneData.StopPublisher)
	if !mpzd.Ready {
		t.Fatal("the zone is not served")
	}
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: "us", ZoneSigned: signed, WeAreSigner: signer}
	mpzd.MP.MultiProvider = &MultiProviderConf{Identity: csyncCombinerID}
	mpzd.MP.PersistContributions = func(zone, sender string, contribs map[string]map[uint16]core.RRset) error {
		return SaveContributions(hdb, zone, sender, contribs)
	}
	mpzd.snapshotUpstreamData(mpzd.ZoneData)
	return mpzd, hdb
}

func csyncRecord(zone string, serial uint32, flags uint16) string {
	return (&dns.CSYNC{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 120},
		Serial: serial, Flags: flags, TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}}).String()
}

// contributeCsync is a CSYNC from an agent arriving at the combiner the way
// every contribution does: the update our agent delivered, processed by the
// combiner's update handler.
func contributeCsync(mpzd *MPZoneData, hdb *HsyncDB, sender string, records ...string) *CombinerSyncResponse {
	return CombinerProcessUpdate(&CombinerSyncRequest{
		SenderID:       sender,
		DeliveredBy:    csyncOurAgent,
		Zone:           mpzd.ZoneName,
		Operations:     []core.RROperation{{Operation: "replace", RRtype: "CSYNC", Records: records}},
		DistributionID: nextDistributionID(),
		Timestamp:      time.Now(),
	}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
}

// servedCsyncs is the zone's CSYNC RRset as the zone serves it.
func servedCsyncs(t *testing.T, mpzd *MPZoneData) []string {
	t.Helper()
	return servedNames(t, mpzd.ZoneData, mpzd.ZoneName, dns.TypeCSYNC)
}

// storedCsyncs is who the combiner's database holds a CSYNC for.
func storedCsyncs(t *testing.T, hdb *HsyncDB, zone string) map[string]string {
	t.Helper()
	all, err := LoadAllContributions(hdb)
	if err != nil {
		t.Fatalf("the stored contributions: %v", err)
	}
	out := map[string]string{}
	for sender, owners := range all[zone] {
		if rrset, ok := owners[zone][dns.TypeCSYNC]; ok {
			for _, rr := range rrset.RRs {
				out[sender] = rr.String()
			}
		}
	}
	return out
}

func wantServed(t *testing.T, mpzd *MPZoneData, what string, want ...string) {
	t.Helper()
	got := servedCsyncs(t, mpzd)
	if len(got) != len(want) || (len(want) == 1 && got[0] != want[0]) {
		t.Errorf("%s: the zone serves the CSYNC RRset %v, want %v", what, got, want)
	}
}

// A CSYNC that an agent contributes is served. A newer one from another
// agent, the next leader, takes its place: the zone serves one, and the
// older one is gone from the combiner's store. An older one that arrives
// late is refused with the reason, and changes nothing.
func TestTheCombinerServesTheNewestContributedCsync(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "one.csync.example.", true, true)
	z := mpzd.ZoneName
	first, second, late := csyncRecord(z, 1000, 1), csyncRecord(z, 1001, 1), csyncRecord(z, 999, 1)

	if resp := contributeCsync(mpzd, hdb, csyncLeaderA, first); resp.Status != "ok" || len(resp.AppliedRecords) != 1 || resp.AppliedRecords[0] != first {
		t.Fatalf("the first CSYNC was answered %q %q, applied %v, rejected %v", resp.Status, resp.Message, resp.AppliedRecords, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after the first CSYNC", first)

	// the leadership has moved, and the new leader's CSYNC is newer
	resp := contributeCsync(mpzd, hdb, csyncLeaderB, second)
	if resp.Status != "ok" || len(resp.AppliedRecords) != 1 || resp.AppliedRecords[0] != second {
		t.Fatalf("the newer CSYNC was answered %q %q, applied %v, rejected %v", resp.Status, resp.Message, resp.AppliedRecords, resp.RejectedItems)
	}
	if len(resp.RemovedRecords) != 1 || resp.RemovedRecords[0] != first {
		t.Errorf("the newer CSYNC removed %v, want the older one", resp.RemovedRecords)
	}
	wantServed(t, mpzd, "after the newer CSYNC", second)
	if stored := storedCsyncs(t, hdb, z); len(stored) != 1 || stored[csyncLeaderB] != second {
		t.Errorf("the store holds the CSYNC records %v, want only the newer one", stored)
	}

	// the previous leader's CSYNC again, late (a retry, a resync): refused
	resp = contributeCsync(mpzd, hdb, csyncLeaderA, first)
	if len(resp.RejectedItems) != 1 || resp.RejectedItems[0].Record != first ||
		!strings.Contains(resp.RejectedItems[0].Reason, "an older CSYNC than the one held for the zone: serial 1000, held is 1001 from "+csyncLeaderB) {
		t.Errorf("the older CSYNC was answered %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	// and one that is older than both, from a sender the combiner holds
	// nothing for
	if resp = contributeCsync(mpzd, hdb, "agent.gamma.example.", late); len(resp.RejectedItems) != 1 {
		t.Errorf("a CSYNC older than the one held was answered %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after the older ones arrived late", second)
	if stored := storedCsyncs(t, hdb, z); len(stored) != 1 || stored[csyncLeaderB] != second {
		t.Errorf("the store holds the CSYNC records %v after the late ones", stored)
	}

	// the same leader's next CSYNC replaces its own
	third := csyncRecord(z, 1002, 1)
	if resp = contributeCsync(mpzd, hdb, csyncLeaderB, third); resp.Status != "ok" {
		t.Errorf("the leader's next CSYNC was answered %q %q", resp.Status, resp.Message)
	}
	wantServed(t, mpzd, "after the leader's next CSYNC", third)

	// two in one contribution: a zone has one
	if resp = contributeCsync(mpzd, hdb, csyncLeaderB, csyncRecord(z, 1003, 1), csyncRecord(z, 1004, 1)); len(resp.RejectedItems) != 2 {
		t.Errorf("two CSYNC records in one contribution were answered %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after two in one contribution", third)
}

// The order is that of RFC 1982: a serial that has wrapped is newer.
func TestTheCsyncSerialOrderIsSerialArithmetic(t *testing.T) {
	for _, tc := range []struct {
		a, b  uint32
		newer bool
	}{
		{2, 1, true}, {1, 2, false}, {1, 1, false},
		{5, 0xfffffff0, true}, {0xfffffff0, 5, false},
		{1 << 31, 0, false}, {0, 1 << 31, false}, // half the number space apart: neither
	} {
		if got := serialNewer(tc.a, tc.b); got != tc.newer {
			t.Errorf("serialNewer(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.newer)
		}
	}
	mpzd, hdb := csyncCombinerZone(t, "wrap.csync.example.", true, true)
	z := mpzd.ZoneName
	before, after := csyncRecord(z, 0xfffffff0, 1), csyncRecord(z, 5, 1)
	contributeCsync(mpzd, hdb, csyncLeaderA, before)
	if resp := contributeCsync(mpzd, hdb, csyncLeaderB, after); resp.Status != "ok" {
		t.Fatalf("a CSYNC whose serial has wrapped was answered %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after the serial wrapped", after)
}

// A combiner of an earlier build made the zone's CSYNC itself and stored it
// under its own identity, with the zone's SOA serial in it. At a start the
// store is loaded as it is and that record is served as before. The first
// CSYNC that an agent contributes takes its place, whatever the numbers
// say, and the combiner's own is removed from the store.
func TestTheCombinersOwnCsyncFromAnEarlierBuildGivesWay(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "legacy.csync.example.", true, true)
	z := mpzd.ZoneName
	// what the earlier build left: a zone serial, far above any time
	own := csyncRecord(z, 4000000000, 0)
	rr, _ := dns.NewRR(own)
	if err := SaveContributions(hdb, z, csyncCombinerID, map[string]map[uint16]core.RRset{
		z: {dns.TypeCSYNC: core.RRset{Name: z, RRtype: dns.TypeCSYNC, RRs: []dns.RR{rr}}}}); err != nil {
		t.Fatalf("the earlier build's store: %v", err)
	}
	// a start: the stored contributions are loaded and combined
	if _, err := CombinerReapplyContributions(z, hdb); err != nil {
		t.Fatalf("loading the stored contributions: %v", err)
	}
	wantServed(t, mpzd, "after the start", own)

	leaders := csyncRecord(z, 1000, 1)
	resp := contributeCsync(mpzd, hdb, csyncLeaderA, leaders)
	if resp.Status != "ok" || len(resp.RejectedItems) != 0 {
		t.Fatalf("the leader's CSYNC was answered %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after the leader's CSYNC", leaders)
	if stored := storedCsyncs(t, hdb, z); len(stored) != 1 || stored[csyncLeaderA] != leaders {
		t.Errorf("the store holds the CSYNC records %v, want only the leader's", stored)
	}
}

// Two stored CSYNC records from two senders, as a store may hold them from
// before this rule: the zone serves one, the newer, from the start.
func TestAStoreWithTwoCsyncsServesOne(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "two.csync.example.", true, true)
	z := mpzd.ZoneName
	older, newer := csyncRecord(z, 1000, 1), csyncRecord(z, 1001, 1)
	for sender, rec := range map[string]string{csyncLeaderA: older, csyncLeaderB: newer} {
		rr, _ := dns.NewRR(rec)
		if err := SaveContributions(hdb, z, sender, map[string]map[uint16]core.RRset{
			z: {dns.TypeCSYNC: core.RRset{Name: z, RRtype: dns.TypeCSYNC, RRs: []dns.RR{rr}}}}); err != nil {
			t.Fatalf("the store: %v", err)
		}
	}
	if _, err := CombinerReapplyContributions(z, hdb); err != nil {
		t.Fatalf("loading the stored contributions: %v", err)
	}
	wantServed(t, mpzd, "after the start", newer)
}

// The combiner makes no CSYNC itself. An NS change still tells the agent
// that delivered it: "ns-changed", the hint that asks the leader for a
// delegation sync.
func TestTheCombinerMakesNoCsyncAndStillSendsItsHint(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "hint.csync.example.", true, true)
	z := mpzd.ZoneName

	// the combiner's transport, and its agent listening on the loopback
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	combiner, agent := env.Alice, env.Bob
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the agent's listener: %v", err)
	}
	agent.Bridge.PeerRegistry.GetOrCreate(combiner.Identity)
	agent.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, agent)
	if err := combiner.Bridge.PeerRegistry.Add(peerFromAddress(agent.Identity, ln.Addr().String())); err != nil {
		t.Fatalf("the agent as the combiner's peer: %v", err)
	}

	// an NS contribution, as the agent delivers it
	resp := CombinerProcessUpdate(&CombinerSyncRequest{
		SenderID:    agent.Identity,
		DeliveredBy: agent.Identity,
		Zone:        z,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS",
			Records: []string{fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)}}},
		DistributionID: nextDistributionID(),
		Timestamp:      time.Now(),
	}, nil, map[string]bool{agent.Identity: true}, hdb, combiner.Bridge)
	if resp.Status != "ok" || !resp.DataChanged {
		t.Fatalf("the NS contribution was answered %q %q, changed %v", resp.Status, resp.Message, resp.DataChanged)
	}
	hint, ok := recvWithin(agent.MsgQs.StatusUpdate, 10*time.Second)
	if !ok {
		t.Fatal("the agent was not told that the NS set changed")
	}
	if hint.SubType != "ns-changed" || hint.Zone != z || len(hint.NSRecords) != 2 {
		t.Errorf("the agent was told %+v", *hint)
	}
	// the hint has gone; nothing was made beside it
	wantServed(t, mpzd, "after an NS change")
	if stored := storedCsyncs(t, hdb, z); len(stored) != 0 {
		t.Errorf("the combiner stored a CSYNC on an NS change: %v", stored)
	}
	if !hasName(servedNames(t, mpzd.ZoneData, z, dns.TypeNS), "ns2.provider.example.") {
		t.Errorf("the NS contribution is not served: %v", servedNames(t, mpzd.ZoneData, z, dns.TypeNS))
	}
}

// A CSYNC is for a signed zone. An unsigned zone serves none: a CSYNC that
// is contributed all the same is stored and not served. Nor does a
// provider that does not sign a signed zone put one into its copy: it
// serves the signer's zone.
func TestAZoneThatIsNotSignedHereServesNoCsync(t *testing.T) {
	for _, tc := range []struct {
		name           string
		signed, signer bool
	}{
		{"unsigned.csync.example.", false, false},
		{"relayed.csync.example.", true, false},
	} {
		mpzd, hdb := csyncCombinerZone(t, tc.name, tc.signed, tc.signer)
		rec := csyncRecord(tc.name, 1000, 1)
		resp := contributeCsync(mpzd, hdb, csyncLeaderA, rec)
		if resp.Status != "ignored" || len(resp.IgnoredRecords) != 1 || len(resp.AppliedRecords) != 0 {
			t.Errorf("%s: the CSYNC was answered %q %q, applied %v, ignored %v", tc.name, resp.Status, resp.Message, resp.AppliedRecords, resp.IgnoredRecords)
		}
		wantServed(t, mpzd, tc.name)
	}
}
