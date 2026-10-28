/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Plan S10, the combiner's side: it acts by what its agent hands it, not by
// its own copy of the zone (design 3.5, rule 5; tdns-mp #235).

const (
	actUs    = "agent.alpha.example." // the combiner's own agent
	actOther = "agent.beta.example."
)

// actRecords are a zone's instructions with alpha and beta listed ON and
// the HSYNCPARAM record param.
func actRecords(param string) []string {
	return []string{
		`3600 IN HSYNC3 ON alpha agent.alpha.example. .`,
		`3600 IN HSYNC3 ON beta agent.beta.example. .`,
		`3600 IN HSYNCPARAM ` + param,
	}
}

// withActing gives the test a combiner's store of hand-overs, kept on hdb
// when it is not nil.
func withActing(t *testing.T, hdb *HsyncDB) *actingStore {
	t.Helper()
	s, err := loadActingStore(hdb)
	if err != nil {
		t.Fatalf("loadActingStore: %v", err)
	}
	prev := actingHeld.Load()
	actingHeld.Store(s)
	t.Cleanup(func() { actingHeld.Store(prev) })
	return s
}

// handoverFor is what an agent hands for a zone whose instructions are
// records (zone-file form without the owner): their reading as records,
// rolesFor's sets.
func handoverFor(t *testing.T, zone string, records ...string) *ActingHandover {
	t.Helper()
	full := make([]string, len(records))
	for i, r := range records {
		full[i] = zone + " " + r
	}
	in, err := readInstructionRecords(zone, full)
	if err != nil || in == nil {
		t.Fatalf("the instructions do not read: %v", err)
	}
	return &ActingHandover{Zone: zone, Serial: in.Serial, Digest: in.Digest(), Records: in.instructionRecords(zone),
		Newest: in.Serial, Phase: PhaseSteady, Sets: rolesFor(in, in, 0), Made: time.Now()}
}

// actingCombiner is a combiner's served zone with the given instructions in
// its copy, its agent alpha's, and its upstream apex snapshotted.
func actingCombiner(t *testing.T, zone string, records ...string) (*Config, *MPZoneData) {
	t.Helper()
	asMPDaemon(t, AppTypeMPCombiner)
	mp := &MultiProviderConf{Role: "combiner", Identity: "combiner.alpha.example.", Agents: []*PeerConf{{Identity: actUs}}}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(mp)
	mpzd := instrTestZone(t, zone, records...)
	mpzd.EnsureMP()
	mpzd.MP.MultiProvider = mp
	mpzd.snapshotUpstreamData(mpzd.ZoneData)
	return conf, mpzd
}

// handTo is the combiner's handler taking h from origin, delivered by it.
func handTo(conf *Config, h *ActingHandover, origin string) *CombinerSyncResponse {
	return conf.combinerTakeHandover(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		OriginatorID: AgentId(origin), DeliveredBy: AgentId(origin), Zone: ZoneName(h.Zone),
		DistributionID: nextDistributionID(), Acting: h}}, map[string]bool{actUs: true})
}

func servedTypes(t *testing.T, mpzd *MPZoneData, rrtype uint16) []string {
	t.Helper()
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var out []string
	for _, rr := range apex.RRtypes.GetOnlyRRSet(rrtype).RRs {
		out = append(out, rr.String())
	}
	slices.Sort(out)
	return out
}

// The records a hand-over carries read back to the instructions handed: the
// same serial and digest, OFF labels, the legacy reading and every key
// included.
func TestTheHandOverRecordsReadAsTheirDigest(t *testing.T) {
	const zone = "records.acting.example."
	for name, records := range map[string][]string{
		"every key":    instrBase,
		"legacy":       instrBase[:3],
		"no lists":     {instrBase[0], `3600 IN HSYNCPARAM serial="3"`},
		"no serial":    withParam(`servers="alpha" signers="alpha"`),
		"owner at all": withParam(`serial="9" servers="alpha,beta" nsmgmt="owner" parentsync="owner"`),
	} {
		h := handoverFor(t, zone, records...)
		back, err := h.read()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if back.Serial != h.Serial || back.Digest() != h.Digest {
			t.Errorf("%s: the records read as %d (%s), handed %d (%s)", name, back.Serial, back.Digest(), h.Serial, h.Digest)
		}
	}
}

// A hand-over whose records do not give the serial and digest it names, or
// that names a record of another type or owner, is refused; nothing is held.
func TestAHandOverWhoseRecordsDoNotGiveItsDigestIsRefused(t *testing.T) {
	const zone = "digest.acting.example."
	conf, _ := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	s := withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)

	wrong := *h
	wrong.Digest = "0000000000000000"
	stranger := *h
	stranger.Records = append(slices.Clone(h.Records), zone+" 3600 IN TXT \"no\"")
	other := *h
	other.Records = append(slices.Clone(h.Records[:len(h.Records)-1]), strings.Replace(h.Records[len(h.Records)-1], zone, "other."+zone, 1))
	for name, bad := range map[string]*ActingHandover{"another digest": &wrong, "a TXT record": &stranger, "another owner": &other} {
		if resp := handTo(conf, bad, actUs); resp.Status != "error" {
			t.Errorf("%s: taken (%s)", name, resp.Message)
		}
	}
	if _, held := s.get(zone); held {
		t.Error("a refused hand-over is held")
	}
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("the agent's hand-over is refused: %s", resp.Message)
	}
}

// A hand-over below the one held is refused, with what is held; one of the
// same key and contents is taken again; one after a forget is taken at a
// lower serial.
func TestAnOlderHandOverIsRefusedWithWhatIsHeld(t *testing.T) {
	const zone = "older.acting.example."
	conf, _ := actingCombiner(t, zone, actRecords(`serial="8" servers="alpha,beta" signers="alpha"`)...)
	s := withActing(t, nil)
	eight := handoverFor(t, zone, actRecords(`serial="8" servers="alpha,beta" signers="alpha"`)...)
	seven := handoverFor(t, zone, actRecords(`serial="7" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, eight, actUs); resp.Status != "ok" {
		t.Fatalf("serial 8 refused: %s", resp.Message)
	}
	resp := handTo(conf, seven, actUs)
	if resp.Status != "error" || !strings.Contains(resp.Message, "acting by 8 ("+eight.Digest+")") {
		t.Errorf("serial 7 after 8: %s %q, want refused with what is held", resp.Status, resp.Message)
	}
	again := *eight
	again.Made = eight.Made.Add(-time.Hour)
	if resp := handTo(conf, &again, actUs); resp.Status != "ok" {
		t.Errorf("the same hand-over again, made earlier, refused: %s", resp.Message)
	}
	otherSets := *eight
	otherSets.Sets.Servers = otherSets.Sets.Servers[:1]
	otherSets.Made = eight.Made.Add(-time.Hour)
	if resp := handTo(conf, &otherSets, actUs); resp.Status != "error" {
		t.Error("a hand-over of the same key with other sets, made before the one held, was taken")
	}
	reset := *seven
	reset.Reset, reset.Made = true, time.Now()
	if resp := handTo(conf, &reset, actUs); resp.Status != "ok" {
		t.Errorf("a hand-over after the agent forgot the zone's serials refused: %s", resp.Message)
	}
	if held, _ := s.get(zone); held.handover.Serial != 7 {
		t.Errorf("acting by %s after the forget, want 7", held.handover)
	}
}

// Only the combiner's own agent hands it anything, and only directly.
func TestAHandOverFromAnyoneButItsOwnAgentIsRefused(t *testing.T) {
	const zone = "sender.acting.example."
	conf, _ := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	s := withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, h, actOther); resp.Status != "error" {
		t.Error("another provider's agent handed the combiner a serial")
	}
	relayed := conf.combinerTakeHandover(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		OriginatorID: actUs, DeliveredBy: actOther, Zone: ZoneName(zone), Acting: h}}, map[string]bool{actUs: true})
	if relayed.Status != "error" {
		t.Error("a hand-over in the agent's name, delivered by another, was taken")
	}
	if _, held := s.get(zone); held {
		t.Error("a refused hand-over is held")
	}
}

// A hand-over waits for no operator: on a zone whose edits wait for manual
// approval it is taken at once, and kept as no pending edit.
func TestAHandOverIsNotHeldForManualApproval(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "manual.acting.example.", true, true)
	zone := mpzd.ZoneName
	apex, _ := mpzd.OwnerForAnalysis(zone)
	var rrs []dns.RR
	for _, l := range []string{"us", "alpha", "beta"} {
		rrs = append(rrs, &dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
			Data: &core.HSYNC3{State: 1, Label: l, Identity: "agent." + l + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: rrs})
	mpzd.Data.Set(zone, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	mpzd.Options[OptMPManualApproval] = true
	s := withActing(t, hdb)
	asMPDaemon(t, AppTypeMPCombiner)

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = hdb.KeyDB
	conf.SetMpConfig(&MultiProviderConf{Role: "combiner", Identity: csyncCombinerID, Agents: []*PeerConf{{Identity: csyncOurAgent}}})
	msgQs := &MsgQs{Msg: make(chan *AgentMsgPostPlus, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); CombinerMsgHandler(ctx, conf, msgQs, nil, nil) }()
	t.Cleanup(func() { cancel(); <-done })

	h := handoverFor(t, zone, `3600 IN HSYNC3 ON us agent.us.example. .`, `3600 IN HSYNC3 ON alpha agent.alpha.example. .`,
		`3600 IN HSYNCPARAM serial="4" servers="us,alpha" signers="us,alpha" nsmgmt="agent" parentsync="agent"`)
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: csyncOurAgent, DeliveredBy: csyncOurAgent,
		Zone: ZoneName(zone), DistributionID: nextDistributionID(), Acting: h}}
	waitUntil(t, "the hand-over was not taken", func() bool { _, held := s.get(zone); return held })
	if edits, _ := ListPendingEdits(hdb, zone); len(edits) > 0 {
		t.Errorf("the hand-over is kept as a pending edit: %+v", edits)
	}
}

// What the combiner was handed survives its restart: a new store on the same
// database holds it.
func TestTheHandedSerialSurvivesACombinerRestart(t *testing.T) {
	const zone = "restart.acting.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if err := hdb.InitCombinerEditTables(); err != nil {
		t.Fatalf("the combiner's tables: %v", err)
	}
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	withActing(t, hdb)
	h := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta"`)...)
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	restarted := withActing(t, hdb)
	held, ok := restarted.get(zone)
	if !ok || !held.handover.sameAs(h) || held.by != actUs {
		t.Fatalf("after a restart the combiner holds %v (by %q), want %s by its agent", held.handover, held.by, h)
	}
	// its copy, at 5, is stale: it acts by the serial handed
	apex, _ := mpzd.OwnerForAnalysis(zone)
	if in := restarted.reading(zone, apex); in == nil || in.Digest() != h.Digest {
		t.Error("the stored hand-over does not read as the one handed")
	}
	if in := instructionsFor(ZoneName(zone)); in == nil || in.Serial != 6 {
		t.Errorf("after a restart with a stale copy the combiner reads %v, want the serial handed", in)
	}
	if reject, why := mpzd.checkDNSKEYPolicy(actOther); reject {
		t.Errorf("after a restart with a stale copy, the signer its copy does not name yet is refused: %s", why)
	}
}

// The combiner acts by the serial handed, not its copy, when its copy is
// older: its copy says nsmgmt=owner and the serial handed says agent, and
// the contributed NS go into the incoming copy at a refresh. Its copy names
// one signer, the hand-over two, and the second signer's DNSKEY is taken.
// (#235's premise, a combiner behind its agent, which an agent that takes
// the zone from its own signer never sees.)
func TestTheCombinerActsByTheHandedSerialNotItsCopy(t *testing.T) {
	const zone = "copy.acting.example."
	copyRecords := actRecords(`serial="5" servers="alpha,beta" signers="alpha" nsmgmt="owner"`)
	conf, mpzd := actingCombiner(t, zone, copyRecords...)
	withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta" nsmgmt="agent"`)...)
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if in := instructionsFor(ZoneName(zone)); in == nil || in.Serial != 6 {
		t.Errorf("instructionsFor reads %v, want the serial handed", in)
	}
	if p := mpzd.getEditPolicy(); p.NSmgmt != core.HsyncNSmgmtAGENT {
		t.Errorf("the edit policy's nsmgmt is %d, want the handed agent", p.NSmgmt)
	}
	if reject, why := mpzd.checkDNSKEYPolicy(actOther); reject {
		t.Errorf("the second signer's DNSKEY, which the copy does not name yet, is refused: %s", why)
	}

	// a refresh: the incoming copy still says owner, and is combined by the
	// serial handed
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeNS: {Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, zone+" 3600 IN NS ns.beta.example.")}}}},
	}
	mpzd.Lock()
	mpzd.RebuildCombinerData()
	mpzd.Unlock()
	incoming := instrTestZone(t, "incoming."+zone, copyRecords...) // a ZoneData to read the copy from
	newZd := &tdns.ZoneData{ZoneName: zone, ZoneStore: tdns.MapZone, ZoneType: tdns.Primary, Logger: incoming.Logger,
		Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}, Data: incoming.Data}
	if apex, _ := incoming.GetOwner(incoming.ZoneName); apex != nil {
		cp := *apex
		cp.Name = zone
		newZd.Data.Set(zone, cp)
	}
	mpzd.MPPreRefresh(newZd, nil, nil, conf.MpConfig())
	apex, _ := newZd.OwnerForAnalysis(zone)
	var ns []string
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
		ns = append(ns, rr.(*dns.NS).Ns)
	}
	if !slices.Contains(ns, "ns.beta.example.") {
		t.Errorf("the refresh combined by the copy's nsmgmt=owner: NS %v lack the contributed one", ns)
	}
}

// At an edit the combiner loads the new serial before its agent, which
// takes the zone from its signer, hands it over: until S7 the combiner acts
// by its copy while that is newer than the hand-over, as before S10. A new
// signer's DNSKEY that reaches it in that gap is taken, and the merge is
// judged by the copy's signing set; then the hand-over of the new serial.
func TestACopyNewerThanTheHandOverIsActedBy(t *testing.T) {
	const zone = "newer.acting.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta"`)...)
	withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if in := instructionsFor(ZoneName(zone)); in == nil || in.Serial != 6 {
		t.Errorf("instructionsFor reads %v, want its copy's newer serial", in)
	}
	key := testDnskey(t, zone, 257)
	add := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(),
		Operations: []core.RROperation{{Operation: "add", RRtype: "DNSKEY", Records: []string{key.String()}}}}
	if resp := mpzd.combinerProcessOperations(add, zone, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy()); len(resp.RejectedItems) > 0 {
		t.Errorf("the new signer's DNSKEY is refused by the older serial handed: %+v", resp.RejectedItems)
	}
	// a DNSKEY stored for an origin in no signing set stays out of the
	// merge meanwhile
	mpzd.Lock()
	mpzd.MP.AgentContributions["agent.gamma.example."] = map[string]map[uint16]core.RRset{
		zone: {dns.TypeDNSKEY: dnskeyContribution(t, zone, testDnskey(t, zone, 257))}}
	mpzd.RebuildCombinerData()
	mpzd.Unlock()
	if od, ok := mpzd.MP.CombinerData.Get(zone); !ok || len(od.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) != 1 {
		t.Error("the merge does not hold the new signer's DNSKEY alone")
	}
	if line := combinerActingLine(mpzd); !strings.HasPrefix(line, "by its own copy, serial 6, newer than the 5 (") {
		t.Errorf("mplist says %q, want its own copy", line)
	}

	h6 := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta"`)...)
	if resp := handTo(conf, h6, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if line := combinerActingLine(mpzd); !strings.HasPrefix(line, "acting by 6 (") {
		t.Errorf("mplist says %q, want the serial handed", line)
	}
}

// A CDS the filter leaves out gives the zone back the upstream's CDS at the
// next combine, as a type the policy does not apply would: the cleanup does
// not delete the owner's RRset.
func TestAFilteredCDSGivesBackTheUpstreamCDS(t *testing.T) {
	const zone = "cds.acting.example."
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	upstream := zone + "\t3600\tIN\tCDS\t1111 15 2 " + strings.ToUpper(hex)
	param := `serial="5" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`
	conf, mpzd := actingCombiner(t, zone, append(actRecords(param), "3600 IN CDS 1111 15 2 "+hex)...)
	withActing(t, nil)
	contributed := zone + "\t3600\tIN\tCDS\t2222 15 2 " + strings.ToUpper(hex)
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeCDS: {Name: zone, RRtype: dns.TypeCDS, RRs: []dns.RR{mustRR(t, contributed)}}}},
	}
	if resp := handTo(conf, handoverFor(t, zone, actRecords(param)...), actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := servedTypes(t, mpzd, dns.TypeCDS); !slices.Equal(got, []string{contributed}) {
		t.Fatalf("with beta among the DS signers the zone serves CDS %v, want beta's", got)
	}
	h := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`)...)
	h.Sets.DSSigners = h.Sets.DSSigners[:1] // alpha
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := servedTypes(t, mpzd, dns.TypeCDS); !slices.Equal(got, []string{upstream}) {
		t.Errorf("with beta's CDS left out the zone serves CDS %v, want the upstream's", got)
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return rr
}

// A hand-over recombines the zone at once, with no transfer: nsmgmt from
// agent to owner takes the contributed NS out of the zone, back to the
// upstream's.
func TestAHandOverRecombinesTheZoneAtOnce(t *testing.T) {
	const zone = "recombine.acting.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha" nsmgmt="agent"`)...)
	withActing(t, nil)
	contributed := zone + "\t3600\tIN\tNS\tns.beta.example."
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeNS: {Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, contributed)}}}},
	}
	agent := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha" nsmgmt="agent"`)...)
	if resp := handTo(conf, agent, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if !slices.Contains(servedTypes(t, mpzd, dns.TypeNS), contributed) {
		t.Fatalf("under nsmgmt=agent the zone does not serve the contributed NS: %v", servedTypes(t, mpzd, dns.TypeNS))
	}
	owner := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha" nsmgmt="owner"`)...)
	if resp := handTo(conf, owner, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := servedTypes(t, mpzd, dns.TypeNS); slices.Contains(got, contributed) || len(got) == 0 {
		t.Errorf("handed nsmgmt=owner, the zone serves NS %v, want the upstream's alone", got)
	}
}

func dnskeyContribution(t *testing.T, zone string, keys ...*dns.DNSKEY) core.RRset {
	set := core.RRset{Name: zone, RRtype: dns.TypeDNSKEY}
	for _, k := range keys {
		set.RRs = append(set.RRs, k)
	}
	return set
}

// A DNSKEY added by an origin outside the KeySigners handed is refused; one
// it removes is not judged.
func TestADNSKEYAddedByAnOriginOutsideKeySignersIsRefused(t *testing.T) {
	const zone = "keysigners.acting.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta"`)...)
	withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	key := testDnskey(t, zone, 257)
	add := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(),
		Operations: []core.RROperation{{Operation: "add", RRtype: "DNSKEY", Records: []string{key.String()}}}}
	resp := mpzd.combinerProcessOperations(add, zone, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy())
	if len(resp.RejectedItems) != 1 || !strings.Contains(resp.RejectedItems[0].Reason, "is not a signer") {
		t.Errorf("a DNSKEY added by an origin the serial handed does not name: %s %+v", resp.Status, resp.RejectedItems)
	}
	// a DNSKEY it stored before, as under an earlier hand-over: its removal
	// is not judged, and removes it
	mpzd.Lock()
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeDNSKEY: dnskeyContribution(t, zone, key)}},
	}
	mpzd.Unlock()
	del := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(),
		Operations: []core.RROperation{{Operation: "delete", RRtype: "DNSKEY", Records: []string{key.String()}}}}
	if resp := mpzd.combinerProcessOperations(del, zone, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy()); len(resp.RejectedItems) > 0 {
		t.Errorf("an origin's removal of its own DNSKEY is judged: %+v", resp.RejectedItems)
	}
	mpzd.Lock()
	left := len(mpzd.MP.AgentContributions[actOther][zone][dns.TypeDNSKEY].RRs)
	mpzd.Unlock()
	if left != 0 {
		t.Errorf("the origin's DNSKEY is still stored after its removal: %d", left)
	}
}

// The rebuild keeps a DNSKEY only from origins in KeySigners and a CDS only
// from those in DSSigners; every other type from every origin, and with no
// hand-over held, everything stored.
func TestTheRebuildFiltersDNSKEYByKeySignersAndCDSByDSSigners(t *testing.T) {
	const zone = "rebuild.acting.example."
	_, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta"`)...)
	s := withActing(t, nil)
	cds := func(tag string) dns.RR {
		return mustRR(t, zone+" 3600 IN CDS "+tag+" 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actUs: {zone: {
			dns.TypeDNSKEY: dnskeyContribution(t, zone, testDnskey(t, zone, 257)),
			dns.TypeCDS:    {Name: zone, RRtype: dns.TypeCDS, RRs: []dns.RR{cds("1")}},
		}},
		actOther: {zone: {
			dns.TypeDNSKEY: dnskeyContribution(t, zone, testDnskey(t, zone, 257)),
			dns.TypeCDS:    {Name: zone, RRtype: dns.TypeCDS, RRs: []dns.RR{cds("2")}},
			dns.TypeNS:     {Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, zone+" 3600 IN NS ns.beta.example.")}},
		}},
	}
	count := func(rrtype uint16) int {
		od, ok := mpzd.MP.CombinerData.Get(zone)
		if !ok {
			return 0
		}
		return len(od.RRtypes.GetOnlyRRSet(rrtype).RRs)
	}
	mpzd.RebuildCombinerData()
	if count(dns.TypeDNSKEY) != 2 || count(dns.TypeCDS) != 2 {
		t.Fatalf("handed nothing, the merge holds %d DNSKEY and %d CDS, want every stored one", count(dns.TypeDNSKEY), count(dns.TypeCDS))
	}
	h := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha,beta"`)...)
	h.Sets.KeySigners = h.Sets.KeySigners[:1] // alpha
	h.Sets.DSSigners = h.Sets.DSSigners[1:]   // beta
	if _, _, err := s.take(h, actUs); err != nil {
		t.Fatalf("take: %v", err)
	}
	mpzd.RebuildCombinerData()
	if count(dns.TypeDNSKEY) != 1 || count(dns.TypeCDS) != 1 || count(dns.TypeNS) != 1 {
		t.Errorf("merged %d DNSKEY, %d CDS, %d NS; want alpha's DNSKEY, beta's CDS and beta's NS", count(dns.TypeDNSKEY), count(dns.TypeCDS), count(dns.TypeNS))
	}
	if len(mpzd.MP.AgentContributions[actOther][zone]) != 3 {
		t.Error("what the filter leaves out is no longer stored")
	}
}

// A stored DNSKEY is judged again when what the combiner was handed
// changes, with no contribution arriving: it leaves the zone, and stays
// stored.
func TestAStoredDNSKEYIsJudgedAgainAtEveryHandOver(t *testing.T) {
	const zone = "judged.acting.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta"`)...)
	withActing(t, nil)
	key := testDnskey(t, zone, 257)
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeDNSKEY: dnskeyContribution(t, zone, key)}},
	}
	both := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta"`)...)
	if resp := handTo(conf, both, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := servedTypes(t, mpzd, dns.TypeDNSKEY); len(got) != 1 {
		t.Fatalf("both signers handed: DNSKEY %v, want beta's", got)
	}
	alone := handoverFor(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, alone, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	if got := servedTypes(t, mpzd, dns.TypeDNSKEY); len(got) != 0 {
		t.Errorf("beta no longer a key signer: the zone serves DNSKEY %v", got)
	}
	if _, stored := mpzd.MP.AgentContributions[actOther][zone][dns.TypeDNSKEY]; !stored {
		t.Error("beta's DNSKEY is no longer stored")
	}
}

// A signer the owner takes out of signers= keeps its DNSKEYs and its CDS at
// every other provider's combiner while its HSYNC3 record stays (#275: the
// agent hands its signing set), and loses them when the record goes.
func TestALeaverKeepsItsDNSKEYsAndCDSAtEveryOtherCombinerUntilItsRecordGoes(t *testing.T) {
	const zone = "leaver.acting.example."
	agentMp := &MultiProviderConf{Role: "agent", Identity: actUs}
	agentConf := &Config{Config: &tdns.Config{}}
	agentConf.SetMpConfig(agentMp)

	// the agent's copy: beta out of signers=, its record kept, beta in the
	// signing set the copy before gave
	asMPDaemon(t, AppTypeMPAgent)
	mpzd := instrTestZone(t, zone, actRecords(`serial="6" servers="alpha,beta" signers="alpha"`)...)
	apex, _ := mpzd.OwnerForAnalysis(zone)
	mpzd.EnsureMP()
	mpzd.populateMPdata(agentMp, nextSigningSet(apex, signingSet{"alpha": actUs, "beta": actOther}))
	h := agentConf.wantedHandover(zone)
	if h == nil || !has(h.Sets.KeySigners, "beta") || !has(h.Sets.DSSigners, "beta") || has(h.Sets.Servers, "gamma") {
		t.Fatalf("the agent hands %+v, want beta among the key and DS signers", h)
	}

	// at the combiner
	asMPDaemon(t, AppTypeMPCombiner)
	s := withActing(t, nil)
	cds := mustRR(t, zone+" 3600 IN CDS 4 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeDNSKEY: dnskeyContribution(t, zone, testDnskey(t, zone, 257)), dns.TypeCDS: {Name: zone, RRtype: dns.TypeCDS, RRs: []dns.RR{cds}}}},
	}
	if _, _, err := s.take(h, actUs); err != nil {
		t.Fatalf("take: %v", err)
	}
	mpzd.RebuildCombinerData()
	od, _ := mpzd.MP.CombinerData.Get(zone)
	if len(od.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) != 1 || len(od.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs) != 1 {
		t.Fatal("the leaver's DNSKEY or CDS left another provider's combiner while it signs on")
	}

	// the owner removes beta's record: the signing set loses it, and so does
	// what the agent hands
	asMPDaemon(t, AppTypeMPAgent)
	actingHeld.Store(nil)
	gone := instrTestZone(t, "gone."+zone, actRecords(`serial="7" servers="alpha" signers="alpha"`)[0], `3600 IN HSYNCPARAM serial="7" servers="alpha" signers="alpha"`)
	goneApex, _ := gone.OwnerForAnalysis(gone.ZoneName)
	cp := *goneApex
	cp.Name = zone
	mpzd.Data.Set(zone, cp)
	mpzd.InstallInitialSnapshot()
	mpzd.populateMPdata(agentMp, nextSigningSet(&cp, mpzd.signingSet()))
	h2 := agentConf.wantedHandover(zone)
	if h2 == nil || has(h2.Sets.KeySigners, "beta") {
		t.Fatalf("with beta's record gone the agent hands %+v", h2)
	}
	actingHeld.Store(s)
	if _, _, err := s.take(h2, actUs); err != nil {
		t.Fatalf("take: %v", err)
	}
	mpzd.RebuildCombinerData()
	od, _ = mpzd.MP.CombinerData.Get(zone)
	if n := len(od.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) + len(od.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs); n != 0 {
		t.Errorf("beta's record is gone, and the combiner still merges %d of its DNSKEY and CDS records", n)
	}
}

// Handed nothing, a combiner acts by its copy: provisional for a copy with
// no serial; for one with a serial it waits for its agent, serving what it
// served, or with nothing restored, the copy as it comes.
func TestAFirstLoadWithNothingHandedIsProvisionalOrWaits(t *testing.T) {
	_, plain := actingCombiner(t, "plain.acting.example.", actRecords(`servers="alpha,beta" signers="alpha"`)...)
	_, serial := actingCombiner(t, "serial.acting.example.", actRecords(`serial="3" servers="alpha,beta" signers="alpha"`)...)
	_, restored := actingCombiner(t, "restored.acting.example.", actRecords(`serial="3" servers="alpha,beta" signers="alpha"`)...)
	restored.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {restored.ZoneName: {dns.TypeNS: {Name: restored.ZoneName, RRtype: dns.TypeNS, RRs: []dns.RR{mustRR(t, restored.ZoneName+" 3600 IN NS ns.beta.example.")}}}},
	}
	if line := combinerActingLine(plain); line != "" {
		t.Errorf("on no combiner store: %q", line)
	}
	withActing(t, nil)
	for _, c := range []struct {
		mpzd *MPZoneData
		want string
	}{
		{plain, "provisional, by its own copy"},
		{serial, "waiting for its agent's hand-over, serving the copy as it comes"},
		{restored, "waiting for its agent's hand-over, serving what it served"},
	} {
		if got := combinerActingLine(c.mpzd); got != c.want {
			t.Errorf("%s: %q, want %q", c.mpzd.ZoneName, got, c.want)
		}
	}
	if !serial.waitsForHandover() || plain.waitsForHandover() {
		t.Error("a zone whose copy carries a serial waits, one without does not")
	}
}

// While it waits, the combiner removes no stored contribution: it merges
// every one, by no origin.
func TestWhileWaitingTheCombinerRemovesNoStoredContribution(t *testing.T) {
	const zone = "waiting.acting.example."
	_, mpzd := actingCombiner(t, zone, actRecords(`serial="3" servers="alpha,beta" signers="alpha"`)...)
	withActing(t, nil)
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actOther: {zone: {dns.TypeDNSKEY: dnskeyContribution(t, zone, testDnskey(t, zone, 257))}},
	}
	mpzd.RebuildCombinerData()
	od, _ := mpzd.MP.CombinerData.Get(zone)
	if len(od.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) != 1 {
		t.Error("a waiting combiner judged a stored DNSKEY by its copy, which names its origin no signer")
	}
}

// The combiner refreshes the zone from its upstream when its agent asks.
func TestTheCombinerRefreshesWhenItsAgentAsks(t *testing.T) {
	const zone = "refresh.acting.example."
	conf, _ := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	conf.Config.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 1)
	withActing(t, nil)
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	h.Refresh = true
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	select {
	case zr := <-conf.Config.Internal.RefreshZoneCh:
		if zr.Name != zone {
			t.Errorf("refresh of %s, want %s", zr.Name, zone)
		}
	default:
		t.Error("the agent's refresh flag asked for no refresh")
	}
}

// The combiner's answer to an own read (EDITS) says what it acts by.
func TestTheEditsAnswerCarriesTheHandOverHeld(t *testing.T) {
	const zone = "edits.acting.example."
	conf, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	withActing(t, nil)
	if a := editsAnswerFor(mpzd, "combiner.alpha.example.", zone, "n"); a.Acting != nil {
		t.Errorf("handed nothing, the answer names %s", a.Acting)
	}
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	if resp := handTo(conf, h, actUs); resp.Status != "ok" {
		t.Fatalf("refused: %s", resp.Message)
	}
	a := editsAnswerFor(mpzd, "combiner.alpha.example.", zone, "n")
	if !a.Acting.sameAs(h) {
		t.Errorf("the answer names %s, want %s", a.Acting, h)
	}
	msg, err := editsAppMessage(a, actUs)
	if err != nil {
		t.Fatal(err)
	}
	var wire DnsEditsPayload
	if err := json.Unmarshal(msg.Payload, &wire); err != nil || !wire.Acting.sameAs(h) {
		t.Errorf("on the wire the answer names %v (%v)", wire.Acting, err)
	}
}

// One agent per part: a combiner configured with two agents is refused.
func TestACombinerWithTwoAgentsIsAConfigError(t *testing.T) {
	one := &MultiProviderConf{Role: "combiner", Agents: []*PeerConf{{Identity: actUs}}}
	two := &MultiProviderConf{Role: "combiner", Agents: []*PeerConf{{Identity: actUs}, {Identity: actOther}}}
	agent := &MultiProviderConf{Role: "agent", Agents: []*PeerConf{{Identity: actUs}, {Identity: actOther}}}
	if err := ValidatePartAgents(one); err != nil {
		t.Errorf("one agent: %v", err)
	}
	if err := ValidatePartAgents(two); err == nil || !strings.Contains(err.Error(), "a multi-provider combiner has more than one agent") {
		t.Errorf("two agents: %v", err)
	}
	if err := ValidatePartAgents(agent); err != nil {
		t.Errorf("not a combiner: %v", err)
	}
}

// The first copy a combiner serves after a start is combined by the serial
// its agent handed it before the restart, not by the copy: the copy names
// both providers signers, the serial handed only this one, and the other's
// persisted DNSKEYs stay out of the first copy (PR #208's harness).
func TestCombinerFirstCopyIsCombinedByTheHandedSerial(t *testing.T) {
	asMPDaemon(t, AppTypeMPCombiner)
	kdb := newMPTestKeyDB(t)
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatalf("InitHsyncTables: %v", err)
	}
	const zone = "firstcopy.acting.example."
	ksk := testDnskey(t, zone, 257)
	contrib := map[string]map[uint16]core.RRset{zone: {dns.TypeDNSKEY: {Name: zone, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{ksk}}}}
	if err := SaveContributions(hdb, zone, relayOther, contrib); err != nil {
		t.Fatalf("SaveContributions: %v", err)
	}
	// handed before the restart, kept in the database
	h := handoverFor(t, zone, `300 IN HSYNC3 ON alpha `+relayOther+` .`, `300 IN HSYNC3 ON beta `+relayUs+` .`,
		`300 IN HSYNCPARAM serial="12" servers="alpha,beta" signers="beta"`)
	if _, _, err := withActing(t, hdb).take(h, relayUs); err != nil {
		t.Fatalf("take: %v", err)
	}
	withActing(t, hdb) // the restart reads it back

	first := make(chan map[uint16]bool, 1)
	up := startMPUpstream(t, zone, "alpha,beta", false, 40)
	mp := &MultiProviderConf{Role: "combiner", Active: true, Identity: "combiner.beta.example.", Agents: []*PeerConf{{Identity: relayUs}}}
	startMPServedZone(t, kdb, up, mp, nil, func(conf *Config, zd *tdns.ZoneData) {
		zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
			tags := map[uint16]bool{}
			if apex, err := zd.GetOwner(zd.ZoneName); err == nil && apex != nil {
				for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
					tags[rr.(*dns.DNSKEY).KeyTag()] = true
				}
			}
			first <- tags
		})
		conf.RegisterCombinerOnFirstLoad()
	})
	select {
	case tags := <-first:
		if tags[ksk.KeyTag()] {
			t.Error("the first copy serves the DNSKEY of a provider the serial handed names no signer, as the copy would have it")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the zone's first load did not complete")
	}
	if in := instructionsFor(ZoneName(zone)); in == nil || in.Serial != 12 {
		t.Errorf("after the first load the combiner reads %v, want the serial handed", in)
	}
}
