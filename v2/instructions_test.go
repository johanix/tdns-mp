/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The canonical reading of the owner's instructions and its digest (plan S1).
 */
package tdnsmp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const instrZone = "instr.example."

// instrBase is a zone's instructions in zone-file form: two ON records, one
// with an upstream, an OFF record, and every known HSYNCPARAM key.
var instrBase = []string{
	`3600 IN HSYNC3 ON alpha agent.alpha.example. .`,
	`3600 IN HSYNC3 ON beta agent.beta.example. alpha`,
	`3600 IN HSYNC3 OFF gamma agent.gamma.example. .`,
	`3600 IN HSYNCPARAM serial="7" servers="alpha,beta" signers="alpha" auditors="beta" nsmgmt="agent" parentsync="agent" suffix="mp" pubkey pubcds`,
}

// apexOf builds the apex of instrZone from records in zone-file form.
func apexOf(t *testing.T, records ...string) *tdns.OwnerData {
	t.Helper()
	var rrs []dns.RR
	for _, s := range records {
		rr, err := dns.NewRR(instrZone + " " + s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		rrs = append(rrs, rr)
	}
	return apexOfRRs(rrs...)
}

// apexOfRRs builds the apex of instrZone from records already made, which
// may bypass tdns's parser.
func apexOfRRs(rrs ...dns.RR) *tdns.OwnerData {
	apex := tdns.NewOwnerData(instrZone)
	sets := map[uint16][]dns.RR{}
	for _, rr := range rrs {
		rrtype := rr.Header().Rrtype
		sets[rrtype] = append(sets[rrtype], rr)
	}
	for rrtype, set := range sets {
		apex.RRtypes.Set(rrtype, core.RRset{Name: instrZone, Class: dns.ClassINET, RRtype: rrtype, RRs: set})
	}
	return apex
}

// readOf reads the instructions of records, which must read.
func readOf(t *testing.T, records ...string) *Instructions {
	t.Helper()
	in, err := ReadInstructions(apexOf(t, records...))
	if err != nil {
		t.Fatalf("ReadInstructions: %v", err)
	}
	if in == nil {
		t.Fatal("ReadInstructions: no reading")
	}
	return in
}

func digestOf(t *testing.T, records ...string) string {
	t.Helper()
	return readOf(t, records...).Digest()
}

// withParam is instrBase with its HSYNCPARAM record replaced.
func withParam(param string) []string {
	return append(slices.Clone(instrBase[:3]), `3600 IN HSYNCPARAM `+numberedText(param))
}

func hsync3RR(state uint8, label, identity, upstream string) dns.RR {
	return &dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: instrZone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNC3{State: state, Label: label, Identity: identity, Upstream: upstream},
	}
}

func TestTheDigestIgnoresOrderTTLAndSignatures(t *testing.T) {
	want := digestOf(t, instrBase...)

	reversed := slices.Clone(instrBase)
	slices.Reverse(reversed)
	if got := digestOf(t, reversed...); got != want {
		t.Errorf("records in another order: digest %s, want %s", got, want)
	}

	var shortTTL []string
	for _, s := range instrBase {
		shortTTL = append(shortTTL, strings.Replace(s, "3600", "300", 1))
	}
	if got := digestOf(t, shortTTL...); got != want {
		t.Errorf("another TTL: digest %s, want %s", got, want)
	}

	apex := apexOf(t, instrBase...)
	for _, rrtype := range []uint16{core.TypeHSYNC3, core.TypeHSYNCPARAM} {
		rrset := apex.RRtypes.GetOnlyRRSet(rrtype)
		rrset.RRSIGs = []dns.RR{&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: instrZone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: rrtype, Algorithm: dns.ED25519, Labels: 2, OrigTtl: 3600,
			Expiration: 2000000000, Inception: 1900000000, KeyTag: 4711,
			SignerName: instrZone, Signature: "AAAA",
		}}
		apex.RRtypes.Set(rrtype, rrset)
	}
	in, err := ReadInstructions(apex)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.Digest(); got != want {
		t.Errorf("signed: digest %s, want %s", got, want)
	}
}

func TestTheDigestIgnoresTheSerial(t *testing.T) {
	seven := readOf(t, instrBase...)
	eight := readOf(t, withParam(`serial="8" servers="alpha,beta" signers="alpha" auditors="beta" nsmgmt="agent" parentsync="agent" suffix="mp" pubkey pubcds`)...)
	zero := readOf(t, withParam(`serial="0" servers="alpha,beta" signers="alpha" auditors="beta" nsmgmt="agent" parentsync="agent" suffix="mp" pubkey pubcds`)...)
	if seven.Serial != 7 || eight.Serial != 8 || zero.Serial != 0 {
		t.Fatalf("serials %d %d %d, want 7 8 0", seven.Serial, eight.Serial, zero.Serial)
	}
	if seven.Digest() != eight.Digest() || seven.Digest() != zero.Digest() {
		t.Errorf("digests %s %s %s differ by the serial alone", seven.Digest(), eight.Digest(), zero.Digest())
	}
}

func TestTheDigestIgnoresUnknownKeys(t *testing.T) {
	want := digestOf(t, instrBase...)
	// key100 is unregistered, key40000 private use: read back, never acted on.
	got := digestOf(t, withParam(`serial="7" servers="alpha,beta" signers="alpha" auditors="beta" nsmgmt="agent" parentsync="agent" suffix="mp" pubkey pubcds key100="x" key40000="y"`)...)
	if got != want {
		t.Errorf("with unknown keys: digest %s, want %s", got, want)
	}
}

func TestTheDigestSeesAnOffLabelButNotItsFields(t *testing.T) {
	base := digestOf(t, instrBase...)
	withoutOff := digestOf(t, instrBase[0], instrBase[1], instrBase[3])
	if withoutOff == base {
		t.Error("dropping the OFF record changed no digest")
	}
	otherFields := digestOf(t, instrBase[0], instrBase[1],
		`3600 IN HSYNC3 OFF gamma agent.other.example. alpha`, instrBase[3])
	if otherFields != base {
		t.Errorf("another identity and upstream under the OFF label: digest %s, want %s", otherFields, base)
	}
	otherLabel := digestOf(t, instrBase[0], instrBase[1],
		`3600 IN HSYNC3 OFF delta agent.gamma.example. .`, instrBase[3])
	if otherLabel == base {
		t.Error("another OFF label changed no digest")
	}
}

func TestTheDigestSeesEveryFieldTheCodeActsOn(t *testing.T) {
	base := readOf(t, instrBase...)
	edits := []struct {
		field string
		edit  func(in *Instructions)
	}{
		{"label", func(in *Instructions) { in.Records[1].Label = "delta" }},
		{"identity", func(in *Instructions) { in.Records[1].Identity = "agent.delta.example." }},
		{"upstream", func(in *Instructions) { in.Records[1].Upstream = "" }},
		{"servers", func(in *Instructions) { in.Servers = []string{"alpha"} }},
		{"signers", func(in *Instructions) { in.Signers = []string{"alpha", "beta"} }},
		{"auditors", func(in *Instructions) { in.Auditors = []string{} }},
		{"nsmgmt", func(in *Instructions) { in.NSmgmt = core.HsyncNSmgmtOWNER }},
		{"parentsync", func(in *Instructions) { in.ParentSync = core.HsyncParentSyncOwner }},
		{"suffix", func(in *Instructions) { in.Suffix = "" }},
		{"pubkey", func(in *Instructions) { in.Pubkey = false }},
		{"pubcds", func(in *Instructions) { in.Pubcds = false }},
		{"HasParam", func(in *Instructions) { in.HasParam = false }},
	}
	seen := map[string]string{base.Digest(): "nothing"}
	for _, e := range edits {
		in := *base
		in.Records = slices.Clone(base.Records)
		e.edit(&in)
		d := in.Digest()
		if prev, dup := seen[d]; dup {
			t.Errorf("an edit of %s gives the digest of an edit of %s, %s", e.field, prev, d)
			continue
		}
		seen[d] = e.field
	}
}

// HSYNC3 without HSYNCPARAM is an owner error (#308): the legacy reading,
// in which every ON record voted, is gone. HSYNC3 with an HSYNCPARAM that
// names no role reads, and nobody has a role in it.
func TestHSYNC3WithoutHSYNCPARAMIsAnOwnerError(t *testing.T) {
	hsync3 := hsync3RR(core.HsyncStateON, "alpha", "agent.alpha.example.", ".")
	in, err := ReadInstructions(apexOfRRs(hsync3))
	if !errors.Is(err, errNoHsyncparam) || in != nil {
		t.Fatalf("reading %v, error %v; want the owner error %v", in, err, errNoHsyncparam)
	}
	if err.Error() != "HSYNC3 without HSYNCPARAM" {
		t.Errorf("error %q", err)
	}
	empty := &dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: instrZone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: numbered(&core.HSYNCPARAM{}),
	}
	param, err := ReadInstructions(apexOfRRs(hsync3, empty))
	if err != nil || param == nil || !param.HasParam {
		t.Fatalf("HSYNC3 with an HSYNCPARAM of no roles: reading %v, error %v", param, err)
	}
	if _, voting := participantsOf(param); len(voting) != 0 {
		t.Errorf("voting %v, want nobody", voting)
	}
}

// HSYNCPARAM without serial= is an owner error (#308), with HSYNC3 and
// without. An explicit serial="0" is a serial like any other.
func TestHSYNCPARAMWithoutASerialIsAnOwnerError(t *testing.T) {
	for _, records := range [][]string{
		{instrBase[0], `3600 IN HSYNCPARAM servers="alpha"`},
		{`3600 IN HSYNCPARAM servers="alpha"`},
	} {
		in, err := ReadInstructions(apexOf(t, records...))
		if !errors.Is(err, errNoSerial) || in != nil {
			t.Errorf("%v: reading %v, error %v; want the owner error %v", records, in, err, errNoSerial)
			continue
		}
		if err.Error() != "HSYNCPARAM without serial=" {
			t.Errorf("error %q", err)
		}
	}
	in := readOf(t, instrBase[0], `3600 IN HSYNCPARAM servers="alpha" serial="0"`)
	if in.Serial != 0 || !slices.Equal(in.Servers, []string{"alpha"}) {
		t.Errorf("serial=\"0\": serial %d servers %v", in.Serial, in.Servers)
	}
}

// One identity under two HSYNC3 labels is an owner error (#306), the
// converse of two records with one label; identities are compared as names.
// An OFF record names no one.
func TestOneIdentityUnderTwoLabelsIsAnOwnerError(t *testing.T) {
	in, err := ReadInstructions(apexOf(t,
		`3600 IN HSYNC3 ON beta agent.alpha.example. .`,
		`3600 IN HSYNC3 ON alpha AGENT.Alpha.Example. .`,
		instrBase[3]))
	if !errors.Is(err, errIdentityTwoLabels) || in != nil {
		t.Fatalf("reading %v, error %v; want the owner error %v", in, err, errIdentityTwoLabels)
	}
	if err.Error() != "one identity under two HSYNC3 labels: agent.alpha.example. under alpha and beta" {
		t.Errorf("error %q", err)
	}
	if _, err := ReadInstructions(apexOf(t,
		`3600 IN HSYNC3 ON alpha agent.alpha.example. .`,
		`3600 IN HSYNC3 OFF beta agent.alpha.example. .`,
		instrBase[3])); err != nil {
		t.Errorf("an identity ON under one label and OFF under another: %v", err)
	}
}

func TestIdentitiesAreCaseFolded(t *testing.T) {
	lower := readOf(t, instrBase...)
	upper := readOf(t, `3600 IN HSYNC3 ON alpha AGENT.Alpha.Example. .`, instrBase[1], instrBase[2], instrBase[3])
	if upper.Records[0].Identity != "agent.alpha.example." {
		t.Errorf("identity %q, want agent.alpha.example.", upper.Records[0].Identity)
	}
	if upper.Digest() != lower.Digest() {
		t.Error("an identity's case changed the digest")
	}
}

func TestALabelsTrailingDotIsNoDifference(t *testing.T) {
	param := &dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: instrZone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: numbered(&core.HSYNCPARAM{}),
	}
	plain, err := ReadInstructions(apexOfRRs(
		hsync3RR(core.HsyncStateON, "alpha", "agent.alpha.example.", "."),
		hsync3RR(core.HsyncStateON, "beta", "agent.beta.example.", "alpha"),
		hsync3RR(core.HsyncStateOFF, "gamma", "agent.gamma.example.", "."), param))
	if err != nil {
		t.Fatal(err)
	}
	dotted, err := ReadInstructions(apexOfRRs(
		hsync3RR(core.HsyncStateON, "alpha.", "agent.alpha.example.", "."),
		hsync3RR(core.HsyncStateON, "beta.", "agent.beta.example.", "alpha."),
		hsync3RR(core.HsyncStateOFF, "gamma.", "agent.gamma.example.", "."), param))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Digest() != dotted.Digest() {
		t.Error("a trailing dot on a label or an upstream changed the digest")
	}
	want := []InstrRecord{
		{Label: "alpha", Identity: "agent.alpha.example.", Upstream: ""},
		{Label: "beta", Identity: "agent.beta.example.", Upstream: "alpha"},
	}
	if !slices.Equal(dotted.Records, want) || !slices.Equal(dotted.Off, []string{"gamma"}) {
		t.Errorf("read %v off %v, want %v off [gamma]", dotted.Records, dotted.Off, want)
	}
}

func TestAbsentAndDefaultKeysReadTheSame(t *testing.T) {
	absent := digestOf(t, withParam(`servers="alpha"`)...)
	defaults := digestOf(t, withParam(`servers="alpha" signers="" auditors="" nsmgmt="owner" parentsync="owner"`)...)
	if absent != defaults {
		t.Errorf("absent keys %s, the same keys at their defaults %s", absent, defaults)
	}
}

func TestListsAreSets(t *testing.T) {
	in := readOf(t, withParam(`servers="beta,alpha,beta" signers="alpha" auditors="beta"`)...)
	if !slices.Equal(in.Servers, []string{"alpha", "beta"}) {
		t.Errorf("servers %v, want [alpha beta]", in.Servers)
	}
	if got, want := in.Digest(), digestOf(t, withParam(`servers="alpha,beta" signers="alpha" auditors="beta"`)...); got != want {
		t.Errorf("a list in another order, with a repeat: digest %s, want %s", got, want)
	}
}

func TestTwoHsyncparamRecordsAreAnOwnerError(t *testing.T) {
	in, err := ReadInstructions(apexOf(t, append(slices.Clone(instrBase), `3600 IN HSYNCPARAM serial="7" servers="alpha"`)...))
	if !errors.Is(err, errTwoHsyncparams) || in != nil {
		t.Fatalf("reading %v, error %v; want the owner error %v", in, err, errTwoHsyncparams)
	}
	if err.Error() != "two HSYNCPARAM records" {
		t.Errorf("error %q", err)
	}
}

func TestTwoRecordsWithOneLabelAreAnOwnerErrorInAnyState(t *testing.T) {
	for _, states := range [][2]string{{"ON", "ON"}, {"ON", "OFF"}, {"OFF", "ON"}, {"OFF", "OFF"}} {
		in, err := ReadInstructions(apexOf(t,
			`3600 IN HSYNC3 `+states[0]+` alpha agent.alpha.example. .`,
			`3600 IN HSYNC3 `+states[1]+` alpha agent.other.example. .`,
			instrBase[3]))
		if !errors.Is(err, errDuplicateLabel) || in != nil {
			t.Errorf("%s and %s: reading %v, error %v; want the owner error", states[0], states[1], in, err)
			continue
		}
		if err.Error() != "two HSYNC3 records with the label alpha" {
			t.Errorf("error %q", err)
		}
	}
}

func TestNeitherRecordIsNoInstructions(t *testing.T) {
	if in, err := ReadInstructions(apexOf(t, `3600 IN TXT "no instructions"`)); in != nil || err != nil {
		t.Errorf("neither record: reading %v, error %v; want neither", in, err)
	}
}

func TestSerialsCompareByRFC1982(t *testing.T) {
	const half = uint32(1) << 31
	for _, c := range []struct {
		a, b uint32
		want int
	}{
		{1, 2, -1},
		{2, 1, 1},
		{7, 7, 0},
		{0xffffffff, 0, -1}, // the wrap: 0 follows 2^32-1
		{0, 0xffffffff, 1},
		{0xfffffff0, 5, -1},
		{0, half - 1, -1},
		{0, half + 1, 1}, // more than 2^31 ahead is behind
		{0, half, 0},     // the undefined half
		{half, 0, 0},
		{5, half + 5, 0},
	} {
		if got := CompareSerial(c.a, c.b); got != c.want {
			t.Errorf("CompareSerial(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareSerials(t *testing.T) {
	param := func(serial string, servers string) []string {
		return withParam(fmt.Sprintf(`serial="%s" servers="%s" signers="alpha" auditors="beta" nsmgmt="agent" parentsync="agent" suffix="mp" pubkey pubcds`, serial, servers))
	}
	held := readOf(t, instrBase...)
	for _, c := range []struct {
		name string
		cp   *Instructions
		want SerialOrder
	}{
		{"the same", readOf(t, param("7", "alpha,beta")...), SerialSame},
		{"a higher serial", readOf(t, param("8", "alpha")...), SerialNewer},
		{"a lower serial", readOf(t, param("6", "alpha")...), SerialOlder},
		{"the same serial, another digest", readOf(t, param("7", "alpha")...), SerialConflict},
		{"2^31 away", readOf(t, param(fmt.Sprint(uint32(7)+1<<31), "alpha,beta")...), SerialUndefined},
		{"no reading", nil, SerialUndefined},
	} {
		if got := CompareSerials(held, c.cp).Order; got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if c := CompareSerials(nil, held); c.Order != SerialNewer || len(c.Added) != 2 || len(c.Removed) != 0 {
		t.Errorf("nothing held: %v added %v removed %v; want newer, both records added", c.Order, c.Added, c.Removed)
	}
	if c := CompareSerials(held, readOf(t, instrBase...)); len(c.Added) != 0 || len(c.Removed) != 0 {
		t.Errorf("the same records: added %v removed %v", c.Added, c.Removed)
	}
}

func TestAnIdentityChangedUnderALabelIsARemovalAndAnAddition(t *testing.T) {
	held := readOf(t, instrBase...)
	cp := readOf(t, instrBase[0], `3600 IN HSYNC3 ON beta agent.other.example. alpha`, instrBase[2],
		strings.Replace(instrBase[3], `serial="7"`, `serial="8"`, 1))
	c := CompareSerials(held, cp)
	if c.Order != SerialNewer {
		t.Errorf("order %v, want newer", c.Order)
	}
	wantRemoved := []InstrRecord{{Label: "beta", Identity: "agent.beta.example.", Upstream: "alpha"}}
	wantAdded := []InstrRecord{{Label: "beta", Identity: "agent.other.example.", Upstream: "alpha"}}
	if !slices.Equal(c.Removed, wantRemoved) || !slices.Equal(c.Added, wantAdded) {
		t.Errorf("removed %v added %v; want removed %v added %v", c.Removed, c.Added, wantRemoved, wantAdded)
	}
	// An upstream changed under the same label and identity removes and adds
	// no record; S4's judge reads upstreams from the records themselves.
	up := CompareSerials(held, readOf(t, instrBase[0], `3600 IN HSYNC3 ON beta agent.beta.example. .`, instrBase[2],
		strings.Replace(instrBase[3], `serial="7"`, `serial="8"`, 1)))
	if up.Order != SerialNewer || len(up.Added)+len(up.Removed) != 0 {
		t.Errorf("an upstream changed: %v added %v removed %v; want newer, none", up.Order, up.Added, up.Removed)
	}
	// The identity's case is no change of identity.
	same := CompareSerials(held, readOf(t, instrBase[0], `3600 IN HSYNC3 ON beta Agent.Beta.Example. alpha`, instrBase[2], instrBase[3]))
	if same.Order != SerialSame || len(same.Added)+len(same.Removed) != 0 {
		t.Errorf("an identity in another case: %v added %v removed %v", same.Order, same.Added, same.Removed)
	}
}

// TestTheDigestIsPinned pins the digest of instrBase. Every agent of a zone
// compares digests, so a change of the encoding must be deliberate: it
// changes every digest, and all agents must run it together.
func TestTheDigestIsPinned(t *testing.T) {
	const golden = "d7294061a3f8f5af"
	if got := digestOf(t, instrBase...); got != golden {
		t.Errorf("digest %s, pinned %s", got, golden)
	}
}

// instrTestZone loads a multi-provider zone whose apex holds records, beside
// its SOA and NS records.
func instrTestZone(t *testing.T, name string, records ...string) *MPZoneData {
	t.Helper()
	text := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n",
		name, name, name, name, name, name)
	for _, r := range records {
		text += name + " " + r + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.Ready = true
	zd.InstallInitialSnapshot()
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	mpzd, ok := Zones.Get(name)
	if !ok {
		t.Fatal("wrapper not found")
	}
	return mpzd
}

// setApex replaces one RRset at the zone's apex, for an owner error the zone
// loader might not let through.
func setApex(t *testing.T, mpzd *MPZoneData, rrtype uint16, records ...string) {
	t.Helper()
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var rrs []dns.RR
	for _, s := range records {
		rr, err := dns.NewRR(mpzd.ZoneName + " " + s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		rrs = append(rrs, rr)
	}
	apex.RRtypes.Set(rrtype, core.RRset{Name: mpzd.ZoneName, Class: dns.ClassINET, RRtype: rrtype, RRs: rrs})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()
}

func TestMplistShowsTheCopysSerialAndDigest(t *testing.T) {
	want := digestOf(t, instrBase...)
	info := MPZoneInfoFromMPZoneData(instrTestZone(t, "list.example.", instrBase...))
	if info.Serial != 7 || info.Digest == "" || info.OwnerError != "" {
		t.Fatalf("serial %d digest %q owner error %q; want 7, a digest, none", info.Serial, info.Digest, info.OwnerError)
	}
	// The zone's name is not in the reading: the same instructions in
	// another zone have the same digest.
	if info.Digest != want {
		t.Errorf("digest %s, want %s", info.Digest, want)
	}
	if !slices.Equal(info.Servers, []string{"alpha", "beta"}) || info.NSmgmt != "agent" {
		t.Errorf("servers %v nsmgmt %s: the lists are as before", info.Servers, info.NSmgmt)
	}

	legacy := MPZoneInfoFromMPZoneData(instrTestZone(t, "legacy.example.", instrBase[:3]...))
	if legacy.OwnerError != "HSYNC3 without HSYNCPARAM" || legacy.Digest != "" {
		t.Errorf("HSYNC3 without HSYNCPARAM: owner error %q digest %q; want the owner error, no digest", legacy.OwnerError, legacy.Digest)
	}

	twice := instrTestZone(t, "twice.example.", instrBase...)
	setApex(t, twice, core.TypeHSYNCPARAM, instrBase[3], `3600 IN HSYNCPARAM serial="7" servers="alpha"`)
	if info := MPZoneInfoFromMPZoneData(twice); info.OwnerError != "two HSYNCPARAM records" || info.Digest != "" {
		t.Errorf("two HSYNCPARAM records: owner error %q digest %q", info.OwnerError, info.Digest)
	}
}

func TestTheAuditorListsTheOwnerErrors(t *testing.T) {
	clean := instrTestZone(t, "clean.example.", instrBase...)
	for _, e := range checkMPZoneHSYNCConfig(clean) {
		if strings.HasPrefix(e, "two ") {
			t.Errorf("a clean zone lists %q", e)
		}
	}

	twice := instrTestZone(t, "twice.example.", instrBase...)
	setApex(t, twice, core.TypeHSYNCPARAM, instrBase[3], `3600 IN HSYNCPARAM serial="7" servers="alpha"`)
	if errs := checkMPZoneHSYNCConfig(twice); len(errs) == 0 || errs[0] != "two HSYNCPARAM records" {
		t.Errorf("two HSYNCPARAM records: config errors %v", errs)
	}

	dup := instrTestZone(t, "dup.example.", instrBase...)
	setApex(t, dup, core.TypeHSYNC3, instrBase[0], instrBase[1], `3600 IN HSYNC3 OFF alpha agent.other.example. .`)
	if errs := checkMPZoneHSYNCConfig(dup); len(errs) == 0 || errs[0] != "two HSYNC3 records with the label alpha" {
		t.Errorf("two records with one label: config errors %v", errs)
	}
}

// numbered is hp with serial 1 when it has no serial=: every reading has the
// owner's serial (#308), and a test that is not about the serial takes 1.
func numbered(hp *core.HSYNCPARAM) *core.HSYNCPARAM {
	if _, ok := hp.GetSerial(); !ok {
		hp.Value = append(hp.Value, &core.HSYNCPARAMSerial{Value: 1})
	}
	return hp
}

// numberedText is an HSYNCPARAM's presentation form with serial="1" when it
// has no serial=, as numbered.
func numberedText(param string) string {
	if strings.Contains(param, "serial=") {
		return param
	}
	return strings.TrimSpace(param + ` serial="1"`)
}
