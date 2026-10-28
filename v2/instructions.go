/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The zone owner's instructions: one canonical reading of a zone's HSYNC3 and
 * HSYNCPARAM records, its digest, and the order of two serials (design rules
 * 1 and 2, docs/2026-10-18-owner-instruction-transitions-design.md). Nothing
 * decides from the reading yet: mplist and the auditor's config errors show
 * it (plan S1).
 */
package tdnsmp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The owner errors of a single copy (design rule 2): the draft allows one
// HSYNCPARAM record per zone and one HSYNC3 record per label.
var (
	errTwoHsyncparams = errors.New("two HSYNCPARAM records")
	errDuplicateLabel = errors.New("two HSYNC3 records with the label")
)

// Instructions is the canonical reading of a zone's HSYNC3 and HSYNCPARAM
// records (design rule 2): what the code acts on, and nothing else. Unknown
// and private-use keys, TTLs and signatures are not in it.
type Instructions struct {
	Serial   uint32        // 0 when the key is absent; not in the digest
	HasParam bool          // false: HSYNC3 without HSYNCPARAM, the legacy case
	Records  []InstrRecord // ON records, sorted by label
	Off      []string      // labels of OFF records, sorted

	// Sorted sets of Labels (P1), compared octet by octet.
	Servers, Signers, Auditors []string

	NSmgmt, ParentSync uint8 // absent reads as the default
	Suffix             string
	Pubkey, Pubcds     bool
}

// InstrRecord is one ON HSYNC3 record as the reading has it: the label and
// the upstream as written, without a trailing dot ("" for no upstream), and
// the identity as a case-folded FQDN.
type InstrRecord struct{ Label, Identity, Upstream string }

// ReadInstructions reads the instructions from a zone's apex. It returns nil
// and no error when the apex holds neither HSYNC3 nor HSYNCPARAM, and an owner
// error when it holds two HSYNCPARAM records or two HSYNC3 records with one
// label, in any state.
func ReadInstructions(apex *tdns.OwnerData) (*Instructions, error) {
	if apex == nil || apex.RRtypes == nil {
		return nil, nil
	}
	h3s := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3).RRs
	hps := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM).RRs
	if len(h3s) == 0 && len(hps) == 0 {
		return nil, nil
	}
	if len(hps) > 1 {
		return nil, errTwoHsyncparams
	}

	// Empty lists are nil, with HSYNCPARAM and without, as sortedUnique
	// leaves them.
	in := &Instructions{
		NSmgmt:     core.HsyncNSmgmtOWNER,
		ParentSync: core.HsyncParentSyncOwner,
	}
	seen := make(map[string]bool, len(h3s))
	for _, rr := range h3s {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			return nil, fmt.Errorf("HSYNC3 record of type %T", rr)
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			return nil, fmt.Errorf("HSYNC3 record with data of type %T", prr.Data)
		}
		// tdns refuses a label with a trailing dot (tdns#929); a record built
		// by a test that bypasses the parser may still carry one.
		label := strings.TrimSuffix(h3.Label, ".")
		if seen[label] {
			return nil, fmt.Errorf("%w %s", errDuplicateLabel, label)
		}
		seen[label] = true
		// Only OFF is no member (design 7); any other state reads as ON, as
		// zoneParticipants has it.
		if h3.State == core.HsyncStateOFF {
			in.Off = append(in.Off, label)
			continue
		}
		in.Records = append(in.Records, InstrRecord{
			Label:    label,
			Identity: core.CanonicalizeName(dns.Fqdn(h3.Identity)),
			// tdns writes "no upstream" as "."; the trim makes it "".
			Upstream: strings.TrimSuffix(h3.Upstream, "."),
		})
	}
	slices.SortFunc(in.Records, func(a, b InstrRecord) int { return strings.Compare(a.Label, b.Label) })
	slices.Sort(in.Off)

	if len(hps) == 0 {
		return in, nil
	}
	prr, ok := hps[0].(*dns.PrivateRR)
	if !ok {
		return nil, fmt.Errorf("HSYNCPARAM record of type %T", hps[0])
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return nil, fmt.Errorf("HSYNCPARAM record with data of type %T", prr.Data)
	}
	in.HasParam = true
	in.Serial, _ = hp.GetSerial()
	in.Servers = sortedUnique(hp.GetServers())
	in.Signers = sortedUnique(hp.GetSigners())
	in.Auditors = sortedUnique(hp.GetAuditors())
	in.NSmgmt = hp.GetNSmgmt()
	in.ParentSync = hp.GetParentSync()
	in.Suffix = hp.GetSuffix()
	in.Pubkey = hp.HasPubkey()
	in.Pubcds = hp.HasPubcds()
	return in, nil
}

// instrDigestVersion is the version of the digest's encoding. A change of the
// encoding changes every digest, so every agent of a zone must run the same
// one (no mixed versions).
const instrDigestVersion = 1

// Digest is the reading's check (design rule 2): SHA-256 over a versioned,
// length-prefixed encoding of the reading without the serial, the first 8
// octets as 16 hex digits, the form of ComputeGroupHash. Every field is
// written in a fixed order under a tag of its own, and every string and list
// with its length, so no two readings write the same bytes.
func (in *Instructions) Digest() string {
	h := sha256.New()
	h.Write([]byte{instrDigestVersion})
	writeBool(h, 'p', in.HasParam)
	h.Write([]byte{'r'})
	binary.Write(h, binary.BigEndian, uint16(len(in.Records)))
	for _, r := range in.Records {
		writeString(h, r.Label)
		writeString(h, r.Identity)
		writeString(h, r.Upstream)
	}
	for _, l := range []struct {
		tag   byte
		items []string
	}{{'o', in.Off}, {'s', in.Servers}, {'g', in.Signers}, {'a', in.Auditors}} {
		h.Write([]byte{l.tag})
		binary.Write(h, binary.BigEndian, uint16(len(l.items)))
		for _, it := range l.items {
			writeString(h, it)
		}
	}
	h.Write([]byte{'n', in.NSmgmt, 'y', in.ParentSync})
	h.Write([]byte{'x'})
	writeString(h, in.Suffix)
	writeBool(h, 'k', in.Pubkey)
	writeBool(h, 'c', in.Pubcds)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func writeString(h hash.Hash, s string) {
	binary.Write(h, binary.BigEndian, uint16(len(s)))
	h.Write([]byte(s))
}

func writeBool(h hash.Hash, tag byte, b bool) {
	v := byte(0)
	if b {
		v = 1
	}
	h.Write([]byte{tag, v})
}

// CompareSerial compares two serials by RFC 1982 arithmetic with
// SERIAL_BITS 32: -1 when a is before b, 1 when a is after b, and 0 when they
// are equal or when RFC 1982 leaves their order undefined (they are 2^31
// apart). 0 is therefore not "equal": neither is newer.
func CompareSerial(a, b uint32) int {
	switch d := b - a; {
	case d == 0, d == 1<<31:
		return 0
	case d < 1<<31:
		return -1
	default:
		return 1
	}
}

// SerialOrder is how a copy of the instructions stands to the serial held.
type SerialOrder int

const (
	SerialSame      SerialOrder = iota // the same serial and digest
	SerialNewer                        // a higher serial
	SerialOlder                        // a lower serial
	SerialConflict                     // the same serial with another digest: an edit without a raised serial
	SerialUndefined                    // RFC 1982's undefined half, read as not newer
)

var serialOrderToString = map[SerialOrder]string{
	SerialSame:      "same",
	SerialNewer:     "newer",
	SerialOlder:     "older",
	SerialConflict:  "conflict",
	SerialUndefined: "undefined",
}

func (o SerialOrder) String() string {
	if s, ok := serialOrderToString[o]; ok {
		return s
	}
	return fmt.Sprintf("SerialOrder(%d)", int(o))
}

// SerialComparison is a copy's serial against the one held, and the ON
// records that differ between the two.
type SerialComparison struct {
	Order SerialOrder
	// Added are the copy's ON records that the held serial lacks, and Removed
	// the held serial's that the copy lacks. Records are matched by label and
	// identity together: an identity changed under a label is one record
	// removed and another added (design rule 2).
	Added, Removed []InstrRecord
}

// CompareSerials compares a copy of the instructions with the serial held
// (the (serial, digest) pair of design rule 2). A nil held is nothing held,
// so any copy is newer; a nil copy is no reading and is never newer.
func CompareSerials(held, cp *Instructions) SerialComparison {
	if cp == nil {
		return SerialComparison{Order: SerialUndefined}
	}
	if held == nil {
		return SerialComparison{Order: SerialNewer, Added: slices.Clone(cp.Records)}
	}
	var c SerialComparison
	switch {
	case cp.Serial == held.Serial && cp.Digest() == held.Digest():
		c.Order = SerialSame
	case cp.Serial == held.Serial:
		c.Order = SerialConflict
	default:
		switch CompareSerial(cp.Serial, held.Serial) {
		case 1:
			c.Order = SerialNewer
		case -1:
			c.Order = SerialOlder
		default:
			c.Order = SerialUndefined
		}
	}
	c.Added = recordsNotIn(cp.Records, held.Records)
	c.Removed = recordsNotIn(held.Records, cp.Records)
	return c
}

// recordsNotIn returns the records of a that b has no record for, by label
// and identity.
func recordsNotIn(a, b []InstrRecord) []InstrRecord {
	var out []InstrRecord
	for _, r := range a {
		if !slices.ContainsFunc(b, func(o InstrRecord) bool {
			return o.Label == r.Label && core.EqualNames(o.Identity, r.Identity)
		}) {
			out = append(out, r)
		}
	}
	return out
}

// --- The one accessor (design rule 5, plan S3) ---
//
// Nothing decides from a zone's HSYNC3 or HSYNCPARAM records but through
// these: instructionsFor for the active instructions (groups, admission,
// discovery, and what is shown), rolesForZone for the sets the parts act by,
// and readingOf for a copy being analysed before it is served.

// instrStore is the store of the zones' serials that the agent's or the
// auditor's initialisation sets (instructions_store.go); nil on the combiner
// and the signer, and in a test that sets none.
var instrStore atomic.Pointer[InstructionStore]

// instructionsFor is the zone's instructions as this daemon acts on them:
// on the agent and the auditor, the store's active reading once the store
// enforces it (S7); on the combiner and the signer, until S10 and S11, the
// reading of their own copy. A zone the store does not have, or does not
// enforce yet, is read from its copy. Nil for a zone with no instructions,
// or not loaded here.
func instructionsFor(zone ZoneName) *Instructions {
	return activeOr(string(zone), zoneApex(zone))
}

// activeOr is instructionsFor for a caller that holds the served apex of
// the zone already: the store's active reading, or the reading of apex.
func activeOr(zone string, apex *tdns.OwnerData) *Instructions {
	if in := instrStore.Load().activeReading(dns.Fqdn(zone)); in != nil {
		return in
	}
	return readingOf(apex)
}

// hsync3Strings are the instructions' HSYNC3 records as text, for display:
// each ON record with its identity and upstream ("." for none), and each OFF
// label, whose other fields nothing acts on.
func (in *Instructions) hsync3Strings(zone string) []string {
	if in == nil {
		return nil
	}
	var out []string
	for _, r := range in.Records {
		up := r.Upstream
		if up == "" {
			up = "."
		}
		out = append(out, fmt.Sprintf("%s IN HSYNC3 ON %s %s %s", dns.Fqdn(zone), r.Label, r.Identity, up))
	}
	for _, l := range in.Off {
		out = append(out, fmt.Sprintf("%s IN HSYNC3 OFF %s . .", dns.Fqdn(zone), l))
	}
	return out
}

// lastGood is each zone's last copy that read; noReading the zones whose
// copy now does not, once logged.
var lastGood, noReading sync.Map

// readingOf reads the instructions of a copy's apex. A copy that has no
// reading (an owner error) keeps the zone's last good reading, with one log
// line, rather than taking its first record (plan S3).
func readingOf(apex *tdns.OwnerData) *Instructions {
	if apex == nil {
		return nil
	}
	zone := dns.Fqdn(apex.Name)
	in, err := ReadInstructions(apex)
	if err != nil {
		if _, logged := noReading.LoadOrStore(zone, true); !logged {
			lg.Warn("the zone's copy has no reading of its instructions, keeping the last", "zone", zone, "error", err)
		}
		if prev, ok := lastGood.Load(zone); ok {
			return prev.(*Instructions)
		}
		return nil
	}
	noReading.Delete(zone)
	if in != nil {
		lastGood.Store(zone, in)
	}
	return in
}

// Provider is a provider as a set names it: its HSYNC3 label and its
// identity, fixed when the step that made the set was taken (design 3.3).
// Identity is "" for a label that no ON record carries.
type Provider struct{ Label, Identity string }

// Roles is what the parts act by for a zone: a set of providers per purpose
// (design 3.5), and the settings that change only at a step (design 3.3).
type Roles struct {
	Servers       []Provider // whose NS records are served
	KeySigners    []Provider // whose DNSKEYs are published, whose foreign rows are kept
	DSSigners     []Provider // whose KSKs have a DS, whose CDS records are published
	KeyConfirmers []Provider // whose confirmations a key's distribution expects
	Signing       []Provider // who signs

	Pubkey, Pubcds     bool  // the zone's KEY and CDS at the providers' _signal names
	NSmgmt, ParentSync uint8 // owner or agent
	Hold               bool  // nothing new starts (S6's freeze); false until then
}

// rolesFor is the sets for a step of the transition from `from` to `to`; at
// rest both are the active serial. Until the reconciliation has steps (S12,
// S13), every set is that of the serial the parts hold: from's during a
// transition (design 3.3), the active serial's at rest. In the legacy reading
// (HSYNC3 without HSYNCPARAM) every ON record serves, and so votes, and
// nobody signs, as today.
func rolesFor(from, to *Instructions, step int) Roles {
	in := from
	if in == nil {
		in = to
	}
	r := Roles{NSmgmt: core.HsyncNSmgmtOWNER, ParentSync: core.HsyncParentSyncOwner}
	if in == nil {
		return r
	}
	if !in.HasParam {
		for _, rec := range in.Records {
			r.Servers = append(r.Servers, Provider{rec.Label, rec.Identity})
		}
		return r
	}
	signers := in.providers(in.Signers)
	r.Servers = in.providers(in.Servers)
	r.KeySigners, r.DSSigners, r.KeyConfirmers, r.Signing = signers, signers, signers, signers
	r.Pubkey, r.Pubcds = in.Pubkey, in.Pubcds
	r.NSmgmt, r.ParentSync = in.NSmgmt, in.ParentSync
	return r
}

// rolesForZone is rolesFor for the zone's current step, as the store has it;
// for a zone the store does not have, the active reading's sets.
func rolesForZone(zone ZoneName) Roles {
	from, to, step := instrStore.Load().transition(string(zone))
	if to == nil {
		in := instructionsFor(zone)
		return rolesFor(in, in, 0)
	}
	return rolesFor(from, to, step)
}

// providers resolves labels through the ON records, in the order given.
func (in *Instructions) providers(labels []string) []Provider {
	out := make([]Provider, 0, len(labels))
	for _, l := range labels {
		out = append(out, Provider{Label: l, Identity: in.identityOf(l)})
	}
	return out
}

// identityOf is the identity of the ON record with the label; "" when none
// carries it. An OFF record gives no label (plan S3).
func (in *Instructions) identityOf(label string) string {
	label = strings.TrimSuffix(label, ".")
	for _, r := range in.Records {
		if r.Label == label {
			return r.Identity
		}
	}
	return ""
}

// labelOf is the label of the ON record of one of the identities, and
// whether there is one. An OFF record gives no label.
func (in *Instructions) labelOf(identities ...string) (string, bool) {
	if in == nil {
		return "", false
	}
	for _, r := range in.Records {
		for _, id := range identities {
			if core.EqualNames(dns.Fqdn(id), r.Identity) {
				return r.Label, true
			}
		}
	}
	return "", false
}

// has reports whether label is among the providers.
func has(set []Provider, label string) bool {
	label = strings.TrimSuffix(label, ".")
	return slices.ContainsFunc(set, func(p Provider) bool { return p.Label == label })
}

// identities are the providers' identities, those with an ON record only.
func identities(set []Provider) []string {
	var out []string
	for _, p := range set {
		if p.Identity != "" {
			out = append(out, p.Identity)
		}
	}
	return out
}

// participantsOf is the zone's members that hold a role (servers, signers,
// auditors), by identity, and the voting subset (servers and signers), each
// sorted and de-duplicated. A label with no ON record names nobody. In the
// legacy reading every ON record is a voting participant.
func participantsOf(in *Instructions) (participants, voting []string) {
	if in == nil {
		return nil, nil
	}
	if !in.HasParam {
		for _, r := range in.Records {
			voting = append(voting, r.Identity)
		}
		voting = sortedUnique(voting)
		return voting, voting
	}
	voting = sortedUnique(append(identities(in.providers(in.Servers)), identities(in.providers(in.Signers))...))
	participants = sortedUnique(append(slices.Clone(voting), identities(in.providers(in.Auditors))...))
	if len(voting) == 0 {
		voting = nil
	}
	if len(participants) == 0 {
		participants = nil
	}
	return participants, voting
}
