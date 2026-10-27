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

	in := &Instructions{
		NSmgmt:     core.HsyncNSmgmtOWNER,
		ParentSync: core.HsyncParentSyncOwner,
		Servers:    []string{},
		Signers:    []string{},
		Auditors:   []string{},
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
