/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// MPZoneInfo carries multi-provider zone details for the mplist command.
type MPZoneInfo struct {
	Servers    []string          `json:"servers"`
	Signers    []string          `json:"signers"`
	Auditors   []string          `json:"auditors"`
	NSmgmt     string            `json:"nsmgmt"`
	ParentSync string            `json:"parentsync"`
	Suffix     string            `json:"suffix,omitempty"`
	Options    []tdns.ZoneOption `json:"options"`
	// ZoneError is the zone's active error message (e.g. a failed inbound
	// transfer), empty when healthy. The CLI renders the Options cell as
	// "ERROR" when set; the full message is in `zone list`.
	ZoneError string `json:"zone_error,omitempty"`
	// Serial and Digest are the copy's instructions (design rules 1 and 2):
	// the owner's serial, 0 when absent, and the digest of the canonical
	// reading. Digest is empty when the copy has no reading: no HSYNC3 and no
	// HSYNCPARAM, or an owner error, which OwnerError then names.
	Serial     uint32 `json:"serial"`
	Digest     string `json:"digest,omitempty"`
	OwnerError string `json:"owner_error,omitempty"`
	// Active and Newest are the serials the agent or the auditor keeps for
	// the zone (instructions_store.go): the active one and the newest held.
	// Nil where none are kept, as on the combiner and the signer.
	Active *SerialDigest `json:"active,omitempty"`
	Newest *SerialDigest `json:"newest,omitempty"`
	// Refused is the newest serial's refusal by the judge (S4), "42
	// refused: ...", which the CLI lists below the table.
	Refused string `json:"refused,omitempty"`
	// Acting is, on a combiner or a signer, what it acts by (plan S10,
	// S11): the serial its agent handed it, provisional, or that it waits
	// for its agent's hand-over. Empty on every other role.
	Acting string `json:"acting,omitempty"`
}

// MPListResponse is returned by /zone/mplist.
type MPListResponse struct {
	Time     time.Time             `json:"time"`
	Error    bool                  `json:"error,omitempty"`
	ErrorMsg string                `json:"error_msg,omitempty"`
	MPZones  map[string]MPZoneInfo `json:"mp_zones"`
}
