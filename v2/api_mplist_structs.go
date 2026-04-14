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
}

// MPListResponse is returned by /zone/mplist.
type MPListResponse struct {
	Time     time.Time             `json:"time"`
	Error    bool                  `json:"error,omitempty"`
	ErrorMsg string                `json:"error_msg,omitempty"`
	MPZones  map[string]MPZoneInfo `json:"mp_zones"`
}
