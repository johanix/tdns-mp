/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor helper functions: extract auditor label from HSYNCPARAM,
 * check if a given label is the auditor.
 */
package tdnsmp

import (
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// GetAuditorLabel extracts the auditor label from the HSYNCPARAM RR
// in the zone's apex. Returns "" if no auditor is declared.
func GetAuditorLabel(zd *tdns.ZoneData) string {
	if zd == nil {
		return ""
	}
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return ""
	}
	hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !exists || len(hsyncparamRRset.RRs) == 0 {
		return ""
	}
	for _, rr := range hsyncparamRRset.RRs {
		priv, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		hp, ok := priv.Data.(*core.HSYNCPARAM)
		if !ok {
			continue
		}
		return hp.GetAuditor()
	}
	return ""
}

// IsAuditorLabel checks if the given HSYNC3 label matches the
// declared auditor in the zone's HSYNCPARAM. Returns false if
// no auditor is declared or if the labels don't match.
func IsAuditorLabel(zd *tdns.ZoneData, label string) bool {
	if label == "" {
		return false
	}
	auditor := GetAuditorLabel(zd)
	return auditor != "" && auditor == label
}

// IsAuditorIdentity checks if the given identity (FQDN) matches the
// auditor declared in the zone's HSYNCPARAM, by resolving the auditor
// label to an HSYNC3 identity.
func IsAuditorIdentity(zd *tdns.ZoneData, identity string) bool {
	auditorLabel := GetAuditorLabel(zd)
	if auditorLabel == "" {
		return false
	}
	// Build label→identity map from HSYNC3 records
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return false
	}
	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return false
	}
	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		if h3.Label == auditorLabel {
			return h3.Identity == identity
		}
	}
	return false
}
