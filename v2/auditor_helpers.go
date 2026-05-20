/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor-related zone-data helpers. Wraps the HSYNCPARAM accessors
 * (tdns/v2/core/rr_hsyncparam.go) at the *MPZoneData level: extract
 * the auditor list from a zone's apex HSYNCPARAM RRset, decide
 * whether a given HSYNC3 label or identity belongs to one of the
 * declared auditors.
 *
 * HSYNCPARAM_AUDITORS is plural (list of labels). All helpers handle
 * the multi-auditor case; "no auditor" is just the empty list.
 */
package tdnsmp

import (
	"slices"
	"strings"

	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

func normalizeHSYNC3Label(label string) string {
	return strings.TrimSuffix(label, ".")
}

// GetAuditors returns the list of auditor labels declared in the
// zone's apex HSYNCPARAM RRset. Returns nil if the zone has no
// HSYNCPARAM or no auditors=.
func (mpzd *MPZoneData) GetAuditors() []string {
	if mpzd == nil {
		return nil
	}
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return nil
	}
	return hp.GetAuditors()
}

// IsAuditorLabel reports whether the given HSYNC3 label is in the
// zone's auditors= list.
func (mpzd *MPZoneData) IsAuditorLabel(label string) bool {
	if mpzd == nil || label == "" {
		return false
	}
	label = normalizeHSYNC3Label(label)
	for _, s := range mpzd.GetAuditors() {
		if normalizeHSYNC3Label(s) == label {
			return true
		}
	}
	return false
}

// hsync3IdentitiesByLabel maps HSYNC3 label → identity FQDN for the
// zone apex. Includes inactive (State==0) members so declared auditors
// still appear when a peer is offline.
func (mpzd *MPZoneData) hsync3IdentitiesByLabel() map[string]string {
	out := make(map[string]string)
	if mpzd == nil {
		return out
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return out
	}
	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return out
	}
	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.Identity == "" {
			continue
		}
		out[normalizeHSYNC3Label(h3.Label)] = dns.Fqdn(h3.Identity)
	}
	return out
}

// hsync3LabelForIdentity returns the HSYNC3 label for identity at the
// zone apex, or "" if not listed.
func (mpzd *MPZoneData) hsync3LabelForIdentity(identity string) string {
	if mpzd == nil || identity == "" {
		return ""
	}
	identity = dns.Fqdn(identity)
	for label, id := range mpzd.hsync3IdentitiesByLabel() {
		if id == identity {
			return label
		}
	}
	return ""
}

// IsAuditorIdentity reports whether identity is declared in auditors=
// for this zone (label resolved via apex HSYNC3).
func (mpzd *MPZoneData) IsAuditorIdentity(identity string) bool {
	if mpzd == nil || identity == "" {
		return false
	}
	label := mpzd.hsync3LabelForIdentity(identity)
	return label != "" && mpzd.IsAuditorLabel(label)
}

// IsAuditorIdentity reports whether identity is declared as an auditor
// for zone (HSYNCPARAM auditors= resolved via apex HSYNC3).
func IsAuditorIdentity(zone, identity string) bool {
	if zone == "" || identity == "" {
		return false
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return false
	}
	return mpzd.IsAuditorIdentity(identity)
}

// IsProviderIdentity reports whether identity is an HSYNC3 member that
// serves the zone (listed in HSYNC3 but not under HSYNCPARAM auditors=).
func IsProviderIdentity(zone, identity string) bool {
	if zone == "" || identity == "" {
		return false
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return true
	}
	return !mpzd.IsAuditorIdentity(identity)
}

// DeclaredAuditorIdentities returns one row per auditors= label from
// apex HSYNCPARAM, with identity filled from matching apex HSYNC3.
func DeclaredAuditorIdentities(zone string) []AuditProviderSummary {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	labels := mpzd.GetAuditors()
	if len(labels) == 0 {
		return nil
	}
	byLabel := mpzd.hsync3IdentitiesByLabel()
	var out []AuditProviderSummary
	for _, lbl := range labels {
		lbl = normalizeHSYNC3Label(lbl)
		s := AuditProviderSummary{Label: lbl}
		if id := byLabel[lbl]; id != "" {
			s.Identity = id
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b AuditProviderSummary) int {
		return strings.Compare(a.Label, b.Label)
	})
	return out
}
