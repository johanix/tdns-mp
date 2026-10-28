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
)

func normalizeHSYNC3Label(label string) string {
	return strings.TrimSuffix(label, ".")
}

// GetAuditors returns the auditor labels of the zone's instructions. Nil if
// the zone has no HSYNCPARAM or no auditors=.
func (mpzd *MPZoneData) GetAuditors() []string {
	if mpzd == nil {
		return nil
	}
	in := mpzd.instructions()
	if in == nil || !in.HasParam || len(in.Auditors) == 0 {
		return nil
	}
	return slices.Clone(in.Auditors)
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

// hsync3IdentitiesByLabel maps HSYNC3 label → identity FQDN by the zone's
// active instructions: ON records only, since an OFF record gives no label
// (plan S3).
func (mpzd *MPZoneData) hsync3IdentitiesByLabel() map[string]string {
	out := make(map[string]string)
	if mpzd == nil {
		return out
	}
	if in := mpzd.instructions(); in != nil {
		for _, r := range in.Records {
			out[r.Label] = r.Identity
		}
	}
	return out
}

// hsync3LabelForIdentity returns the label of identity's ON record in the
// zone's active instructions, compared as a DNS name, or "" if none lists it.
func (mpzd *MPZoneData) hsync3LabelForIdentity(identity string) string {
	if mpzd == nil || identity == "" {
		return ""
	}
	label, _ := mpzd.instructions().labelOf(identity)
	return label
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
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
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
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok || mpzd == nil {
		return true
	}
	return !mpzd.IsAuditorIdentity(identity)
}

// DeclaredAuditorIdentities returns one row per auditors= label from
// apex HSYNCPARAM, with identity filled from matching apex HSYNC3.
func DeclaredAuditorIdentities(zone string) []AuditProviderSummary {
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
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
