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
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return false
	}
	return hp.IsAuditorLabel(label)
}

// IsAuditorIdentity reports whether the given identity (FQDN) is one
// of the declared auditors. Resolves auditor labels back to HSYNC3
// identities by walking the apex HSYNC3 RRset.
func (mpzd *MPZoneData) IsAuditorIdentity(identity string) bool {
	if mpzd == nil || identity == "" {
		return false
	}
	auditorLabels := mpzd.GetAuditors()
	if len(auditorLabels) == 0 {
		return false
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return false
	}
	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return false
	}
	identity = dns.Fqdn(identity)
	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		if dns.Fqdn(h3.Identity) != identity {
			continue
		}
		// HSYNC3 labels are short tokens, but some sources serialize
		// them with a trailing dot. Normalize before comparing.
		h3Label := strings.TrimSuffix(h3.Label, ".")
		for _, lbl := range auditorLabels {
			if h3Label == strings.TrimSuffix(lbl, ".") {
				return true
			}
		}
	}
	return false
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

// DeclaredAuditorIdentities returns HSYNC3 identities for the zone's
// auditors= labels (from apex HSYNCPARAM), sorted by label.
func DeclaredAuditorIdentities(zone string) []AuditProviderSummary {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	hsync3RRset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return nil
	}
	var out []AuditProviderSummary
	seen := map[string]bool{}
	for _, rr := range hsync3RRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.State == 0 {
			continue
		}
		if !mpzd.IsAuditorIdentity(h3.Identity) {
			continue
		}
		id := dns.Fqdn(h3.Identity)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, AuditProviderSummary{
			Identity: id,
			Label:    strings.TrimSuffix(h3.Label, "."),
		})
	}
	slices.SortFunc(out, func(a, b AuditProviderSummary) int {
		return strings.Compare(a.Label, b.Label)
	})
	return out
}
