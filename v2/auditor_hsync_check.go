/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Static HSYNC/HSYNCPARAM consistency checks for loaded MP zones.
 * Runs on zone load and after each zone refresh (AXFR), not on a timer.
 */
package tdnsmp

import (
	"fmt"
	"slices"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

// CheckZoneHSYNCConfig returns zone-file configuration errors for zone.
// Empty slice means no problems detected.
func CheckZoneHSYNCConfig(zone string) []string {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || !mpzd.Options[tdns.OptMultiProvider] {
		return nil
	}
	return checkMPZoneHSYNCConfig(mpzd)
}

func checkMPZoneHSYNCConfig(mpzd *MPZoneData) []string {
	return checkHSYNCConfig(MPZoneInfoFromMPZoneData(mpzd), mpzd.hsync3IdentitiesByLabel())
}

func checkHSYNCConfig(info MPZoneInfo, byLabel map[string]string) []string {
	if len(info.Servers) == 0 && len(info.Signers) == 0 && len(info.Auditors) == 0 {
		return nil
	}
	identityLabels := make(map[string][]string)

	var errs []string
	for _, lbl := range declaredRoleLabels(info) {
		id := byLabel[lbl]
		if id == "" {
			errs = append(errs, fmt.Sprintf("HSYNCPARAM role %q has no matching HSYNC3 record", lbl))
			continue
		}
		identityLabels[id] = append(identityLabels[id], lbl)
	}
	// The role errors above follow the declared order; the duplicate-identity
	// errors come out of a map, so sort them for a stable listing.
	var dups []string
	for id, labels := range identityLabels {
		if len(labels) <= 1 {
			continue
		}
		slices.Sort(labels)
		dups = append(dups, fmt.Sprintf(
			"HSYNC3 labels %s map to the same identity %s",
			strings.Join(labels, ", "), id))
	}
	slices.Sort(dups)
	return append(errs, dups...)
}

// RefreshZoneHSYNCConfig re-runs CheckZoneHSYNCConfig and stores the
// result on the zone's audit state (replaced wholesale each refresh).
func (m *AuditStateManager) RefreshZoneHSYNCConfig(zone string) {
	if m == nil {
		return
	}
	errs := CheckZoneHSYNCConfig(zone)
	zs := m.GetOrCreateZone(zone)
	zs.mu.Lock()
	if len(errs) == 0 {
		zs.ConfigErrors = nil
	} else {
		zs.ConfigErrors = append([]string(nil), errs...)
	}
	zs.mu.Unlock()
}

// SnapshotZoneConfigErrors returns stored config errors for zone.
func (m *AuditStateManager) SnapshotZoneConfigErrors(zone string) []string {
	if m == nil {
		return CheckZoneHSYNCConfig(zone)
	}
	zs := m.GetZone(zone)
	if zs == nil {
		return CheckZoneHSYNCConfig(zone)
	}
	zs.mu.RLock()
	defer zs.mu.RUnlock()
	if len(zs.ConfigErrors) == 0 {
		return nil
	}
	out := make([]string, len(zs.ConfigErrors))
	copy(out, zs.ConfigErrors)
	return out
}
