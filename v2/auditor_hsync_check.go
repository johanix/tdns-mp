/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Static HSYNC/HSYNCPARAM consistency checks for loaded MP zones.
 * Runs on zone load and after each zone refresh (AXFR), not on a timer.
 */
package tdnsmp

import (
	"fmt"

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

// checkMPZoneHSYNCConfig lists an owner error first, if there is one: the
// copy's own (S1), or else the store's (S2), since hsync3IdentitiesByLabel
// keeps one record per label and the checks below cannot see two records
// with one label, nor one identity under two (#306), nor a copy without its
// serial (#308). Then the store's refusal of its newest serial (S4).
func checkMPZoneHSYNCConfig(mpzd *MPZoneData) []string {
	info := MPZoneInfoFromMPZoneData(mpzd)
	instrStore.Load().fillMPZoneInfo(mpzd.ZoneName, &info)
	errs := checkHSYNCConfig(info, mpzd.hsync3IdentitiesByLabel())
	if info.Refused != "" {
		errs = append([]string{info.Refused}, errs...)
	}
	if info.OwnerError != "" {
		errs = append([]string{info.OwnerError}, errs...)
	}
	return errs
}

func checkHSYNCConfig(info MPZoneInfo, byLabel map[string]string) []string {
	if len(info.Servers) == 0 && len(info.Signers) == 0 && len(info.Auditors) == 0 {
		return nil
	}
	// One identity under two labels is an owner error of the copy (#306),
	// listed first by checkMPZoneHSYNCConfig; a reading has none.
	var errs []string
	for _, lbl := range declaredRoleLabels(info) {
		if byLabel[lbl] == "" {
			errs = append(errs, fmt.Sprintf("HSYNCPARAM role %q has no matching HSYNC3 record", lbl))
		}
	}
	return errs
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
