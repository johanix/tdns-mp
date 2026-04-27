/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor anomaly detectors. Phase B' wires two detectors that the
 * Phase B handler did not need to know about per-message:
 *
 *   - provider-silent: any tracked provider whose last BEAT is older
 *     than audit.silence_threshold (default 90s). One observation per
 *     transition into silence; cleared automatically when a fresh
 *     BEAT arrives.
 *   - missing-provider: any HSYNC3 identity in an MP zone the auditor
 *     has never seen inbound traffic from. Re-evaluated each tick.
 *
 * Both detectors run from a single periodic goroutine. They never
 * touch state outside of AuditStateManager and the read-only HSYNC3
 * RRset.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	core "github.com/johanix/tdns/v2/core"
)

// detectorRunState remembers which (zone, provider) pairs are
// currently flagged silent or missing, so we only emit one
// observation per transition rather than one every tick.
type detectorRunState struct {
	mu      sync.Mutex
	silent  map[string]bool // key: zone + "|" + identity
	missing map[string]bool // key: zone + "|" + identity
}

func newDetectorRunState() *detectorRunState {
	return &detectorRunState{
		silent:  make(map[string]bool),
		missing: make(map[string]bool),
	}
}

// StartAuditDetectors runs provider-silent and missing-provider
// detection on the given interval until ctx is cancelled.
// silenceThreshold and interval ≤ 0 disable the detector.
func StartAuditDetectors(ctx context.Context, sm *AuditStateManager,
	silenceThreshold, interval time.Duration) {
	if sm == nil || silenceThreshold <= 0 || interval <= 0 {
		return
	}
	state := newDetectorRunState()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runDetectorsOnce(sm, state, silenceThreshold)
			}
		}
	}()
}

func runDetectorsOnce(sm *AuditStateManager, state *detectorRunState,
	silenceThreshold time.Duration) {
	now := time.Now()
	zones := sm.SnapshotAllZones()
	for _, zsum := range zones {
		zs := sm.GetZone(zsum.Zone)
		if zs == nil {
			continue
		}
		detectSilentProviders(zs, state, now, silenceThreshold)
		detectMissingProviders(zs, state)
	}
}

// detectSilentProviders flags providers whose LastBeat is older than
// silenceThreshold and clears the flag for any that have come back.
func detectSilentProviders(zs *AuditZoneState, state *detectorRunState,
	now time.Time, threshold time.Duration) {
	zs.mu.RLock()
	type providerSnap struct {
		identity string
		lastBeat time.Time
	}
	snaps := make([]providerSnap, 0, len(zs.Providers))
	for id, ps := range zs.Providers {
		snaps = append(snaps, providerSnap{identity: id, lastBeat: ps.LastBeat})
	}
	zs.mu.RUnlock()

	for _, s := range snaps {
		key := zs.Zone + "|" + s.identity
		// Never-beat providers are handled by missing-provider; skip here.
		if s.lastBeat.IsZero() {
			continue
		}
		silent := now.Sub(s.lastBeat) > threshold
		state.mu.Lock()
		wasSilent := state.silent[key]
		if silent && !wasSilent {
			state.silent[key] = true
			state.mu.Unlock()
			zs.AddObservation("warning", s.identity,
				fmt.Sprintf("provider %s has not beaten in %s",
					s.identity, now.Sub(s.lastBeat).Round(time.Second)))
			continue
		}
		if !silent && wasSilent {
			delete(state.silent, key)
			state.mu.Unlock()
			zs.AddObservation("info", s.identity,
				fmt.Sprintf("provider %s recovered (BEAT received)", s.identity))
			continue
		}
		state.mu.Unlock()
	}
}

// detectMissingProviders flags HSYNC3 identities the auditor has
// never seen inbound traffic from. Cleared once any traffic arrives.
func detectMissingProviders(zs *AuditZoneState, state *detectorRunState) {
	expected := expectedHSYNC3Identities(zs.Zone)
	if len(expected) == 0 {
		return
	}
	zs.mu.RLock()
	seen := make(map[string]bool, len(zs.Providers))
	for id := range zs.Providers {
		seen[id] = true
	}
	zs.mu.RUnlock()

	for _, identity := range expected {
		key := zs.Zone + "|" + identity
		state.mu.Lock()
		wasMissing := state.missing[key]
		if !seen[identity] {
			if !wasMissing {
				state.missing[key] = true
				state.mu.Unlock()
				zs.AddObservation("warning", identity,
					fmt.Sprintf("provider %s declared in HSYNC3 but never seen",
						identity))
				continue
			}
			state.mu.Unlock()
			continue
		}
		// Provider has been seen — clear any prior missing flag.
		if wasMissing {
			delete(state.missing, key)
			state.mu.Unlock()
			zs.AddObservation("info", identity,
				fmt.Sprintf("provider %s now seen (was previously missing)", identity))
			continue
		}
		state.mu.Unlock()
	}
}

// expectedHSYNC3Identities returns the set of FQDN identities listed
// in the apex HSYNC3 RRset for zone, excluding any auditor entries
// (the auditor doesn't audit itself or other auditors).
func expectedHSYNC3Identities(zone string) []string {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	rrset, exists := apex.RRtypes.Get(core.TypeHSYNC3)
	if !exists {
		return nil
	}
	auditorLabels := mpzd.GetAuditors()
	auditorSet := make(map[string]bool, len(auditorLabels))
	for _, lbl := range auditorLabels {
		auditorSet[lbl] = true
	}
	var out []string
	for _, rr := range rrset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok {
			continue
		}
		if auditorSet[h3.Label] {
			continue
		}
		identity := dns.Fqdn(h3.Identity)
		out = append(out, identity)
	}
	return out
}
