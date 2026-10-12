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
 * A third follows the distributions (tdns-mp #152):
 *
 *   - waiting-distribution: a member whose confirmation a distribution
 *     has waited for longer than audit.pending_threshold (default 2m).
 *     One observation per member and distribution; cleared when the
 *     member's confirmation arrives. Only for a member that sends the
 *     auditor its confirmations: of the others nothing is known.
 *
 * The detectors run from a single periodic goroutine. They never
 * touch state outside of AuditStateManager and the read-only HSYNC3
 * RRset.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"strings"
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
	// waiting: the members flagged as waited for, per zone; key:
	// distributionKey + "|" + identity.
	waiting map[string]map[string]bool
}

func newDetectorRunState() *detectorRunState {
	return &detectorRunState{
		silent:  make(map[string]bool),
		missing: make(map[string]bool),
		waiting: make(map[string]map[string]bool),
	}
}

// StartAuditDetectors runs provider-silent, missing-provider and
// waiting-distribution detection on the given interval until ctx is
// cancelled. silenceThreshold and interval ≤ 0 disable the detectors;
// pendingThreshold ≤ 0 disables waiting-distribution alone.
func StartAuditDetectors(ctx context.Context, sm *AuditStateManager,
	silenceThreshold, pendingThreshold, interval time.Duration) {
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
				runDetectorsOnce(sm, state, time.Now(), silenceThreshold, pendingThreshold)
			}
		}
	}()
}

// runDetectorsOnce is one detector round over every tracked zone, judged
// at now.
func runDetectorsOnce(sm *AuditStateManager, state *detectorRunState,
	now time.Time, silenceThreshold, pendingThreshold time.Duration) {
	zones := sm.SnapshotAllZones()
	reporters := sm.Reporters()
	for _, zsum := range zones {
		zs := sm.GetZone(zsum.Zone)
		if zs == nil {
			continue
		}
		detectSilentProviders(zs, state, now, silenceThreshold)
		detectMissingProviders(zs, state)
		zs.pruneDistributions(now)
		detectWaitingDistributions(zs, state, now, pendingThreshold, reporters)
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

// detectWaitingDistributions flags each member whose confirmation a
// distribution has waited for longer than threshold, counted from when the
// distribution reached the auditor, and clears the flag when the member's
// confirmation has arrived. The observation names the distribution, its
// originator and the member. A member is flagged only when it is one of
// reporters, the members that send the auditor their confirmations: a
// missing confirmation from any other says nothing. A distribution that has
// left the zone's state takes its flags with it.
func detectWaitingDistributions(zs *AuditZoneState, state *detectorRunState,
	now time.Time, threshold time.Duration, reporters map[string]bool) {
	if threshold <= 0 {
		return
	}
	type wait struct {
		key, what, originator, member, status string
		rejected                              bool
		waited                                time.Duration
	}
	zs.mu.RLock()
	var waits []wait
	for dkey, d := range zs.Distributions {
		if d.Received.IsZero() {
			continue
		}
		what := d.DistributionID
		if d.Summary != "" {
			what += " (" + d.Summary + ")"
		}
		for id, m := range d.Members {
			if !m.Awaited {
				continue
			}
			w := wait{key: dkey + "|" + id, what: what, originator: d.Originator, member: id,
				status: m.Status, rejected: m.Rejected, waited: now.Sub(d.Received)}
			if m.Status != "" {
				w.waited = m.Seen.Sub(d.Received)
			}
			waits = append(waits, w)
		}
	}
	zs.mu.RUnlock()

	state.mu.Lock()
	flagged := state.waiting[zs.Zone]
	still := make(map[string]bool, len(flagged))
	var raised, cleared []wait
	for _, w := range waits {
		switch {
		case w.status == "" && flagged[w.key]:
			still[w.key] = true
		case w.status == "" && w.waited > threshold && reporters[w.member]:
			still[w.key] = true
			raised = append(raised, w)
		case w.status != "" && flagged[w.key]:
			cleared = append(cleared, w)
		}
	}
	if len(still) > 0 {
		state.waiting[zs.Zone] = still
	} else {
		delete(state.waiting, zs.Zone)
	}
	state.mu.Unlock()

	for _, w := range raised {
		zs.AddObservation("warning", w.member,
			fmt.Sprintf("distribution %s from %s has waited %s for a confirmation from %s",
				w.what, w.originator, w.waited.Round(time.Second), w.member))
	}
	for _, w := range cleared {
		answer := "confirmed"
		if w.rejected {
			answer = "answered " + w.status
		}
		zs.AddObservation("info", w.member,
			fmt.Sprintf("distribution %s from %s: %s %s after %s",
				w.what, w.originator, w.member, answer, w.waited.Round(time.Second)))
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
		auditorSet[strings.ToLower(normalizeHSYNC3Label(lbl))] = true
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
		if auditorSet[strings.ToLower(normalizeHSYNC3Label(h3.Label))] {
			continue
		}
		identity := dns.Fqdn(h3.Identity)
		out = append(out, identity)
	}
	return out
}
