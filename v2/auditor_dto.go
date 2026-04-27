/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor wire-format DTOs and Snapshot builders.
 *
 * The runtime types in auditor_state.go are mutable and protected by
 * an RWMutex; their fields can change underneath any goroutine that
 * holds a reference. The DTOs in this file are plain values, taken
 * inside the lock, and intended for the JSON API and for any other
 * caller that needs a stable view. Keep all field copies happening
 * inside the lock — never hand out *AuditProviderState directly.
 */
package tdnsmp

import "time"

// AuditZoneSummary is the JSON shape returned by /auditor "zones"
// and "zone" commands. Snapshotted from AuditZoneState.
type AuditZoneSummary struct {
	Zone          string                 `json:"zone"`
	ProviderCount int                    `json:"provider_count"`
	LastRefresh   time.Time              `json:"last_refresh,omitempty"`
	ZoneSerial    uint32                 `json:"zone_serial,omitempty"`
	Providers     []AuditProviderSummary `json:"providers,omitempty"`
}

// AuditProviderSummary is the JSON shape for one provider's state.
// Derived fields (e.g. SecondsSinceBeat) are computed at snapshot
// time so dashboards never have to re-derive from the raw timestamps.
type AuditProviderSummary struct {
	Identity         string    `json:"identity"`
	Label            string    `json:"label,omitempty"`
	IsSigner         bool      `json:"is_signer"`
	LastBeat         time.Time `json:"last_beat,omitempty"`
	LastSync         time.Time `json:"last_sync,omitempty"`
	GossipState      string    `json:"gossip_state,omitempty"`
	ContributionRRs  int       `json:"contribution_rrs"`
	KeyCount         int       `json:"key_count"`
	SecondsSinceBeat int64     `json:"seconds_since_beat,omitempty"`
	SecondsSinceSync int64     `json:"seconds_since_sync,omitempty"`
}

// Snapshot returns an immutable summary of zs. Safe to call without
// holding any lock; takes the zone lock internally.
func (zs *AuditZoneState) Snapshot() AuditZoneSummary {
	zs.mu.RLock()
	defer zs.mu.RUnlock()
	now := time.Now()
	summary := AuditZoneSummary{
		Zone:          zs.Zone,
		ProviderCount: len(zs.Providers),
		LastRefresh:   zs.LastRefresh,
		ZoneSerial:    zs.ZoneSerial,
	}
	if len(zs.Providers) == 0 {
		return summary
	}
	summary.Providers = make([]AuditProviderSummary, 0, len(zs.Providers))
	for _, ps := range zs.Providers {
		summary.Providers = append(summary.Providers, providerSummary(ps, now))
	}
	return summary
}

// SnapshotObservations returns a copy of zs.Observations under the lock.
func (zs *AuditZoneState) SnapshotObservations() []AuditObservation {
	zs.mu.RLock()
	defer zs.mu.RUnlock()
	if len(zs.Observations) == 0 {
		return nil
	}
	out := make([]AuditObservation, len(zs.Observations))
	copy(out, zs.Observations)
	return out
}

// providerSummary builds a value-typed summary for one provider.
// Caller must hold zs.mu (read or write).
func providerSummary(ps *AuditProviderState, now time.Time) AuditProviderSummary {
	rrCount := 0
	for _, byType := range ps.Contributions {
		for _, n := range byType {
			rrCount += n
		}
	}
	s := AuditProviderSummary{
		Identity:        ps.Identity,
		Label:           ps.Label,
		IsSigner:        ps.IsSigner,
		LastBeat:        ps.LastBeat,
		LastSync:        ps.LastSync,
		GossipState:     ps.GossipState,
		ContributionRRs: rrCount,
		KeyCount:        len(ps.KeyInventory),
	}
	if !ps.LastBeat.IsZero() {
		s.SecondsSinceBeat = int64(now.Sub(ps.LastBeat).Seconds())
	}
	if !ps.LastSync.IsZero() {
		s.SecondsSinceSync = int64(now.Sub(ps.LastSync).Seconds())
	}
	return s
}

// SnapshotAllZones returns summaries for every tracked zone.
func (m *AuditStateManager) SnapshotAllZones() []AuditZoneSummary {
	m.mu.RLock()
	zones := make([]*AuditZoneState, 0, len(m.zones))
	for _, zs := range m.zones {
		zones = append(zones, zs)
	}
	m.mu.RUnlock()
	out := make([]AuditZoneSummary, 0, len(zones))
	for _, zs := range zones {
		out = append(out, zs.Snapshot())
	}
	return out
}

// SnapshotAllObservations returns all observations across all zones,
// optionally filtered by zone (empty string = no filter).
func (m *AuditStateManager) SnapshotAllObservations(zoneFilter string) []AuditObservation {
	m.mu.RLock()
	zones := make([]*AuditZoneState, 0, len(m.zones))
	for _, zs := range m.zones {
		if zoneFilter == "" || zs.Zone == zoneFilter {
			zones = append(zones, zs)
		}
	}
	m.mu.RUnlock()
	var out []AuditObservation
	for _, zs := range zones {
		out = append(out, zs.SnapshotObservations()...)
	}
	return out
}
