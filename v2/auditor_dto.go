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

// SnapshotAllProviders returns one entry per distinct provider
// identity across all tracked zones. Merge semantics per field:
//   - Identity, Label: first occurrence wins (in map-iteration
//     order of zones, which is non-deterministic).
//   - IsSigner: OR-merged — true if any zone reports the provider
//     as a signer, since "signer in any zone" is the useful answer.
//   - GossipState: most recent non-empty value wins; the order in
//     which non-empty values are seen is map-iteration dependent
//     and therefore non-deterministic across snapshots. Don't rely
//     on this for anything beyond a quick at-a-glance display.
//   - LastBeat / LastSync: most recent timestamp across zones,
//     deterministic.
func (m *AuditStateManager) SnapshotAllProviders() []AuditProviderSummary {
	m.mu.RLock()
	zones := make([]*AuditZoneState, 0, len(m.zones))
	for _, zs := range m.zones {
		zones = append(zones, zs)
	}
	m.mu.RUnlock()
	now := time.Now()
	merged := make(map[string]AuditProviderSummary)
	for _, zs := range zones {
		zs.mu.RLock()
		for _, ps := range zs.Providers {
			cur, exists := merged[ps.Identity]
			s := providerSummary(ps, now)
			if !exists {
				merged[ps.Identity] = s
				continue
			}
			if s.LastBeat.After(cur.LastBeat) {
				cur.LastBeat = s.LastBeat
				cur.SecondsSinceBeat = s.SecondsSinceBeat
			}
			if s.LastSync.After(cur.LastSync) {
				cur.LastSync = s.LastSync
				cur.SecondsSinceSync = s.SecondsSinceSync
			}
			if s.IsSigner {
				cur.IsSigner = true
			}
			if s.GossipState != "" {
				cur.GossipState = s.GossipState
			}
			merged[ps.Identity] = cur
		}
		zs.mu.RUnlock()
	}
	out := make([]AuditProviderSummary, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}
	return out
}

// GossipMatrixDTO is the JSON-friendly per-group view of the gossip
// state matrix. Rows are members reporting (their own MemberState);
// columns are peers; cells are state strings.
type GossipMatrixDTO struct {
	GroupHash string            `json:"group_hash"`
	GroupName string            `json:"group_name,omitempty"`
	Members   []string          `json:"members"`
	Rows      []GossipMemberRow `json:"rows"`
	Election  GossipElectionDTO `json:"election,omitempty"`
	ZoneCount int               `json:"zone_count"`
	Zones     []string          `json:"zones,omitempty"`
}

// GossipMemberRow is one member's report of their view of all peers.
type GossipMemberRow struct {
	Reporter         string            `json:"reporter"`
	Timestamp        time.Time         `json:"timestamp,omitempty"`
	BeatInterval     uint32            `json:"beat_interval,omitempty"`
	SecondsSinceBeat int64             `json:"seconds_since_beat,omitempty"`
	PeerStates       map[string]string `json:"peer_states"`
	Zones            []string          `json:"zones,omitempty"`
}

// GossipElectionDTO is the per-group election state.
type GossipElectionDTO struct {
	Leader       string    `json:"leader,omitempty"`
	Term         uint32    `json:"term,omitempty"`
	LeaderExpiry time.Time `json:"leader_expiry,omitempty"`
}

// SnapshotGossip returns one DTO per provider group known to the
// registry, with that group's full member×peer state matrix and
// current election state. Reads ProviderGroupManager + GossipStateTable
// under their respective locks.
func SnapshotGossip(ar *AgentRegistry) []GossipMatrixDTO {
	if ar == nil || ar.ProviderGroupManager == nil || ar.GossipStateTable == nil {
		return nil
	}
	pgm := ar.ProviderGroupManager
	gst := ar.GossipStateTable

	pgm.mu.RLock()
	groups := make([]*ProviderGroup, 0, len(pgm.Groups))
	for _, g := range pgm.Groups {
		groups = append(groups, g)
	}
	pgm.mu.RUnlock()

	now := time.Now()
	out := make([]GossipMatrixDTO, 0, len(groups))
	for _, g := range groups {
		dto := GossipMatrixDTO{
			GroupHash: g.GroupHash,
			Members:   append([]string(nil), g.Members...),
			ZoneCount: len(g.Zones),
		}
		if g.Name != "" {
			dto.GroupName = g.Name
		}
		for _, z := range g.Zones {
			dto.Zones = append(dto.Zones, string(z))
		}
		gst.mu.RLock()
		if states, ok := gst.States[g.GroupHash]; ok {
			for _, member := range g.Members {
				ms := states[member]
				row := GossipMemberRow{Reporter: member}
				if ms != nil {
					row.Timestamp = ms.Timestamp
					row.BeatInterval = ms.BeatInterval
					if !ms.Timestamp.IsZero() {
						row.SecondsSinceBeat = int64(now.Sub(ms.Timestamp).Seconds())
					}
					if len(ms.PeerStates) > 0 {
						row.PeerStates = make(map[string]string, len(ms.PeerStates))
						for k, v := range ms.PeerStates {
							row.PeerStates[k] = v
						}
					}
					if len(ms.Zones) > 0 {
						row.Zones = append([]string(nil), ms.Zones...)
					}
				}
				dto.Rows = append(dto.Rows, row)
			}
		}
		if elec := gst.Elections[g.GroupHash]; elec != nil {
			dto.Election = GossipElectionDTO{
				Leader:       elec.Leader,
				Term:         elec.Term,
				LeaderExpiry: elec.LeaderExpiry,
			}
		}
		gst.mu.RUnlock()
		out = append(out, dto)
	}
	return out
}
