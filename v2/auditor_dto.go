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

import (
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
)

// AuditZoneSummary is the JSON shape returned by /auditor "zones"
// and "zone" commands. Snapshotted from AuditZoneState.
type AuditZoneSummary struct {
	Zone          string                 `json:"zone"`
	ProviderCount int                    `json:"provider_count"`
	AuditorCount  int                    `json:"auditor_count"`
	LastRefresh   time.Time              `json:"last_refresh,omitempty"`
	ZoneSerial    uint32                 `json:"zone_serial,omitempty"`
	Servers       []string               `json:"servers,omitempty"`
	Signers       []string               `json:"signers,omitempty"`
	AuditorLabels []string               `json:"auditor_labels,omitempty"`
	NSmgmt        string                 `json:"nsmgmt,omitempty"`
	ParentSync    string                 `json:"parentsync,omitempty"`
	Providers     []AuditProviderSummary `json:"providers,omitempty"`
	Auditors      []AuditProviderSummary `json:"auditors,omitempty"`
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
	Local            bool      `json:"local,omitempty"`
}

// markLocalAuditors sets Local on rows matching this auditor instance.
func markLocalAuditors(localIdentity string, out []AuditProviderSummary) {
	if localIdentity == "" {
		return
	}
	localIdentity = dns.Fqdn(localIdentity)
	for i := range out {
		if out[i].Identity != "" && dns.Fqdn(out[i].Identity) == localIdentity {
			out[i].Local = true
		}
	}
}

// auditorMergeKey keys an auditor row for merging: by identity once the
// apex HSYNC3 record has resolved it, otherwise by the auditors= label,
// so two declared auditors that have not published HSYNC3 yet stay
// distinct rows instead of collapsing into one.
func auditorMergeKey(s AuditProviderSummary) string {
	if s.Identity != "" {
		return s.Identity
	}
	return "label:" + s.Label
}

// enrichLocalAuditorGossip fills gossip for the local auditor from the
// agent registry (this host does not receive its own inbound beats).
func enrichLocalAuditorGossip(ar *AgentRegistry, zone string, out []AuditProviderSummary) {
	if ar == nil {
		return
	}
	for i := range out {
		if !out[i].Local {
			continue
		}
		_, gossip, _ := providerBeatMeta(ar, ZoneName(zone), out[i].Identity)
		if gossip != "" && out[i].GossipState == "" {
			out[i].GossipState = gossip
		}
	}
}

// Snapshot returns an immutable summary of zs. Safe to call without
// holding any lock; takes the zone lock internally. localIdentity
// marks the running auditor row (no self beats).
func (zs *AuditZoneState) Snapshot(localIdentity string) AuditZoneSummary {
	zs.mu.RLock()
	defer zs.mu.RUnlock()
	now := time.Now()
	summary := AuditZoneSummary{
		Zone:        zs.Zone,
		LastRefresh: zs.LastRefresh,
		ZoneSerial:  zs.ZoneSerial,
	}
	for _, ps := range zs.Providers {
		if !IsProviderIdentity(zs.Zone, ps.Identity) {
			continue
		}
		summary.Providers = append(summary.Providers, providerSummary(ps, now))
	}
	summary.ProviderCount = len(summary.Providers)
	summary.Auditors = snapshotAuditorsLocked(zs, now, localIdentity)
	summary.AuditorCount = len(summary.Auditors)
	return summary
}

// snapshotAuditorsLocked builds auditor summaries for zs. Caller must
// hold zs.mu (read or write).
func snapshotAuditorsLocked(zs *AuditZoneState, now time.Time, localIdentity string) []AuditProviderSummary {
	byID := make(map[string]AuditProviderSummary)
	for _, s := range DeclaredAuditorIdentities(zs.Zone) {
		byID[auditorMergeKey(s)] = s
	}
	for _, as := range zs.Auditors {
		if !IsAuditorIdentity(zs.Zone, as.Identity) {
			continue
		}
		byID[as.Identity] = providerSummary(as, now)
	}
	out := make([]AuditProviderSummary, 0, len(byID))
	for _, s := range byID {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b AuditProviderSummary) int {
		if a.Label != b.Label {
			return strings.Compare(a.Label, b.Label)
		}
		return strings.Compare(a.Identity, b.Identity)
	})
	markLocalAuditors(localIdentity, out)
	return out
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

// SnapshotDashboardZones returns zone rows for the web dashboard:
// audit state (beats/sync) merged with MP provider-group zones and
// loaded multi-provider zones so links appear before first beat.
func SnapshotDashboardZones(ar *AgentRegistry, sm *AuditStateManager) []AuditZoneSummary {
	byZone := make(map[string]AuditZoneSummary)
	if sm != nil {
		for _, z := range sm.SnapshotAllZones() {
			byZone[z.Zone] = z
		}
	}
	if ar != nil && ar.ProviderGroupManager != nil {
		ar.ProviderGroupManager.mu.RLock()
		for _, g := range ar.ProviderGroupManager.Groups {
			for _, zn := range g.Zones {
				name := string(zn)
				if _, ok := byZone[name]; !ok {
					byZone[name] = AuditZoneSummary{Zone: name}
				}
			}
		}
		ar.ProviderGroupManager.mu.RUnlock()
	}
	for zname, zd := range Zones.Items() {
		if !zd.Ready || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		name := string(zname)
		if _, ok := byZone[name]; !ok {
			byZone[name] = AuditZoneSummary{Zone: name}
		}
	}
	out := make([]AuditZoneSummary, 0, len(byZone))
	for _, z := range byZone {
		enrichZoneSummaryMPList(&z)
		out = append(out, z)
	}
	slices.SortFunc(out, func(a, b AuditZoneSummary) int {
		return strings.Compare(a.Zone, b.Zone)
	})
	return out
}

func enrichZoneSummaryMPList(z *AuditZoneSummary) {
	if z == nil || z.Zone == "" {
		return
	}
	mpzd, ok := Zones.Get(z.Zone)
	if !ok || mpzd == nil {
		return
	}
	info := MPZoneInfoFromMPZoneData(mpzd)
	z.Servers = info.Servers
	z.Signers = info.Signers
	z.AuditorLabels = info.Auditors
	z.NSmgmt = info.NSmgmt
	z.ParentSync = info.ParentSync
}

// SnapshotAllZones returns summaries for every tracked zone.
func (m *AuditStateManager) SnapshotAllZones() []AuditZoneSummary {
	m.mu.RLock()
	zones := make([]*AuditZoneState, 0, len(m.zones))
	local := m.LocalIdentity
	for _, zs := range m.zones {
		zones = append(zones, zs)
	}
	m.mu.RUnlock()
	out := make([]AuditZoneSummary, 0, len(zones))
	for _, zs := range zones {
		out = append(out, zs.Snapshot(local))
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
			if !IsProviderIdentity(zs.Zone, ps.Identity) {
				continue
			}
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

// SnapshotAllAuditors returns one entry per distinct auditor identity
// across all tracked zones (HSYNCPARAM auditors=), merged like providers.
func (m *AuditStateManager) SnapshotAllAuditors() []AuditProviderSummary {
	m.mu.RLock()
	zones := make([]*AuditZoneState, 0, len(m.zones))
	local := m.LocalIdentity
	for _, zs := range m.zones {
		zones = append(zones, zs)
	}
	m.mu.RUnlock()
	now := time.Now()
	merged := make(map[string]AuditProviderSummary)
	for zname, zd := range Zones.Items() {
		if !zd.Ready || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		for _, s := range DeclaredAuditorIdentities(string(zname)) {
			if _, exists := merged[auditorMergeKey(s)]; !exists {
				merged[auditorMergeKey(s)] = s
			}
		}
	}
	for _, zs := range zones {
		zs.mu.RLock()
		for _, s := range snapshotAuditorsLocked(zs, now, local) {
			cur, exists := merged[auditorMergeKey(s)]
			if !exists {
				merged[auditorMergeKey(s)] = s
				continue
			}
			if s.LastBeat.After(cur.LastBeat) {
				cur.LastBeat = s.LastBeat
				cur.SecondsSinceBeat = s.SecondsSinceBeat
			}
			if s.GossipState != "" {
				cur.GossipState = s.GossipState
			}
			if cur.Label == "" && s.Label != "" {
				cur.Label = s.Label
			}
			merged[auditorMergeKey(s)] = cur
		}
		zs.mu.RUnlock()
	}
	out := make([]AuditProviderSummary, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b AuditProviderSummary) int {
		return strings.Compare(a.Label, b.Label)
	})
	markLocalAuditors(local, out)
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

	// Snapshot the value-typed fields of every group under pgm.mu.
	// ProposeGroupName mutates Name in place, so reading g.Name (and
	// the slice headers for Members/Zones) after RUnlock would race.
	type groupSnap struct {
		hash    string
		name    string
		members []string
		zones   []ZoneName
	}
	pgm.mu.RLock()
	snaps := make([]groupSnap, 0, len(pgm.Groups))
	for _, g := range pgm.Groups {
		snaps = append(snaps, groupSnap{
			hash:    g.GroupHash,
			name:    g.Name,
			members: append([]string(nil), g.Members...),
			zones:   append([]ZoneName(nil), g.Zones...),
		})
	}
	pgm.mu.RUnlock()

	// Auditors often receive gossip before ProviderGroupManager has been
	// populated from local zone files; still show matrices from gst.
	seen := make(map[string]bool, len(snaps))
	for _, g := range snaps {
		seen[g.hash] = true
	}
	gst.mu.RLock()
	for hash, states := range gst.States {
		if seen[hash] {
			continue
		}
		members := make([]string, 0, len(states))
		for member := range states {
			members = append(members, member)
		}
		slices.Sort(members)
		name := ""
		if np := gst.Names[hash]; np != nil {
			name = np.Name
		}
		snaps = append(snaps, groupSnap{
			hash:    hash,
			name:    name,
			members: members,
		})
		seen[hash] = true
	}
	gst.mu.RUnlock()

	now := time.Now()
	out := make([]GossipMatrixDTO, 0, len(snaps))
	for _, g := range snaps {
		// The inner States map is written by the inbound beat path under
		// gst.mu; the union must range over it with the lock still held.
		gst.mu.RLock()
		states := gst.States[g.hash]
		members := unionGossipMembers(g.members, states)
		gst.mu.RUnlock()

		dto := GossipMatrixDTO{
			GroupHash: g.hash,
			Members:   members,
			ZoneCount: len(g.zones),
		}
		if g.name != "" {
			dto.GroupName = g.name
		}
		for _, z := range g.zones {
			dto.Zones = append(dto.Zones, string(z))
		}
		gst.mu.RLock()
		if states != nil {
			reported := make(map[string]bool, len(states))
			for reporter, ms := range states {
				reported[reporter] = true
				dto.Rows = append(dto.Rows, gossipMemberRow(reporter, ms, now))
			}
			for _, member := range members {
				if reported[member] {
					continue
				}
				dto.Rows = append(dto.Rows, GossipMemberRow{Reporter: member})
			}
		}
		if elec := gst.Elections[g.hash]; elec != nil {
			dto.Election = GossipElectionDTO{
				Leader:       elec.Leader,
				Term:         elec.Term,
				LeaderExpiry: elec.LeaderExpiry,
			}
		}
		gst.mu.RUnlock()
		slices.SortFunc(dto.Rows, func(a, b GossipMemberRow) int {
			return strings.Compare(a.Reporter, b.Reporter)
		})
		out = append(out, dto)
	}
	slices.SortFunc(out, func(a, b GossipMatrixDTO) int {
		return strings.Compare(a.GroupHash, b.GroupHash)
	})
	return out
}

func unionGossipMembers(declared []string, states map[string]*MemberState) []string {
	seen := make(map[string]bool, len(declared)+len(states))
	for _, m := range declared {
		seen[m] = true
	}
	for m := range states {
		seen[m] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	slices.Sort(out)
	return out
}

func gossipMemberRow(reporter string, ms *MemberState, now time.Time) GossipMemberRow {
	row := GossipMemberRow{Reporter: reporter}
	if ms == nil {
		return row
	}
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
	return row
}

// SnapshotGossipForZone returns gossip matrices for groups tied to zone
// (listed in the group or any member is an apex HSYNC3 identity).
func SnapshotGossipForZone(ar *AgentRegistry, zone string) []GossipMatrixDTO {
	all := SnapshotGossip(ar)
	if zone == "" {
		return all
	}
	zone = dns.Fqdn(zone)
	ids := zoneMemberIdentities(zone)
	var out []GossipMatrixDTO
	for _, g := range all {
		if gossipGroupMatchesZone(g, zone, ids) {
			out = append(out, g)
		}
	}
	return out
}

func gossipGroupMatchesZone(g GossipMatrixDTO, zone string, zoneIDs map[string]bool) bool {
	for _, z := range g.Zones {
		if dns.Fqdn(z) == zone {
			return true
		}
	}
	if len(zoneIDs) == 0 {
		return false
	}
	for _, m := range g.Members {
		if zoneIDs[dns.Fqdn(m)] {
			return true
		}
	}
	return false
}
