/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor state types: per-zone and per-provider state maintained
 * by the auditor for reporting and observation.
 */
package tdnsmp

import (
	"sync"
	"time"
)

// AuditZoneState tracks the auditor's view of one zone.
type AuditZoneState struct {
	mu           sync.RWMutex
	Zone         string
	Providers    map[string]*AuditProviderState
	LastRefresh  time.Time
	ZoneSerial   uint32
	Observations []AuditObservation
}

// AuditProviderState tracks the auditor's view of one provider.
type AuditProviderState struct {
	Identity      string
	Label         string
	IsSigner      bool
	LastBeat      time.Time
	LastSync      time.Time
	GossipState   string
	Contributions map[string]map[uint16]int // owner → rrtype → count
	KeyInventory  []KeySummary
}

// KeySummary is a condensed view of a DNSKEY seen from a provider.
type KeySummary struct {
	KeyTag    uint16
	Algorithm uint8
	Flags     uint16
	FirstSeen time.Time
	LastSeen  time.Time
}

// AuditObservation is an anomaly or notable event detected by the auditor.
type AuditObservation struct {
	Time     time.Time
	Severity string // "info", "warning", "error"
	Zone     string
	Provider string
	Message  string
}

// AuditStateManager holds per-zone audit state.
type AuditStateManager struct {
	mu    sync.RWMutex
	zones map[string]*AuditZoneState
}

// NewAuditStateManager creates a new audit state manager.
func NewAuditStateManager() *AuditStateManager {
	return &AuditStateManager{
		zones: make(map[string]*AuditZoneState),
	}
}

// GetOrCreateZone returns the AuditZoneState for a zone, creating it if needed.
func (m *AuditStateManager) GetOrCreateZone(zone string) *AuditZoneState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if zs, ok := m.zones[zone]; ok {
		return zs
	}
	zs := &AuditZoneState{
		Zone:      zone,
		Providers: make(map[string]*AuditProviderState),
	}
	m.zones[zone] = zs
	return zs
}

// GetZone returns the AuditZoneState for a zone, or nil if not tracked.
func (m *AuditStateManager) GetZone(zone string) *AuditZoneState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones[zone]
}

// GetAllZones returns a snapshot of all tracked zones.
func (m *AuditStateManager) GetAllZones() map[string]*AuditZoneState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]*AuditZoneState, len(m.zones))
	for k, v := range m.zones {
		result[k] = v
	}
	return result
}

// UpdateProviderBeat updates the provider state on beat receipt.
func (zs *AuditZoneState) UpdateProviderBeat(identity, label, gossipState string, isSigner bool) {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	ps, ok := zs.Providers[identity]
	if !ok {
		ps = &AuditProviderState{
			Identity:      identity,
			Label:         label,
			Contributions: make(map[string]map[uint16]int),
		}
		zs.Providers[identity] = ps
	}
	ps.IsSigner = isSigner
	ps.GossipState = gossipState
	ps.LastBeat = time.Now()
}

// UpdateProviderSync updates the provider state on sync receipt.
func (zs *AuditZoneState) UpdateProviderSync(identity string, rrCounts map[string]map[uint16]int) {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	ps, ok := zs.Providers[identity]
	if !ok {
		ps = &AuditProviderState{
			Identity:      identity,
			Contributions: make(map[string]map[uint16]int),
		}
		zs.Providers[identity] = ps
	}
	ps.LastSync = time.Now()
	if rrCounts != nil {
		ps.Contributions = rrCounts
	}
}

// AddObservation appends an observation, capping the list at 1000.
func (zs *AuditZoneState) AddObservation(severity, provider, message string) {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	obs := AuditObservation{
		Time:     time.Now(),
		Severity: severity,
		Zone:     zs.Zone,
		Provider: provider,
		Message:  message,
	}
	zs.Observations = append(zs.Observations, obs)
	if len(zs.Observations) > 1000 {
		zs.Observations = zs.Observations[len(zs.Observations)-1000:]
	}
}
