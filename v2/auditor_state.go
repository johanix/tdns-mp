/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor state types: per-zone and per-provider state maintained
 * by the auditor for reporting and observation.
 */
package tdnsmp

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// AuditZoneState tracks the auditor's view of one zone.
type AuditZoneState struct {
	mu           sync.RWMutex
	Zone         string
	Providers    map[string]*AuditProviderState
	Auditors     map[string]*AuditProviderState
	LastRefresh  time.Time
	ZoneSerial   uint32
	ConfigErrors []string // HSYNC/HSYNCPARAM zone-file errors; reset on zone refresh
	Observations []AuditObservation
	// Distributions is the zone's recent distributions and what each member
	// said of them (tdns-mp #152), by originator and distribution ID
	// (distributionKey). Bounded in number and in age: pruneDistributions.
	Distributions map[string]*AuditDistribution
}

// AuditDistribution is what the auditor knows of one distribution in a zone
// (tdns-mp #152): who originated it, which members are to confirm it, and
// what each of them has said. The distribution itself reaches the auditor as
// it reaches every member; each member's final confirmation reaches it as a
// copy (MPTransportBridge.copyConfirmationToAuditors). Either can come
// first.
type AuditDistribution struct {
	DistributionID string
	Originator     string
	Summary        string    // what it carries, as the event log summarises it
	FirstSeen      time.Time // when the auditor first saw it: the distribution, or a confirmation of it
	Received       time.Time // when the distribution itself reached the auditor; zero while only confirmations have
	Updated        time.Time // when the auditor last saw anything of it
	Members        map[string]*AuditMemberConfirmation
}

// AuditMemberConfirmation is one member's part in a distribution.
type AuditMemberConfirmation struct {
	// Awaited: the member was a voting member of the zone, and not the
	// originator, when the distribution reached the auditor. A member that
	// confirmed without being awaited is listed all the same.
	Awaited  bool
	Status   string    // its final confirmation's status (SUCCESS, PARTIAL, FAILED, REJECTED, IGNORED); "" while none was seen
	Rejected bool      // the confirmation refused the distribution, or part of it
	Reason   string    // why, as the member said it
	Seen     time.Time // when its confirmation reached the auditor
}

const (
	// auditDistributionsMax is how many distributions a zone keeps.
	auditDistributionsMax = 200
	// auditDistributionKeep is how long a distribution stays after the
	// auditor last saw anything of it, once no awaited confirmation is
	// missing, and how long one stays that the auditor never received
	// itself.
	auditDistributionKeep = time.Hour
	// auditDistributionGiveUp is how long a distribution with an awaited
	// confirmation missing stays. The sender's reliable queue gives a
	// message up after 24 hours, so no confirmation comes after that.
	auditDistributionGiveUp = 24 * time.Hour
	// auditReasonMax bounds the text of a rejection, and of a summary,
	// that the auditor keeps: it is what a peer sent.
	auditReasonMax = 300
	// auditDistributionIDMax is the longest distribution ID the auditor
	// follows. An ID travels as a DNS label; a longer one in a payload is
	// not one a sender made.
	auditDistributionIDMax = 63
)

func distributionKey(originator, distID string) string {
	return dns.Fqdn(originator) + "|" + distID
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
	// LocalIdentity is this auditor's HSYNC3 FQDN. The process never
	// receives beats from itself, so snapshots mark that row Local.
	LocalIdentity string
	// Started is when this auditor's state began. The confirmations of a
	// distribution that was sent before then may have gone to a process
	// that is no more, so such a distribution is not followed.
	Started time.Time
	// reporters are the members that have sent this auditor a copy of a
	// confirmation since it started, in any zone. An agent on older code
	// sends none: what a member that is not among them has confirmed is
	// not known here, and the auditor does not say that a distribution
	// waits for it.
	reporters map[string]bool
}

// NewAuditStateManager creates a new audit state manager.
func NewAuditStateManager() *AuditStateManager {
	return &AuditStateManager{
		zones:     make(map[string]*AuditZoneState),
		Started:   time.Now(),
		reporters: make(map[string]bool),
	}
}

// GetOrCreateZone returns the AuditZoneState for a zone, creating it if
// needed. The zone name is stored as an FQDN whichever form the caller
// passed, so beats, sync messages and API requests share one entry.
func (m *AuditStateManager) GetOrCreateZone(zone string) *AuditZoneState {
	zone = dns.Fqdn(zone)
	m.mu.Lock()
	defer m.mu.Unlock()
	if zs, ok := m.zones[zone]; ok {
		return zs
	}
	zs := &AuditZoneState{
		Zone:      zone,
		Providers: make(map[string]*AuditProviderState),
		Auditors:  make(map[string]*AuditProviderState),
	}
	m.zones[zone] = zs
	return zs
}

// GetZone returns the AuditZoneState for a zone, or nil if not tracked.
// Accepts a zone name with or without a trailing dot.
func (m *AuditStateManager) GetZone(zone string) *AuditZoneState {
	zone = dns.Fqdn(zone)
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

// UpdateProviderBeat updates the provider state on beat receipt. An empty
// label leaves the recorded one: the entry may have been created by a sync
// that arrived before the zone's roles were known.
func (zs *AuditZoneState) UpdateProviderBeat(identity, label, gossipState string, isSigner bool) {
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
	if label != "" {
		ps.Label = label
	}
	ps.IsSigner = isSigner
	ps.GossipState = gossipState
	ps.LastBeat = time.Now()
}

// NoteProviderRole records a provider's role in the zone, resolved from the
// zone when one of its messages arrives (#108): its HSYNC3 label and
// whether it signs. A beat records the same from the same source.
func (zs *AuditZoneState) NoteProviderRole(identity, label string, isSigner bool) {
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
	if label != "" {
		ps.Label = label
	}
	ps.IsSigner = isSigner
}

// UpdateAuditorBeat updates the auditor state on beat receipt.
func (zs *AuditZoneState) UpdateAuditorBeat(identity, label, gossipState string) {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	as, ok := zs.Auditors[identity]
	if !ok {
		as = &AuditProviderState{
			Identity:      identity,
			Label:         label,
			Contributions: make(map[string]map[uint16]int),
		}
		zs.Auditors[identity] = as
	}
	if label != "" {
		as.Label = label
	}
	as.GossipState = gossipState
	as.LastBeat = time.Now()
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

// NoteConfirmation records a member's final confirmation of a distribution
// in zone, from the copy the member sent, and that the member is one that
// sends copies.
func (m *AuditStateManager) NoteConfirmation(zone, distID, originator, member, status, message string, rejected []RejectedItemInfo) {
	if strings.EqualFold(status, "PENDING") {
		return // not a final word
	}
	if distID == "" || len(distID) > auditDistributionIDMax {
		return
	}
	m.mu.Lock()
	m.reporters[dns.Fqdn(member)] = true
	m.mu.Unlock()
	m.GetOrCreateZone(zone).noteConfirmation(distID, originator, member, status, message, rejected)
}

// Reporters returns the members that have sent this auditor a copy of a
// confirmation.
func (m *AuditStateManager) Reporters() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool, len(m.reporters))
	for id := range m.reporters {
		out[id] = true
	}
	return out
}

// missing reports whether the distribution has reached the auditor and an
// awaited member's confirmation has not.
func (d *AuditDistribution) missing() bool {
	if d.Received.IsZero() {
		return false
	}
	for _, m := range d.Members {
		if m.Awaited && m.Status == "" {
			return true
		}
	}
	return false
}

// NoteDistribution records that a distribution reached the auditor: its
// originator, what it carries, and the members whose confirmation it now
// waits for. Confirmations that came before it are kept. A resend of a
// distribution already recorded changes nothing.
func (zs *AuditZoneState) NoteDistribution(distID, originator, summary string, awaited []string) {
	if distID == "" || len(distID) > auditDistributionIDMax {
		return
	}
	if len(summary) > auditReasonMax {
		summary = summary[:auditReasonMax] + "..."
	}
	now := time.Now()
	zs.mu.Lock()
	defer zs.mu.Unlock()
	d := zs.distributionLocked(distID, originator, now)
	if !d.Received.IsZero() {
		return
	}
	d.Received, d.Updated = now, now
	d.Summary = summary
	for _, id := range awaited {
		id = dns.Fqdn(id)
		if m, ok := d.Members[id]; ok {
			m.Awaited = true
		} else {
			d.Members[id] = &AuditMemberConfirmation{Awaited: true}
		}
	}
}

// noteConfirmation records a member's final confirmation of a distribution:
// the status as sent and, for a refusal, the reason. The member's latest
// word stands.
func (zs *AuditZoneState) noteConfirmation(distID, originator, member, status, message string, rejected []RejectedItemInfo) {
	switch status = strings.ToUpper(status); status {
	case "OK":
		status = "SUCCESS"
	case "SUCCESS", "PARTIAL", "REJECTED", "IGNORED":
	default: // "FAILED", "ERROR", and whatever else the transport reads as a failure
		status = "FAILED"
	}
	refused := status == "FAILED" || status == "REJECTED" || len(rejected) > 0
	reason := ""
	if refused {
		reason = message
		if len(rejected) > 0 {
			reason = rejected[0].Reason
			if len(rejected) > 1 {
				reason = fmt.Sprintf("%s (and %d more)", reason, len(rejected)-1)
			}
		}
		if len(reason) > auditReasonMax {
			reason = reason[:auditReasonMax] + "..."
		}
	}

	now := time.Now()
	zs.mu.Lock()
	defer zs.mu.Unlock()
	d := zs.distributionLocked(distID, originator, now)
	m, ok := d.Members[dns.Fqdn(member)]
	if !ok {
		m = &AuditMemberConfirmation{}
		d.Members[dns.Fqdn(member)] = m
	}
	m.Status, m.Rejected, m.Reason, m.Seen = status, refused, reason, now
	d.Updated = now
}

// distributionLocked returns the zone's record of a distribution, creating
// it, and making room for it, when it is new. Caller holds zs.mu.
func (zs *AuditZoneState) distributionLocked(distID, originator string, now time.Time) *AuditDistribution {
	key := distributionKey(originator, distID)
	if d, ok := zs.Distributions[key]; ok {
		return d
	}
	if zs.Distributions == nil {
		zs.Distributions = make(map[string]*AuditDistribution)
	}
	for len(zs.Distributions) >= auditDistributionsMax {
		zs.dropOneDistributionLocked()
	}
	d := &AuditDistribution{
		DistributionID: distID,
		Originator:     dns.Fqdn(originator),
		FirstSeen:      now,
		Updated:        now,
		Members:        make(map[string]*AuditMemberConfirmation),
	}
	zs.Distributions[key] = d
	return d
}

// dropOneDistributionLocked makes room: the oldest of the distributions the
// auditor never received itself goes first, then the oldest with no awaited
// confirmation missing, and only then the oldest that still misses one. So
// confirmations of distributions that never come cannot push out one that is
// being followed. Caller holds zs.mu.
func (zs *AuditZoneState) dropOneDistributionLocked() {
	victim, victimRank := "", 3
	var victimSeen time.Time
	for key, d := range zs.Distributions {
		rank := 1
		switch {
		case d.Received.IsZero():
			rank = 0
		case d.missing():
			rank = 2
		}
		if rank < victimRank || (rank == victimRank && d.FirstSeen.Before(victimSeen)) {
			victim, victimRank, victimSeen = key, rank, d.FirstSeen
		}
	}
	delete(zs.Distributions, victim)
}

// pruneDistributions drops the distributions that have aged out at now: one
// with no awaited confirmation missing, and one the auditor never received
// itself, auditDistributionKeep after the auditor last saw anything of it;
// one that still misses a confirmation auditDistributionGiveUp after it
// arrived.
func (zs *AuditZoneState) pruneDistributions(now time.Time) {
	zs.mu.Lock()
	defer zs.mu.Unlock()
	for key, d := range zs.Distributions {
		gone := now.Sub(d.Updated) > auditDistributionKeep
		if d.missing() {
			gone = now.Sub(d.Received) > auditDistributionGiveUp
		}
		if gone {
			delete(zs.Distributions, key)
		}
	}
}
