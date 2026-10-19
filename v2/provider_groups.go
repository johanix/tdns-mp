package tdnsmp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var lgProviderGroup *slog.Logger = tdns.Logger("provider-group")

// NewProviderGroupManager creates a new provider group manager.
func NewProviderGroupManager(localIdentity string) *ProviderGroupManager {
	return &ProviderGroupManager{
		Groups:  make(map[string]*ProviderGroup),
		LocalID: localIdentity,
	}
}

// ComputeGroupHash computes a deterministic hash from a sorted,
// deduplicated list of provider identities. Uses length-prefixed
// encoding to prevent collisions (e.g., ["a","bb"] vs ["ab","b"]).
func ComputeGroupHash(identities []string) string {
	sorted := make([]string, len(identities))
	copy(sorted, identities)
	slices.Sort(sorted)
	// Deduplicate
	deduped := sorted[:0]
	for i, id := range sorted {
		if i == 0 || id != sorted[i-1] {
			deduped = append(deduped, id)
		}
	}
	h := sha256.New()
	for _, id := range deduped {
		// Length-prefix each identity to prevent concatenation collisions
		binary.Write(h, binary.BigEndian, uint16(len(id)))
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// apexHSYNCPARAM returns the zone apex's HSYNCPARAM, or nil if absent.
func apexHSYNCPARAM(apex *tdns.OwnerData) *core.HSYNCPARAM {
	if apex == nil || apex.RRtypes == nil {
		return nil
	}
	hpRRset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !ok || len(hpRRset.RRs) == 0 {
		return nil
	}
	prr, ok := hpRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return nil
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return nil
	}
	return hp
}

// zoneParticipants returns the identities that hold a membership-conferring
// HSYNCPARAM role in the zone (servers, signers, auditors), each label
// resolved through the zone's ON HSYNC3 label→identity map. HSYNC3 is only an
// identity↔label declaration and confers no membership on its own, so an
// identity present in HSYNC3 but granted no HSYNCPARAM role is excluded.
// Returned slices are sorted and de-duplicated. voting is the election-voting
// subset (servers ∪ signers); auditors are non-voting members.
//
// Legacy fallback: a zone with HSYNC3 but no HSYNCPARAM (mid-migration) treats
// every ON HSYNC3 identity as a participant, with a warning.
func zoneParticipants(apex *tdns.OwnerData) (participants, voting []string) {
	if apex == nil || apex.RRtypes == nil {
		return nil, nil
	}
	hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
	if len(hsyncRRset.RRs) == 0 {
		return nil, nil
	}

	// Build label→identity from ON (non-decommissioned) HSYNC3 records only.
	labelToIdentity := map[string]string{}
	var allIdentities []string
	for _, rr := range hsyncRRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.State == 0 { // skip OFF (decommissioned)
			continue
		}
		labelToIdentity[strings.TrimSuffix(h3.Label, ".")] = h3.Identity
		allIdentities = append(allIdentities, h3.Identity)
	}

	hp := apexHSYNCPARAM(apex)
	if hp == nil {
		lgProviderGroup.Warn("zone has HSYNC3 but no HSYNCPARAM; treating all HSYNC3 identities as participants (legacy fallback)",
			"zone", apex.Name)
		slices.Sort(allIdentities)
		allIdentities = slices.Compact(allIdentities)
		return allIdentities, allIdentities
	}

	seen := map[string]bool{}
	addRole := func(labels []string, isVoting bool) {
		for _, label := range labels {
			id, ok := labelToIdentity[strings.TrimSuffix(label, ".")]
			if !ok {
				continue
			}
			if !seen[id] {
				participants = append(participants, id)
				seen[id] = true
			}
			if isVoting {
				voting = append(voting, id)
			}
		}
	}
	// Membership-conferring HSYNCPARAM keys. Extend this list as HSYNCPARAM
	// (an open-ended, SVCB-like param set) gains new membership-conferring
	// roles.
	addRole(hp.GetServers(), true)
	addRole(hp.GetSigners(), true)
	addRole(hp.GetAuditors(), false)

	slices.Sort(participants)
	participants = slices.Compact(participants)
	slices.Sort(voting)
	voting = slices.Compact(voting)
	return participants, voting
}

// zoneApex resolves a zone's apex OwnerData via the MP zone map, or nil.
func zoneApex(zone ZoneName) *tdns.OwnerData {
	zd, ok := Zones.Get(string(zone))
	if !ok || zd == nil {
		return nil
	}
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil
	}
	return apex
}

// mayHoldZoneSig0Key: the agent may be handed the zone's SIG(0) key. The key
// is the provider group's, for the zone's delegation sync with its parent, so
// any agent that can be elected the zone's leader may hold it: a member with
// a voting role (servers or signers). Who transfers the zone from whom
// (HSYNC3's upstream) has nothing to do with it. Identities compare as FQDNs
// (isAmong): the zone's records carry the trailing dot, and an agent's
// configured identity need not.
func mayHoldZoneSig0Key(zone ZoneName, agent AgentId) bool {
	_, voting := zoneParticipants(zoneApex(zone))
	return isAmong(voting, agent)
}

// sig0KeyPeers are the zone's agents a new leader asks for the zone's SIG(0)
// key: the others that may hold it. An auditor never answers (its engine
// only records the request), so asking one cost the full timeout; and a key
// from an agent that may not hold the zone's key is not the group's key.
func sig0KeyPeers(zone ZoneName, agents []*Agent, self AgentId) []*Agent {
	var peers []*Agent
	for _, a := range agents {
		if !isAmong([]string{string(self)}, a.ID) && mayHoldZoneSig0Key(zone, a.ID) {
			peers = append(peers, a)
		}
	}
	return peers
}

// ParticipantsForZone is the single membership truth for agent/auditor reads:
// the identities holding a membership-conferring HSYNCPARAM role in the zone
// (resolved via ON HSYNC3 labels). Returns nil for an unknown zone or one with
// no HSYNC3. Every membership reader routes through this (or the apex/FQDN-set
// variants below) so there is one derivation — zoneParticipants — and no
// raw-HSYNC3 co-presence path survives.
func ParticipantsForZone(zone ZoneName) []AgentId {
	participants, _ := zoneParticipants(zoneApex(zone))
	out := make([]AgentId, len(participants))
	for i, id := range participants {
		out[i] = AgentId(id)
	}
	return out
}

// participantFQDNSetForApex returns the FQDN-keyed participant set for a zone
// apex. Used by the wire boundary (auth/HELLO), which already holds the zone
// data, so it never re-looks-up through a second accessor.
func participantFQDNSetForApex(apex *tdns.OwnerData) map[string]bool {
	participants, _ := zoneParticipants(apex)
	set := make(map[string]bool, len(participants))
	for _, id := range participants {
		set[dns.Fqdn(id)] = true
	}
	return set
}

// sharedParticipantZones returns the zones in which both the local identity and
// the given identity hold a membership role — the derived shared-zone set that
// replaces the stored agent.Zones for outbound beats, HELLO, and the
// OPERATIONAL/LEGACY transition (LEGACY == derived participations == 0).
func (ar *AgentRegistry) sharedParticipantZones(identity AgentId) []ZoneName {
	localFQDN := dns.Fqdn(string(ar.LocalAgent.Identity))
	idFQDN := dns.Fqdn(string(identity))
	var out []ZoneName
	for zoneName, zd := range Zones.Items() {
		if zd == nil {
			continue
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			continue
		}
		set := participantFQDNSetForApex(apex)
		if set[localFQDN] && set[idFQDN] {
			out = append(out, ZoneName(zoneName))
		}
	}
	return out
}

// SetOnZoneJoinedGroup sets the callback that RecomputeGroups tells of each
// zone it has put into a group the zone was not in before: to is that group,
// from the group the zone was in, empty when it had none. It is called once
// the new group map is in place, with the manager's lock free: whoever is
// told may read the groups. It must not start a recompute: the one that
// tells is not over until the callback returns, so that two recomputes tell
// in the order in which they ran. A zone whose group did not change is not
// reported, so a recompute that moves nothing calls nothing.
func (pgm *ProviderGroupManager) SetOnZoneJoinedGroup(f func(zone ZoneName, from, to string)) {
	pgm.mu.Lock()
	defer pgm.mu.Unlock()
	pgm.onZoneJoinedGroup = f
}

// SetOnGroupGone sets the callback that RecomputeGroups tells of each group
// it has dropped: a group that had zones, and has none now that its last zone
// has moved to another group or is gone. It is called as the callback of
// SetOnZoneJoinedGroup is: once the new group map is in place, with the
// manager's lock free, and it must not start a recompute. A group that
// comes back later is a new group to whoever was told.
func (pgm *ProviderGroupManager) SetOnGroupGone(f func(groupHash string)) {
	pgm.mu.Lock()
	defer pgm.mu.Unlock()
	pgm.onGroupGone = f
}

// groupsThatAreGone returns the groups of the map before a recompute that
// the map after it does not have, in the order of their hashes.
func groupsThatAreGone(before, after map[string]*ProviderGroup) []string {
	var gone []string
	for hash := range before {
		if _, ok := after[hash]; !ok {
			gone = append(gone, hash)
		}
	}
	slices.Sort(gone)
	return gone
}

// zoneGroupChange is a zone that a recompute has put into a group it was not
// in before: from is the group it was in, empty when it had none.
type zoneGroupChange struct {
	zone     ZoneName
	from, to string
}

// zonesThatJoined compares the group map before a recompute with the one
// after it, and returns the zones that are now in another group than before
// or in a group for the first time, in the order of their names. A zone that
// only left its group is not among them.
func zonesThatJoined(before, after map[string]*ProviderGroup) []zoneGroupChange {
	was := make(map[ZoneName]string)
	for hash, pg := range before {
		for _, z := range pg.Zones {
			was[z] = hash
		}
	}
	var joined []zoneGroupChange
	for hash, pg := range after {
		for _, z := range pg.Zones {
			if was[z] != hash {
				joined = append(joined, zoneGroupChange{zone: z, from: was[z], to: hash})
			}
		}
	}
	sort.Slice(joined, func(i, j int) bool {
		return joined[i].zone < joined[j].zone
	})
	return joined
}

// RecomputeGroups scans all loaded zones, extracts HSYNC3 identity sets,
// and rebuilds the provider group map. This is a pure function of zone data.
// The zones it moves into a group are reported to the callback set with
// SetOnZoneJoinedGroup, if there is one, and the groups it drops to the one
// set with SetOnGroupGone.
//
// Recomputes run one at a time, each from its scan to the last word of what
// it changed. The scan used to run under no lock, and only the swap under
// the manager's: of two recomputes at once, started by the refreshes of two
// zones, the one that had scanned first could swap last, and the map then
// held a zone in the group it had before its providers changed, until
// something recomputed again (tdns-mp #181).
func (pgm *ProviderGroupManager) RecomputeGroups() {
	// A scan that has begun by now may have read the zones before the change
	// this call is for. One that begins later has not.
	pgm.recomputeSince(pgm.scansBegun.Load())
}

// recomputeSince is RecomputeGroups for a call that was made when begun scans
// had begun. When it gets its turn and finds a scan in place that began
// after that, it returns at once: that scan read everything this one would,
// and has told what it changed. The caller has what it came for either way,
// a map made from the zones as they were at its call or later.
func (pgm *ProviderGroupManager) recomputeSince(begun uint64) {
	pgm.recomputeMu.Lock()
	defer pgm.recomputeMu.Unlock()
	if pgm.installedScan > begun {
		return
	}
	scan := pgm.scansBegun.Add(1)

	type zoneGroup struct {
		identities    []string
		votingMembers []string // union of voting identities across zones in this group
		zones         []ZoneName
	}
	groupMap := make(map[string]*zoneGroup)

	for zname, zd := range Zones.Items() {
		if !zd.Ready {
			continue
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			lgProviderGroup.Warn("skipping zone due to apex lookup failure", "zone", zd.ZoneName, "err", err)
			continue
		}

		// Membership is defined by HSYNCPARAM roles (resolved through the
		// zone's ON HSYNC3 label→identity map), NOT by the raw HSYNC3
		// identity set. An identity with an HSYNC3 record but no HSYNCPARAM
		// role is not a member. participants/voting are sorted+deduped.
		identities, votingMembers := zoneParticipants(apex)
		if len(identities) < 2 {
			continue
		}
		key := strings.Join(identities, ",")

		if zg, exists := groupMap[key]; exists {
			zg.zones = append(zg.zones, ZoneName(zname))
			// Union voting members across zones in the group.
			// Compare incoming-vs-existing directly (rather than
			// merged-vs-existing) so subset disagreements still
			// warn — iteration order over Zones.Items() is
			// randomized and the merged-equals-existing path
			// would silence the warning depending on which zone
			// happened to be processed first.
			if len(zg.votingMembers) > 0 && !slices.Equal(votingMembers, zg.votingMembers) {
				lgProviderGroup.Warn("voting members differ across zones in the same provider group; using union",
					"group_key", key, "zone", zname, "previous", zg.votingMembers, "current", votingMembers)
			}
			merged := append(append([]string(nil), zg.votingMembers...), votingMembers...)
			slices.Sort(merged)
			zg.votingMembers = slices.Compact(merged)
		} else {
			groupMap[key] = &zoneGroup{
				identities:    identities,
				votingMembers: votingMembers,
				zones:         []ZoneName{ZoneName(zname)},
			}
		}
	}

	// Build provider groups
	newGroups := make(map[string]*ProviderGroup)
	for _, zg := range groupMap {
		hash := ComputeGroupHash(zg.identities)

		sort.Slice(zg.zones, func(i, j int) bool {
			return zg.zones[i] < zg.zones[j]
		})

		pg := &ProviderGroup{
			GroupHash:     hash,
			Members:       zg.identities,
			VotingMembers: zg.votingMembers,
			Zones:         zg.zones,
			Name:          hash[:8],
		}

		newGroups[hash] = pg
	}

	if pgm.afterScan != nil {
		pgm.afterScan()
	}

	// Merge with existing groups (preserve name proposals)
	pgm.mu.Lock()

	for hash, pg := range newGroups {
		if existing, ok := pgm.Groups[hash]; ok {
			pg.NameProposal = existing.NameProposal
			pg.Name = existing.Name
		}
	}
	onJoined := pgm.onZoneJoinedGroup
	var joined []zoneGroupChange
	if onJoined != nil {
		joined = zonesThatJoined(pgm.Groups, newGroups)
	}
	onGone := pgm.onGroupGone
	var gone []string
	if onGone != nil {
		gone = groupsThatAreGone(pgm.Groups, newGroups)
	}
	pgm.Groups = newGroups
	pgm.mu.Unlock()
	pgm.installedScan = scan

	// Told with the manager's lock free, and with the new map in place:
	// whoever is told may look the zone's group up.
	for _, j := range joined {
		onJoined(j.zone, j.from, j.to)
	}
	for _, hash := range gone {
		onGone(hash)
	}
}

// ProposeGroupName sets our name proposal for a group.
func (pgm *ProviderGroupManager) ProposeGroupName(groupHash, name string) {
	pgm.mu.Lock()
	defer pgm.mu.Unlock()

	pg, ok := pgm.Groups[groupHash]
	if !ok {
		return
	}
	pg.NameProposal = &GroupNameProposal{
		GroupHash:  groupHash,
		Name:       name,
		Proposer:   pgm.LocalID,
		ProposedAt: time.Now(),
	}
	pg.Name = name
}

// cloneProviderGroup returns a deep copy of a ProviderGroup.
func cloneProviderGroup(pg *ProviderGroup) *ProviderGroup {
	if pg == nil {
		return nil
	}
	cp := *pg
	cp.Members = append([]string(nil), pg.Members...)
	cp.VotingMembers = append([]string(nil), pg.VotingMembers...)
	cp.Zones = append([]ZoneName(nil), pg.Zones...)
	if pg.NameProposal != nil {
		np := *pg.NameProposal
		cp.NameProposal = &np
	}
	return &cp
}

// GetGroups returns a snapshot of all current provider groups.
func (pgm *ProviderGroupManager) GetGroups() []*ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	groups := make([]*ProviderGroup, 0, len(pgm.Groups))
	for _, pg := range pgm.Groups {
		groups = append(groups, cloneProviderGroup(pg))
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].GroupHash < groups[j].GroupHash
	})
	return groups
}

// GetGroup returns a specific provider group by hash.
func (pgm *ProviderGroupManager) GetGroup(groupHash string) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	return cloneProviderGroup(pgm.Groups[groupHash])
}

// GetGroupByName returns a provider group by its human-friendly name.
func (pgm *ProviderGroupManager) GetGroupByName(name string) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	for _, pg := range pgm.Groups {
		if pg.Name == name {
			return cloneProviderGroup(pg)
		}
	}
	return nil
}

// GetGroupsForIdentity returns all groups that include the given identity.
func (pgm *ProviderGroupManager) GetGroupsForIdentity(identity string) []*ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	var result []*ProviderGroup
	for _, pg := range pgm.Groups {
		for _, member := range pg.Members {
			if member == identity {
				result = append(result, cloneProviderGroup(pg))
				break
			}
		}
	}
	return result
}

// GetGroupForZone returns the provider group that contains the given zone.
func (pgm *ProviderGroupManager) GetGroupForZone(zone ZoneName) *ProviderGroup {
	pgm.mu.RLock()
	defer pgm.mu.RUnlock()
	for _, pg := range pgm.Groups {
		for _, z := range pg.Zones {
			if z == zone {
				return cloneProviderGroup(pg)
			}
		}
	}
	return nil
}

// GroupSummary returns a compact string representation for logging.
func (pg *ProviderGroup) GroupSummary() string {
	memberStr := strings.Join(pg.Members, ", ")
	return fmt.Sprintf("group %s (%s): %d zones, members: [%s]",
		pg.Name, pg.GroupHash[:8], len(pg.Zones), memberStr)
}
