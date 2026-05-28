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

// RecomputeGroups scans all loaded zones, extracts HSYNC3 identity sets,
// and rebuilds the provider group map. This is a pure function of zone data.
func (pgm *ProviderGroupManager) RecomputeGroups() {
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

	// Merge with existing groups (preserve name proposals)
	pgm.mu.Lock()
	defer pgm.mu.Unlock()

	for hash, pg := range newGroups {
		if existing, ok := pgm.Groups[hash]; ok {
			pg.NameProposal = existing.NameProposal
			pg.Name = existing.Name
		}
	}
	pgm.Groups = newGroups
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
