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

		hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
		if len(hsyncRRset.RRs) == 0 {
			continue
		}

		// Extract identities and label→identity map from HSYNC3 records.
		var identities []string
		labelToIdentity := map[string]string{}
		for _, rr := range hsyncRRset.RRs {
			prr, ok := rr.(*dns.PrivateRR)
			if !ok {
				continue
			}
			h3, ok := prr.Data.(*core.HSYNC3)
			if !ok {
				continue
			}
			if h3.State == 0 { // OFF
				continue
			}
			identities = append(identities, h3.Identity)
			labelToIdentity[h3.Label] = h3.Identity
		}

		if len(identities) < 2 {
			continue
		}

		// Voting members for this zone = union of HSYNCPARAM
		// signers and servers, translated through the HSYNC3
		// label→identity map. Non-voting roles (auditors etc.)
		// appear in HSYNC3 but not in signers/servers, so they
		// are excluded here by construction. Future role
		// categories (e.g. "secretary") add HSYNC3 records but
		// don't list themselves under signers/servers, so this
		// stays correct.
		var votingMembers []string
		if hpRRset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM); ok && len(hpRRset.RRs) > 0 {
			if prr, ok := hpRRset.RRs[0].(*dns.PrivateRR); ok {
				if hp, ok := prr.Data.(*core.HSYNCPARAM); ok {
					seen := map[string]bool{}
					for _, label := range hp.GetSigners() {
						if id, ok := labelToIdentity[label]; ok && !seen[id] {
							votingMembers = append(votingMembers, id)
							seen[id] = true
						}
					}
					for _, label := range hp.GetServers() {
						if id, ok := labelToIdentity[label]; ok && !seen[id] {
							votingMembers = append(votingMembers, id)
							seen[id] = true
						}
					}
				}
			}
		}
		// Fallback for zones with HSYNC3 but no HSYNCPARAM yet:
		// treat all HSYNC3 identities as voting (legacy behaviour).
		// Logged so the operator notices the missing HSYNCPARAM.
		if len(votingMembers) == 0 {
			lgProviderGroup.Warn("zone has HSYNC3 but no HSYNCPARAM with signers/servers; treating all HSYNC3 identities as voting (legacy fallback)",
				"zone", zname)
			votingMembers = append(votingMembers, identities...)
		}
		slices.Sort(votingMembers)
		votingMembers = slices.Compact(votingMembers)

		slices.Sort(identities)
		identities = slices.Compact(identities)
		key := strings.Join(identities, ",")

		if zg, exists := groupMap[key]; exists {
			zg.zones = append(zg.zones, ZoneName(zname))
			// Union voting members across zones in the group.
			// Inconsistency is unusual but possible; warn so the
			// operator notices.
			before := len(zg.votingMembers)
			merged := append(append([]string(nil), zg.votingMembers...), votingMembers...)
			slices.Sort(merged)
			merged = slices.Compact(merged)
			if len(merged) != before || !slices.Equal(merged, zg.votingMembers) {
				if before > 0 {
					lgProviderGroup.Warn("voting members differ across zones in the same provider group; using union",
						"group_key", key, "zone", zname, "previous", zg.votingMembers, "current", votingMembers)
				}
				zg.votingMembers = merged
			}
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
