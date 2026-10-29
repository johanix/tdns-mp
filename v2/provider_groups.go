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

// ComputeGroupHash computes a deterministic hash of a group's make-up (step
// 8, design 4.3): its voting members, its auditors and its members with no
// role, each list sorted and deduplicated, under a label of its own. Two
// groups of the same providers with another make-up are two groups. Each
// list is written as its label, its length and its length-prefixed
// identities, so no two make-ups write the same bytes (e.g. ["a","bb"] vs
// ["ab","b"], or one identity moved from one list to another).
func ComputeGroupHash(voting, auditors, noRole []string) string {
	h := sha256.New()
	for _, l := range []struct {
		label byte
		ids   []string
	}{{'v', voting}, {'a', auditors}, {'n', noRole}} {
		ids := sortedUnique(l.ids)
		h.Write([]byte{l.label})
		binary.Write(h, binary.BigEndian, uint16(len(ids)))
		for _, id := range ids {
			binary.Write(h, binary.BigEndian, uint16(len(id)))
			h.Write([]byte(id))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func sortedUnique(ids []string) []string {
	out := append([]string(nil), ids...)
	slices.Sort(out)
	return slices.Compact(out)
}

// groupMakeUp is a zone's make-up: who votes, who audits, and who is listed
// with no role. Until step 10 the third list is empty: a member with no role
// is no member.
type groupMakeUp struct {
	voting, auditors, noRole []string
}

// zoneMakeUp is the zone's make-up by its instructions, each list sorted and
// deduplicated.
func zoneMakeUp(in *Instructions) groupMakeUp {
	participants, voting := participantsOf(in)
	var auditors []string
	for _, id := range participants {
		if !slices.Contains(voting, id) {
			auditors = append(auditors, id)
		}
	}
	return groupMakeUp{voting: voting, auditors: auditors}
}

// key is the make-up as a map key: each list under its label.
func (m groupMakeUp) key() string {
	return "v=" + strings.Join(m.voting, ",") + ";a=" + strings.Join(m.auditors, ",") + ";n=" + strings.Join(m.noRole, ",")
}

// members is every member, whatever its role: the gossip membership.
func (m groupMakeUp) members() []string {
	return sortedUnique(append(append(append([]string(nil), m.voting...), m.auditors...), m.noRole...))
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

// standing is what a zone makes of an identity (the membership design, 2.1).
type standing int

const (
	standingNone    standing = iota // no HSYNC3 record in state ON
	standingNoRole                  // an ON record, in none of servers=, signers=, auditors=
	standingAuditor                 // in auditors= only
	standingVoting                  // in servers= or signers=
)

// zoneStanding is the identity's standing by the zone's instructions. Who
// votes is participantsOf's voting set, as VotingMembersForZone and
// isVotingMember have it.
func zoneStanding(in *Instructions, identity string) standing {
	participants, voting := participantsOf(in)
	return standingIn(in, participants, voting, identity)
}

// standingIn is zoneStanding for a caller that has read the zone's
// participants already.
func standingIn(in *Instructions, participants, voting []string, identity string) standing {
	switch {
	case isAmong(voting, AgentId(identity)):
		return standingVoting
	case isAmong(participants, AgentId(identity)):
		return standingAuditor
	case listsAgent(in, AgentId(identity)):
		return standingNoRole
	}
	return standingNone
}

// hasHSYNC3 reports whether the instructions have HSYNC3 records: only such
// a zone is a multi-provider zone, whose standings decide who votes. A zone
// with none, or one not loaded here, elects as it always has.
func hasHSYNC3(in *Instructions) bool {
	return in != nil && len(in.Records)+len(in.Off) > 0
}

// votesInZone: the identity may vote in the zone's own election, by its
// active instructions. True for a zone that is not known here or has no
// HSYNC3 records: that zone has no standings, and elects as before.
func votesInZone(zone ZoneName, id AgentId) bool {
	return votesIn(instructionsFor(zone), id)
}

// votesIn is votesInZone for a caller that holds the instructions it judges
// by.
func votesIn(in *Instructions, id AgentId) bool {
	if !hasHSYNC3(in) {
		return true
	}
	return zoneStanding(in, string(id)) == standingVoting
}

// signingPeers are the zone's providers that sign, other than self, by the
// zone's current sets. None for a zone without an HSYNCPARAM, which names no
// signer.
func signingPeers(zone ZoneName, self AgentId) []AgentId {
	var out []AgentId
	for _, id := range identities(rolesForZone(zone).Signing) {
		if isAmong([]string{string(self)}, AgentId(id)) || slices.Contains(out, AgentId(id)) {
			continue
		}
		out = append(out, AgentId(id))
	}
	return out
}

// votingPeers are the zone's voting members other than self. For an agent
// that does not vote in the zone that is every voting member.
func votingPeers(zone ZoneName, self AgentId) []AgentId {
	var out []AgentId
	for _, id := range VotingMembersForZone(zone) {
		if !isAmong([]string{string(self)}, id) {
			out = append(out, id)
		}
	}
	return out
}

// configuredVotingPeers is the count an election expects for the zone: its
// voting members other than self. An auditor and a record with no role are
// not counted (the membership design, 4.2).
func configuredVotingPeers(zone ZoneName, self AgentId) int {
	return len(votingPeers(zone, self))
}

// operationalVotingPeers counts the zone's voting members other than self
// that are OPERATIONAL here.
func (ar *AgentRegistry) operationalVotingPeers(zone ZoneName, self AgentId) int {
	n := 0
	for _, id := range votingPeers(zone, self) {
		if ar.isAgentOperational(id) {
			n++
		}
	}
	return n
}

// mayHoldZoneSig0Key: the agent may be handed the zone's SIG(0) key. The key
// is the provider group's, for the zone's delegation sync with its parent, so
// any agent that can be elected the zone's leader may hold it: a member with
// a voting role (servers or signers). Who transfers the zone from whom
// (HSYNC3's upstream) has nothing to do with it. Identities compare as FQDNs
// (isAmong): the zone's records carry the trailing dot, and an agent's
// configured identity need not.
func mayHoldZoneSig0Key(zone ZoneName, agent AgentId) bool {
	_, voting := participantsOf(instructionsFor(zone))
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

// zoneKeyPeers are the agents leaderKeySetup asks for the zone's SIG(0) key:
// sig0KeyPeers, and also previous, the agents the zone lists with no role
// (roleLessKeyHolders), those not among them already. They hand the key to
// a voting member as any holder does.
func zoneKeyPeers(zone ZoneName, agents []*Agent, self AgentId, previous []*Agent) []*Agent {
	peers := sig0KeyPeers(zone, agents, self)
	for _, prev := range previous {
		if isAmong([]string{string(self)}, prev.ID) ||
			slices.ContainsFunc(peers, func(p *Agent) bool { return isAmong([]string{string(p.ID)}, prev.ID) }) {
			continue
		}
		peers = append(peers, prev)
	}
	return peers
}

// zoneTakesKey: the zone publishes no KEY at its apex, or it publishes
// this one alone (same flags, protocol, algorithm and public key). A zone
// that has not loaded here publishes nothing to compare with. A zone that
// publishes several KEYs takes none: no local key is then the zone's key,
// and no answer can say which one the parent trusts (step 7b).
func zoneTakesKey(zone ZoneName, key *dns.KEY) bool {
	published := publishedKeys(zone)
	switch len(published) {
	case 0:
		return true
	case 1:
		return sameKey(published[0], key)
	default:
		return false
	}
}

// zoneListsAgent: the zone's active instructions have an ON record for the
// agent, with a role or without.
func zoneListsAgent(zone ZoneName, id AgentId) bool {
	return listsAgent(instructionsFor(zone), id)
}

// listsAgent is zoneListsAgent for a caller that holds the instructions.
func listsAgent(in *Instructions, id AgentId) bool {
	_, ok := in.labelOf(string(id))
	return ok
}

// roleLessKeyHolders are the agents the zone's HSYNC3 lists ON with no role
// in HSYNCPARAM, as the registry has them, other than this agent. The owner
// takes a provider's role first and its HSYNC3 record later, and in between
// that provider may hold the zone's SIG(0) key: it led the zone's group, and
// set the key up. It is no voting member and none of the zone's agents
// (GetZoneAgentData has the role holders only), so the voting members alone
// were asked, none had a key to hand over, the new leader made none while
// the zone published one, and the zone's delegation sync waited for good.
//
// Read from the zone as it is, so nothing is lost at a restart, and a leader
// that was never in the group the zone left asks as well. Outside such an
// edit the zone lists no agent without a role, and nobody more is asked.
func (ar *AgentRegistry) roleLessKeyHolders(zone ZoneName) []*Agent {
	in := instructionsFor(zone)
	if in == nil {
		return nil
	}
	participants, _ := participantsOf(in)
	var out []*Agent
	for _, r := range in.Records {
		if isAmong(participants, AgentId(r.Identity)) ||
			(ar.LocalAgent != nil && isAmong([]string{ar.LocalAgent.Identity}, AgentId(r.Identity))) {
			continue
		}
		if agent, err := ar.GetAgentInfo(AgentId(r.Identity)); err == nil {
			out = append(out, agent)
		}
	}
	return out
}

// ParticipantsForZone is the single membership truth for agent/auditor reads:
// the identities holding a membership-conferring HSYNCPARAM role in the zone
// (resolved via ON HSYNC3 labels). Returns nil for an unknown zone or one with
// no HSYNC3. Every membership reader routes through this (or the apex/FQDN-set
// variants below) so there is one derivation — zoneParticipants — and no
// raw-HSYNC3 co-presence path survives.
func ParticipantsForZone(zone ZoneName) []AgentId {
	participants, _ := participantsOf(instructionsFor(zone))
	out := make([]AgentId, len(participants))
	for i, id := range participants {
		out[i] = AgentId(id)
	}
	return out
}

// AuditorsForZone returns the zone's members that are auditors and nothing
// else: the participants without a vote, auditors= being the one role that
// confers membership and no vote (zoneParticipants). An identity that the
// zone lists as a server or signer too is a provider, and is not returned.
// Nil for an unknown zone, and for a zone without HSYNCPARAM, which declares
// no auditors.
func AuditorsForZone(zone ZoneName) []AgentId {
	participants, voting := participantsOf(instructionsFor(zone))
	var out []AgentId
	for _, id := range participants {
		if !slices.Contains(voting, id) {
			out = append(out, AgentId(id))
		}
	}
	return out
}

// VotingMembersForZone returns the zone's voting members: the identities
// with a servers= or signers= role (zoneParticipants). Nil for an unknown
// zone.
func VotingMembersForZone(zone ZoneName) []AgentId {
	_, voting := participantsOf(instructionsFor(zone))
	out := make([]AgentId, len(voting))
	for i, id := range voting {
		out[i] = AgentId(id)
	}
	return out
}

// isVotingMember reports whether identity is one of the zone's voting
// members, identities compared as canonical names (lower case, with the
// trailing dot), as every standing check compares them (isAmong).
func isVotingMember(zone ZoneName, identity string) bool {
	identity = canonicalName(identity)
	for _, id := range VotingMembersForZone(zone) {
		if canonicalName(string(id)) == identity {
			return true
		}
	}
	return false
}

// participantFQDNSet returns the FQDN-keyed participant set of a zone's
// instructions. Used by the wire boundary (auth/HELLO).
func participantFQDNSet(in *Instructions) memberSet {
	participants, _ := participantsOf(in)
	set := make(memberSet, len(participants))
	for _, id := range participants {
		set[canonicalName(id)] = true
	}
	return set
}

// memberSet is a zone's participants, each identity folded as a DNS name
// (canonicalName): the reading's identities are folded, and an identity
// asked about from elsewhere, a registry entry or a sender, is folded the
// same way before it is looked up.
type memberSet map[string]bool

// has reports whether id, compared as a DNS name, is a participant.
func (s memberSet) has(id string) bool { return s[canonicalName(id)] }

// sharedParticipantZones returns the zones in which both the local identity and
// the given identity hold a membership role — the derived shared-zone set that
// replaces the stored agent.Zones for outbound beats, HELLO, and the
// OPERATIONAL/LEGACY transition (LEGACY == derived participations == 0).
func (ar *AgentRegistry) sharedParticipantZones(identity AgentId) []ZoneName {
	var out []ZoneName
	for zoneName, zd := range Zones.Items() {
		if zd == nil {
			continue
		}
		set := participantFQDNSet(instructionsFor(ZoneName(zoneName)))
		if set.has(string(ar.LocalAgent.Identity)) && set.has(string(identity)) {
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

// zonesThatLeft compares the group map before a recompute with the one
// after it, and returns each zone that was in a group before and is not in
// that group after: in another group (to), or in none (to empty), as a zone
// reduced to one provider is (#149). zonesThatJoined reports only a zone
// that lands in a group.
func zonesThatLeft(before, after map[string]*ProviderGroup) []zoneGroupChange {
	now := make(map[ZoneName]string)
	for hash, pg := range after {
		for _, z := range pg.Zones {
			now[z] = hash
		}
	}
	var left []zoneGroupChange
	for hash, pg := range before {
		for _, z := range pg.Zones {
			if now[z] != hash {
				left = append(left, zoneGroupChange{zone: z, from: hash, to: now[z]})
			}
		}
	}
	sort.Slice(left, func(i, j int) bool {
		return left[i].zone < left[j].zone
	})
	return left
}

// SetOnZoneLeftGroup sets the callback that RecomputeGroups tells of each
// zone it has taken out of a group (zonesThatLeft). It is told as the
// callback of SetOnZoneJoinedGroup is, before it: once the new group map is
// in place, with the manager's lock free, and it must not start a
// recompute. The zones that left are told before the groups that are gone:
// whoever is told may still need to read who led the group a zone left.
func (pgm *ProviderGroupManager) SetOnZoneLeftGroup(f func(zone ZoneName, from, to string)) {
	pgm.mu.Lock()
	defer pgm.mu.Unlock()
	pgm.onZoneLeftGroup = f
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
		makeUp groupMakeUp
		zones  []ZoneName
	}
	groupMap := make(map[string]*zoneGroup)

	for zname, zd := range Zones.Items() {
		if !zd.Ready {
			continue
		}
		// Membership is defined by the roles of the zone's active
		// instructions (resolved through its ON HSYNC3 records), NOT by the
		// raw HSYNC3 identity set. An identity with an HSYNC3 record but no
		// role is not a member. participants/voting are sorted+deduped.
		// The group is the make-up (step 8): zones with the same providers
		// and another split of who votes and who audits are two groups,
		// and every zone of a group agrees on who votes.
		makeUp := zoneMakeUp(instructionsFor(ZoneName(zname)))
		if len(makeUp.members()) < 2 {
			continue
		}
		key := makeUp.key()
		if zg, exists := groupMap[key]; exists {
			zg.zones = append(zg.zones, ZoneName(zname))
		} else {
			groupMap[key] = &zoneGroup{makeUp: makeUp, zones: []ZoneName{ZoneName(zname)}}
		}
	}

	// Build provider groups
	newGroups := make(map[string]*ProviderGroup)
	for _, zg := range groupMap {
		m := zg.makeUp
		hash := ComputeGroupHash(m.voting, m.auditors, m.noRole)

		sort.Slice(zg.zones, func(i, j int) bool {
			return zg.zones[i] < zg.zones[j]
		})

		pg := &ProviderGroup{
			GroupHash:     hash,
			Members:       m.members(),
			VotingMembers: m.voting,
			Auditors:      m.auditors,
			NoRole:        m.noRole,
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
	onLeft := pgm.onZoneLeftGroup
	var left []zoneGroupChange
	if onLeft != nil {
		left = zonesThatLeft(pgm.Groups, newGroups)
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
	// whoever is told may look the zone's group up. The zones that left
	// first, then those that joined, then the groups that are gone.
	for _, l := range left {
		onLeft(l.zone, l.from, l.to)
	}
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
	cp.Auditors = append([]string(nil), pg.Auditors...)
	cp.NoRole = append([]string(nil), pg.NoRole...)
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
