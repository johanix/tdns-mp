package tdnsmp

import (
	"fmt"
	"log/slog"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var lgGossip *slog.Logger = tdns.Logger("gossip")

// shortHash returns a truncated hash for logging. Safe for short/empty strings.
func shortHash(h string) string {
	if len(h) < 8 {
		return h
	}
	return h[:8]
}

// deepCopyMemberState returns an independent copy of a MemberState.
func deepCopyMemberState(src *MemberState) *MemberState {
	dst := &MemberState{
		Identity:         src.Identity,
		Timestamp:        src.Timestamp,
		BeatInterval:     src.BeatInterval,
		PropagationDelay: src.PropagationDelay,
	}
	if src.PeerStates != nil {
		dst.PeerStates = make(map[string]string, len(src.PeerStates))
		for k, v := range src.PeerStates {
			dst.PeerStates[k] = v
		}
	}
	if src.Zones != nil {
		dst.Zones = make([]string, len(src.Zones))
		copy(dst.Zones, src.Zones)
	}
	return dst
}

// NewGossipStateTable creates a new gossip state table.
func NewGossipStateTable(localID string) *GossipStateTable {
	return &GossipStateTable{
		States:            make(map[string]map[string]*MemberState),
		Elections:         make(map[string]*GroupElectionState),
		Names:             make(map[string]*GroupNameProposal),
		LocalID:           localID,
		operationalGroups: make(map[string]bool),
		localWritten:      make(map[string]bool),
	}
}

// HoldFirstLocalRows holds back this process's first row of each group until
// every other member is OPERATIONAL from here, or until the given time,
// whichever comes first. After that the row is refreshed on every round.
//
// The engine's first beat round used to come one beat interval after its
// start, and that delay hid an agent's half-built row after a restart: by its
// first round its links were usually up again, so its peers never saw the
// KNOWN cells, and the group never lost mutual OPERATIONAL. Now that the first
// rounds come within seconds, the hold keeps that: good news goes out at once,
// news of a member that is not up yet no sooner than before. Without the hold
// a restart would degrade the group and invalidate its leader, and the
// re-election would follow a moment later.
func (gst *GossipStateTable) HoldFirstLocalRows(until time.Time) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.firstRowHoldUntil = until
}

// holdFirstLocalRows starts the hold when an engine starts: one beat interval
// from now, when the first beat round used to come.
func holdFirstLocalRows(ar *AgentRegistry, beatInterval time.Duration) {
	if ar == nil || ar.GossipStateTable == nil || beatInterval <= 0 {
		return
	}
	ar.GossipStateTable.HoldFirstLocalRows(time.Now().Add(beatInterval))
}

// refreshLocalRow writes our row for one group, unless it is held: the first
// row of the group, in the hold, with a member that is not OPERATIONAL from
// here. It reports whether it wrote the row.
func (gst *GossipStateTable) refreshLocalRow(groupHash string, peerStates map[string]string, zones []string, beatInterval uint32, now time.Time) bool {
	gst.mu.RLock()
	held := !gst.localWritten[groupHash] && now.Before(gst.firstRowHoldUntil)
	gst.mu.RUnlock()
	if held {
		for _, st := range peerStates {
			if st != AgentStateToString[AgentStateOperational] {
				lgGossip.Debug("holding the first local row until every member is OPERATIONAL",
					"group", shortHash(groupHash), "peerStates", peerStates)
				return false
			}
		}
	}
	gst.UpdateLocalState(groupHash, peerStates, zones, beatInterval)
	return true
}

// UpdateLocalState updates our own state entry for a group.
// This sets the Timestamp to now — only we update our own state.
// beatInterval is this agent's configured local heartbeat interval in
// seconds (multi-provider.syncengine.intervals.beatinterval). It rides
// in gossip so peers can display "Ns beats" alongside the AGE column
// and understand why a particular reporter detects degradation faster
// or slower than another.
func (gst *GossipStateTable) UpdateLocalState(groupHash string, peerStates map[string]string, zones []string, beatInterval uint32) {
	gst.mu.Lock()
	defer gst.mu.Unlock()

	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}

	gst.States[groupHash][gst.LocalID] = &MemberState{
		Identity:     gst.LocalID,
		PeerStates:   peerStates,
		Zones:        zones,
		Timestamp:    time.Now(),
		BeatInterval: beatInterval,
		// whole seconds on the wire, rounded up: a delay below a second is
		// not announced as none
		PropagationDelay: uint32((gst.propagationDelay + time.Second - 1) / time.Second),
	}
	if gst.localWritten == nil {
		gst.localWritten = make(map[string]bool)
	}
	gst.localWritten[groupHash] = true
}

// SetPropagationDelay sets this provider's propagation delay: how long a
// change needs to reach all of its nameservers
// (dnssec.kasp.propagation-delay). It rides in gossip, in our own row of
// every group, so that the leader of a zone knows how long the slowest of
// the zone's serving providers needs before a NOTIFY to the parent is worth
// sending (delegationNotifyWait).
func (gst *GossipStateTable) SetPropagationDelay(d time.Duration) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.propagationDelay = max(d, 0)
}

// PropagationDelay is this provider's own propagation delay, as set.
func (gst *GossipStateTable) PropagationDelay() time.Duration {
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	return gst.propagationDelay
}

// AnnouncedPropagationDelay is the propagation delay a member announces in
// its own row: the newest row of the member over all groups, since the value
// is the provider's and not a group's. Not known: the member has no row
// here, or announces none.
func (gst *GossipStateTable) AnnouncedPropagationDelay(identity string) (time.Duration, bool) {
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	var newest *MemberState
	for _, members := range gst.States {
		for id, ms := range members {
			if ms != nil && dns.Fqdn(id) == dns.Fqdn(identity) && (newest == nil || ms.Timestamp.After(newest.Timestamp)) {
				newest = ms
			}
		}
	}
	if newest == nil || newest.PropagationDelay == 0 {
		return 0, false
	}
	return time.Duration(newest.PropagationDelay) * time.Second, true
}

// MergeGossip merges gossip that from sent, about group, into the local
// state table, by the sender rule (the plan's 3.2, decision 10 and 35). It
// takes nothing for a group this agent does not have (group nil), or of
// which from is not a member. From a member that does not vote it takes
// that member's own row and nothing else. From the answer to a beat
// (fromAnswer, from the peer that was beaten, which nothing authenticates)
// it takes the rows only: no election record and no term, whoever the
// answer names. Election records come in every peer's own beats.
func (gst *GossipStateTable) MergeGossip(msg *GossipMessage, from string, group *ProviderGroup, fromAnswer bool) {
	if msg == nil || group == nil || group.GroupHash != msg.GroupHash || !isAmong(group.Members, AgentId(from)) {
		lgGossip.Debug("gossip not taken: the group is not known here, or the sender is not its member", "group", msgGroup(msg), "from", from)
		return
	}
	taken := *msg
	switch {
	case !isAmong(group.VotingMembers, AgentId(from)):
		// its own row only
		taken.Members = map[string]*MemberState{}
		for id, ms := range msg.Members {
			if isAmong([]string{id}, AgentId(from)) {
				taken.Members[id] = ms
			}
		}
		taken.Election, taken.GroupName = GroupElectionState{}, GroupNameProposal{}
	case fromAnswer:
		taken.Election, taken.GroupName = GroupElectionState{}, GroupNameProposal{}
	}
	// An agent that does not vote in the group is an observer (design 4.7)
	gst.mergeGossipAs(&taken, !isAmong(group.VotingMembers, AgentId(gst.LocalID)))
}

// observerTakes: an observer of a group, an agent that does not vote in it,
// takes an election record with a term at or below the one it holds once
// the lease it holds has run out (step 8, design 4.7): voting members that
// have all restarted elect at term 1 again. The same term is news when it
// names another leader or a later end of the lease. A voting member never
// takes a lower term. The lease's end is the telling agent's clock: a clock
// that is off moves the moment by as much.
func observerTakes(observer bool, rec GroupElectionState, heldTerm uint64, heldLeader string, heldExpiry time.Time, now time.Time) bool {
	if !observer || !now.After(heldExpiry) {
		return false
	}
	switch {
	case uint64(rec.Term) < heldTerm:
		return true
	case uint64(rec.Term) == heldTerm:
		return rec.Leader != heldLeader || rec.LeaderExpiry.After(heldExpiry)
	}
	return false
}

func msgGroup(msg *GossipMessage) string {
	if msg == nil {
		return ""
	}
	return msg.GroupHash
}

// mergeGossip merges gossip into the local state table as it is, with no
// rule of its own, as a voting member does. For each member's state entry,
// keep the one with the latest timestamp.
func (gst *GossipStateTable) mergeGossip(msg *GossipMessage) {
	gst.mergeGossipAs(msg, false)
}

// mergeGossipAs is mergeGossip for an agent that is, or is not, an observer
// of the group (observerTakes).
func (gst *GossipStateTable) mergeGossipAs(msg *GossipMessage, observer bool) {
	var electionCallback func(string, GroupElectionState)
	var electionHash string
	var electionState GroupElectionState

	gst.mu.Lock()

	groupHash := msg.GroupHash

	// Merge member states
	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}
	for id, remote := range msg.Members {
		if remote == nil {
			// a decoded beat may carry a null member
			continue
		}
		local, exists := gst.States[groupHash][id]
		if !exists || remote.Timestamp.After(local.Timestamp) {
			gst.States[groupHash][id] = deepCopyMemberState(remote)
		}
	}

	// Merge election state (higher term wins; an observer also takes a
	// lower or the same term once the lease it holds has run out). A record
	// without a leader is no election's result. Stored, it would stand for
	// its term and keep out the result that follows it, which is of the same
	// term (#154).
	if msg.Election.Term > 0 && msg.Election.Leader != "" {
		existing := gst.Elections[groupHash]
		if existing == nil || msg.Election.Term > existing.Term ||
			observerTakes(observer, msg.Election, uint64(existing.Term), existing.Leader, existing.LeaderExpiry, time.Now()) {
			elCopy := msg.Election
			gst.Elections[groupHash] = &elCopy
			if gst.onElectionUpdate != nil {
				electionCallback = gst.onElectionUpdate
				electionHash = groupHash
				electionState = elCopy
			}
		}
	}

	// Merge group name proposal (earliest ProposedAt wins)
	if msg.GroupName.Name != "" {
		existing := gst.Names[groupHash]
		if existing == nil || msg.GroupName.ProposedAt.Before(existing.ProposedAt) {
			nameCopy := msg.GroupName
			gst.Names[groupHash] = &nameCopy
		}
	}

	gst.mu.Unlock()

	// Invoke callback outside the lock to avoid deadlocks
	if electionCallback != nil {
		electionCallback(electionHash, electionState)
	}
}

// BuildGossipForPeer builds gossip messages for all groups shared with a peer.
// Acquires pgm.mu first, copies needed data, releases it, then takes gst.mu:
// the two are never held together, here or in RefreshLocalStates.
func (gst *GossipStateTable) BuildGossipForPeer(peerID string, pgm *ProviderGroupManager, lem ...*LeaderElectionManager) []GossipMessage {
	if pgm == nil {
		return nil
	}

	// Snapshot group metadata under pgm lock only
	type groupInfo struct {
		hash         string
		members      []string
		nameProposal *GroupNameProposal
	}
	pgm.mu.RLock()
	groups := make([]groupInfo, 0, len(pgm.Groups))
	for hash, pg := range pgm.Groups {
		gi := groupInfo{hash: hash, members: pg.Members}
		if pg.NameProposal != nil {
			np := *pg.NameProposal
			gi.nameProposal = &np
		}
		groups = append(groups, gi)
	}
	pgm.mu.RUnlock()

	// Now build messages under gst lock only
	gst.mu.RLock()
	defer gst.mu.RUnlock()

	var messages []GossipMessage

	for _, gi := range groups {
		localInGroup := false
		peerInGroup := false
		for _, member := range gi.members {
			if member == gst.LocalID {
				localInGroup = true
			}
			if member == peerID {
				peerInGroup = true
			}
		}
		if !localInGroup || !peerInGroup {
			lgGossip.Debug("BuildGossipForPeer: skipping group",
				"group", shortHash(gi.hash), "peerID", peerID,
				"localID", gst.LocalID, "members", gi.members,
				"localInGroup", localInGroup, "peerInGroup", peerInGroup)
			continue
		}

		msg := GossipMessage{
			GroupHash: gi.hash,
			Members:   make(map[string]*MemberState),
		}

		// Deep-copy member states for outgoing message
		if groupStates, ok := gst.States[gi.hash]; ok {
			for id, state := range groupStates {
				msg.Members[id] = deepCopyMemberState(state)
			}
		}

		// Include election state. The member's own word comes first: a term
		// that is decided (GroupElectionForGossip). With an election of its
		// own that is not decided it tells nothing, and passes on no record
		// heard from a peer either: it may have invalidated that very leader.
		// Only a member with no election of its own passes on what it heard.
		passOn := true
		if len(lem) > 0 && lem[0] != nil {
			es, decided, known := lem[0].GroupElectionForGossip(gi.hash)
			if decided {
				msg.Election = es
			}
			passOn = !known
		}
		if passOn {
			if el, ok := gst.Elections[gi.hash]; ok {
				msg.Election = *el
			}
		}

		// Include best group name proposal
		if name, ok := gst.Names[gi.hash]; ok {
			msg.GroupName = *name
		} else if gi.nameProposal != nil {
			msg.GroupName = *gi.nameProposal
		}

		lgGossip.Debug("BuildGossipForPeer: including group",
			"group", shortHash(gi.hash), "peerID", peerID, "memberStates", len(msg.Members))
		messages = append(messages, msg)
	}

	return messages
}

// GetGroupState returns a deep copy of the state matrix for a group.
func (gst *GossipStateTable) GetGroupState(groupHash string) (map[string]*MemberState, *GroupElectionState, *GroupNameProposal) {
	gst.mu.RLock()
	defer gst.mu.RUnlock()

	// Deep copy member states
	var statesCopy map[string]*MemberState
	if src := gst.States[groupHash]; src != nil {
		statesCopy = make(map[string]*MemberState, len(src))
		for k, ms := range src {
			cp := *ms
			cp.PeerStates = make(map[string]string, len(ms.PeerStates))
			for pk, pv := range ms.PeerStates {
				cp.PeerStates[pk] = pv
			}
			cp.Zones = append([]string(nil), ms.Zones...)
			statesCopy[k] = &cp
		}
	}

	// Shallow copy election and name (scalar + time fields)
	var electionCopy *GroupElectionState
	if e := gst.Elections[groupHash]; e != nil {
		ec := *e
		electionCopy = &ec
	}
	var nameCopy *GroupNameProposal
	if n := gst.Names[groupHash]; n != nil {
		nc := *n
		nameCopy = &nc
	}

	return statesCopy, electionCopy, nameCopy
}

func (gst *GossipStateTable) SetOnGroupOperational(fn func(groupHash string)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onGroupOperational = fn
}

func (gst *GossipStateTable) SetOnGroupDegraded(fn func(groupHash string)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onGroupDegraded = fn
}

func (gst *GossipStateTable) SetOnElectionUpdate(fn func(groupHash string, state GroupElectionState)) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	gst.onElectionUpdate = fn
}

// forgetGroup is the word that a provider group is gone: its last zone has
// left it. The table forgets what would stand in the way of the group if it
// comes back. That it was mutually OPERATIONAL: a group's election is called
// when it becomes so, and a group still marked would come back without one.
// And the election record: a group that comes back starts its terms again,
// and the record of a higher term would keep its results out. The members'
// rows stay: beats bring newer ones.
func (gst *GossipStateTable) forgetGroup(groupHash string) {
	gst.mu.Lock()
	defer gst.mu.Unlock()
	delete(gst.operationalGroups, groupHash)
	delete(gst.Elections, groupHash)
}

// CheckGroupState checks if all cells in the NxN matrix for a group are
// OPERATIONAL. Its callers pass the group's voting members (step 8, design
// 4.3): an auditor that is down holds no election back, and does not take a
// leader's group out of mutual OPERATIONAL. With one voting member, its own
// row opens the gate.
func (gst *GossipStateTable) CheckGroupState(groupHash string, expectedMembers []string) {
	gst.mu.Lock()

	groupStates := gst.States[groupHash]
	allOperational := true

	if len(groupStates) < len(expectedMembers) {
		allOperational = false
	} else {
		for _, member := range expectedMembers {
			ms, ok := groupStates[member]
			if !ok {
				allOperational = false
				break
			}
			for _, peer := range expectedMembers {
				if peer == member {
					continue
				}
				state, ok := ms.PeerStates[peer]
				if !ok || state != AgentStateToString[AgentStateOperational] {
					allOperational = false
					break
				}
			}
			if !allOperational {
				break
			}
		}
	}

	wasOperational := gst.operationalGroups[groupHash]
	gst.operationalGroups[groupHash] = allOperational

	// Capture callbacks before releasing lock
	onOp := gst.onGroupOperational
	onDeg := gst.onGroupDegraded
	gst.mu.Unlock()

	if allOperational && !wasOperational {
		lgGossip.Info("group reached mutual OPERATIONAL", "group", shortHash(groupHash))
		if onOp != nil {
			onOp(groupHash)
		}
	} else if !allOperational && wasOperational {
		lgGossip.Info("group lost mutual OPERATIONAL", "group", shortHash(groupHash))
		if onDeg != nil {
			onDeg(groupHash)
		}
	}
}

// RefreshLocalStates updates our local state entries for all groups
// based on current agent registry state.
func (gst *GossipStateTable) RefreshLocalStates(ar *AgentRegistry, pgm *ProviderGroupManager) {
	if ar == nil || pgm == nil {
		return
	}

	// The groups are copied out and the manager's lock is free while the rows
	// are built and written: what is called from here takes the locks of the
	// peers, of the zones and of this table, and a recompute of the groups
	// must not wait for any of them with the manager's readers behind it
	// (tdns-mp #180).
	now := time.Now()
	for _, pg := range pgm.GetGroups() {
		hash := pg.GroupHash
		// Build our peer states for this group
		peerStates := make(map[string]string)
		var zones []string

		for _, member := range pg.Members {
			if member == gst.LocalID {
				continue
			}
			// Look up agent state
			agent, exists := ar.S.Get(AgentId(member))
			if !exists {
				peerStates[member] = AgentStateToString[AgentStateNeeded]
				continue
			}
			state := ar.effectiveAgentState(agent.ID)
			peerStates[member] = AgentStateToString[state]
			lgGossip.Debug("RefreshLocalStates peer", "group", shortHash(hash),
				"peer", member, "state", AgentStateToString[state], "ptr", fmt.Sprintf("%p", agent))
		}

		// Zones this member serves
		for _, z := range pg.Zones {
			zones = append(zones, string(z))
		}

		// Our local heartbeat interval — included in the gossiped
		// MemberState so other agents can display per-reporter beat
		// frequency alongside the AGE column.
		beatInterval := ar.LocalAgent.Remote.BeatInterval

		lgGossip.Debug("RefreshLocalStates", "group", shortHash(hash),
			"localID", gst.LocalID, "peerStates", peerStates, "zones", zones, "beatInterval", beatInterval)
		gst.refreshLocalRow(hash, peerStates, zones, beatInterval, now)
	}
}
