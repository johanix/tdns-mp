package tdnsmp

import (
	"fmt"
	"log/slog"
	"time"

	tdns "github.com/johanix/tdns/v2"
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
		Identity:  src.Identity,
		Timestamp: src.Timestamp,
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
	}
}

// UpdateLocalState updates our own state entry for a group.
// This sets the Timestamp to now — only we update our own state.
func (gst *GossipStateTable) UpdateLocalState(groupHash string, peerStates map[string]string, zones []string) {
	gst.mu.Lock()
	defer gst.mu.Unlock()

	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}

	gst.States[groupHash][gst.LocalID] = &MemberState{
		Identity:   gst.LocalID,
		PeerStates: peerStates,
		Zones:      zones,
		Timestamp:  time.Now(),
	}
}

// MergeGossip merges received gossip into the local state table.
// For each member's state entry, keep the one with the latest timestamp.
func (gst *GossipStateTable) MergeGossip(msg *GossipMessage) {
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
		local, exists := gst.States[groupHash][id]
		if !exists || remote.Timestamp.After(local.Timestamp) {
			gst.States[groupHash][id] = deepCopyMemberState(remote)
		}
	}

	// Merge election state (higher term wins)
	if msg.Election.Term > 0 {
		existing := gst.Elections[groupHash]
		if existing == nil || msg.Election.Term > existing.Term {
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
// Acquires pgm.mu first, copies needed data, releases it, then takes gst.mu
// to avoid deadlock with RefreshLocalStates (which takes pgm.mu then gst.mu).
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

		// Include election state — prefer live state from LeaderElectionManager
		electionIncluded := false
		if len(lem) > 0 && lem[0] != nil {
			es := lem[0].GetGroupElectionState(gi.hash)
			if es.Term > 0 {
				msg.Election = es
				electionIncluded = true
			}
		}
		if !electionIncluded {
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

// CheckGroupState checks if all cells in the NxN matrix for a group are OPERATIONAL.
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

	pgm.mu.RLock()
	defer pgm.mu.RUnlock()

	for hash, pg := range pgm.Groups {
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
			agent.Mu.RLock()
			state := agent.EffectiveState()
			agent.Mu.RUnlock()
			peerStates[member] = AgentStateToString[state]
			lgGossip.Debug("RefreshLocalStates peer", "group", shortHash(hash),
				"peer", member, "state", AgentStateToString[state], "ptr", fmt.Sprintf("%p", agent))
		}

		// Zones this member serves
		for _, z := range pg.Zones {
			zones = append(zones, string(z))
		}

		lgGossip.Debug("RefreshLocalStates", "group", shortHash(hash),
			"localID", gst.LocalID, "peerStates", peerStates, "zones", zones)
		gst.UpdateLocalState(hash, peerStates, zones)
	}
}
