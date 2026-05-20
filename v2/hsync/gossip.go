/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"sync"
	"time"
)

// GossipMessage carries gossip state for one provider group.
type GossipMessage struct {
	GroupHash string                  `json:"group_hash"`
	GroupName GroupNameProposal       `json:"group_name"`
	Members   map[string]*MemberState `json:"members"`
	Election  GroupElectionState      `json:"election"`
}

// MemberState is one member's view of peers in a group.
type MemberState struct {
	Identity     string            `json:"identity"`
	PeerStates   map[string]string `json:"peer_states"`
	Zones        []string          `json:"zones"`
	Timestamp    time.Time         `json:"timestamp"`
	BeatInterval uint32            `json:"beat_interval,omitempty"`
}

// GroupElectionState carries election state for a provider group.
type GroupElectionState struct {
	Leader       string    `json:"leader,omitempty"`
	Term         uint32    `json:"term,omitempty"`
	LeaderExpiry time.Time `json:"leader_expiry,omitempty"`
}

// GroupNameProposal is a proposed human-friendly group name.
type GroupNameProposal struct {
	GroupHash  string    `json:"group_hash"`
	Name       string    `json:"name"`
	Proposer   string    `json:"proposer"`
	ProposedAt time.Time `json:"proposed_at"`
}

// GossipStateTable manages the NxN state matrix for provider groups.
type GossipStateTable struct {
	mu                 sync.RWMutex
	States             map[string]map[string]*MemberState
	Elections          map[string]*GroupElectionState
	Names              map[string]*GroupNameProposal
	LocalID            string
	onGroupOperational func(groupHash string)
	onGroupDegraded    func(groupHash string)
	onElectionUpdate   func(groupHash string, state GroupElectionState)
	operationalGroups  map[string]bool
}

func NewGossipStateTable(localID string) *GossipStateTable {
	return &GossipStateTable{
		States:            make(map[string]map[string]*MemberState),
		Elections:         make(map[string]*GroupElectionState),
		Names:             make(map[string]*GroupNameProposal),
		LocalID:           localID,
		operationalGroups: make(map[string]bool),
	}
}

func deepCopyMemberState(src *MemberState) *MemberState {
	dst := &MemberState{
		Identity:     src.Identity,
		Timestamp:    src.Timestamp,
		BeatInterval: src.BeatInterval,
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
	}
}

func (gst *GossipStateTable) MergeGossip(msg *GossipMessage) {
	var electionCallback func(string, GroupElectionState)
	var electionHash string
	var electionState GroupElectionState

	gst.mu.Lock()
	groupHash := msg.GroupHash
	if gst.States[groupHash] == nil {
		gst.States[groupHash] = make(map[string]*MemberState)
	}
	for id, remote := range msg.Members {
		local, exists := gst.States[groupHash][id]
		if !exists || remote.Timestamp.After(local.Timestamp) {
			gst.States[groupHash][id] = deepCopyMemberState(remote)
		}
	}
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
	if msg.GroupName.Name != "" {
		existing := gst.Names[groupHash]
		if existing == nil || msg.GroupName.ProposedAt.Before(existing.ProposedAt) {
			nameCopy := msg.GroupName
			gst.Names[groupHash] = &nameCopy
		}
	}
	gst.mu.Unlock()

	if electionCallback != nil {
		electionCallback(electionHash, electionState)
	}
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
				if !ok || state != StateToString[PeerStateOperational] {
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
	onOp := gst.onGroupOperational
	onDeg := gst.onGroupDegraded
	gst.mu.Unlock()

	if allOperational && !wasOperational && onOp != nil {
		onOp(groupHash)
	} else if !allOperational && wasOperational && onDeg != nil {
		onDeg(groupHash)
	}
}

func (gst *GossipStateTable) RefreshLocalStates(reg *Registry, pgm ProviderGroupLookup, beatInterval uint32) {
	if reg == nil || pgm == nil {
		return
	}
	for _, pg := range pgm.Groups() {
		peerStates := make(map[string]string)
		var zones []string
		for _, member := range pg.Members {
			if member == gst.LocalID {
				continue
			}
			peer, exists := reg.S.Get(PeerID(member))
			if !exists {
				peerStates[member] = StateToString[PeerStateNeeded]
				continue
			}
			peer.Mu.RLock()
			state := peer.EffectiveState()
			peer.Mu.RUnlock()
			peerStates[member] = StateToString[state]
		}
		for _, z := range pg.Zones {
			zones = append(zones, string(z))
		}
		gst.UpdateLocalState(pg.GroupHash, peerStates, zones, beatInterval)
	}
}

func (gst *GossipStateTable) BuildGossipForPeer(peerID string, pgm ProviderGroupLookup, elections ElectionStateLookup) []GossipMessage {
	if pgm == nil {
		return nil
	}
	type groupInfo struct {
		hash         string
		members      []string
		nameProposal *GroupNameProposal
	}
	var groups []groupInfo
	for _, pg := range pgm.Groups() {
		gi := groupInfo{hash: pg.GroupHash, members: pg.Members}
		groups = append(groups, gi)
	}

	gst.mu.RLock()
	defer gst.mu.RUnlock()

	var messages []GossipMessage
	for _, gi := range groups {
		localInGroup, peerInGroup := false, false
		for _, member := range gi.members {
			if member == gst.LocalID {
				localInGroup = true
			}
			if member == peerID {
				peerInGroup = true
			}
		}
		if !localInGroup || !peerInGroup {
			continue
		}
		msg := GossipMessage{
			GroupHash: gi.hash,
			Members:   make(map[string]*MemberState),
		}
		if groupStates, ok := gst.States[gi.hash]; ok {
			for id, state := range groupStates {
				msg.Members[id] = deepCopyMemberState(state)
			}
		}
		if elections != nil {
			es := elections.GetGroupElectionState(gi.hash)
			if es.Term > 0 {
				msg.Election = es
			}
		}
		if el, ok := gst.Elections[gi.hash]; ok && msg.Election.Term == 0 {
			msg.Election = *el
		}
		if name, ok := gst.Names[gi.hash]; ok {
			msg.GroupName = *name
		}
		messages = append(messages, msg)
	}
	return messages
}
