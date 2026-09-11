/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
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
