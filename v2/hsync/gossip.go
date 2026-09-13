/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"time"
)

// The gossip wire types have one definition, here (cleanup plan, step 6);
// package tdnsmp aliases them. The JSON tags are the wire.

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
