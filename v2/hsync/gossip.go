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
	// PropagationDelay is how long, in seconds, a change needs to reach all
	// of this member's nameservers. Zero: the member does not say (an agent
	// that serves nothing, or one from before the field).
	PropagationDelay uint32 `json:"propagation_delay,omitempty"`
	// DnssecValidationOff is set when this member's resolver takes data it
	// could not validate, peer discovery included
	// (imrengine.require-dnssec-validation: false).
	DnssecValidationOff bool `json:"dnssec_validation_off,omitempty"`
	// PeerChains is the DNSSEC verdict on the discovery data of each peer in
	// PeerStates whose chain is not secure: "insecure" or "bogus". A peer
	// whose chain is secure, or not known, is not in it. The state in
	// PeerStates says what this member did with the data: NEEDED when it
	// refused it, OPERATIONAL when it took it with validation off.
	PeerChains map[string]string `json:"peer_chains,omitempty"`
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
