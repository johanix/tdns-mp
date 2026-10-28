/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"fmt"
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
	// DnssecValidationNotEnforced is set when this member's resolver takes data it
	// could not validate, peer discovery included
	// (imrengine.require-dnssec-validation: false).
	DnssecValidationNotEnforced bool `json:"dnssec_validation_not_enforced,omitempty"`
	// PeerChains is the DNSSEC verdict on the discovery data of each peer in
	// PeerStates whose chain is not secure: "insecure" or "bogus". A peer
	// whose chain is secure, or not known, is not in it. The state in
	// PeerStates says what this member did with the data: NEEDED when it
	// refused it, OPERATIONAL when it took it with validation not enforced.
	PeerChains map[string]string `json:"peer_chains,omitempty"`

	// The row of the stamp entry (StampGroupHash) carries what its sender
	// tells of its zones' instructions, by zone (design rule 4), with the
	// epoch of its start and the sequence of the telling within it, its
	// provider's own nameserver names, and whether payload encryption is on
	// at the sender. A group's rows carry none of it.
	Instr       map[string]InstrStamp `json:"instr,omitempty"`
	Epoch       uint64                `json:"epoch,omitempty"`
	Seq         uint64                `json:"seq,omitempty"`
	Nameservers []string              `json:"nameservers,omitempty"`
	Crypto      bool                  `json:"crypto,omitempty"`
}

// StampGroupHash is the group hash of the stamp entry, reserved: no group's
// hash is empty. Its one row is its sender's own, and it is never merged as
// a group (plan decision 30).
const StampGroupHash = ""

// SerialDigest names a set of the owner's instructions: its serial, checked
// by its digest (design rule 2).
type SerialDigest struct {
	Serial uint32 `json:"serial"`
	Digest string `json:"digest"`
}

func (sd SerialDigest) String() string { return fmt.Sprintf("%d (%s)", sd.Serial, sd.Digest) }

// Thaw is a thaw's pair of serials, from N to V (design 3.2).
type Thaw struct {
	From SerialDigest `json:"from"`
	To   SerialDigest `json:"to"`
}

// InstrStamp is what an agent tells of one zone's instructions (design rule
// 4, plan S5a): its active serial, its newest and the serial it agrees on,
// each with its digest, whether it refuses its newest and why, an owner
// error, whether its provider has a key rollover under way, whether its
// signer has confirmed the hold (plan S6), and the last thaw it heard. Known
// is false while it knows no active serial.
type InstrStamp struct {
	Active         uint32 `json:"active"`
	ActiveDigest   string `json:"active_digest"`
	Newest         uint32 `json:"newest"`
	NewestDigest   string `json:"newest_digest"`
	Agreeing       uint32 `json:"agreeing,omitempty"`
	AgreeingDigest string `json:"agreeing_digest,omitempty"`
	Known          bool   `json:"known"`
	Refused        string `json:"refused,omitempty"` // the judge's first code
	Error          string `json:"error,omitempty"`   // the owner error
	Rollover       bool   `json:"rollover,omitempty"`
	Hold           bool   `json:"hold,omitempty"` // its signer has confirmed the hold since it held the serial agreed on
	// WaitsOn: the other signers whose confirmations the provider's
	// rollover under way misses, by its signer's inventory (plan S11).
	WaitsOn []string `json:"waits_on,omitempty"`
	Thaw    *Thaw    `json:"thaw,omitempty"`
}

// MsgStamp is the stamp a message or a confirmation carries (plan S5b): its
// sender's telling of the message's zone, with the epoch and the sequence
// that order it among all of the sender's stamps, its beats' included.
type MsgStamp struct {
	Epoch uint64 `json:"epoch"`
	Seq   uint64 `json:"seq"`
	InstrStamp
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
