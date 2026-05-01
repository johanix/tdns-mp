/*
 * Type definitions for gossip protocol, provider groups, and
 * leader election subsystems.
 * Copied from tdns/v2/gossip.go, provider_groups.go,
 * parentsync_leader.go.
 */

package tdnsmp

import (
	"sync"
	"time"
)

// --- From gossip.go ---

// GossipMessage carries gossip state for one provider group.
// Included in beats between agents that share group membership.
type GossipMessage struct {
	GroupHash string                  `json:"group_hash"`
	GroupName GroupNameProposal       `json:"group_name"`
	Members   map[string]*MemberState `json:"members"` // key: provider identity
	Election  GroupElectionState      `json:"election"`
}

// MemberState is one member's view of all other members in the group.
// Only the member itself updates its own MemberState (sets Timestamp).
// Other agents propagate it via gossip without modification.
type MemberState struct {
	Identity     string            `json:"identity"`
	PeerStates   map[string]string `json:"peer_states"`             // key: peer identity, value: state string
	Zones        []string          `json:"zones"`                   // zones this member serves in this group
	Timestamp    time.Time         `json:"timestamp"`               // set by the member itself
	BeatInterval uint32            `json:"beat_interval,omitempty"` // member's configured local beatinterval in seconds; zero from old agents that don't report it
}

// GroupElectionState carries election state for a provider group.
type GroupElectionState struct {
	Leader       string    `json:"leader,omitempty"` // identity of current leader
	Term         uint32    `json:"term,omitempty"`
	LeaderExpiry time.Time `json:"leader_expiry,omitempty"`
}

// GossipStateTable manages the NxN state matrix for all provider groups.
// Each entry is a MemberState keyed by (groupHash, memberIdentity).
type GossipStateTable struct {
	mu sync.RWMutex
	// key: group hash → member identity → MemberState
	States map[string]map[string]*MemberState
	// key: group hash → GroupElectionState
	Elections map[string]*GroupElectionState
	// key: group hash → GroupNameProposal (best proposal seen)
	Names map[string]*GroupNameProposal
	// Our identity
	LocalID string
	// Callbacks
	onGroupOperational func(groupHash string)
	onGroupDegraded    func(groupHash string)
	onElectionUpdate   func(groupHash string, state GroupElectionState)
	// Track which groups have fired operational callback
	operationalGroups map[string]bool
}

// --- From provider_groups.go ---

// ProviderGroup represents a set of providers that together serve a group of zones.
// The group is identified by a hash of the sorted member identities.
//
// Locking: read or modify any *ProviderGroup field only while
// holding pgm.mu (RLock for read, Lock for write). RecomputeGroups
// replaces map entries wholesale; ProposeGroupName mutates Name and
// NameProposal in place — so callers cannot assume the struct is
// immutable once stored. Snapshot fields under the lock.
type ProviderGroup struct {
	GroupHash    string             // truncated SHA-256 of sorted member identities
	Name         string             // human-friendly name (resolved via naming protocol)
	Members      []string           // sorted provider identities (FQDNs)
	Zones        []ZoneName         // zones served by this exact set of providers
	NameProposal *GroupNameProposal // our proposal for this group's name
}

// GroupNameProposal is a name proposed by a provider for a group.
type GroupNameProposal struct {
	GroupHash  string    `json:"group_hash"`
	Name       string    `json:"name"`
	Proposer   string    `json:"proposer"`    // provider identity that chose the name
	ProposedAt time.Time `json:"proposed_at"` // when the name was chosen
}

// ProviderGroupManager manages provider group computation and naming.
type ProviderGroupManager struct {
	mu      sync.RWMutex
	Groups  map[string]*ProviderGroup // key: group hash
	LocalID string                    // our own identity
}

// --- From parentsync_leader.go ---

// LeaderElection tracks the per-zone election state.
type LeaderElection struct {
	mu            sync.Mutex
	Zone          ZoneName
	Leader        AgentId
	LeaderExpiry  time.Time
	Active        bool
	Term          uint64
	MyVote        uint32
	Votes         map[AgentId]uint32
	Confirms      map[AgentId]AgentId
	ExpectedPeers int
	VoteTimer     *time.Timer
	ConfirmTimer  *time.Timer
	ReelectTimer  *time.Timer
}

// LeaderElectionManager coordinates leader election across all zones.
// Supports both per-zone elections (legacy) and per-group elections.
// When a ProviderGroupManager is set, elections are per-group and the leader
// covers all zones in the group. IsLeader checks group membership first.
type LeaderElectionManager struct {
	mu                    sync.RWMutex
	elections             map[ZoneName]*LeaderElection
	pendingElections      map[ZoneName]bool          // zones where election was deferred (peers not yet operational)
	groupElections        map[string]*LeaderElection // key: group hash
	pendingGroupElections map[string]bool            // group hashes waiting for OnGroupOperational
	localID               AgentId
	leaderTTL             time.Duration
	broadcastFunc         func(zone ZoneName, rfiType string, records map[string][]string) error
	operationalPeersFunc  func(zone ZoneName) int   // returns count of operational peers for a zone
	configuredPeersFunc   func(zone ZoneName) int   // returns count of configured peers for a zone
	onLeaderElected       func(zone ZoneName) error // called when local agent wins election
	providerGroupMgr      *ProviderGroupManager
}

// LeaderStatus holds the current leader status for a zone.
type LeaderStatus struct {
	Zone   ZoneName
	Leader AgentId
	IsSelf bool
	Term   uint64
	Expiry time.Time
}

// PeerSyncInfo describes a peer agent's sync status for a zone.
type PeerSyncInfo struct {
	Identity    AgentId `json:"identity"`
	State       string  `json:"state"`
	Transport   string  `json:"transport"`
	Operational bool    `json:"operational"`
}

// DsyncSchemeInfo describes a parent DSYNC sync scheme.
type DsyncSchemeInfo struct {
	Scheme string `json:"scheme"` // "UPDATE", "NOTIFY", etc.
	Type   string `json:"type"`   // "CDS", "CSYNC", "ANY", etc.
	Target string `json:"target"` // target host
	Port   uint16 `json:"port"`
}

// ParentSyncStatus holds on-demand status information about parent delegation sync for a zone.
type ParentSyncStatus struct {
	Zone            ZoneName          `json:"zone"`
	Leader          AgentId           `json:"leader"`
	LeaderExpiry    time.Time         `json:"leader_expiry"`
	ElectionTerm    uint64            `json:"election_term"`
	IsLeader        bool              `json:"is_leader"`
	KeyAlgorithm    string            `json:"key_algorithm,omitempty"`
	KeyID           uint16            `json:"key_id,omitempty"`
	KeyRR           string            `json:"key_rr,omitempty"`
	ApexPublished   bool              `json:"apex_published"`
	ParentState     uint8             `json:"parent_state"`
	ParentStateName string            `json:"parent_state_name,omitempty"`
	ChildNS         []string          `json:"child_ns,omitempty"`
	KeyPublication  map[string]bool   `json:"key_publication,omitempty"`
	LastChecked     time.Time         `json:"last_checked"`
	ParentZone      string            `json:"parent_zone,omitempty"`
	SyncSchemes     []DsyncSchemeInfo `json:"sync_schemes,omitempty"`
	ActiveScheme    string            `json:"active_scheme,omitempty"` // best scheme: "UPDATE", "NOTIFY", etc.
	CdsPublished    bool              `json:"cds_published"`
	CsyncPublished  bool              `json:"csync_published"`
	ZoneSigned      bool              `json:"zone_signed"`
	Peers           []PeerSyncInfo    `json:"peers,omitempty"`
}
