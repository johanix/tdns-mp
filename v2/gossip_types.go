/*
 * Type definitions for the gossip protocol, provider groups and leader
 * election: the state table, the group manager and their messages.
 */

package tdnsmp

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
)

// --- Gossip wire types: defined once in package hsync (cleanup step 6) ---

// GossipMessage carries gossip state for one provider group. Included in
// beats between agents that share group membership.
type GossipMessage = hsync.GossipMessage

// MemberState is one member's view of all other members in the group.
// Only the member itself updates its own MemberState (sets Timestamp);
// other agents propagate it via gossip without modification.
type MemberState = hsync.MemberState

// GroupElectionState carries election state for a provider group.
type GroupElectionState = hsync.GroupElectionState

// GroupNameProposal is a name proposed by a provider for a group.
type GroupNameProposal = hsync.GroupNameProposal

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
	// firstRowHoldUntil: until then, a group's first local row is written
	// only once every other member is OPERATIONAL from here
	// (HoldFirstLocalRows). Zero: no hold.
	firstRowHoldUntil time.Time
	// localWritten: the groups this process has written its own row for.
	localWritten map[string]bool
	// propagationDelay: this provider's propagation delay, announced in our
	// own row of every group (SetPropagationDelay). Zero: nothing announced.
	propagationDelay time.Duration
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
	GroupHash string     // truncated SHA-256 of sorted member identities
	Name      string     // human-friendly name (resolved via naming protocol)
	Members   []string   // sorted provider identities (FQDNs) — all HSYNC3 participants regardless of role
	Zones     []ZoneName // zones served by this exact set of providers
	// VotingMembers is the subset of Members that may participate
	// in leader elections — derived from union(HSYNCPARAM.signers,
	// HSYNCPARAM.servers) translated through HSYNC3 labels to
	// identities. Non-voting roles (e.g. auditors) appear in
	// Members but not here. Quorum computations and initiator
	// selection MUST use VotingMembers, not Members.
	VotingMembers []string
	NameProposal  *GroupNameProposal // our proposal for this group's name
}

// ProviderGroupManager manages provider group computation and naming.
//
// Locking: mu is held only to read or replace what it guards, and nothing is
// called with it held. A caller that needs the groups for a call into the
// gossip table or the election manager copies them out first (GetGroups,
// GetGroup): those call back into the manager, and a second read of mu on a
// goroutine that holds one already blocks for good once a recompute is
// waiting for the write lock in between (tdns-mp #180).
type ProviderGroupManager struct {
	mu      sync.RWMutex
	Groups  map[string]*ProviderGroup // key: group hash
	LocalID string                    // our own identity
	// recomputeMu serialises RecomputeGroups, from its scan of the zones to
	// the last word of what changed. It is not mu, which the readers of the
	// groups need while a scan runs.
	recomputeMu sync.Mutex
	// scansBegun counts the scans of the zones that have begun, and
	// installedScan is the number of the scan whose map is in place (guarded
	// by recomputeMu): a recompute that finds a scan in place that began
	// after it was called has nothing to add (RecomputeGroups).
	scansBegun    atomic.Uint64
	installedScan uint64
	// afterScan, when set, is called by a recompute between its scan and
	// its swap. Tests only.
	afterScan func()
	// onZoneJoinedGroup is told of each zone a recompute has put into a
	// group it was not in before (SetOnZoneJoinedGroup). Guarded by mu.
	onZoneJoinedGroup func(zone ZoneName, from, to string)
	// onGroupGone is told of each group a recompute has dropped: its last
	// zone has left it (SetOnGroupGone). Guarded by mu.
	onGroupGone func(groupHash string)
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
	RetryTimer    *time.Timer // the retry after an aborted group election (retryGroupElection)
	askedTerm     uint64      // the term in which this agent, leading, last asked what an election's winner asks (once per term)
	// leaderTerm is the term Leader was elected in. Term runs ahead of it
	// while an election is running and after one that was aborted: the
	// leader then is still the one of the term before.
	leaderTerm uint64
	// leadStart names this agent's present lead: a number given when the
	// lead began, unique in this process across every election, so that a
	// lead in one group is never taken for a lead in another, and a lead at
	// term 0 (a lone voter's self-election) is a lead. A renewal, which
	// names this agent again while its lease runs, keeps it; a lead that
	// follows another agent's, an invalidated or a lapsed one gets a new
	// one. Zero while another agent leads (noteLeaderLocked).
	leadStart uint64
	// holdStart names this agent's present hold of the lead: the lead
	// (leadStart) that began it. A renewal keeps it, and so does every new
	// lead this agent takes while no other agent has led in between: an
	// election after an invalidation that names it again, or one after its
	// lease lapsed. An invalidation keeps it too: the next agent named leads
	// after it. Another agent named leader ends the hold (onLeadLost). Zero
	// while another agent leads (noteLeaderLocked).
	holdStart uint64
	// gone: the provider group of this election is gone, and the manager
	// has dropped the entry (groupGone). Nothing starts on it any more.
	gone bool

	// Votes that arrived for a term this member has not joined yet: a VOTE
	// can overtake the CALL it answers, since the two come from different
	// members. Only the newest such term is kept, and joining it applies
	// them (keepEarlyVote, takeEarlyVotes).
	earlyTerm  uint64
	earlyVotes map[AgentId]uint32
}

// LeaderElectionManager coordinates leader election across all zones.
// Supports both per-zone elections (legacy) and per-group elections.
// When a ProviderGroupManager is set, elections are per-group and the leader
// covers all zones in the group. IsLeader checks group membership first.
type LeaderElectionManager struct {
	// leads numbers this agent's leads in this process, across every
	// election, the groups' and the zones' own (noteLeaderLocked): two
	// leads never share a number.
	leads                atomic.Uint64
	mu                   sync.RWMutex
	elections            map[ZoneName]*LeaderElection
	pendingElections     map[ZoneName]bool          // zones where election was deferred (peers not yet operational)
	groupElections       map[string]*LeaderElection // key: group hash
	localID              AgentId
	leaderTTL            time.Duration
	broadcastFunc        func(zone ZoneName, rfiType string, records map[string][]string) error
	operationalPeersFunc func(zone ZoneName) int   // returns count of operational peers for a zone
	configuredPeersFunc  func(zone ZoneName) int   // returns count of configured peers for a zone
	onLeaderElected      func(zone ZoneName) error // called when local agent wins election
	onZoneJoined         func(zone ZoneName) error // called when a zone joins a group the local agent already leads
	onZoneRegrouped      func(zone ZoneName)       // called when a zone enters a provider group, whoever leads it (SetOnZoneRegrouped)
	onLeaderNamed        func()                    // called when an election names a leader, this agent or another (SetOnLeaderNamed)
	onLeadLost           func(hold uint64)         // called when another agent takes a lead this agent held (SetOnLeadLost)
	keySetups            sync.Map                  // ZoneName -> *sync.Mutex: one SIG(0) key setup per zone at a time (inKeySetup)
	hooks                sync.WaitGroup            // the callbacks that run in goroutines of their own (onLeadLost, onLeaderNamed), until each has returned
	providerGroupMgr     *ProviderGroupManager
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
	Zone          ZoneName  `json:"zone"`
	Leader        AgentId   `json:"leader"`
	LeaderExpiry  time.Time `json:"leader_expiry"`
	ElectionTerm  uint64    `json:"election_term"`
	IsLeader      bool      `json:"is_leader"`
	KeyAlgorithm  string    `json:"key_algorithm,omitempty"`
	KeyID         uint16    `json:"key_id,omitempty"`
	KeyRR         string    `json:"key_rr,omitempty"`
	ApexPublished bool      `json:"apex_published"`
	// ApexKeys: how many KEY records the apex carries. More than one is no
	// zone key at all (step 7b): an operator has to leave one.
	ApexKeys        int               `json:"apex_keys,omitempty"`
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
	CatchUp         *CatchUpStatus    `json:"catch_up,omitempty"`
	// ParentSync says that the leader's sync with the parent is held until
	// the zone is caught up, or is owed and waits for room in the delegation
	// sync queue (step 5). Empty when neither.
	ParentSync string `json:"parent_sync,omitempty"`
	// KeyHold: the leader's sync waits for the zone's SIG(0) key, and why
	// (step 7b). Empty when it does not.
	KeyHold string `json:"key_hold,omitempty"`
	// DSSet is "known", or "unknown, waiting for" whom, for a zone that
	// names a signer. Empty for one that names none.
	DSSet string `json:"ds_set,omitempty"`
}
