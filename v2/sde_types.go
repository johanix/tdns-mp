/*
 * Type definitions for SynchedDataEngine and related subsystems.
 * Copied from tdns/v2/syncheddataengine.go, hsyncengine.go,
 * agent_utils.go, zone_utils.go, hsync_utils.go.
 */

package tdnsmp

import (
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- From syncheddataengine.go ---

type SynchedDataUpdate struct {
	Zone              ZoneName
	AgentId           AgentId
	UpdateType        string // "local" or "remote"
	Update            *ZoneUpdate
	OriginatingDistID string   // Distribution ID from the originating agent (for remote updates)
	Force             bool     // Bypass dedup check (always send even if RR already present)
	SkipCombiner      bool     // Don't send to combiner (e.g. local DNSKEY changes — signer adds its own)
	DnskeyKeyTags     []uint16 // Key tags for DNSKEY propagation tracking (mpdist flow)
	Response          chan *AgentMsgResponse
}

type SynchedDataResponse struct {
	Zone        ZoneName
	AgentId     AgentId
	Time        time.Time
	Msg         string
	RfiResponse RfiData
	Error       bool
	ErrorMsg    string
}

type SynchedDataCmd struct {
	Cmd         string
	Zone        ZoneName
	TargetAgent AgentId // For "resync-targeted": send only to this agent
	Response    chan *SynchedDataCmdResponse
}

type SynchedDataCmdResponse struct {
	Cmd      string
	Msg      string
	Error    bool
	ErrorMsg string
	Zone     ZoneName
	ZDR      map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo
}

type ZoneDataRepo struct {
	Repo                  core.ConcurrentMap[ZoneName, *AgentRepo]
	Tracking              map[ZoneName]map[AgentId]map[uint16]*TrackedRRset
	mu                    sync.Mutex
	PendingRemoteConfirms map[string]*PendingRemoteConfirmation
}

type PendingRemoteConfirmation struct {
	OriginatingDistID string
	OriginatingSender string
	Zone              ZoneName
	CreatedAt         time.Time
}

type RemoteConfirmationDetail struct {
	OriginatingDistID string
	OriginatingSender string
	Zone              ZoneName
	Status            string
	Message           string
	AppliedRecords    []string
	RemovedRecords    []string
	RejectedItems     []RejectedItemInfo
	IgnoredRecords    []string
	Truncated         bool
}

type AgentRepo struct {
	Data core.ConcurrentMap[AgentId, *OwnerData]
}

// RRState represents the lifecycle state of a tracked RR.
type RRState uint8

const (
	RRStatePending        RRState = iota // Sent to combiner, awaiting confirmation
	RRStateAccepted                      // Combiner accepted
	RRStateRejected                      // Combiner rejected (see Reason)
	RRStatePendingRemoval                // Delete sent to combiner, awaiting confirmation
	RRStateRemoved                       // Combiner confirmed removal (audit trail)
	RRStateIgnored                       // Combiner persisted but did not apply (role-based filter)
)

func (s RRState) String() string {
	switch s {
	case RRStatePending:
		return "pending"
	case RRStateAccepted:
		return "accepted"
	case RRStateRejected:
		return "rejected"
	case RRStatePendingRemoval:
		return "pending-removal"
	case RRStateRemoved:
		return "removed"
	case RRStateIgnored:
		return "ignored"
	default:
		return "unknown"
	}
}

type RRConfirmation struct {
	Status    string    `json:"status"`           // "accepted", "rejected", "removed", "pending"
	Reason    string    `json:"reason,omitempty"` // rejection reason
	Timestamp time.Time `json:"timestamp"`
}

type TrackedRR struct {
	RR                 dns.RR
	State              RRState
	Reason             string // Rejection reason (empty unless rejected)
	DistributionID     string // Last distribution this RR was part of
	UpdatedAt          time.Time
	Confirmations      map[string]RRConfirmation // recipientID → per-recipient status
	ExpectedRecipients []string                  // Who must confirm before state transitions to accepted
}

type TrackedRRset struct {
	Tracked []TrackedRR
}

type ConfirmationDetail struct {
	DistributionID string
	Zone           ZoneName
	Source         string // Identifies the confirming peer (combiner ID or agent ID)
	Status         string // "ok", "partial", "error", "IGNORED"
	Message        string
	AppliedRecords []string
	RemovedRecords []string // RR strings confirmed as removed by combiner
	RejectedItems  []RejectedItemInfo
	IgnoredRecords []string // RR strings persisted but not applied (role-based filter)
	Truncated      bool
	Timestamp      time.Time
}

type RejectedItemInfo struct {
	Record string
	Reason string
}

type TrackedRRInfo struct {
	RR             string                    `json:"rr"`
	State          string                    `json:"state"`
	KeyState       string                    `json:"key_state,omitempty"`
	Reason         string                    `json:"reason,omitempty"`
	DistributionID string                    `json:"distribution_id"`
	UpdatedAt      string                    `json:"updated_at"`
	Confirmations  map[string]RRConfirmation `json:"confirmations,omitempty"`
}

// --- From hsyncengine.go ---
// SyncQ is owned by tdns-mp; SyncRequest uses *tdns.ZoneData for the embedded zone blob.
type SyncRequest struct {
	Command      string
	ZoneName     ZoneName
	ZoneData     *tdns.ZoneData
	SyncStatus   *HsyncStatus
	OldDnskeys   *core.RRset
	NewDnskeys   *core.RRset
	DnskeyStatus *DnskeyStatus
	Response     chan SyncResponse
}

type SyncResponse struct {
	Status   bool
	Error    bool
	ErrorMsg string
	Msg      string
}

type SyncStatus struct {
	Identity AgentId
	Agents   map[AgentId]*Agent
	Error    bool
	Response chan SyncStatus
}

type DeferredTask struct {
	Action      string
	Target      string
	ZoneName    string
	RetryCount  int
	MaxRetries  int
	LastAttempt time.Time
}

// --- From agent_utils.go ---

type ZoneAgentData struct {
	ZoneName      ZoneName
	Agents        []*Agent
	MyUpstream    AgentId
	MyDownstreams []AgentId
}

// --- From zone_utils.go ---

type HsyncStatus struct {
	Time         time.Time
	ZoneName     string
	Command      string
	Status       bool
	Error        bool
	ErrorMsg     string
	Msg          string
	HsyncAdds    []dns.RR
	HsyncRemoves []dns.RR
}

// --- From hsync_utils.go ---

type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR
	LocalRemoves     []dns.RR
	CurrentLocalKeys []dns.RR
}
