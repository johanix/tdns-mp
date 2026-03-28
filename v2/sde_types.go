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
	Status         string // "ok", "partial", "error"
	Message        string
	AppliedRecords []string
	RemovedRecords []string // RR strings confirmed as removed by combiner
	RejectedItems  []RejectedItemInfo
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
// SyncRequest and SyncResponse stay as aliases because the tdns refresh
// callback (MPPostRefresh in tdns/v2/hsync_utils.go) sends tdns.SyncRequest
// to zd.SyncQ, and HsyncEngine in tdns-mp reads from the same channel.
type SyncRequest = tdns.SyncRequest
type SyncResponse = tdns.SyncResponse

// SyncStatus stays as alias for same reason as SyncRequest.
type SyncStatus = tdns.SyncStatus

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

// HsyncStatus stays as alias — embedded in tdns.SyncRequest which crosses
// the tdns/tdns-mp boundary via the shared SyncQ channel.
type HsyncStatus = tdns.HsyncStatus

// --- From hsync_utils.go ---

// DnskeyStatus stays as alias — same reason as HsyncStatus.
type DnskeyStatus = tdns.DnskeyStatus
