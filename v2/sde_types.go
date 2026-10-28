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
	OriginatingDistID string // Distribution ID from the originating agent (for remote updates)
	// OriginatingInstr is the originating agent's stamp of the zone, as its
	// message carried it (S5b); S8 judges a remote update by it.
	OriginatingInstr *MsgStamp
	Mechanism        string // The mechanism a remote update arrived on: its final confirmation's first choice of path
	// OriginatingTime is when the originating agent enqueued a remote
	// update: the wire timestamp, stable across the sender's retries. With
	// OriginatingDistID it orders REPLACEs from one agent (see
	// ZoneDataRepo.lastReplace).
	OriginatingTime time.Time
	// DeliveredBy is the sender of a remote update as the transport
	// established it, which the update's own word on where it comes from
	// (AgentId) is not. A CSYNC is taken from the zone's leader only, and
	// that is asked of this sender.
	DeliveredBy   AgentId
	Force         bool     // Bypass dedup check (always send even if RR already present)
	SkipCombiner  bool     // Don't send to combiner (e.g. local DNSKEY changes — signer adds its own)
	DnskeyKeyTags []uint16 // Key tags for DNSKEY propagation tracking (mpdist flow)
	// DnskeyRemovedKeyTags are those of DnskeyKeyTags the distribution
	// removes: their confirmation goes to the signer as "removed", the
	// others' as "propagated", so the signer knows which kind it answers.
	DnskeyRemovedKeyTags []uint16
	// KeyStatesChanged: what this provider says about its keys changed
	// (a state, a ds) with the DNSKEY set as it was; the REPLACE goes to
	// the other providers all the same, for the key states it carries.
	KeyStatesChanged bool
	// Resend: a distribution the signer's key lifecycle sends again
	// (#256). The update goes to the peers, tracked, even when the repo
	// already held it.
	Resend bool
	// Inventory: the signer's inventory brought this DNSKEY distribution.
	// It passes a freeze (plan S6): a rollover under way, or an emergency
	// one, as the signer starts no other.
	Inventory bool
	// replay: an owed change the release hands the engine again (plan S6);
	// owed: this agent's owed changes, which a delete is checked against
	// with the data (EvaluateUpdate).
	replay bool
	owed   []keptEntry
	// CatchUp: the update is the answer to a request for the zone's state
	// (the membership design, 5.4).
	CatchUp  *CatchUp `json:"catch_up,omitempty"`
	Response chan *AgentMsgResponse
	// staleTypes: the types whose replace the repo found older than the
	// one it has applied (noteReplaceOrigin). What those replaces say about
	// keys is not noted either (freshOperations). An add or a delete of the
	// same type in the same update is not stale: the repo applied it.
	staleTypes map[uint16]bool
}

// dropStaleOperations takes the operations the repo found stale out of the
// update, so that they go no further: not to the key states, and not to the
// combiner, which would put an older set back in the zone it publishes.
func (u *SynchedDataUpdate) dropStaleOperations() {
	if u.Update != nil && len(u.staleTypes) > 0 {
		u.Update.Operations = u.freshOperations()
	}
}

// staleOperations are the update's operations whose type the repo found
// stale. What the repo holds of them goes in the update's confirmation all
// the same: a newer message put it there, and the sender tracks its
// distribution by the records it lists.
func (u *SynchedDataUpdate) staleOperations() []core.RROperation {
	if u.Update == nil || len(u.staleTypes) == 0 {
		return nil
	}
	var out []core.RROperation
	for _, op := range u.Update.Operations {
		if u.isStale(op) {
			out = append(out, op)
		}
	}
	return out
}

// isStale: the operation is a replace whose type the repo found stale.
func (u *SynchedDataUpdate) isStale(op core.RROperation) bool {
	t, ok := dns.StringToType[op.RRtype]
	return ok && op.Operation == "replace" && u.staleTypes[t]
}

// freshOperations are the update's operations other than its stale
// replaces.
func (u *SynchedDataUpdate) freshOperations() []core.RROperation {
	if u.Update == nil {
		return nil
	}
	if len(u.staleTypes) == 0 {
		return u.Update.Operations
	}
	var out []core.RROperation
	for _, op := range u.Update.Operations {
		if u.isStale(op) {
			continue
		}
		out = append(out, op)
	}
	return out
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
	// CatchUp: the request for the zone's state that a "resync-targeted"
	// answers (the membership design, 5.3).
	CatchUp  *CatchUp `json:"catch_up,omitempty"`
	Response chan *SynchedDataCmdResponse
	// ownRead: for "own-read", what a re-read of the zone brought
	// (own_read.go)
	ownRead *ownReadAnswer
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
	// lastReplace records, per (zone, agent, rrtype), where the REPLACE
	// last applied came from: the originating agent's enqueue time and
	// distribution id. A REPLACE carries the sender's whole set, so one
	// that was sent earlier but arrives later -- the retry of a message
	// the peer had rejected while it did not yet hold the zone -- must not
	// roll the set back to what it was. Keyed under mu; persisted in
	// ZoneDataReplaceOrigin so a restart still rejects an older replace
	// (tdns-mp #249). hdb is the store used by noteReplaceOrigin / load.
	lastReplace map[string]replaceOrigin
	hdb         *HsyncDB
	// ownState: when this agent last read its own state of each zone from
	// its combiner, with the combiner's word that its stored contributions
	// were loaded; ownStateNote: why not, when it has not. Under mu: the
	// syncher and the status read them (own_read.go).
	ownState     map[ZoneName]time.Time
	ownStateNote map[ZoneName]string
	// olderApplied: the zones for which an answer of a combiner older than
	// this agent has been applied (applyOwnRead). Engine only.
	olderApplied map[ZoneName]bool
	// catchUpAnswers: per zone and asker, the distribution ID of the last
	// answer to a request for the zone's state. A newer answer takes the
	// older one out of the queue (catchUpAnswer). Engine only.
	catchUpAnswers map[ZoneName]map[AgentId]string
	// notes: per zone, agent and type, the last change the engine stored
	// and passed to its combiner (setNote). Engine only.
	notes map[ZoneName]map[AgentId]map[uint16]*setNote
	// staleWaits: per distribution to this agent's combiner, the stale
	// DNSKEY replaces whose final confirmation waits for the combiner's word
	// on that distribution's set (waitForCombiner). Engine only.
	staleWaits map[string][]*staleWait
}

type replaceOrigin struct {
	Time   time.Time
	DistID string
}

type PendingRemoteConfirmation struct {
	OriginatingDistID string
	OriginatingSender string
	Mechanism         string
	Zone              ZoneName
	CreatedAt         time.Time
	// StaleHeld: the records of the update's stale replaces that the repo
	// holds. They did not go to the combiner; the confirmation to the
	// sender names them beside what the combiner applied.
	StaleHeld []string
	// StaleWaiting: DNSKEY records of the update's stale replaces that an
	// answer's forward, not confirmed yet, put in the repo
	// (dnskeyAwaitingAnswer). Not named; a success becomes PARTIAL.
	StaleWaiting []string
	// NotHeldTypes: the types of the update's stale replaces whose set's last
	// hand-over to this agent's combiner failed. Their records are left out
	// of StaleHeld and of whatever the final confirmation names, also when
	// it is made from the repo, and the confirmation is PARTIAL.
	NotHeldTypes map[uint16]bool
	// FromAnswer: the forward is of an answer to a request for the zone's
	// state.
	FromAnswer bool
	// DnskeyOps: the update's DNSKEY add and replace operations. The
	// combiner's success is checked against what the repo holds when it
	// comes (heldSuccess): a newer set may have dropped a key since.
	DnskeyOps []core.RROperation
}

type RemoteConfirmationDetail struct {
	OriginatingDistID string
	OriginatingSender string
	Mechanism         string // The mechanism the SYNC arrived on: the confirmation's first choice of path
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
	Instr          *MsgStamp // the confirmer's stamp (S5b); nil from a confirmer that sends none
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

// ZoneAgentInfo is ZoneAgentData as the management API reports it.
type ZoneAgentInfo struct {
	ZoneName      ZoneName
	Agents        []*AgentInfo
	MyUpstream    AgentId
	MyDownstreams []AgentId
}

// --- From zone_utils.go ---

type HsyncStatus struct {
	Time     time.Time
	ZoneName string
	Command  string
	Status   bool
	Error    bool
	ErrorMsg string
	Msg      string
	// ParamChanged is true when the zone's instructions differ between
	// the old and the new copy, by serial or digest (HsyncChanged).
	ParamChanged bool
}

// --- From hsync_utils.go ---

type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR
	LocalRemoves     []dns.RR
	CurrentLocalKeys []dns.RR
	// CurrentKeyStates is what this provider says about each of
	// CurrentLocalKeys to the other providers (tdns-mp #58): the key's
	// state and its ds, from the signer's inventory. StatesChanged: they
	// differ from what was last sent, though the key set may not.
	CurrentKeyStates []core.KeyState
	StatesChanged    bool
	// Resend: the signer sends keys of LocalAdds, or the removals of
	// ResendRemovedTags, again (#256); the set is distributed even when
	// nothing changed.
	Resend bool
	// ResendRemovedTags: this provider's withdrawn keys whose removal the
	// signer sends again. The removal travels in the REPLACE of the current
	// set, without a delete record: the repo no longer holds the key, and a
	// local delete of a record this agent does not own is refused.
	ResendRemovedTags []uint16
}
