/*
 * Type aliases for types being migrated from tdns to tdns-mp.
 * These are currently aliases (= tdns.Foo) so both packages
 * use identical types. When the types are removed from tdns,
 * convert these to full struct definitions.
 */

package tdnsmp

import (
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// Combiner API types
type CombinerPost = tdns.CombinerPost
type CombinerResponse = tdns.CombinerResponse
type CombinerEditPost = tdns.CombinerEditPost
type CombinerEditResponse = tdns.CombinerEditResponse
type CombinerDebugPost = tdns.CombinerDebugPost
type CombinerDebugResponse = tdns.CombinerDebugResponse
type CombinerDistribPost = tdns.CombinerDistribPost

// CombinerDistribResponse defined locally (uses local DistributionSummary)
type CombinerDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"`
}

// Combiner sync types (local definitions; wire format matches tdns types)
type CombinerSyncRequest struct {
	SenderID       string
	DeliveredBy    string
	Zone           string
	ZoneClass      string
	SyncType       string
	Records        map[string][]string
	Operations     []core.RROperation
	Publish        *core.PublishInstruction
	Serial         uint32
	DistributionID string
	Timestamp      time.Time
}

type CombinerSyncResponse struct {
	DistributionID string
	Zone           string
	Nonce          string
	Status         string
	Message        string
	AppliedRecords []string
	RemovedRecords []string
	RejectedItems  []RejectedItem
	IgnoredRecords []string
	Timestamp      time.Time
	DataChanged    bool
}

type RejectedItem struct {
	Record string
	Reason string
}

type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// Combiner edit record types (moved from db_combiner_edits.go)
type PendingEditRecord = tdns.PendingEditRecord
type ApprovedEditRecord = tdns.ApprovedEditRecord
type RejectedEditRecord = tdns.RejectedEditRecord

// Combiner option types
type CombinerOption = tdns.CombinerOption

const CombinerOptAddSignature = tdns.CombinerOptAddSignature

// Signer types
type KeyInventoryItem = tdns.KeyInventoryItem
type DnssecKeyWithTimestamps = tdns.DnssecKeyWithTimestamps

// Pervasive types that stay as aliases (no methods, used everywhere)
type AgentId = tdns.AgentId
type ZoneName = tdns.ZoneName
type ZoneUpdate = tdns.ZoneUpdate
type OwnerData = tdns.OwnerData

// Distribution types now defined locally in distribution_cache.go
// Chunk types now defined locally in chunk_store.go

// Transaction API types
type TransactionPost = tdns.TransactionPost
type TransactionResponse = tdns.TransactionResponse
type TransactionSummary = tdns.TransactionSummary
type TransactionErrorSummary = tdns.TransactionErrorSummary

// NewMsgQs creates and returns a *MsgQs with all channels initialized.
func NewMsgQs() *MsgQs {
	return &MsgQs{
		Hello:             make(chan *AgentMsgReport, 100),
		Beat:              make(chan *AgentMsgReport, 100),
		Ping:              make(chan *AgentMsgReport, 100),
		Msg:               make(chan *AgentMsgPostPlus, 100),
		Command:           make(chan *AgentMgmtPostPlus, 100),
		DebugCommand:      make(chan *AgentMgmtPostPlus, 100),
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 100),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 100),
		Confirmation:      make(chan *ConfirmationDetail, 100),
		KeystateInventory: make(chan *KeystateInventoryMsg, 10),
		KeystateSignal:    make(chan *KeystateSignalMsg, 10),
		EditsResponse:     make(chan *EditsResponseMsg, 10),
		ConfigResponse:    make(chan *ConfigResponseMsg, 10),
		AuditResponse:     make(chan *AuditResponseMsg, 10),
		StatusUpdate:      make(chan *StatusUpdateMsg, 10),
	}
}
