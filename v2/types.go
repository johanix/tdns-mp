/*
 * Type aliases for types being migrated from tdns to tdns-mp.
 * These are currently aliases (= tdns.Foo) so both packages
 * use identical types. When the types are removed from tdns,
 * convert these to full struct definitions.
 */

package tdnsmp

import (
	tdns "github.com/johanix/tdns/v2"
)

// Combiner API types
type CombinerPost = tdns.CombinerPost
type CombinerResponse = tdns.CombinerResponse
type CombinerEditPost = tdns.CombinerEditPost
type CombinerEditResponse = tdns.CombinerEditResponse
type CombinerDebugPost = tdns.CombinerDebugPost
type CombinerDebugResponse = tdns.CombinerDebugResponse
type CombinerDistribPost = tdns.CombinerDistribPost
type CombinerDistribResponse = tdns.CombinerDistribResponse

// Combiner sync types (moved from combiner_chunk.go)
type CombinerSyncRequest = tdns.CombinerSyncRequest
type CombinerSyncResponse = tdns.CombinerSyncResponse
type RejectedItem = tdns.RejectedItem
type CombinerSyncRequestPlus = tdns.CombinerSyncRequestPlus

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

// Types that stay as aliases until their defining files are copied
type DistributionCache = tdns.DistributionCache
type DistributionInfo = tdns.DistributionInfo
type ChunkPayloadStore = tdns.ChunkPayloadStore

// Internal state types that stay as aliases during dual-write period
type CombinerState = tdns.CombinerState

// Functions re-exported from tdns (not yet moved)
var NewDistributionCache = tdns.NewDistributionCache
var StartDistributionGC = tdns.StartDistributionGC

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
