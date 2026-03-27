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

// Transport bridge types (MP-only, will eventually move here as full definitions)
// MPTransportBridge and MPTransportBridgeConfig are defined in hsync_transport.go (local copy)
// AgentDiscoveryResult is defined in agent_discovery.go (local copy)
// PendingDnskeyPropagation is defined in hsync_transport.go (local copy)
type AgentRegistry = tdns.AgentRegistry
type Agent = tdns.Agent
type AgentDetails = tdns.AgentDetails
type AgentState = tdns.AgentState
type AgentId = tdns.AgentId
type MsgQs = tdns.MsgQs
type KeystateInventoryMsg = tdns.KeystateInventoryMsg
type KeystateSignalMsg = tdns.KeystateSignalMsg
type DistributionCache = tdns.DistributionCache
type DistributionInfo = tdns.DistributionInfo
type ChunkPayloadStore = tdns.ChunkPayloadStore
type ConfirmationDetail = tdns.ConfirmationDetail
type RemoteConfirmationDetail = tdns.RemoteConfirmationDetail
type RejectedItemInfo = tdns.RejectedItemInfo
type AgentMsgPost = tdns.AgentMsgPost
type AgentMsgPostPlus = tdns.AgentMsgPostPlus
type AgentMsgReport = tdns.AgentMsgReport
type AgentMgmtPostPlus = tdns.AgentMgmtPostPlus
type SynchedDataUpdate = tdns.SynchedDataUpdate
type SynchedDataCmd = tdns.SynchedDataCmd
type EditsResponseMsg = tdns.EditsResponseMsg
type ConfigResponseMsg = tdns.ConfigResponseMsg
type AuditResponseMsg = tdns.AuditResponseMsg
type StatusUpdateMsg = tdns.StatusUpdateMsg
type GossipMessage = tdns.GossipMessage
type MessageRetentionConf = tdns.MessageRetentionConf
type AgentMsg = tdns.AgentMsg

// AgentState constants
const (
	AgentStateNeeded      = tdns.AgentStateNeeded
	AgentStateKnown       = tdns.AgentStateKnown
	AgentStateIntroduced  = tdns.AgentStateIntroduced
	AgentStateOperational = tdns.AgentStateOperational
	AgentStateLegacy      = tdns.AgentStateLegacy
	AgentStateDegraded    = tdns.AgentStateDegraded
	AgentStateInterrupted = tdns.AgentStateInterrupted
	AgentStateError       = tdns.AgentStateError
)

// AgentStateToString map
var AgentStateToString = tdns.AgentStateToString

// AgentMsg constants
const (
	AgentMsgHello  = tdns.AgentMsgHello
	AgentMsgBeat   = tdns.AgentMsgBeat
	AgentMsgNotify = tdns.AgentMsgNotify
	AgentMsgPing   = tdns.AgentMsgPing
	AgentMsgStatus = tdns.AgentMsgStatus
	AgentMsgEdits  = tdns.AgentMsgEdits
	AgentMsgRfi    = tdns.AgentMsgRfi
)

// Internal state types (for InternalMpConf)
type SyncRequest = tdns.SyncRequest
type SyncStatus = tdns.SyncStatus
type ZoneDataRepo = tdns.ZoneDataRepo
type CombinerState = tdns.CombinerState
type LeaderElectionManager = tdns.LeaderElectionManager

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
