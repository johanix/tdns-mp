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
