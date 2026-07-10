/*
 * CLI-facing aliases to tdns-mp types (wire-compatible with tdns originals).
 */

package cli

import (
	tdnsmp "github.com/johanix/tdns-mp/v2"
)

// Combiner API types
type CombinerPost = tdnsmp.CombinerPost
type CombinerResponse = tdnsmp.CombinerResponse
type CombinerConfigPost = tdnsmp.CombinerConfigPost
type CombinerConfigResponse = tdnsmp.CombinerConfigResponse
type CombinerEditPost = tdnsmp.CombinerEditPost
type CombinerEditResponse = tdnsmp.CombinerEditResponse
type CombinerDebugPost = tdnsmp.CombinerDebugPost
type CombinerDebugResponse = tdnsmp.CombinerDebugResponse

type AgentId = tdnsmp.AgentId
type ZoneName = tdnsmp.ZoneName

type AgentMgmtPost = tdnsmp.AgentMgmtPost
type AgentMgmtResponse = tdnsmp.AgentMgmtResponse
type Agent = tdnsmp.Agent

var AgentStateToString = tdnsmp.AgentStateToString

const (
	AgentMsgNotify = tdnsmp.AgentMsgNotify
	AgentMsgRfi    = tdnsmp.AgentMsgRfi
)

// Auditor API types
type AuditPost = tdnsmp.AuditPost
type AuditResponse = tdnsmp.AuditResponse
type AuditEvent = tdnsmp.AuditEvent
type AuditObservation = tdnsmp.AuditObservation
type AuditZoneSummary = tdnsmp.AuditZoneSummary
type AuditProviderSummary = tdnsmp.AuditProviderSummary
type AuditWebUser = tdnsmp.AuditWebUser
