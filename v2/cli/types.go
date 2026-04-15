/*
 * Type aliases for types being migrated from tdns to tdns-mp.
 * These are currently aliases (= tdns.Foo) so both packages
 * use identical types. When the types are removed from tdns,
 * convert these to full struct definitions.
 */

package cli

import (
	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
)

// Combiner API types
type CombinerPost = tdns.CombinerPost
type CombinerResponse = tdns.CombinerResponse
type CombinerEditPost = tdns.CombinerEditPost
type CombinerEditResponse = tdns.CombinerEditResponse
type CombinerDebugPost = tdns.CombinerDebugPost
type CombinerDebugResponse = tdns.CombinerDebugResponse

type AgentId = tdns.AgentId
type ZoneName = tdns.ZoneName

type AgentMgmtPost = tdnsmp.AgentMgmtPost
type AgentMgmtResponse = tdnsmp.AgentMgmtResponse
type Agent = tdnsmp.Agent
type AgentDetails = tdnsmp.AgentDetails

var AgentStateToString = tdnsmp.AgentStateToString

const (
	AgentMsgNotify = tdnsmp.AgentMsgNotify
	AgentMsgRfi    = tdnsmp.AgentMsgRfi
)
