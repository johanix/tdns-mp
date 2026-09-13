/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"github.com/johanix/tdns-mp/v2/hsync"
)

// agentGossipPort routes hsync gossip operations to AgentRegistry.GossipStateTable.
type agentGossipPort struct {
	gst *GossipStateTable
	ar  *AgentRegistry
}

func newAgentGossipPort(ar *AgentRegistry) hsync.GossipPort {
	if ar == nil || ar.GossipStateTable == nil {
		return nil
	}
	return &agentGossipPort{gst: ar.GossipStateTable, ar: ar}
}

func (g *agentGossipPort) MergeGossip(msg *hsync.GossipMessage) {
	if g == nil || g.gst == nil || msg == nil {
		return
	}
	g.gst.MergeGossip(msg)
}

func (g *agentGossipPort) CheckGroupState(groupHash string, members []string) {
	if g == nil || g.gst == nil {
		return
	}
	g.gst.CheckGroupState(groupHash, members)
}

func (g *agentGossipPort) RefreshLocalStates(_ *hsync.Registry, _ hsync.ProviderGroupLookup, _ uint32) {
	if g == nil || g.gst == nil || g.ar == nil || g.ar.ProviderGroupManager == nil {
		return
	}
	g.gst.RefreshLocalStates(g.ar, g.ar.ProviderGroupManager)
}

func (g *agentGossipPort) SetOnGroupOperational(fn func(groupHash string)) {
	if g != nil && g.gst != nil {
		g.gst.SetOnGroupOperational(fn)
	}
}

func (g *agentGossipPort) SetOnGroupDegraded(fn func(groupHash string)) {
	if g != nil && g.gst != nil {
		g.gst.SetOnGroupDegraded(fn)
	}
}

func (g *agentGossipPort) SetOnElectionUpdate(fn func(groupHash string, state hsync.GroupElectionState)) {
	if g != nil && g.gst != nil {
		g.gst.SetOnElectionUpdate(fn)
	}
}
