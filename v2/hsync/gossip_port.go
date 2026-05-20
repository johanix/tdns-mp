/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

// GossipPort is the gossip matrix surface used by hsync.Engine.
// Production wiring uses AgentRegistry.GossipStateTable via a bridge type.
type GossipPort interface {
	MergeGossip(msg *GossipMessage)
	CheckGroupState(groupHash string, members []string)
	RefreshLocalStates(reg *Registry, pgm ProviderGroupLookup, beatInterval uint32)
	SetOnGroupOperational(fn func(groupHash string))
	SetOnGroupDegraded(fn func(groupHash string))
	SetOnElectionUpdate(fn func(groupHash string, state GroupElectionState))
}
