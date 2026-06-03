/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"github.com/johanix/tdns-mp/v2/hsync"
)

func hsyncPeerToAgent(peer *hsync.Peer) *Agent {
	if peer == nil {
		return nil
	}
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	agent := &Agent{
		Identity:    AgentId(peer.ID),
		PeerID:      peer.TransportID,
		ApiDetails:  hsyncDetailsToAgent(peer.ApiDetails),
		DnsDetails:  hsyncDetailsToAgent(peer.DnsDetails),
		ApiMethod:   peer.ApiMethod,
		DnsMethod:   peer.DnsMethod,
		IsInfraPeer: peer.IsInfraPeer,
		Zones:       make(map[ZoneName]bool),
		State:       AgentState(peer.State),
		LastState:   peer.LastState,
	}
	for z := range peer.Zones {
		agent.Zones[ZoneName(z)] = true
	}
	for _, t := range peer.Deferred {
		agent.DeferredTasks = append(agent.DeferredTasks, DeferredAgentTask{
			Precondition: t.Precondition,
			Action:       t.Action,
			Desc:         t.Desc,
		})
	}
	return agent
}

func syncHsyncPeerFromAgent(peer *hsync.Peer, agent *Agent) {
	if peer == nil || agent == nil {
		return
	}
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	peer.Mu.Lock()
	defer peer.Mu.Unlock()
	peer.ApiDetails = agentDetailsToHsync(agent.ApiDetails)
	peer.DnsDetails = agentDetailsToHsync(agent.DnsDetails)
	peer.ApiMethod = agent.ApiMethod
	peer.DnsMethod = agent.DnsMethod
	peer.IsInfraPeer = agent.IsInfraPeer
	peer.State = hsync.PeerState(agent.State)
	peer.LastState = agent.LastState
}

func persistAgentAndPeer(ar *AgentRegistry, peer *hsync.Peer, agent *Agent) {
	if ar == nil || peer == nil || agent == nil {
		return
	}
	syncHsyncPeerFromAgent(peer, agent)
	ar.S.Set(agent.Identity, agent)
}

func agentToHsyncPeer(agent *Agent) *hsync.Peer {
	if agent == nil {
		return nil
	}
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	peer := hsync.NewPeer(hsync.PeerID(agent.Identity))
	peer.TransportID = agent.PeerID
	peer.ApiDetails = agentDetailsToHsync(agent.ApiDetails)
	peer.DnsDetails = agentDetailsToHsync(agent.DnsDetails)
	peer.ApiMethod = agent.ApiMethod
	peer.DnsMethod = agent.DnsMethod
	peer.IsInfraPeer = agent.IsInfraPeer
	peer.State = hsync.PeerState(agent.State)
	peer.LastState = agent.LastState
	for z := range agent.Zones {
		peer.Zones[hsync.ZoneName(z)] = true
	}
	return peer
}

func hsyncDetailsToAgent(d *hsync.PeerDetails) *AgentDetails {
	if d == nil {
		return &AgentDetails{State: AgentStateNeeded}
	}
	return &AgentDetails{
		Addrs:             append([]string(nil), d.Addrs...),
		Port:              d.Port,
		BaseUri:           d.BaseUri,
		ContactInfo:       d.ContactInfo,
		JWKData:           d.JWKData,
		KeyAlgorithm:      d.KeyAlgorithm,
		State:             AgentState(d.State),
		LatestError:       d.LatestError,
		LatestErrorTime:   d.LatestErrorTime,
		DiscoveryFailures: d.DiscoveryFailures,
		HelloTime:         d.HelloTime,
		LastContactTime:   d.LastContactTime,
		BeatInterval:      d.BeatInterval,
		SentBeats:         d.SentBeats,
		ReceivedBeats:     d.ReceivedBeats,
		LatestSBeat:       d.LatestSBeat,
		LatestRBeat:       d.LatestRBeat,
	}
}

func agentDetailsToHsync(d *AgentDetails) *hsync.PeerDetails {
	if d == nil {
		return &hsync.PeerDetails{State: hsync.PeerStateNeeded}
	}
	return &hsync.PeerDetails{
		Addrs:             append([]string(nil), d.Addrs...),
		Port:              d.Port,
		BaseUri:           d.BaseUri,
		ContactInfo:       d.ContactInfo,
		JWKData:           d.JWKData,
		KeyAlgorithm:      d.KeyAlgorithm,
		State:             hsync.PeerState(d.State),
		LatestError:       d.LatestError,
		LatestErrorTime:   d.LatestErrorTime,
		DiscoveryFailures: d.DiscoveryFailures,
		HelloTime:         d.HelloTime,
		LastContactTime:   d.LastContactTime,
		BeatInterval:      d.BeatInterval,
		SentBeats:         d.SentBeats,
		ReceivedBeats:     d.ReceivedBeats,
		LatestSBeat:       d.LatestSBeat,
		LatestRBeat:       d.LatestRBeat,
	}
}

func agentForTransport(ar *AgentRegistry, peer *hsync.Peer) *Agent {
	agent := hsyncPeerToAgent(peer)
	if ar == nil || agent == nil {
		return agent
	}
	if existing, ok := ar.S.Get(agent.Identity); ok {
		mergeAgentDetails(agent.ApiDetails, existing.ApiDetails)
		mergeAgentDetails(agent.DnsDetails, existing.DnsDetails)
	}
	return agent
}

func syncHsyncPeerToAgent(ar *AgentRegistry, peer *hsync.Peer) {
	if ar == nil || peer == nil {
		return
	}
	existing, _ := ar.S.Get(AgentId(peer.ID))
	agent := hsyncPeerToAgent(peer)
	if existing != nil {
		mergeAgentDetails(agent.ApiDetails, existing.ApiDetails)
		mergeAgentDetails(agent.DnsDetails, existing.DnsDetails)
	}
	ar.S.Set(agent.Identity, agent)
	syncHsyncPeerFromAgent(peer, agent)
}

func mergeAgentDetails(dst, src *AgentDetails) {
	if dst == nil || src == nil {
		return
	}
	if dst.BaseUri == "" {
		dst.BaseUri = src.BaseUri
	}
	if dst.ContactInfo == "" {
		dst.ContactInfo = src.ContactInfo
	}
	if len(dst.Addrs) == 0 && len(src.Addrs) > 0 {
		dst.Addrs = append([]string(nil), src.Addrs...)
	}
	if dst.Port == 0 {
		dst.Port = src.Port
	}
	if dst.JWKData == "" {
		dst.JWKData = src.JWKData
	}
	if dst.KeyAlgorithm == "" {
		dst.KeyAlgorithm = src.KeyAlgorithm
	}
	if dst.KeyRR == nil {
		dst.KeyRR = src.KeyRR
	}
	if dst.TlsaRR == nil {
		dst.TlsaRR = src.TlsaRR
	}
}
