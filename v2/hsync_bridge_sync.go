/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"github.com/johanix/tdns-mp/v2/hsync"
)

// hsyncPeerToAgent builds the MP-side Agent VIEW over a hsync.Peer (E1.a). The
// Agent now EMBEDS the *hsync.Peer, so ID / Zones / Deferred / ApiMethod /
// DnsMethod / IsInfraPeer / LastState come directly from the shared peer — no
// copy. Only the different-typed shadowing fields (ApiDetails/DnsDetails as
// *AgentDetails, State as AgentState) are derived from the peer's connection
// state (now dead post-D2.5, kept until A5/D). The peer pointer is shared, not
// cloned; E1.b removes this function and the dual map entirely.
func hsyncPeerToAgent(peer *hsync.Peer) *Agent {
	if peer == nil {
		return nil
	}
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	return &Agent{
		Peer:       peer,
		ApiDetails: hsyncDetailsToAgent(peer.ApiDetails),
		DnsDetails: hsyncDetailsToAgent(peer.DnsDetails),
		State:      AgentState(peer.State),
	}
}

func syncHsyncPeerFromAgent(peer *hsync.Peer, agent *Agent) {
	if peer == nil || agent == nil {
		return
	}
	// E1.a: ApiMethod/DnsMethod/IsInfraPeer/LastState now PROMOTE from agent.Peer
	// (one copy) — no longer copied here. Only the different-typed connection
	// state (ApiDetails/DnsDetails/State) is mirrored onto the embed's same-named
	// fields, keeping the NG store in step (dead post-D2.5; retires A5/D). When
	// peer == agent.Peer (the shared embed) this is a self-update of those fields.
	if peer == agent.Peer {
		peer.Mu.Lock()
		defer peer.Mu.Unlock()
		peer.ApiDetails = agentDetailsToHsync(agent.ApiDetails)
		peer.DnsDetails = agentDetailsToHsync(agent.DnsDetails)
		peer.State = hsync.PeerState(agent.State)
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
	ar.S.Set(agent.ID, agent)
}

func agentToHsyncPeer(agent *Agent) *hsync.Peer {
	if agent == nil {
		return nil
	}
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	peer := hsync.NewPeer(agent.ID)
	peer.TransportID = string(agent.ID)
	peer.ApiDetails = agentDetailsToHsync(agent.ApiDetails)
	peer.DnsDetails = agentDetailsToHsync(agent.DnsDetails)
	peer.ApiMethod = agent.ApiMethod
	peer.DnsMethod = agent.DnsMethod
	peer.IsInfraPeer = agent.IsInfraPeer
	peer.State = hsync.PeerState(agent.State)
	peer.LastState = agent.LastState
	for z := range agent.Zones {
		peer.Zones[z] = true
	}
	return peer
}

func hsyncDetailsToAgent(d *hsync.PeerDetails) *AgentDetails {
	if d == nil {
		return &AgentDetails{State: AgentStateNeeded}
	}
	return &AgentDetails{
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
	// S2: address fields no longer live on AgentDetails (they are on
	// transport.Peer, which these hsync-rebuilds do not touch), so the
	// former mergeAgentDetails address-preservation is a no-op and gone.
	return agent
}

func syncHsyncPeerToAgent(ar *AgentRegistry, peer *hsync.Peer) {
	if ar == nil || peer == nil {
		return
	}
	existing, _ := ar.S.Get(peer.ID)
	agent := hsyncPeerToAgent(peer)
	_ = existing // S2: address-merge removed (addresses live on transport.Peer)
	ar.S.Set(agent.ID, agent)
	syncHsyncPeerFromAgent(peer, agent)
}
