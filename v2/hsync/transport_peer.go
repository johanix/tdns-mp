/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import "time"

const (
	TransportAPI = "API"
	TransportDNS = "DNS"
)

func peerDetailsFor(peer *Peer, transport string) *PeerDetails {
	switch transport {
	case TransportDNS:
		if peer.DnsMethod && peer.DnsDetails != nil {
			return peer.DnsDetails
		}
	case TransportAPI:
		if peer.ApiMethod && peer.ApiDetails != nil {
			return peer.ApiDetails
		}
	}
	return nil
}

func forEachEnabledTransport(peer *Peer, fn func(name string, td *PeerDetails)) {
	if peer.DnsMethod && peer.DnsDetails != nil {
		fn(TransportDNS, peer.DnsDetails)
	}
	if peer.ApiMethod && peer.ApiDetails != nil {
		fn(TransportAPI, peer.ApiDetails)
	}
}

func beatOutboundSequence(peer *Peer) uint64 {
	var seq uint64
	forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
		if uint64(td.SentBeats) > seq {
			seq = uint64(td.SentBeats)
		}
	})
	return seq
}

// transportParticipating is true once discovery or protocol has advanced past NEEDED.
func transportParticipating(state PeerState) bool {
	return state >= PeerStateKnown
}

func transportReady(state PeerState) bool {
	switch state {
	case PeerStateIntroduced, PeerStateOperational, PeerStateLegacy,
		PeerStateDegraded, PeerStateInterrupted:
		return true
	}
	return false
}

func peerAnyTransportReady(peer *Peer) bool {
	ready := false
	peer.Mu.RLock()
	forEachEnabledTransport(peer, func(_ string, td *PeerDetails) {
		if transportReady(td.State) {
			ready = true
		}
	})
	peer.Mu.RUnlock()
	return ready
}

func (e *Engine) mergeGossipFromBeat(report *InboundReport) {
	if e == nil || e.deps.Gossip == nil || report == nil {
		return
	}
	abp, ok := report.Msg.(*BeatPost)
	if !ok || len(abp.Gossip) == 0 {
		return
	}
	for i := range abp.Gossip {
		e.deps.Gossip.MergeGossip(&abp.Gossip[i])
	}
	if e.deps.ProviderGroups != nil {
		for i := range abp.Gossip {
			pg := e.deps.ProviderGroups.GetGroup(abp.Gossip[i].GroupHash)
			if pg != nil {
				e.deps.Gossip.CheckGroupState(pg.GroupHash, pg.Members)
			}
		}
	}
}

func applyInboundBeat(peer *Peer, transport string, beatInterval uint32, now time.Time) {
	td := peerDetailsFor(peer, transport)
	if td == nil {
		return
	}
	td.LatestRBeat = now
	td.ReceivedBeats++
	if beatInterval > 0 {
		td.BeatInterval = beatInterval
	}
}
