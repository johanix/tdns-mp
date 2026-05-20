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
