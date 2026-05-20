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
