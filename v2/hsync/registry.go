/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// Registry owns the HSYNC peer map and zone index.
type Registry struct {
	S            core.ConcurrentMap[PeerID, *Peer]
	RemoteAgents map[ZoneName][]PeerID
	mu           sync.RWMutex
	LocalID      PeerID
	helloCancel  map[PeerID]context.CancelFunc
	transport    TransportBridge
}

func NewRegistry(localID PeerID, transport TransportBridge) *Registry {
	return &Registry{
		S:            core.NewStringer[PeerID, *Peer](),
		RemoteAgents: make(map[ZoneName][]PeerID),
		LocalID:      localID,
		helloCancel:  make(map[PeerID]context.CancelFunc),
		transport:    transport,
	}
}

func (r *Registry) SetTransport(tb TransportBridge) {
	r.transport = tb
}

func (r *Registry) AddZoneToPeer(id PeerID, zone ZoneName) {
	peer, exists := r.S.Get(id)
	if !exists {
		return
	}
	peer.Mu.Lock()
	if peer.Zones == nil {
		peer.Zones = make(map[ZoneName]bool)
	}
	peer.Zones[zone] = true
	peer.Mu.Unlock()
	r.addRemoteAgent(zone, peer)
	r.S.Set(id, peer)
}

func (r *Registry) addRemoteAgent(zone ZoneName, peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.RemoteAgents[zone] {
		if existing == peer.ID {
			return
		}
	}
	r.RemoteAgents[zone] = append(r.RemoteAgents[zone], peer.ID)
}

func (r *Registry) GetPeersForZone(zone ZoneName) []*Peer {
	var peers []*Peer
	for _, peer := range r.S.Items() {
		peer.Mu.RLock()
		_, inZone := peer.Zones[zone]
		peer.Mu.RUnlock()
		if inZone {
			peers = append(peers, peer)
		}
	}
	return peers
}

func (r *Registry) RemovePeerFromZone(zone ZoneName, id PeerID) {
	r.mu.Lock()
	ids := r.RemoteAgents[zone]
	for i, a := range ids {
		if a == id {
			r.RemoteAgents[zone] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	r.mu.Unlock()

	if peer, ok := r.S.Get(id); ok {
		peer.Mu.Lock()
		delete(peer.Zones, zone)
		peer.Mu.Unlock()
		r.S.Set(id, peer)
	}
}

func (r *Registry) RecomputeSharedZones(peer *Peer) {
	if peer == nil {
		return
	}
	peer.Mu.Lock()
	zoneCount := len(peer.Zones)
	oldState := peer.State
	if zoneCount == 0 && (oldState == PeerStateOperational || oldState == PeerStateIntroduced) {
		peer.State = PeerStateLegacy
		peer.LastState = time.Now()
	} else if zoneCount > 0 && oldState == PeerStateLegacy {
		peer.State = PeerStateOperational
		peer.LastState = time.Now()
	}
	peer.Mu.Unlock()

	if r.transport != nil {
		r.transport.SyncPeerZones(peer)
	}
}

func (r *Registry) setHelloCancel(id PeerID, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.helloCancel[id]; ok {
		existing()
	}
	r.helloCancel[id] = cancel
}

func (r *Registry) clearHelloCancel(id PeerID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.helloCancel, id)
}

func (r *Registry) sharedZones(peer *Peer) []string {
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	out := make([]string, 0, len(peer.Zones))
	for z := range peer.Zones {
		out = append(out, string(z))
	}
	return out
}
