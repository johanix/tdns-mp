/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"sync"

	"github.com/johanix/tdns/v2/core"
)

// Registry owns the HSYNC peer map. (END.4 / Phase 3b: the RemoteAgents
// zone→peer index is gone — it was write-only; zone→peer derives on read
// via peer.Zones / GetPeersForZone, and membership itself derives from
// HSYNCPARAM via ParticipantsForZone.)
type Registry struct {
	S           core.ConcurrentMap[PeerID, *Peer]
	mu          sync.RWMutex
	LocalID     PeerID
	helloCancel map[PeerID]helloRun
	transport   TransportBridge
}

// helloRun is a running hello retrier: the peer object it greets, and how to
// stop it.
type helloRun struct {
	peer   *Peer
	cancel context.CancelFunc
}

func NewRegistry(localID PeerID, transport TransportBridge) *Registry {
	return &Registry{
		S:           core.NewStringer[PeerID, *Peer](),
		LocalID:     localID,
		helloCancel: make(map[PeerID]helloRun),
		transport:   transport,
	}
}

func (r *Registry) SetTransport(tb TransportBridge) {
	r.transport = tb
}

// AddZoneToPeer adds the zone to the stored peer, and reports whether the
// registry held one. The zone is added under the lock of the peer's shard, so
// a peer that is removed meanwhile is not stored again, and a removal that
// tests the peer's zones sees the new one (#132).
func (r *Registry) AddZoneToPeer(id PeerID, zone ZoneName) bool {
	return r.S.UpdateIf(id, func(peer *Peer) (*Peer, bool) {
		peer.Mu.Lock()
		if peer.Zones == nil {
			peer.Zones = make(map[ZoneName]bool)
		}
		peer.Zones[zone] = true
		peer.Mu.Unlock()
		return peer, true
	})
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

// RemovePeerFromZone takes the zone off the stored peer, under the lock of
// the peer's shard as AddZoneToPeer adds one. A peer that is not stored is
// left alone.
func (r *Registry) RemovePeerFromZone(zone ZoneName, id PeerID) {
	r.S.UpdateIf(id, func(peer *Peer) (*Peer, bool) {
		peer.Mu.Lock()
		delete(peer.Zones, zone)
		peer.Mu.Unlock()
		return peer, true
	})
}

func (r *Registry) RecomputeSharedZones(peer *Peer) {
	if peer == nil {
		return
	}
	// The LEGACY/OPERATIONAL flip that used to live here wrote
	// hsync.Peer.State, which nothing reads any more (v4 D0): connection
	// state is transport.Peer's, and LEGACY is the MP display overlay
	// (effectiveAgentState). Only the zone sync remains.
	if r.transport != nil {
		r.transport.SyncPeerZones(peer)
	}
}

// registerHello registers a hello retrier for peer and returns its context,
// unless one is already registered for the identity. The test and the
// registration are one step, so two callers cannot both start one.
func (r *Registry) registerHello(peer *Peer) (context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.helloCancel[peer.ID]; ok {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.helloCancel[peer.ID] = helloRun{peer: peer, cancel: cancel}
	return ctx, true
}

// clearHelloCancel takes a finished retrier's registration off. A retrier of
// a peer object that was removed leaves alone the registration of a retrier
// for the new object under the same identity (#132).
func (r *Registry) clearHelloCancel(peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run, ok := r.helloCancel[peer.ID]; ok && run.peer == peer {
		run.cancel()
		delete(r.helloCancel, peer.ID)
	}
}

// cancelHello stops the hello retrier running for the removed peer object
// and clears its registration. A retrier registered for a new object under
// the same identity is left alone.
func (r *Registry) cancelHello(peer *Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run, ok := r.helloCancel[peer.ID]; ok && run.peer == peer {
		run.cancel()
		delete(r.helloCancel, peer.ID)
	}
}

// hasHelloCancel reports whether a hello retrier is already running for this
// peer (its cancel func is registered). Used to avoid launching a duplicate
// retrier when retryPendingDiscoveries starts the hello for a KNOWN peer that
// was discovered out-of-band (e.g. the chunk-notify kick).
func (r *Registry) hasHelloCancel(id PeerID) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.helloCancel[id]
	return ok
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
