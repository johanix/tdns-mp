/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// handshakeTransport accepts every hello and every beat, and moves the peer's
// DNS mechanism the way the MP bridge does: INTRODUCING on an accepted hello,
// OPERATIONAL on a beat round trip. It notes when the first of each left.
type handshakeTransport struct {
	*d25Transport
	helloAt atomic.Int64
	beatAt  atomic.Int64
	beats   atomic.Int32
}

func newHandshakeTransport() *handshakeTransport {
	return &handshakeTransport{d25Transport: newD25Transport()}
}

func (h *handshakeTransport) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	h.helloAt.CompareAndSwap(0, time.Now().UnixNano())
	h.seed(string(peer.ID), TransportDNS, transport.PeerStateIntroducing)
	return nil
}

func (h *handshakeTransport) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, string, error) {
	h.beatAt.CompareAndSwap(0, time.Now().UnixNano())
	h.beats.Add(1)
	h.seed(string(peer.ID), TransportDNS, transport.PeerStateOperational)
	return true, TransportDNS, nil
}

// An accepted hello is followed by the first beat at once, not at the next
// hello attempt's slot hello_fast_interval later.
func TestTheFirstBeatFollowsAnAcceptedHelloAtOnce(t *testing.T) {
	h := newHandshakeTransport()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: h}, DefaultConfig())
	peer := knownDNSPeer(e, h.d25Transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.helloRetrierNG(ctx, peer)

	deadline := time.Now().Add(3 * time.Second)
	for h.beatAt.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if h.beatAt.Load() == 0 {
		t.Fatal("no beat after the hello was accepted")
	}
	gap := time.Duration(h.beatAt.Load() - h.helloAt.Load())
	if gap >= DefaultConfig().HelloFastSpacing/2 {
		t.Errorf("the first beat left %v after the accepted hello, want at once (hello_fast_interval is %v)",
			gap, DefaultConfig().HelloFastSpacing)
	}
}
