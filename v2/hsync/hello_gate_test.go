/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// helloCounter is the d25 transport with a count of the hellos it was asked
// to send.
type helloCounter struct {
	*d25Transport
	hellos atomic.Int32
}

func (c *helloCounter) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	c.hellos.Add(1)
	return nil
}

func knownDNSPeer(e *Engine, tb *d25Transport) *Peer {
	peer := NewPeer("remote.example.")
	peer.DnsMethod = true
	peer.ApiMethod = false
	e.registry.S.Set(peer.ID, peer)
	tb.seed(string(peer.ID), TransportDNS, transport.PeerStateKnown)
	return peer
}

func waitForHellos(t *testing.T, c *helloCounter, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for c.hellos.Load() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.hellos.Load(); got < want {
		t.Fatalf("%d hello(s) sent, want at least %d", got, want)
	}
}

// A peer whose lookup of this agent lands before the agent's identity is
// published finds a zone that is not there yet (tdns #653). So the engine's
// first hello to any peer waits on Deps.HelloReady, which the host closes once
// the identity zone is published, and every later hello passes it at once.
func TestTheFirstHelloWaitsForTheIdentity(t *testing.T) {
	c := &helloCounter{d25Transport: newD25Transport()}
	ready := make(chan struct{})
	e := NewEngine(Deps{
		LocalID:   "local.example.",
		Transport: c,
		HelloReady: func(ctx context.Context) bool {
			select {
			case <-ready:
				return true
			case <-ctx.Done():
				return false
			}
		},
	}, DefaultConfig())
	peer := knownDNSPeer(e, c.d25Transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		e.helloRetrierNG(ctx, peer)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond)
	if got := c.hellos.Load(); got != 0 {
		t.Fatalf("%d hello(s) left before the identity was published", got)
	}
	close(ready)
	waitForHellos(t, c, 1)

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the hello retrier did not stop with its context")
	}
}

// A retrier whose context ends while it waits sends nothing and stops.
func TestAHelloThatIsNeverAllowedIsNeverSent(t *testing.T) {
	c := &helloCounter{d25Transport: newD25Transport()}
	e := NewEngine(Deps{
		LocalID:   "local.example.",
		Transport: c,
		HelloReady: func(ctx context.Context) bool {
			<-ctx.Done()
			return false
		},
	}, DefaultConfig())
	peer := knownDNSPeer(e, c.d25Transport)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.helloRetrierNG(ctx, peer)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the hello retrier did not stop with its context")
	}
	if got := c.hellos.Load(); got != 0 {
		t.Fatalf("%d hello(s) sent by a retrier that was never allowed one", got)
	}
}

// Without a HelloReady dependency the hello leaves at once.
func TestAHelloWithNoGateLeavesAtOnce(t *testing.T) {
	c := &helloCounter{d25Transport: newD25Transport()}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: c}, DefaultConfig())
	peer := knownDNSPeer(e, c.d25Transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		e.helloRetrierNG(ctx, peer)
		close(done)
	}()
	waitForHellos(t, c, 1)
	cancel()
	<-done
}
