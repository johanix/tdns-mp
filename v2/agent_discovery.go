/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent discovery — Phase 2.6: the discovery PROCESS (lookups → resolve →
 * register → KNOWN) lives in tdns-transport (transport/discovery.go). MP
 * keeps the GATE — deciding WHICH peers are needed (HSYNC3/zone knowledge
 * transport never has) — and materializes its *Agent view of a completed
 * peer in the OnPeerDiscovered callback (hsync_transport.go).
 */

package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// DiscoverAndRegisterAgent performs discovery and registration in one step.
// Thin shim over the transport-owned process; kept so the MP call sites
// (the chunk-notify discovery kick, distrib-time discovery) read naturally.
func (tm *MPTransportBridge) DiscoverAndRegisterAgent(ctx context.Context, identity string) error {
	if tm.TransportManager == nil {
		return fmt.Errorf("no transport manager configured for discovery")
	}
	return tm.TransportManager.DiscoverAndRegisterPeer(ctx, identity)
}

// flushAndDiscover flushes the resolver cache for the peer's discovery names
// and discovers the peer again. What the lookup finds replaces what is held:
// the address, and the peer's key in the payload crypto when the JWK lookup
// returns one. It is the discovery kick for a sender whose key is missing,
// and what a peer that keeps refusing our hellos gets (noteHelloRefused).
func (tm *MPTransportBridge) flushAndDiscover(peerID string) {
	// Flush IMR cache for this peer's discovery names before re-discovery
	if tm.getImrEngine != nil {
		if removed := flushDiscoveryCache(tm.getImrEngine(), peerID); removed > 0 {
			lgTransport.Info("flushed IMR cache for peer discovery", "peer", peerID, "removed", removed)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := tm.DiscoverAndRegisterAgent(ctx, peerID)
	if err != nil {
		lgTransport.Warn("discovery incomplete for peer", "peer", peerID, "err", err)
	} else {
		lgTransport.Info("successfully discovered peer, verification key now available", "peer", peerID)
	}
}

// A peer's long-term key is looked up when the peer is discovered. When the
// key that lookup returned is not the one the peer uses, because a resolver
// cache or a secondary still served an older JWK record, or because the peer
// has replaced its key since, nothing the two exchange gets through: what we
// encrypt to the key we hold the peer cannot decrypt, and what the peer signs
// does not verify with it. The peer answers our hello with REFUSED, and the
// hello retrier used to go on like that until the daemon was restarted
// (tdns-mp #145).
//
// So a peer that keeps refusing our hello is looked up again, as a sender
// whose key is missing is (flushAndDiscover): after
// helloRefusalsBeforeRediscovery refused hellos in a row, and then at most
// once every peerRediscoveryInterval for as long as the refusals go on.
//
// REFUSED is also the answer of a peer that does not, or not yet, hold us
// authorized for a zone. The lookup changes nothing then, and the interval
// bounds what it costs. Only the answer to a hello of our own counts, so
// nothing a third party sends us makes this agent look anything up.
const (
	// helloRefusalsBeforeRediscovery: one refused hello is common while a
	// peer starts and has not loaded the zone that authorizes us. Three in a
	// row is the whole fast phase of the hello retrier.
	helloRefusalsBeforeRediscovery = 3
	peerRediscoveryInterval        = time.Minute
)

// refusedHellos is the count behind noteHelloRefused, for one peer.
type refusedHellos struct {
	inARow       int       // refused hellos since the last accepted one
	rediscovered time.Time // when the peer was last looked up again for them
}

// helloRefused reports whether a DNS hello failed because the peer answered
// REFUSED, as opposed to not answering or failing in another way. The
// transport reports the answer's rcode in the text of its error and nowhere
// else.
func helloRefused(err error) bool {
	var te *transport.TransportError
	if !errors.As(err, &te) || te.Err == nil {
		return false
	}
	return te.Err.Error() == "NOTIFY returned rcode "+dns.RcodeToString[dns.RcodeRefused]
}

// noteHelloRefused counts a hello that the peer refused and, when the
// refusals have gone on for long enough, has the peer looked up again.
func (tm *MPTransportBridge) noteHelloRefused(peerID string) {
	interval := tm.rediscoveryInterval
	if interval <= 0 {
		interval = peerRediscoveryInterval
	}
	tm.refusedHellosMu.Lock()
	if tm.refusedHellos == nil {
		tm.refusedHellos = make(map[string]*refusedHellos)
	}
	r := tm.refusedHellos[peerID]
	if r == nil {
		r = &refusedHellos{}
		tm.refusedHellos[peerID] = r
	}
	r.inARow++
	refused := r.inARow
	due := refused >= helloRefusalsBeforeRediscovery && time.Since(r.rediscovered) >= interval
	if due {
		r.rediscovered = time.Now()
	}
	tm.refusedHellosMu.Unlock()
	if !due {
		return
	}
	lgTransport.Warn("peer keeps refusing our hello, flushing IMR cache and discovering it again: the key held for it may not be the one it uses",
		"peer", peerID, "refused", refused)
	go tm.flushAndDiscover(peerID)
}

// noteHelloAccepted ends the peer's run of refused hellos. When the peer was
// last looked up stays on the books: the interval holds across it.
func (tm *MPTransportBridge) noteHelloAccepted(peerID string) {
	tm.refusedHellosMu.Lock()
	if r := tm.refusedHellos[peerID]; r != nil {
		r.inARow = 0
	}
	tm.refusedHellosMu.Unlock()
}
