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

	"github.com/johanix/tdns-mp/v2/hsync"
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

// zoneNamesPeer reports whether a zone this agent holds names the identity
// as a peer, by the test the engine's ReconcileZone makes. With no engine
// wired (harnesses) every identity counts as named.
func (tm *MPTransportBridge) zoneNamesPeer(identity string) bool {
	if tm.agentRegistry == nil || tm.agentRegistry.HsyncEngine == nil {
		return true
	}
	return tm.agentRegistry.HsyncEngine.ZoneNamesPeer(hsync.PeerID(dns.Fqdn(identity)))
}

// flushAndDiscover flushes the resolver cache for the peer's discovery names
// and discovers the peer again. What the lookup finds replaces what is held:
// the address, and the peer's key in the payload crypto when the JWK lookup
// returns one. It is the discovery kick for a sender whose key is missing,
// what a peer that keeps refusing our hellos or our beats gets (noteRefused),
// and what a hello from a sender with no address gets (routeHelloMessage).
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
// (tdns-mp #145). A peer that we are past the hello with gets beats and no
// hello, also when the beats fail, so a peer that replaces its key while we
// run refuses our beats instead.
//
// So a peer that keeps refusing our hello, or our beats, is looked up again,
// as a sender whose key is missing is (flushAndDiscover): after
// helloRefusalsBeforeRediscovery refused messages in a row, and then at most
// once every peerRediscoveryInterval for as long as the refusals go on.
//
// REFUSED is also the answer of a peer that does not, or not yet, hold us
// authorized for a zone. The lookup changes nothing then, and the interval
// bounds what it costs. Only the answer to a hello or a beat of our own
// counts, so nothing a third party sends us makes this agent look anything
// up.
//
// The interval is one per peer for every lookup past the cache that a
// message can ask for. A hello from a sender with no address asks for one
// too (freshLookupDue), and the two share the book: a peer is looked up past
// the cache at most once an interval, whichever asks.
const (
	// helloRefusalsBeforeRediscovery: one refused hello is common while a
	// peer starts and has not loaded the zone that authorizes us. Three in a
	// row is the whole fast phase of the hello retrier.
	helloRefusalsBeforeRediscovery = 3
	peerRediscoveryInterval        = time.Minute
)

// refusedHellos is the count behind noteRefused, for one peer, and when the
// peer was last looked up past the cache.
type refusedHellos struct {
	inARow       int       // refused hellos and beats since the last accepted one
	rediscovered time.Time // when the peer was last looked up past the cache, for them or for a hello of its own
}

// freshLookupInterval is the least time between two lookups of one peer past
// the cache.
func (tm *MPTransportBridge) freshLookupInterval() time.Duration {
	if tm.rediscoveryInterval > 0 {
		return tm.rediscoveryInterval
	}
	return peerRediscoveryInterval
}

// lookupBook returns the peer's entry in the book, and makes it when there
// is none. The caller holds refusedHellosMu. The entry is one for the peer
// however its identity is spelled: one caller has it from the registry, the
// other from the peer's own hello.
func (tm *MPTransportBridge) lookupBook(peerID string) *refusedHellos {
	if tm.refusedHellos == nil {
		tm.refusedHellos = make(map[string]*refusedHellos)
	}
	peerID = dns.CanonicalName(peerID)
	r := tm.refusedHellos[peerID]
	if r == nil {
		r = &refusedHellos{}
		tm.refusedHellos[peerID] = r
	}
	return r
}

// freshLookupDue reports whether the peer may be looked up past the cache
// now, and books the lookup when it may: the interval has passed since the
// last one, whichever asked for that.
func (tm *MPTransportBridge) freshLookupDue(peerID string) bool {
	interval := tm.freshLookupInterval()
	tm.refusedHellosMu.Lock()
	defer tm.refusedHellosMu.Unlock()
	r := tm.lookupBook(peerID)
	if time.Since(r.rediscovered) < interval {
		return false
	}
	r.rediscovered = time.Now()
	return true
}

// helloRefused reports whether a DNS hello, or a DNS beat, failed because the
// peer answered REFUSED, as opposed to not answering or failing in another
// way. The transport reports the answer's rcode in the text of its error and
// nowhere else.
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
	tm.noteRefused(peerID, "hello")
}

// noteBeatRefused does the same for a beat. A peer that was OPERATIONAL gets
// beats and no hellos, also when its beats start to fail, so a peer that is
// given a new key while this agent runs never refuses a hello of ours: it
// refuses our beats. Without this the key held for it stayed the old one
// until a restart. The hellos and the beats share one count and one book.
func (tm *MPTransportBridge) noteBeatRefused(peerID string) {
	tm.noteRefused(peerID, "beats")
}

// noteRefused counts a message of ours that the peer answered with REFUSED.
// what names it in the log: "hello" or "beats". It reports whether it had the
// peer looked up again.
func (tm *MPTransportBridge) noteRefused(peerID string, what string) bool {
	interval := tm.freshLookupInterval()
	tm.refusedHellosMu.Lock()
	r := tm.lookupBook(peerID)
	r.inARow++
	refused := r.inARow
	due := refused >= helloRefusalsBeforeRediscovery && time.Since(r.rediscovered) >= interval
	if due {
		r.rediscovered = time.Now()
	}
	tm.refusedHellosMu.Unlock()
	if !due {
		return false
	}
	// A peer that no zone names any more is not looked up: at the end of
	// comms the side that removes it last sees its beats refused (design 3.3).
	if !tm.zoneNamesPeer(peerID) {
		lgTransport.Debug("peer refuses our "+what+" and no zone names it any more, not looked up again",
			"peer", peerID, "refused", refused)
		return false
	}
	lgTransport.Warn("peer keeps refusing our "+what+", flushing IMR cache and discovering it again: the key held for it may not be the one it uses",
		"peer", peerID, "refused", refused)
	go tm.flushAndDiscover(peerID)
	return true
}

// noteHelloAccepted ends the peer's run of refused hellos and beats: the peer
// took a hello of ours, or a beat. When the peer was last looked up stays on
// the books: the interval holds across it.
func (tm *MPTransportBridge) noteHelloAccepted(peerID string) {
	tm.refusedHellosMu.Lock()
	if r := tm.refusedHellos[dns.CanonicalName(peerID)]; r != nil {
		r.inARow = 0
	}
	tm.refusedHellosMu.Unlock()
}
