/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent authorization checks for secure agent introduction.
 * Prevents discovery amplification attacks by requiring authorization before discovery.
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var lgAgent = tdns.Logger("agent")

// IsPeerAuthorized checks if a peer is authorized to communicate with us.
// Authorization can come from three sources:
//
// 1. Configured peers: Provided via AuthorizedPeers callback (role-specific)
// 2. LEGACY state: Established relationship with zero shared zones
// 3. HSYNC3 membership: Both peers listed in HSYNC3 RRset for a shared zone
//
// This function is role-agnostic. Each role injects its own AuthorizedPeers
// callback at TransportManager creation time.
//
// Parameters:
//   - senderID: Identity of the agent attempting to communicate
//   - zone: Optional zone name for HSYNC3 membership check (empty string skips HSYNC3 check)
//
// Returns:
//   - authorized: true if agent is authorized
//   - reason: human-readable explanation of authorization decision
func (tm *MPTransportBridge) IsPeerAuthorized(senderID string, zone string) (bool, string) {
	// Check 1: Authorization via role-specific configured peers
	// The AuthorizedPeers callback is injected at config time by each role.
	if tm.isAuthorizedPeer(senderID) {
		return true, "authorized via configured peer"
	}

	// Check 2: a peer this agent holds that shares no zone with it, whatever
	// its state. Such a peer is kept for the hold time and then removed (the
	// end of comms, design 3.1, decision 11); until then its hellos and beats
	// are taken, also once its beats have failed for a while and it reads
	// DEGRADED, a hello after its restart included. Every rule that asks for
	// a member refuses it. A removed peer is not in the registry, and is
	// refused here.
	if tm.agentRegistry.isKnownLegacy(senderID) {
		return true, "authorized via LEGACY state (a held peer with zero shared zones, whatever its state)"
	}

	// Check 3: Implicit authorization via HSYNC3 membership
	if zone != "" {
		// Specific zone provided - check HSYNC3 for that zone
		authorized, reason := tm.isInHSYNC(senderID, zone)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC3 membership for zone %s", zone)
		}
		lgAgent.Debug("sender not in HSYNC3", "sender", senderID, "zone", zone, "reason", reason)
		if tm.keyHandOverAdmits(senderID, zone) {
			return true, fmt.Sprintf("authorized for the hand-over of zone %s's SIG(0) key only", zone)
		}
	} else {
		// No specific zone - check if sender is in HSYNC3 for ANY zone we share
		// This is used for zone-agnostic operations like heartbeats
		authorized, foundZone := tm.isInHSYNCAnyZone(senderID)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC3 membership for zone %s", foundZone)
		}
	}

	// Not authorized via either path
	return false, fmt.Sprintf("not authorized (not in config or HSYNC3 for zone %q)", zone)
}

// isAuthorizedPeer checks if senderID is in the role-specific authorized peers list.
// The list is provided via the AuthorizedPeers callback in TransportManagerConfig.
// This replaces the former isConfiguredPeer + isInAuthorizedPeers methods which
// hardcoded role-specific Conf checks. Now any role (agent, combiner, signer, kdc, krs)
// provides its own callback returning the list of authorized peer identities.
func (tm *MPTransportBridge) isAuthorizedPeer(senderID string) bool {
	if tm.authorizedPeers == nil {
		return false
	}
	senderFQDN := dns.Fqdn(senderID)
	for _, peerID := range tm.authorizedPeers() {
		if dns.Fqdn(peerID) == senderFQDN {
			return true
		}
	}
	return false
}

// isInHSYNC checks whether senderID and our own identity are both members of
// the specified zone (zoneParticipants): an ON HSYNC3 record, with a role or
// without (plan S15), or a removal under way. This is the admission
// boundary where an OFF record, or no record, is rejected.
func (tm *MPTransportBridge) isInHSYNC(senderID string, zone string) (bool, string) {
	if zone == "" {
		return false, "empty zone name"
	}

	if tm.getZone == nil {
		return false, "no zone accessor configured"
	}

	// Check if we have this zone
	zd, exists := tm.getZone(zone)
	if !exists {
		return false, fmt.Sprintf("we don't know about zone %q", zone)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return false, fmt.Sprintf("zone %q apex unavailable", zone)
	}
	members := participantFQDNSet(zd.ZoneName, activeOr(zd.ZoneName, apex))
	if !members.has(tm.LocalID) {
		return false, fmt.Sprintf("our identity %q is not a member of zone %s", tm.LocalID, zone)
	}
	if !members.has(senderID) {
		return false, fmt.Sprintf("sender %q is not a member of zone %s", senderID, zone)
	}

	lgAgent.Debug("both identities are members", "local", tm.LocalID, "sender", senderID, "zone", zone)
	return true, ""
}

// isInHSYNCAnyZone checks if senderID is in the HSYNC3 RRset for ANY zone we share.
// This is used for zone-agnostic authorization (e.g., heartbeats, general peer communication).
// Returns true and the first matching zone name if found.
func (tm *MPTransportBridge) isInHSYNCAnyZone(senderID string) (bool, string) {
	if tm.getZoneNames == nil || tm.getZone == nil {
		return false, ""
	}

	// Iterate through all zones we know about
	for _, zoneName := range tm.getZoneNames() {
		zd, exists := tm.getZone(zoneName)
		if !exists {
			continue
		}
		apex, err := zd.GetOwner(zd.ZoneName)
		if err != nil || apex == nil {
			continue
		}
		members := participantFQDNSet(zd.ZoneName, activeOr(zd.ZoneName, apex))
		// Both our identity and the sender must be members of this zone.
		if members.has(tm.LocalID) && members.has(senderID) {
			lgAgent.Debug("both identities are members (any-zone check)",
				"local", tm.LocalID, "sender", senderID, "zone", zoneName)
			return true, zoneName
		}
	}

	// Not a shared member of any zone
	return false, ""
}

// --- The answer to a request for a zone's SIG(0) key from a non-member ---
//
// PR #217 let a provider that the zone lists with no role hand over the
// zone's SIG(0) key, which it may hold from when it led the zone's group:
// the request at the holder and the answer at the asker, between a voting
// member and a provider with no role, which admission refused then. From
// the switch (plan S15) such a provider is a member, and admission lets
// both in. What admission still refuses is the answer of an agent this
// agent asked that is no member under the active serial: a voting member
// under the zone's other serial (transitionVoters, plan S14), with no
// record under the active one.
//
// keyHandOverAdmits lets that answer in, and keyHandOverOnly lets nothing
// else through that came in that way.

// keyHandOverAdmits: a message about zone from senderID that isInHSYNC
// refuses is let in for the zone's SIG(0) key alone, when this agent has
// asked the sender for the zone's key and the answer is due (keyAsks).
func (tm *MPTransportBridge) keyHandOverAdmits(senderID, zone string) bool {
	return tm.keyAsks.open(senderID, dns.Fqdn(zone))
}

// admittedForKeyOnly: the message came in through keyHandOverAdmits alone.
// The checks that admit a message in full are asked again, and only when
// they refuse it.
func (tm *MPTransportBridge) admittedForKeyOnly(senderID, zone string) bool {
	if zone == "" || tm.isAuthorizedPeer(senderID) {
		return false
	}
	if tm.agentRegistry.isKnownLegacy(senderID) {
		return false
	}
	ok, _ := tm.isInHSYNC(senderID, zone)
	return !ok
}

// keyHandOverGate is the router middleware that applies keyHandOverOnly
// before the verb handlers run: a message let in for the zone's SIG(0) key
// alone that is not about the key is refused, and no handler takes it or
// acknowledges it as taken. As in refuseNamedSender, the refusal is the
// rcode the outermost reply middleware answers with, and keyHandOverOnly's
// warning is its log line: nothing goes on to the next middleware, so no
// handler error is logged.
func (tm *MPTransportBridge) keyHandOverGate(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
	if msg, ok := ctx.Incoming(); ok && !tm.keyHandOverOnly(msg) {
		ctx.SetResponseRcode(dns.RcodeRefused)
		return nil
	}
	return next(ctx)
}

// keyHandOverOnly: a message that came in for the zone's SIG(0) key alone
// (admittedForKeyOnly) is the request for the key, its answer, or the
// delivery confirmation of either. Anything else that came in that way is
// not acted on.
func (tm *MPTransportBridge) keyHandOverOnly(msg *transport.IncomingMessage) bool {
	// The sender is the one admission judged: the transport's, never the
	// author the payload names.
	sender := msg.TransportSender
	if !tm.admittedForKeyOnly(sender, msg.Zone) {
		return true
	}
	switch msg.Token() {
	case "confirm":
		// The delivery confirmation of the key's request or of its answer,
		// and of no other message: its distribution id is one this agent
		// sent the key exchange with, to this sender (expectConfirm).
		var p transport.DnsConfirmPayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil && tm.keyAsks.confirmExpected(sender, p.DistributionID) {
			return true
		}
	case "rfi":
		// Routed by the payload's MessageType, which defaults to a sync
		// (routeSyncMessage): the payload must say rfi itself, and carry
		// nothing an update would apply.
		if p, err := ParseSyncPayload(msg.Payload); err == nil && p.MessageType == string(AgentMsgRfi) &&
			p.RfiType == "CONFIG" && p.RfiSubtype == "sig0key" && len(p.GetRecords()) == 0 && len(p.GetOperations()) == 0 {
			return true
		}
	case "config":
		var p DnsConfigPayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil && p.Subtype == "sig0key" {
			return true
		}
	}
	lgAgent.Warn("a message let in for the zone's SIG(0) key alone is not about the key, refusing",
		"sender", sender, "zone", msg.Zone, "type", msg.Token())
	return false
}

// keyAskTable is the requests for a zone's SIG(0) key this agent has out,
// by peer and zone: an answer from that peer about that zone is due. And the
// distribution ids of the key exchange's own messages, by the peer they went
// to, whose delivery confirmations are due (expectConfirm).
type keyAskTable struct {
	mu       sync.Mutex
	asks     map[string]int
	confirms map[string]keyConfirm
}

// keyConfirm is a delivery confirmation due from peer until expires.
type keyConfirm struct {
	peer    string
	expires time.Time
}

// keyConfirmWait is how long a key exchange message's delivery confirmation
// is let in: well past the transport's retries.
const keyConfirmWait = 5 * time.Minute

// expectConfirm notes a key exchange message sent to peer under id.
func (t *keyAskTable) expectConfirm(peer, id string) {
	if id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.confirms == nil {
		t.confirms = map[string]keyConfirm{}
	}
	now := time.Now()
	for k, c := range t.confirms {
		if now.After(c.expires) {
			delete(t.confirms, k)
		}
	}
	t.confirms[id] = keyConfirm{peer: canonicalName(peer), expires: now.Add(keyConfirmWait)}
}

// confirmExpected: a delivery confirmation from peer for id is due.
func (t *keyAskTable) confirmExpected(peer, id string) bool {
	if id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.confirms[id]
	return ok && c.peer == canonicalName(peer) && time.Now().Before(c.expires)
}

// keyAskKey: identities and zone names compare as canonical names, so a
// peer configured in another case is the same peer.
func keyAskKey(peer, zone string) string {
	return canonicalName(peer) + " " + canonicalName(zone)
}

// start notes a request out, and returns the call that ends it. The call
// ends that request once, however often it is made: a second call never
// ends another request to the same peer for the same zone.
func (t *keyAskTable) start(peer, zone string) func() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.asks == nil {
		t.asks = map[string]int{}
	}
	k := keyAskKey(peer, zone)
	t.asks[k]++
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.asks[k]--; t.asks[k] <= 0 {
				delete(t.asks, k)
			}
		})
	}
}

func (t *keyAskTable) open(peer, zone string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.asks[keyAskKey(peer, zone)] > 0
}
