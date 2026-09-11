/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent authorization checks for secure agent introduction.
 * Prevents discovery amplification attacks by requiring authorization before discovery.
 */

package tdnsmp

import (
	"fmt"

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

	// Check 2: LEGACY state agents (established relationship, zero zones)
	// These agents were previously in HSYNC3 but all shared zones have been removed
	// We still allow beat messages to maintain the relationship
	if tm.agentRegistry != nil {
		if agent, exists := tm.agentRegistry.S.Get(AgentId(dns.Fqdn(senderID))); exists {
			if agent.State == AgentStateLegacy {
				return true, "authorized via LEGACY state (established relationship, zero shared zones)"
			}
		}
	}

	// Check 3: Implicit authorization via HSYNC3 membership
	if zone != "" {
		// Specific zone provided - check HSYNC3 for that zone
		authorized, reason := tm.isInHSYNC(senderID, zone)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC3 membership for zone %s", zone)
		}
		lgAgent.Debug("sender not in HSYNC3", "sender", senderID, "zone", zone, "reason", reason)
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

// isInHSYNC checks whether senderID and our own identity are both participants
// (HSYNCPARAM role-holders) in the specified zone. Membership is derived, not raw
// HSYNC3 co-presence: an identity listed in HSYNC3 but granted no role is NOT
// authorized — this is the admission boundary where role-less/OFF identities are
// rejected.
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
	members := participantFQDNSetForApex(apex)
	if !members[dns.Fqdn(tm.LocalID)] {
		return false, fmt.Sprintf("our identity %q is not a participant in zone %s", tm.LocalID, zone)
	}
	if !members[dns.Fqdn(senderID)] {
		return false, fmt.Sprintf("sender %q is not a participant in zone %s", senderID, zone)
	}

	lgAgent.Debug("both identities are participants", "local", tm.LocalID, "sender", senderID, "zone", zone)
	return true, ""
}

// isInHSYNCAnyZone checks if senderID is in the HSYNC3 RRset for ANY zone we share.
// This is used for zone-agnostic authorization (e.g., heartbeats, general peer communication).
// Returns true and the first matching zone name if found.
func (tm *MPTransportBridge) isInHSYNCAnyZone(senderID string) (bool, string) {
	if tm.getZoneNames == nil || tm.getZone == nil {
		return false, ""
	}

	localFQDN := dns.Fqdn(tm.LocalID)
	senderFQDN := dns.Fqdn(senderID)

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
		members := participantFQDNSetForApex(apex)
		// Both our identity and the sender must be participants in this zone.
		if members[localFQDN] && members[senderFQDN] {
			lgAgent.Debug("both identities are participants (any-zone check)",
				"local", tm.LocalID, "sender", senderID, "zone", zoneName)
			return true, zoneName
		}
	}

	// Not a shared participant in any zone
	return false, ""
}
