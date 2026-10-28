/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A rule for the sender of every message (the membership design, 3; the
 * plan's 3.2 and step 6). The payload of a message to an agent or an
 * auditor names the sender the transport established, and each kind of
 * message asks that sender for a standing in the zone it is about.
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// canonicalName is a name as the sender rules compare names: in lower
// case, with its trailing dot.
func canonicalName(name string) string {
	if name == "" {
		return ""
	}
	return core.CanonicalizeName(dns.Fqdn(name))
}

// refuseNamedSender is the router middleware of the agent and the auditor:
// a message whose payload names another sender than the one the transport
// established (the context's peer: the name in the query name over DNS,
// the client certificate's name over HTTPS), or names none, is refused
// before any handler runs. Every sender in tdns-mp and tdns-transport names
// itself, the agent's own combiner and signer included. The refusal is the
// rcode the outermost reply middleware answers with; nothing goes on to the
// next middleware, so no handler error is logged. A combiner's or a
// signer's router does not get it: there the deliverer and the named origin
// differ by design.
func (tm *MPTransportBridge) refuseNamedSender(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
	msg, ok := ctx.Incoming()
	if !ok {
		return next(ctx)
	}
	sender := ctx.PeerID
	if sender == "" {
		sender = msg.TransportSender
	}
	if sender == "" {
		// nothing the transport established to compare with; the route
		// functions drop such a message
		return next(ctx)
	}
	switch {
	case msg.SenderID == "":
		lgTransport.Warn("message refused: its payload names no sender", "verb", msg.Token(), "sender", sender)
	case canonicalName(msg.SenderID) != canonicalName(sender):
		lgTransport.Warn("message refused: its payload names another sender than the one it came from",
			"verb", msg.Token(), "named", msg.SenderID, "sender", sender)
	default:
		return next(ctx)
	}
	ctx.SetResponseRcode(dns.RcodeRefused)
	return nil
}

// keystateSenderRefusal is the rule for a KEYSTATE's sender (the membership
// design, 3): an agent takes one only from its own signer, and a signer only
// from its own agents, the ones its configuration names. A KEYSTATE moves
// the zone's key inventory, its own read and its DS intent at an agent, and
// the key lifecycle at a signer; admission lets in every member of a zone
// and a held peer, which is not that. The other roles keep what admission
// lets in.
func (tm *MPTransportBridge) keystateSenderRefusal(role, sender string) string {
	switch role {
	case roleAgent:
		if sender == "" || tm.signerID == "" || canonicalName(sender) != canonicalName(tm.signerID) {
			return fmt.Sprintf("keystate refused: %s is not this agent's signer", sender)
		}
	case roleSigner:
		if sender != "" && tm.authorizedPeers != nil {
			for _, a := range tm.authorizedPeers() {
				if canonicalName(a) == canonicalName(sender) {
					return ""
				}
			}
		}
		return fmt.Sprintf("keystate refused: %s is not one of this signer's agents", sender)
	}
	return ""
}

// refuseForeignKeystate is the router middleware of an agent and a signer
// for a KEYSTATE's sender (keystateSenderRefusal). It runs before the
// message is handled and routed: a refusal is REFUSED and a warning, as the
// other sender rules refuse, and nothing goes on, so no handler error is
// logged and the message reaches no queue. The sender is the one the
// transport established.
func (tm *MPTransportBridge) refuseForeignKeystate(ctx *transport.MessageContext, next transport.MessageHandlerFunc) error {
	msg, ok := ctx.Incoming()
	if !ok || msg.Token() != "keystate" {
		return next(ctx)
	}
	sender := ctx.PeerID
	if sender == "" {
		sender = msg.TransportSender
	}
	if why := tm.keystateSenderRefusal(tm.role, sender); why != "" {
		lgTransport.Warn("keystate refused: not from this agent's signer or this signer's agent",
			"role", tm.role, "sender", sender, "zone", msg.Zone, "reason", why)
		ctx.SetResponseRcode(dns.RcodeRefused)
		return nil
	}
	return next(ctx)
}

// refuseWithReason answers a message with a refusal that carries its
// reason, as the refusal of a LEGACY peer's sync does: REFUSED, and a
// payload that says why.
func refuseWithReason(ctx *transport.MessageContext, reason string) error {
	payload, err := json.Marshal(struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "error",
		DistributionID: ctx.DistributionID,
		Status:         "rejected",
		Message:        reason,
		Timestamp:      time.Now().Unix(),
	})
	if err == nil {
		ctx.SetResponsePayload(payload)
		ctx.SetResponseRcode(dns.RcodeRefused)
	}
	return fmt.Errorf("%s", reason)
}

// syncSenderRefusal: a SYNC whose sender is not a voting member of the zone
// is refused (design 3.3). A zone with no HSYNC3 records here has no
// standings, and is left as it is.
func syncSenderRefusal(zone ZoneName, sender string) string {
	if zone == "" || votesInZone(zone, AgentId(sender)) {
		return ""
	}
	return fmt.Sprintf("sync refused: %s is not a voting member of zone %s", sender, zone)
}

// rfiSenderRefusal is the plan's 3.2 for an RFI to an agent or an auditor,
// by its type: RFI SYNC and RFI AUDIT ask that the sender be a member of
// the zone; CONFIG upstream and downstream that it be a member, related to
// this agent by an ON record's upstream field, and not an auditor only.
// Each asks that this agent have a standing in the zone, as admission does.
// Every other type passes: the election's (step 1 checks those), and CONFIG
// sig0key, which MsgHandler answers to any voting member and which a holder
// with no role lets in for the key alone (keyHandOverGate).
func (tm *MPTransportBridge) rfiSenderRefusal(zone ZoneName, sender, rfiType, subtype string) string {
	member := func() string {
		participants, _ := participantsOf(instructionsFor(zone))
		if !isAmong(participants, AgentId(tm.LocalID)) {
			return fmt.Sprintf("rfi %s refused: this agent is not a member of zone %s", rfiType, zone)
		}
		if !isAmong(participants, AgentId(sender)) {
			return fmt.Sprintf("rfi %s refused: %s is not a member of zone %s", rfiType, sender, zone)
		}
		return ""
	}
	switch rfiType {
	case "SYNC", "AUDIT":
		return member()
	case "CONFIG":
		if subtype != "upstream" && subtype != "downstream" {
			return ""
		}
		if why := member(); why != "" {
			return why
		}
		if zoneStanding(instructionsFor(zone), sender) == standingAuditor {
			return fmt.Sprintf("rfi CONFIG %s refused: %s is an auditor only in zone %s", subtype, sender, zone)
		}
		ar := tm.agentRegistry
		if ar == nil {
			return ""
		}
		zad, err := ar.GetZoneAgentData(zone)
		if err != nil {
			return fmt.Sprintf("rfi CONFIG %s refused: %v", subtype, err)
		}
		related := false
		switch subtype {
		case "upstream": // the sender has this agent as its upstream
			for _, d := range zad.MyDownstreams {
				related = related || canonicalName(string(d)) == canonicalName(sender)
			}
		case "downstream": // the sender is this agent's upstream
			related = canonicalName(string(zad.MyUpstream)) == canonicalName(sender)
		}
		if !related {
			return fmt.Sprintf("rfi CONFIG %s refused: %s is not related to this agent in zone %s by an ON record's upstream", subtype, sender, zone)
		}
	}
	return ""
}

// ownInfraPeer: the agent's own combiner or signer, to which the rules for
// peers do not apply.
func (tm *MPTransportBridge) ownInfraPeer(sender string) bool {
	return canonicalName(sender) == canonicalName(string(tm.combinerID)) || canonicalName(sender) == canonicalName(tm.signerID)
}
