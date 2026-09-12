/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Application verb handlers (transport redesign, Stage C3).
 *
 * These are the per-verb receive handlers that lived in
 * tdns-transport/transport/handlers.go until C3: they validate the
 * payload, store the parsed message on the context for the RouteToCallback
 * seam, and prepare the inline confirmation the sender reads from the DNS
 * response. The verb table in mp_verbs.go registers them on the router per
 * role and dispatches the callback. The context is read and written through
 * transport's typed accessors (cleanup plan, steps 1 and 2); the parsed
 * message is always present, RouteViaRouter stores it before the router is
 * entered.
 *
 * Do not add MP business logic here; that stays in the route* functions
 * (hsync_transport.go) which the table calls after the handler.
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// handleAppSync processes sync messages and sends acknowledgment.
func handleAppSync(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing sync", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// LEGACY gate (C3 moved it here; C7 keyed it on MP's own participant
	// view): an established peer with zero shared participant zones must
	// not send sync messages (only beats). Unknown senders were already
	// vetted by the authorization middleware and pass through.
	if tm != nil && tm.agentRegistry != nil && tm.agentRegistry.isKnownLegacy(ctx.PeerID) {
		// Agent is LEGACY (zero shared zones) - reject sync with informative error payload
		lgTransport.Warn("rejecting sync from LEGACY agent (zero shared zones)", "peer", ctx.PeerID)
		errorPayload := struct {
			Type           string `json:"type"`
			DistributionID string `json:"distribution_id"`
			Status         string `json:"status"`
			Message        string `json:"message"`
			Timestamp      int64  `json:"timestamp"`
		}{
			Type:           "error",
			DistributionID: ctx.DistributionID,
			Status:         "rejected",
			Message:        fmt.Sprintf("LEGACY agent %s cannot send sync messages (zero shared zones); re-introduce via HELLO with updated HSYNC zones", ctx.PeerID),
			Timestamp:      time.Now().Unix(),
		}
		payloadBytes, err := json.Marshal(errorPayload)
		if err == nil {
			ctx.SetResponsePayload(payloadBytes)
			ctx.SetResponseRcode(dns.RcodeRefused)
		}
		return fmt.Errorf("LEGACY agent %s cannot send sync messages (zero shared zones)", ctx.PeerID)
	}

	// The parsed message, stored by RouteViaRouter before the router was entered.
	syncMsg, ok := ctx.Incoming()
	if !ok {
		return fmt.Errorf("sync handler: no parsed message in context")
	}

	if syncMsg.Token() != "sync" {
		return fmt.Errorf("invalid message type for sync handler: %s", syncMsg.Token())
	}

	ctx.SetHandledType("sync")

	// Create sync acknowledgment response — format must match extractConfirmFromResponse
	ack := map[string]interface{}{
		"type":            "confirm",
		"status":          "ok",
		"distribution_id": ctx.DistributionID,
		"message":         fmt.Sprintf("sync received from %s", ctx.PeerID),
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		lgTransport.Error("failed to marshal sync acknowledgment", "err", err)
		// Don't return error - ack failure shouldn't prevent sync processing
	} else {
		// Store acknowledgment in context for response middleware
		ctx.SetResponsePayload(ackPayload)
		lgTransport.Debug("sync acknowledgment prepared", "peer", ctx.PeerID, "distrib", ctx.DistributionID)
	}

	lgTransport.Debug("sync processed", "peer", ctx.PeerID)
	return nil
}

// handleAppRfi processes RFI (Request For Information) messages.
func handleAppRfi(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing RFI", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// The parsed message, stored by RouteViaRouter before the router was entered.
	rfiMsg, ok := ctx.Incoming()
	if !ok {
		return fmt.Errorf("rfi handler: no parsed message in context")
	}

	if rfiMsg.Token() != "rfi" {
		return fmt.Errorf("invalid message type for rfi handler: %s", rfiMsg.Token())
	}

	ctx.SetHandledType("rfi")

	// Create RFI acknowledgment response — format must match extractConfirmFromResponse
	ack := map[string]interface{}{
		"type":            "confirm",
		"status":          "ok",
		"distribution_id": ctx.DistributionID,
		"message":         fmt.Sprintf("rfi received from %s", ctx.PeerID),
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		lgTransport.Error("failed to marshal rfi acknowledgment", "err", err)
	} else {
		ctx.SetResponsePayload(ackPayload)
		lgTransport.Debug("RFI acknowledgment prepared", "peer", ctx.PeerID, "distrib", ctx.DistributionID)
	}

	lgTransport.Debug("RFI processed", "peer", ctx.PeerID)
	return nil
}

// handleAppKeystate processes KEYSTATE messages for key lifecycle signaling.
// Used for agent↔signer communication about DNSKEY propagation status.
// Signals: propagated, rejected, removed (agent→signer), published, retired (signer→agent).
func handleAppKeystate(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing keystate", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the keystate message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
	var keystate DnsKeystatePayload
	if err := json.Unmarshal(ctx.ChunkPayload, &keystate); err != nil {
		return fmt.Errorf("failed to parse keystate: %w", err)
	}

	// Validate message type
	msgType := keystate.MessageType
	if msgType == "" {
		msgType = keystate.Type
	}
	if msgType != "keystate" {
		return fmt.Errorf("invalid message type for keystate handler: %s", msgType)
	}

	// Validate signal
	switch keystate.Signal {
	case "propagated", "rejected", "removed", "published", "retired":
		// per-key signals
	case "inventory":
		// full inventory signal — KeyInventory carries the data, KeyTag not required
	default:
		return fmt.Errorf("unknown keystate signal: %q", keystate.Signal)
	}

	if keystate.Zone == "" {
		return fmt.Errorf("keystate message missing zone")
	}
	if keystate.Signal == "inventory" {
		// Empty inventory is valid (signer has no keys for this zone).
		// The recipient decides what to do with it.
	} else if keystate.KeyTag == 0 {
		return fmt.Errorf("keystate message missing key tag")
	}

	// Store for processing by the recipient (signer or agent)
	ctx.SetHandledType("keystate")
	ctx.SetIncoming(&transport.IncomingMessage{
		TypeToken: "keystate",
		SenderID:  keystate.GetSenderID(),
		Zone:      keystate.Zone,
		Payload:   ctx.ChunkPayload,
	})

	// Create confirmation response using standard "confirm" type so sendNotifyWithPayload
	// can extract it via extractConfirmFromResponse
	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("keystate %s received for zone %s", keystate.Signal, keystate.Zone),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal keystate confirmation: %w", err)
	}

	// Store confirmation in context for response middleware
	ctx.SetResponsePayload(payloadBytes)

	if keystate.Signal == "inventory" {
		lgTransport.Info("keystate inventory received", "peer", ctx.PeerID, "zone", keystate.Zone, "keys", len(keystate.KeyInventory))
	} else {
		lgTransport.Info("keystate processed", "signal", keystate.Signal, "peer", ctx.PeerID, "keytag", keystate.KeyTag, "zone", keystate.Zone)
	}
	return nil
}

// handleAppEdits processes EDITS messages carrying an agent's current contributions
// from the combiner. Modeled on HandleKeystate.
// Sent by the combiner in response to an RFI EDITS request.
func handleAppEdits(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing edits", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// Parse the edits message.
	// Size bounded: ctx.ChunkPayload originates from a DNS message (max ~65535 bytes over TCP).
	var edits DnsEditsPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &edits); err != nil {
		return fmt.Errorf("failed to parse edits: %w", err)
	}

	// Validate message type
	msgType := edits.MessageType
	if msgType == "" {
		msgType = edits.Type
	}
	if msgType != "edits" {
		return fmt.Errorf("invalid message type for edits handler: %s", msgType)
	}

	if edits.Zone == "" {
		return fmt.Errorf("edits message missing zone")
	}

	// Store for processing by the agent
	ctx.SetHandledType("edits")
	ctx.SetIncoming(&transport.IncomingMessage{
		TypeToken: "edits",
		SenderID:  edits.GetSenderID(),
		Zone:      edits.Zone,
		Payload:   ctx.ChunkPayload,
	})

	// Create confirmation response using standard "confirm" type
	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("edits received for zone %s (%d agents)", edits.Zone, len(edits.AgentRecords)),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal edits confirmation: %w", err)
	}

	ctx.SetResponsePayload(payloadBytes)

	lgTransport.Info("edits received", "peer", ctx.PeerID, "zone", edits.Zone, "agents", len(edits.AgentRecords))
	return nil
}

// handleAppConfig processes CONFIG response messages carrying config data from a peer agent.
// Sent by the receiving agent in response to an RFI CONFIG request.
func handleAppConfig(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing config", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	var config DnsConfigPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	msgType := config.MessageType
	if msgType == "" {
		msgType = config.Type
	}
	if msgType != "config" {
		return fmt.Errorf("invalid message type for config handler: %s", msgType)
	}

	if config.Zone == "" {
		return fmt.Errorf("config message missing zone")
	}

	ctx.SetHandledType("config")
	ctx.SetIncoming(&transport.IncomingMessage{
		TypeToken: "config",
		SenderID:  config.GetSenderID(),
		Zone:      config.Zone,
		Payload:   ctx.ChunkPayload,
	})

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("config received for zone %s subtype %s", config.Zone, config.Subtype),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal config confirmation: %w", err)
	}

	ctx.SetResponsePayload(payloadBytes)

	lgTransport.Info("config received", "peer", ctx.PeerID, "zone", config.Zone, "subtype", config.Subtype)
	return nil
}

// handleAppAudit processes AUDIT response messages carrying audit data from a peer agent.
// Sent by the receiving agent in response to an RFI AUDIT request.
func handleAppAudit(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing audit", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	var audit DnsAuditPayload
	if err := json.Unmarshal(ctx.ChunkPayload, &audit); err != nil {
		return fmt.Errorf("failed to parse audit: %w", err)
	}

	msgType := audit.MessageType
	if msgType == "" {
		msgType = audit.Type
	}
	if msgType != "audit" {
		return fmt.Errorf("invalid message type for audit handler: %s", msgType)
	}

	if audit.Zone == "" {
		return fmt.Errorf("audit message missing zone")
	}

	ctx.SetHandledType("audit")
	ctx.SetIncoming(&transport.IncomingMessage{
		TypeToken: "audit",
		SenderID:  audit.GetSenderID(),
		Zone:      audit.Zone,
		Payload:   ctx.ChunkPayload,
	})

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("audit received for zone %s", audit.Zone),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal audit confirmation: %w", err)
	}

	ctx.SetResponsePayload(payloadBytes)

	lgTransport.Info("audit received", "peer", ctx.PeerID, "zone", audit.Zone)
	return nil
}

// handleAppStatusUpdate processes STATUS-UPDATE messages.
// Used for combiner→agent notifications (delegation changes) and
// agent→agent notifications (parent sync completed).
func handleAppStatusUpdate(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing status-update", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	var statusUpdate DnsStatusUpdatePayload
	if err := json.Unmarshal(ctx.ChunkPayload, &statusUpdate); err != nil {
		return fmt.Errorf("failed to parse status-update: %w", err)
	}

	msgType := statusUpdate.MessageType
	if msgType == "" {
		msgType = statusUpdate.Type
	}
	if msgType != "status-update" {
		return fmt.Errorf("invalid message type for status-update handler: %s", msgType)
	}

	if statusUpdate.Zone == "" {
		return fmt.Errorf("status-update message missing zone")
	}

	ctx.SetHandledType("status-update")
	ctx.SetIncoming(&transport.IncomingMessage{
		TypeToken: "status-update",
		SenderID:  statusUpdate.GetSenderID(),
		Zone:      statusUpdate.Zone,
		Payload:   ctx.ChunkPayload,
	})

	confirmPayload := struct {
		Type           string `json:"type"`
		DistributionID string `json:"distribution_id"`
		Status         string `json:"status"`
		Message        string `json:"message"`
		Timestamp      int64  `json:"timestamp"`
	}{
		Type:           "confirm",
		DistributionID: ctx.DistributionID,
		Status:         "ok",
		Message:        fmt.Sprintf("status-update received for zone %s", statusUpdate.Zone),
		Timestamp:      time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(confirmPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal status-update confirmation: %w", err)
	}

	ctx.SetResponsePayload(payloadBytes)

	lgTransport.Info("status-update received", "peer", ctx.PeerID, "zone", statusUpdate.Zone, "subtype", statusUpdate.SubType)
	return nil
}

// handleAppRelocate processes relocate messages for DDoS mitigation.
func handleAppRelocate(tm *MPTransportBridge, ctx *transport.MessageContext) error {
	lgTransport.Debug("processing relocate", "peer", ctx.PeerID, "distrib", ctx.DistributionID)

	// The parsed message, stored by RouteViaRouter before the router was entered.
	relocateMsg, ok := ctx.Incoming()
	if !ok {
		return fmt.Errorf("relocate handler: no parsed message in context")
	}

	if relocateMsg.Token() != "relocate" {
		return fmt.Errorf("invalid message type for relocate handler: %s", relocateMsg.Token())
	}

	ctx.SetHandledType("relocate")

	lgTransport.Debug("relocate processed", "peer", ctx.PeerID)
	return nil
}
