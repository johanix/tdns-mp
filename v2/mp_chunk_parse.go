/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Application payload parsing for the receive path (transport redesign,
 * Stage C5). tdns-transport fetches and decrypts a CHUNK payload and then
 * asks the application, through ChunkNotifyHandler.ParseApp, for the verb,
 * the application-level sender, the scope (zone) and the nonce. The field
 * names — MessageType/type, OriginatorID/MyIdentity/sender_id, Zone/zone,
 * nonce, Zones — are the multi-provider wire conventions and live here.
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// parseAppPayload is installed as ChunkNotifyHandler.ParseApp on every role.
func parseAppPayload(distributionID string, payload []byte, sourceAddr string) (*transport.IncomingMessage, error) {
	var fields struct {
		MessageType  string   `json:"MessageType"`  // Standard format ("sync", "update", "beat", ...)
		Type         string   `json:"type"`         // Legacy format (fallback)
		OriginatorID string   `json:"OriginatorID"` // Sync/update messages
		MyIdentity   string   `json:"MyIdentity"`   // Hello/beat/ping messages
		SenderID     string   `json:"sender_id"`    // Legacy
		Zone         string   `json:"Zone"`
		LegacyZone   string   `json:"zone"`  // Legacy
		Nonce        string   `json:"nonce"` // Nonce for replay protection
		Zones        []string `json:"Zones"` // Beats: shared zones; the first is the authorization scope
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}
	// Reject messages that set both standard and legacy fields to different
	// values: an attacker must not be able to make routing and
	// authorization read different verbs or zones.
	if fields.MessageType != "" && fields.Type != "" && fields.MessageType != fields.Type {
		return nil, fmt.Errorf("conflicting message type fields: MessageType=%q vs type=%q", fields.MessageType, fields.Type)
	}
	if fields.Zone != "" && fields.LegacyZone != "" && fields.Zone != fields.LegacyZone {
		return nil, fmt.Errorf("conflicting zone fields: Zone=%q vs zone=%q", fields.Zone, fields.LegacyZone)
	}
	msgType := fields.MessageType
	if msgType == "" {
		msgType = fields.Type
	}
	if msgType == "" {
		return nil, fmt.Errorf("no message type found in payload")
	}
	// Sender precedence: OriginatorID (sync/update), MyIdentity (hello/beat/ping), sender_id (legacy).
	senderID := fields.OriginatorID
	if senderID == "" {
		senderID = fields.MyIdentity
	}
	if senderID == "" {
		senderID = fields.SenderID
	}
	zone := fields.Zone
	if zone == "" {
		zone = fields.LegacyZone
	}
	if zone == "" && msgType == "beat" && len(fields.Zones) > 0 {
		// A beat has no single zone; its first shared zone is the scope
		// the zone-peer authorization check uses.
		zone = fields.Zones[0]
	}
	return &transport.IncomingMessage{
		TypeToken:      msgType,
		DistributionID: distributionID,
		SenderID:       senderID,
		Zone:           zone,
		Nonce:          fields.Nonce,
		Payload:        payload,
		ReceivedAt:     time.Now(),
		SourceAddr:     sourceAddr,
	}, nil
}
