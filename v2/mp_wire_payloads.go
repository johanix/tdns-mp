/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Wire payload types for the application verbs (transport redesign, Stage
 * C6). Moved verbatim from tdns-transport/transport/dns.go, transport.go and
 * handler.go: the JSON tags ARE the wire, and golden_wire_test.go locks
 * every one of them. Transport keeps only its own verbs' payloads (hello,
 * beat, ping, ping_confirm, confirm).
 */

package tdnsmp

import (
	"encoding/json"

	"github.com/johanix/tdns/v2/core"
)

// DnsSyncPayload represents a sync message payload.
type DnsSyncPayload struct {
	MessageType    string                   `json:"MessageType"`
	OriginatorID   string                   `json:"OriginatorID"`
	YourIdentity   string                   `json:"YourIdentity"`
	Zone           string                   `json:"Zone"`
	Nonce          string                   `json:"nonce,omitempty"`      // Nonce for replay protection (echoed in confirmation)
	Records        map[string][]string      `json:"Records"`              // RRs grouped by owner name (legacy: Class-overloaded)
	Operations     []core.RROperation       `json:"Operations,omitempty"` // Explicit operations (takes precedence over Records)
	Time           string                   `json:"Time"`                 // RFC3339 timestamp
	RfiType        string                   `json:"RfiType"`
	RfiSubtype     string                   `json:"rfi_subtype,omitempty"`
	Timestamp      int64                    `json:"timestamp"` // Unix timestamp (legacy compat)
	DistributionID string                   `json:"distribution_id"`
	ZoneClass      string                   `json:"zone_class,omitempty"`
	Publish        *core.PublishInstruction `json:"publish,omitempty"`
}

// GetPublish returns the publish instruction (may be nil).
func (d *DnsSyncPayload) GetPublish() *core.PublishInstruction {
	return d.Publish
}

// DnsAddress represents an address in DNS payloads.
type DnsAddress struct {
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
	Path      string `json:"path,omitempty"`
}

// DnsRelocatePayload represents a relocate message payload.
type DnsRelocatePayload struct {
	Type       string     `json:"type"`
	SenderID   string     `json:"sender_id"`
	NewAddress DnsAddress `json:"new_address"`
	Reason     string     `json:"reason"`
	ValidUntil int64      `json:"valid_until"`
}

// GetSenderID returns the sender ID.
func (d *DnsSyncPayload) GetSenderID() string {
	return d.OriginatorID
}

// GetRecords returns records grouped by owner name.
func (d *DnsSyncPayload) GetRecords() map[string][]string {
	return d.Records
}

// GetOperations returns explicit operations (takes precedence over Records).
func (d *DnsSyncPayload) GetOperations() []core.RROperation {
	return d.Operations
}

// DnsKeystatePayload represents a KEYSTATE message payload.
// Used for agent↔signer key lifecycle signaling.
type DnsKeystatePayload struct {
	// Standard fields
	MessageType  string `json:"MessageType"`  // "keystate"
	MyIdentity   string `json:"MyIdentity"`   // Sender identity
	YourIdentity string `json:"YourIdentity"` // Recipient identity

	// KEYSTATE-specific fields
	Zone         string              `json:"Zone"`                   // Zone this key belongs to (FQDN)
	KeyTag       uint16              `json:"KeyTag"`                 // DNSKEY key tag (unused for inventory)
	Algorithm    uint8               `json:"Algorithm"`              // DNSKEY algorithm number (unused for inventory)
	Signal       string              `json:"Signal"`                 // "propagated", "rejected", "removed", "published", "retired", "inventory"
	Message      string              `json:"Message,omitempty"`      // Optional detail (e.g. rejection reason)
	KeyInventory []KeyInventoryEntry `json:"KeyInventory,omitempty"` // Complete key inventory (only when Signal == "inventory")
	Timestamp    int64               `json:"timestamp"`              // Unix timestamp

	// Legacy fields (fallback)
	Type     string `json:"type"`      // "keystate"
	SenderID string `json:"sender_id"` // Sender identity (legacy)
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsKeystatePayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// DnsKeystateConfirmPayload is the response to a KEYSTATE message.
type DnsKeystateConfirmPayload struct {
	Type      string `json:"type"`              // "keystate_confirm"
	SenderID  string `json:"sender_id"`         // Responder identity
	Zone      string `json:"zone"`              // Echoed zone
	KeyTag    uint16 `json:"key_tag"`           // Echoed key tag
	Signal    string `json:"signal"`            // Echoed signal
	Status    string `json:"status"`            // "ok" or "error"
	Message   string `json:"message,omitempty"` // Optional detail
	Timestamp int64  `json:"timestamp"`
}

// DnsEditsPayload represents an EDITS message payload.
// Carries an agent's current contributions from combiner back to the agent.
// Modeled on DnsKeystatePayload.
type DnsEditsPayload struct {
	// Standard fields
	MessageType  string `json:"MessageType"`  // "edits"
	MyIdentity   string `json:"MyIdentity"`   // Sender (combiner) identity
	YourIdentity string `json:"YourIdentity"` // Recipient (agent) identity

	// EDITS-specific fields
	Zone         string                         `json:"Zone"`                   // Zone (FQDN)
	AgentRecords map[string]map[string][]string `json:"AgentRecords,omitempty"` // All agents' contributions (agentID → owner → []RR strings)
	Message      string                         `json:"Message,omitempty"`      // Optional status message

	Timestamp int64 `json:"timestamp"` // Unix timestamp

	// Legacy fields (fallback)
	Type     string `json:"type"`      // "edits"
	SenderID string `json:"sender_id"` // Sender identity (legacy)
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsEditsPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// DnsConfigPayload represents a CONFIG response message payload.
// Carries config data from a peer agent back to the requester.
type DnsConfigPayload struct {
	MessageType  string            `json:"MessageType"`
	MyIdentity   string            `json:"MyIdentity"`
	YourIdentity string            `json:"YourIdentity"`
	Zone         string            `json:"Zone"`
	Subtype      string            `json:"Subtype"`
	ConfigData   map[string]string `json:"ConfigData,omitempty"`
	Message      string            `json:"Message,omitempty"`
	Timestamp    int64             `json:"timestamp"`
	Type         string            `json:"type"`
	SenderID     string            `json:"sender_id"`
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsConfigPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// DnsAuditPayload represents an AUDIT response message payload.
// Carries audit data from a peer agent back to the requester.
type DnsAuditPayload struct {
	MessageType  string      `json:"MessageType"`
	MyIdentity   string      `json:"MyIdentity"`
	YourIdentity string      `json:"YourIdentity"`
	Zone         string      `json:"Zone"`
	AuditData    interface{} `json:"AuditData,omitempty"`
	Message      string      `json:"Message,omitempty"`
	Timestamp    int64       `json:"timestamp"`
	Type         string      `json:"type"`
	SenderID     string      `json:"sender_id"`
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsAuditPayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// DnsStatusUpdatePayload represents a STATUS-UPDATE message payload.
// Used for combiner→agent notifications (delegation changes) and
// agent→agent notifications (parent sync completed).
type DnsStatusUpdatePayload struct {
	MessageType  string   `json:"MessageType"`
	MyIdentity   string   `json:"MyIdentity"`
	YourIdentity string   `json:"YourIdentity"`
	Zone         string   `json:"Zone"`
	SubType      string   `json:"SubType"`
	NSRecords    []string `json:"NSRecords,omitempty"`
	DSRecords    []string `json:"DSRecords,omitempty"`
	Result       string   `json:"Result,omitempty"`
	Msg          string   `json:"Msg,omitempty"`
	Timestamp    int64    `json:"timestamp"`
	Type         string   `json:"type"`
	SenderID     string   `json:"sender_id"`
}

// GetSenderID returns the sender ID from either standard or legacy format.
func (d *DnsStatusUpdatePayload) GetSenderID() string {
	if d.MyIdentity != "" {
		return d.MyIdentity
	}
	return d.SenderID
}

// KeyInventoryEntry describes a single DNSKEY in a KEYSTATE inventory message.
// Used when Signal == "inventory" to carry the complete set of keys for a zone.
type KeyInventoryEntry struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	State     string `json:"state"` // "created","published","standby","active","retired","foreign"
	KeyRR     string `json:"keyrr"` // Full DNSKEY RR string (public key data)
}

// ParseSyncPayload parses a sync message payload.
func ParseSyncPayload(payload []byte) (*DnsSyncPayload, error) {
	var p DnsSyncPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ParseRelocatePayload parses a relocate message payload.
func ParseRelocatePayload(payload []byte) (*DnsRelocatePayload, error) {
	var p DnsRelocatePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
