/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Application-level request/response shapes for messages to a peer
 * (transport redesign, Stage C4). These lived in tdns-transport as
 * SyncRequest/SyncResponse, PeerKeystateRequest/Response, PeerEditsRequest/Response,
 * PeerConfigRequest/Response and PeerAuditRequest/Response; transport now carries
 * only the opaque AppMessage/AppResponse, and these are the typed views the
 * MP code builds and consumes (mp_send.go marshals them to the wire).
 */

package tdnsmp

import (
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

// PeerSyncType classifies zone-data synchronization.
type PeerSyncType uint8

const (
	PeerSyncTypeNS     PeerSyncType = iota + 1 // NS record coordination
	PeerSyncTypeDNSKEY                         // DNSKEY sharing for multi-signer
	PeerSyncTypeGLUE                           // Glue record coordination
	PeerSyncTypeCDS                            // CDS/CDNSKEY for key rollover
	PeerSyncTypeCSYNC                          // CSYNC for delegation updates
)

func (s PeerSyncType) String() string {
	switch s {
	case PeerSyncTypeNS:
		return "NS"
	case PeerSyncTypeDNSKEY:
		return "DNSKEY"
	case PeerSyncTypeGLUE:
		return "GLUE"
	case PeerSyncTypeCDS:
		return "CDS"
	case PeerSyncTypeCSYNC:
		return "CSYNC"
	default:
		return "UNKNOWN"
	}
}

// PeerSyncRequest is a sync-family message ("sync", "update", "rfi") to a peer.
type PeerSyncRequest struct {
	SenderID       string                   // Identity of the sender
	Zone           string                   // The zone this sync applies to (FQDN)
	SyncType       PeerSyncType             // What type of data is being synced
	Records        map[string][]string      // RRs grouped by owner name (legacy: Class-overloaded)
	Operations     []core.RROperation       // Explicit operations (takes precedence over Records)
	Timestamp      time.Time                // When this data was generated
	Serial         uint32                   // Zone serial at time of sync
	DistributionID string                   // For tracking confirmations
	Nonce          string                   // Unique nonce for replay protection
	Signature      []byte                   // Optional signature over the request
	MessageType    string                   // "sync" (agent→agent), "update" (agent→combiner), "rfi" (RFI)
	RfiType        string                   // For RFI messages: "SYNC", "AUDIT", "CONFIG"
	RfiSubtype     string                   // Subtype within an RFI type (e.g. "upstream", "sig0key" for CONFIG)
	ZoneClass      string                   // "mp" (default) or "provider"
	Publish        *core.PublishInstruction // KEY/CDS publication instruction for combiner
}

// PeerSyncResponse is the receiver's confirmation of a PeerSyncRequest.
type PeerSyncResponse struct {
	ResponderID    string                      // Identity of the responder
	Zone           string                      // Echoed zone name
	DistributionID string                      // Echoed correlation ID
	Status         transport.ConfirmStatus     // Result of processing
	Message        string                      // Optional status message
	Timestamp      time.Time                   // Response timestamp
	AppliedRecords []string                    // RRs accepted by recipient (additions)
	RemovedRecords []string                    // RRs confirmed removed by recipient (deletions)
	RejectedItems  []transport.RejectedItemDTO // RRs rejected with reasons
	Truncated      bool                        // True if applied/removed_records was dropped for size
}

// PeerKeystateRequest is a KEYSTATE message (agent↔signer key lifecycle signal).
type PeerKeystateRequest struct {
	SenderID     string              // Identity of the sender
	Zone         string              // Zone this key belongs to (FQDN)
	KeyTag       uint16              // DNSKEY key tag (unused for inventory)
	Algorithm    uint8               // DNSKEY algorithm number (unused for inventory)
	Signal       string              // "propagated", "rejected", "removed", "published", "retired", "inventory"
	Message      string              // Optional detail (e.g. rejection reason)
	KeyInventory []KeyInventoryEntry // Complete key inventory (only when Signal == "inventory")
	Timestamp    time.Time           // Request timestamp
}

type PeerKeystateResponse struct {
	ResponderID string    // Identity of the responder
	Zone        string    // Echoed zone name
	KeyTag      uint16    // Echoed key tag
	Signal      string    // Echoed signal
	Accepted    bool      // Whether the signal was accepted
	Message     string    // Optional status message
	Timestamp   time.Time // Response timestamp
}

// PeerEditsRequest carries an agent's current contributions from the combiner.
type PeerEditsRequest struct {
	SenderID     string                         // Combiner identity
	Zone         string                         // Zone (FQDN)
	AgentRecords map[string]map[string][]string // All agents' contributions (agentID → owner → []RR strings)
	Message      string                         // Optional status
	Timestamp    time.Time
}

type PeerEditsResponse struct {
	ResponderID string    // Identity of the responder
	Zone        string    // Echoed zone name
	Accepted    bool      // Whether the message was accepted
	Message     string    // Optional status message
	Timestamp   time.Time // Response timestamp
}

// PeerConfigRequest carries config data in answer to an RFI CONFIG.
type PeerConfigRequest struct {
	SenderID   string            // Sender identity
	Zone       string            // Zone (FQDN)
	Subtype    string            // Config subtype: "upstream", "downstream", "sig0key"
	ConfigData map[string]string // Key-value config data
	Message    string            // Optional status
	Timestamp  time.Time
}

type PeerConfigResponse struct {
	ResponderID string
	Zone        string
	Accepted    bool
	Message     string
	Timestamp   time.Time
}

// PeerAuditRequest carries audit data in answer to an RFI AUDIT.
type PeerAuditRequest struct {
	SenderID  string      // Sender identity
	Zone      string      // Zone (FQDN)
	AuditData interface{} // Zone data repo snapshot (placeholder)
	Message   string      // Optional status
	Timestamp time.Time
}

type PeerAuditResponse struct {
	ResponderID string
	Zone        string
	Accepted    bool
	Message     string
	Timestamp   time.Time
}
