/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Data access layer for HSYNC database tables.
 * Migrated from tdns/v2/db_hsync.go — all methods now on
 * *HsyncDB instead of *tdns.KeyDB.
 *
 * Provides CRUD operations for peers, sync operations,
 * and confirmations.
 */

package tdnsmp

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// PeerRecord represents a row in the PeerRegistry table.
type PeerRecord struct {
	ID                   int64
	PeerID               string
	DiscoveryTime        time.Time
	DiscoverySource      string
	APIEndpoint          string
	APIHost              string
	APIPort              int
	APITlsaRecord        string
	APIAvailable         bool
	DNSHost              string
	DNSPort              int
	DNSKeyRecord         string
	DNSAvailable         bool
	OperationalHost      string
	OperationalPort      int
	OperationalTransport string
	EncryptionPubkey     string
	VerificationPubkey   string
	State                string
	StateReason          string
	StateChangedAt       time.Time
	PreferredTransport   string
	LastContactAt        time.Time
	LastHelloAt          time.Time
	LastBeatAt           time.Time
	BeatInterval         int
	BeatsSent            int64
	BeatsReceived        int64
	FailedContacts       int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// SyncOperationRecord represents a row in the SyncOperations table.
type SyncOperationRecord struct {
	ID             int64
	DistributionID string
	ZoneName       string
	SyncType       string
	Direction      string
	SenderID       string
	ReceiverID     string
	Records        []string
	Serial         uint32
	Transport      string
	Encrypted      bool
	Status         string
	StatusMessage  string
	CreatedAt      time.Time
	SentAt         time.Time
	ReceivedAt     time.Time
	ConfirmedAt    time.Time
	ExpiresAt      time.Time
	RetryCount     int
	LastError      string
	LastErrorAt    time.Time
}

// SyncConfirmationRecord represents a row in the SyncConfirmations table.
type SyncConfirmationRecord struct {
	ID                 int64
	DistributionID     string
	ConfirmerID        string
	Status             string
	Message            string
	ItemsProcessed     []ConfirmationItem
	SignedProof        string
	ConfirmerSignature string
	ConfirmedAt        time.Time
	ReceivedAt         time.Time
}

// ConfirmationItem represents a single item in a confirmation.
type ConfirmationItem struct {
	RecordType string `json:"record_type"`
	Zone       string `json:"zone"`
	Status     string `json:"status"`
	Details    string `json:"details,omitempty"`
}

// SavePeer inserts or updates a peer in the database.
func (hdb *HsyncDB) SavePeer(peer *PeerRecord) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	peer.UpdatedAt = time.Now()

	_, err := hdb.DB.Exec(`
INSERT INTO PeerRegistry (
peer_id, discovery_time, discovery_source,
api_endpoint, api_host, api_port, api_tlsa_record, api_available,
dns_host, dns_port, dns_key_record, dns_available,
operational_host, operational_port, operational_transport,
encryption_pubkey, verification_pubkey,
state, state_reason, state_changed_at, preferred_transport,
last_contact_at, last_hello_at, last_beat_at, beat_interval,
beats_sent, beats_received, failed_contacts,
created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(peer_id) DO UPDATE SET
api_endpoint = excluded.api_endpoint,
api_host = excluded.api_host,
api_port = excluded.api_port,
api_tlsa_record = excluded.api_tlsa_record,
api_available = excluded.api_available,
dns_host = excluded.dns_host,
dns_port = excluded.dns_port,
dns_key_record = excluded.dns_key_record,
dns_available = excluded.dns_available,
operational_host = excluded.operational_host,
operational_port = excluded.operational_port,
operational_transport = excluded.operational_transport,
encryption_pubkey = excluded.encryption_pubkey,
verification_pubkey = excluded.verification_pubkey,
state = excluded.state,
state_reason = excluded.state_reason,
state_changed_at = excluded.state_changed_at,
preferred_transport = excluded.preferred_transport,
last_contact_at = excluded.last_contact_at,
last_hello_at = excluded.last_hello_at,
last_beat_at = excluded.last_beat_at,
beat_interval = excluded.beat_interval,
beats_sent = excluded.beats_sent,
beats_received = excluded.beats_received,
failed_contacts = excluded.failed_contacts,
updated_at = excluded.updated_at
`,
		peer.PeerID, peer.DiscoveryTime.Unix(), peer.DiscoverySource,
		peer.APIEndpoint, peer.APIHost, peer.APIPort, peer.APITlsaRecord, boolToInt(peer.APIAvailable),
		peer.DNSHost, peer.DNSPort, peer.DNSKeyRecord, boolToInt(peer.DNSAvailable),
		peer.OperationalHost, peer.OperationalPort, peer.OperationalTransport,
		peer.EncryptionPubkey, peer.VerificationPubkey,
		peer.State, peer.StateReason, peer.StateChangedAt.Unix(), peer.PreferredTransport,
		nullableUnix(peer.LastContactAt), nullableUnix(peer.LastHelloAt), nullableUnix(peer.LastBeatAt), peer.BeatInterval,
		peer.BeatsSent, peer.BeatsReceived, peer.FailedContacts,
		now, now,
	)
	return err
}

// GetPeer retrieves a peer by ID.
func (hdb *HsyncDB) GetPeer(peerID string) (*PeerRecord, error) {
	hdb.Lock()
	defer hdb.Unlock()

	row := hdb.DB.QueryRow(`
SELECT id, peer_id, discovery_time, discovery_source,
api_endpoint, api_host, api_port, api_tlsa_record, api_available,
dns_host, dns_port, dns_key_record, dns_available,
operational_host, operational_port, operational_transport,
encryption_pubkey, verification_pubkey,
state, state_reason, state_changed_at, preferred_transport,
last_contact_at, last_hello_at, last_beat_at, beat_interval,
beats_sent, beats_received, failed_contacts,
created_at, updated_at
FROM PeerRegistry WHERE peer_id = ?
`, peerID)

	peer := &PeerRecord{}
	var discoveryTime, stateChangedAt, lastContactAt, lastHelloAt, lastBeatAt, createdAt, updatedAt sql.NullInt64
	var apiAvailable, dnsAvailable int

	err := row.Scan(
		&peer.ID, &peer.PeerID, &discoveryTime, &peer.DiscoverySource,
		&peer.APIEndpoint, &peer.APIHost, &peer.APIPort, &peer.APITlsaRecord, &apiAvailable,
		&peer.DNSHost, &peer.DNSPort, &peer.DNSKeyRecord, &dnsAvailable,
		&peer.OperationalHost, &peer.OperationalPort, &peer.OperationalTransport,
		&peer.EncryptionPubkey, &peer.VerificationPubkey,
		&peer.State, &peer.StateReason, &stateChangedAt, &peer.PreferredTransport,
		&lastContactAt, &lastHelloAt, &lastBeatAt, &peer.BeatInterval,
		&peer.BeatsSent, &peer.BeatsReceived, &peer.FailedContacts,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	peer.DiscoveryTime = unixToTime(discoveryTime)
	peer.StateChangedAt = unixToTime(stateChangedAt)
	peer.LastContactAt = unixToTime(lastContactAt)
	peer.LastHelloAt = unixToTime(lastHelloAt)
	peer.LastBeatAt = unixToTime(lastBeatAt)
	peer.CreatedAt = unixToTime(createdAt)
	peer.UpdatedAt = unixToTime(updatedAt)
	peer.APIAvailable = apiAvailable == 1
	peer.DNSAvailable = dnsAvailable == 1

	return peer, nil
}

// ListPeers retrieves all peers, optionally filtered by state.
func (hdb *HsyncDB) ListPeers(state string) ([]*PeerRecord, error) {
	hdb.Lock()
	defer hdb.Unlock()

	query := `
SELECT id, peer_id, discovery_time, discovery_source,
api_endpoint, api_host, api_port, api_tlsa_record, api_available,
dns_host, dns_port, dns_key_record, dns_available,
operational_host, operational_port, operational_transport,
encryption_pubkey, verification_pubkey,
state, state_reason, state_changed_at, preferred_transport,
last_contact_at, last_hello_at, last_beat_at, beat_interval,
beats_sent, beats_received, failed_contacts,
created_at, updated_at
FROM PeerRegistry
`
	var args []interface{}
	if state != "" {
		query += " WHERE state = ?"
		args = append(args, state)
	}
	query += " ORDER BY peer_id"

	rows, err := hdb.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []*PeerRecord
	for rows.Next() {
		peer := &PeerRecord{}
		var discoveryTime, stateChangedAt, lastContactAt, lastHelloAt, lastBeatAt, createdAt, updatedAt sql.NullInt64
		var apiAvailable, dnsAvailable int

		err := rows.Scan(
			&peer.ID, &peer.PeerID, &discoveryTime, &peer.DiscoverySource,
			&peer.APIEndpoint, &peer.APIHost, &peer.APIPort, &peer.APITlsaRecord, &apiAvailable,
			&peer.DNSHost, &peer.DNSPort, &peer.DNSKeyRecord, &dnsAvailable,
			&peer.OperationalHost, &peer.OperationalPort, &peer.OperationalTransport,
			&peer.EncryptionPubkey, &peer.VerificationPubkey,
			&peer.State, &peer.StateReason, &stateChangedAt, &peer.PreferredTransport,
			&lastContactAt, &lastHelloAt, &lastBeatAt, &peer.BeatInterval,
			&peer.BeatsSent, &peer.BeatsReceived, &peer.FailedContacts,
			&createdAt, &updatedAt,
		)
		if err != nil {
			return nil, err
		}

		peer.DiscoveryTime = unixToTime(discoveryTime)
		peer.StateChangedAt = unixToTime(stateChangedAt)
		peer.LastContactAt = unixToTime(lastContactAt)
		peer.LastHelloAt = unixToTime(lastHelloAt)
		peer.LastBeatAt = unixToTime(lastBeatAt)
		peer.CreatedAt = unixToTime(createdAt)
		peer.UpdatedAt = unixToTime(updatedAt)
		peer.APIAvailable = apiAvailable == 1
		peer.DNSAvailable = dnsAvailable == 1

		peers = append(peers, peer)
	}

	return peers, nil
}

// UpdatePeerState updates just the state fields of a peer.
func (hdb *HsyncDB) UpdatePeerState(peerID, state, reason string) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	_, err := hdb.DB.Exec(`
UPDATE PeerRegistry SET state = ?, state_reason = ?, state_changed_at = ?, updated_at = ?
WHERE peer_id = ?
`, state, reason, now, now, peerID)
	return err
}

// UpdatePeerContact updates the last contact timestamp.
func (hdb *HsyncDB) UpdatePeerContact(peerID string) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	_, err := hdb.DB.Exec(`
UPDATE PeerRegistry SET last_contact_at = ?, failed_contacts = 0, updated_at = ?
WHERE peer_id = ?
`, now, now, peerID)
	return err
}

// IncrementPeerFailedContacts increments the failed contacts counter.
func (hdb *HsyncDB) IncrementPeerFailedContacts(peerID string) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	_, err := hdb.DB.Exec(`
UPDATE PeerRegistry SET failed_contacts = failed_contacts + 1, updated_at = ?
WHERE peer_id = ?
`, now, peerID)
	return err
}

// SaveSyncOperation inserts a new sync operation.
func (hdb *HsyncDB) SaveSyncOperation(op *SyncOperationRecord) error {
	hdb.Lock()
	defer hdb.Unlock()

	recordsJSON, err := json.Marshal(op.Records)
	if err != nil {
		return fmt.Errorf("failed to marshal records: %w", err)
	}

	_, err = hdb.DB.Exec(`
INSERT INTO SyncOperations (
distribution_id, zone_name, sync_type, direction,
sender_id, receiver_id, records, serial,
transport, encrypted, status, status_message,
created_at, sent_at, received_at, confirmed_at, expires_at,
retry_count, last_error, last_error_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		op.DistributionID, op.ZoneName, op.SyncType, op.Direction,
		op.SenderID, op.ReceiverID, string(recordsJSON), op.Serial,
		op.Transport, boolToInt(op.Encrypted), op.Status, op.StatusMessage,
		op.CreatedAt.Unix(), nullableUnix(op.SentAt), nullableUnix(op.ReceivedAt),
		nullableUnix(op.ConfirmedAt), nullableUnix(op.ExpiresAt),
		op.RetryCount, op.LastError, nullableUnix(op.LastErrorAt),
	)
	return err
}

// UpdateSyncOperationStatus updates the status of a sync operation.
func (hdb *HsyncDB) UpdateSyncOperationStatus(distributionID, status, message string) error {
	hdb.Lock()
	defer hdb.Unlock()

	_, err := hdb.DB.Exec(`
UPDATE SyncOperations SET status = ?, status_message = ?
WHERE distribution_id = ?
`, status, message, distributionID)
	return err
}

// MarkSyncOperationConfirmed marks a sync operation as confirmed.
func (hdb *HsyncDB) MarkSyncOperationConfirmed(distributionID string) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	_, err := hdb.DB.Exec(`
UPDATE SyncOperations SET status = 'confirmed', confirmed_at = ?
WHERE distribution_id = ?
`, now, distributionID)
	return err
}

// SaveSyncConfirmation inserts a confirmation record.
func (hdb *HsyncDB) SaveSyncConfirmation(c *SyncConfirmationRecord) error {
	hdb.Lock()
	defer hdb.Unlock()

	itemsJSON, err := json.Marshal(c.ItemsProcessed)
	if err != nil {
		return fmt.Errorf("failed to marshal items: %w", err)
	}

	_, err = hdb.DB.Exec(`
INSERT INTO SyncConfirmations (
distribution_id, confirmer_id, status, message,
items_processed, signed_proof, confirmer_signature,
confirmed_at, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		c.DistributionID, c.ConfirmerID, c.Status, c.Message,
		string(itemsJSON), c.SignedProof, c.ConfirmerSignature,
		c.ConfirmedAt.Unix(), c.ReceivedAt.Unix(),
	)
	return err
}

// GetSyncOperation retrieves a sync operation by distribution ID.
func (hdb *HsyncDB) GetSyncOperation(distributionID string) (*SyncOperationRecord, error) {
	hdb.Lock()
	defer hdb.Unlock()

	row := hdb.DB.QueryRow(`
SELECT id, distribution_id, zone_name, sync_type, direction,
sender_id, receiver_id, records, serial,
transport, encrypted, status, status_message,
created_at, sent_at, received_at, confirmed_at, expires_at,
retry_count, last_error, last_error_at
FROM SyncOperations WHERE distribution_id = ?
`, distributionID)

	op := &SyncOperationRecord{}
	var recordsJSON string
	var encrypted int
	var createdAt, sentAt, receivedAt, confirmedAt, expiresAt, lastErrorAt sql.NullInt64

	err := row.Scan(
		&op.ID, &op.DistributionID, &op.ZoneName, &op.SyncType, &op.Direction,
		&op.SenderID, &op.ReceiverID, &recordsJSON, &op.Serial,
		&op.Transport, &encrypted, &op.Status, &op.StatusMessage,
		&createdAt, &sentAt, &receivedAt, &confirmedAt, &expiresAt,
		&op.RetryCount, &op.LastError, &lastErrorAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if err := json.Unmarshal([]byte(recordsJSON), &op.Records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal records: %w", err)
	}

	op.Encrypted = encrypted == 1
	op.CreatedAt = unixToTime(createdAt)
	op.SentAt = unixToTime(sentAt)
	op.ReceivedAt = unixToTime(receivedAt)
	op.ConfirmedAt = unixToTime(confirmedAt)
	op.ExpiresAt = unixToTime(expiresAt)
	op.LastErrorAt = unixToTime(lastErrorAt)

	return op, nil
}

// LogTransportEvent logs a transport event for debugging.
func (hdb *HsyncDB) LogTransportEvent(peerID, zoneName, eventType, transportType, direction string, success bool, errorCode, errorMessage string, context map[string]interface{}) error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()
	expiresAt := now + (7 * 24 * 60 * 60) // 7 days

	var contextJSON string
	if context != nil {
		b, _ := json.Marshal(context)
		contextJSON = string(b)
	}

	_, err := hdb.DB.Exec(`
INSERT INTO TransportEvents (
event_time, peer_id, zone_name, event_type, transport, direction,
success, error_code, error_message, context, expires_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		now, peerID, zoneName, eventType, transportType, direction,
		boolToInt(success), errorCode, errorMessage, contextJSON, expiresAt,
	)
	return err
}

// PeerRecordFromAgent creates a PeerRecord from an Agent.
func PeerRecordFromAgent(agent *tdns.Agent) *PeerRecord {
	record := &PeerRecord{
		PeerID:          string(agent.Identity),
		DiscoveryTime:   time.Now(),
		DiscoverySource: "hsync",
		State:           agentStateToString(agent.State),
		StateChangedAt:  agent.LastState,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// API transport details
	if agent.ApiDetails != nil {
		record.APIEndpoint = agent.ApiDetails.Endpoint
		record.APIHost = agent.ApiDetails.Host
		record.APIPort = int(agent.ApiDetails.Port)
		record.APIAvailable = agent.ApiMethod
		if agent.ApiDetails.TlsaRR != nil {
			record.APITlsaRecord = agent.ApiDetails.TlsaRR.String()
		}
		// Use latest beat time as last contact proxy
		if !agent.ApiDetails.LatestSBeat.IsZero() {
			record.LastContactAt = agent.ApiDetails.LatestSBeat
		} else if !agent.ApiDetails.LatestRBeat.IsZero() {
			record.LastContactAt = agent.ApiDetails.LatestRBeat
		}
	}

	// DNS transport details
	if agent.DnsDetails != nil {
		record.DNSHost = agent.DnsDetails.Host
		record.DNSPort = int(agent.DnsDetails.Port)
		record.DNSAvailable = agent.DnsMethod
		if agent.DnsDetails.KeyRR != nil {
			record.DNSKeyRecord = agent.DnsDetails.KeyRR.String()
		}
	}

	// Determine preferred transport
	if agent.ApiMethod {
		record.PreferredTransport = "api"
	} else if agent.DnsMethod {
		record.PreferredTransport = "dns"
	}

	return record
}

// PeerRecordFromTransportPeer creates a PeerRecord from a transport.Peer.
func PeerRecordFromTransportPeer(peer *transport.Peer) *PeerRecord {
	record := &PeerRecord{
		PeerID:             peer.ID,
		DiscoveryTime:      time.Now(),
		DiscoverySource:    "transport",
		APIEndpoint:        peer.APIEndpoint,
		PreferredTransport: peer.PreferredTransport,
		State:              peerStateToString(peer.State),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	// Discovery address
	if addr := peer.DiscoveryAddr; addr != nil {
		if peer.PreferredTransport == "API" || peer.PreferredTransport == "api" {
			record.APIHost = addr.Host
			record.APIPort = int(addr.Port)
			record.APIAvailable = true
		} else {
			record.DNSHost = addr.Host
			record.DNSPort = int(addr.Port)
			record.DNSAvailable = true
		}
	}

	// Operational address
	if addr := peer.OperationalAddr; addr != nil {
		record.OperationalHost = addr.Host
		record.OperationalPort = int(addr.Port)
		record.OperationalTransport = addr.Transport
	}

	return record
}

// Helper functions

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableUnix(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func unixToTime(n sql.NullInt64) time.Time {
	if !n.Valid || n.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0)
}

func agentStateToString(state tdns.AgentState) string {
	switch state {
	case tdns.AgentStateNeeded:
		return "needed"
	case tdns.AgentStateKnown:
		return "known"
	case tdns.AgentStateIntroduced:
		return "introduced"
	case tdns.AgentStateOperational:
		return "operational"
	case tdns.AgentStateDegraded:
		return "degraded"
	case tdns.AgentStateInterrupted:
		return "interrupted"
	case tdns.AgentStateError:
		return "error"
	default:
		return "unknown"
	}
}

func peerStateToString(state transport.PeerState) string {
	switch state {
	case transport.PeerStateNeeded:
		return "needed"
	case transport.PeerStateDiscovering:
		return "discovering"
	case transport.PeerStateKnown:
		return "known"
	case transport.PeerStateIntroducing:
		return "introducing"
	case transport.PeerStateOperational:
		return "operational"
	case transport.PeerStateDegraded:
		return "degraded"
	case transport.PeerStateInterrupted:
		return "interrupted"
	case transport.PeerStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Conversion functions for CLI display

// PeerRecordToInfo converts a PeerRecord to HsyncPeerInfo for CLI display.
func PeerRecordToInfo(peer *PeerRecord) *HsyncPeerInfo {
	return &HsyncPeerInfo{
		PeerID:             peer.PeerID,
		State:              peer.State,
		StateReason:        peer.StateReason,
		DiscoverySource:    peer.DiscoverySource,
		DiscoveryTime:      peer.DiscoveryTime,
		PreferredTransport: peer.PreferredTransport,
		APIHost:            peer.APIHost,
		APIPort:            peer.APIPort,
		APIAvailable:       peer.APIAvailable,
		DNSHost:            peer.DNSHost,
		DNSPort:            peer.DNSPort,
		DNSAvailable:       peer.DNSAvailable,
		LastContactAt:      peer.LastContactAt,
		LastHelloAt:        peer.LastHelloAt,
		LastBeatAt:         peer.LastBeatAt,
		BeatInterval:       peer.BeatInterval,
		BeatsSent:          peer.BeatsSent,
		BeatsReceived:      peer.BeatsReceived,
		FailedContacts:     peer.FailedContacts,
	}
}

// SyncOpRecordToInfo converts a SyncOperationRecord to HsyncSyncOpInfo for CLI display.
func SyncOpRecordToInfo(op *SyncOperationRecord) *HsyncSyncOpInfo {
	return &HsyncSyncOpInfo{
		DistributionID: op.DistributionID,
		ZoneName:       op.ZoneName,
		SyncType:       op.SyncType,
		Direction:      op.Direction,
		SenderID:       op.SenderID,
		ReceiverID:     op.ReceiverID,
		Status:         op.Status,
		StatusMessage:  op.StatusMessage,
		Transport:      op.Transport,
		CreatedAt:      op.CreatedAt,
		SentAt:         op.SentAt,
		ReceivedAt:     op.ReceivedAt,
		ConfirmedAt:    op.ConfirmedAt,
		RetryCount:     op.RetryCount,
	}
}

// ConfirmRecordToInfo converts a SyncConfirmationRecord to HsyncConfirmationInfo for CLI display.
func ConfirmRecordToInfo(c *SyncConfirmationRecord) *HsyncConfirmationInfo {
	return &HsyncConfirmationInfo{
		DistributionID: c.DistributionID,
		ConfirmerID:    c.ConfirmerID,
		Status:         c.Status,
		Message:        c.Message,
		ConfirmedAt:    c.ConfirmedAt,
		ReceivedAt:     c.ReceivedAt,
	}
}

// ListSyncOperations retrieves sync operations, optionally filtered by zone.
func (hdb *HsyncDB) ListSyncOperations(zoneName string, limit int) ([]*SyncOperationRecord, error) {
	hdb.Lock()
	defer hdb.Unlock()

	if limit < 0 {
		limit = 0
	}
	if limit > 10000 {
		limit = 10000
	}

	query := `
SELECT id, distribution_id, zone_name, sync_type, direction,
sender_id, receiver_id, records, serial,
transport, encrypted, status, status_message,
created_at, sent_at, received_at, confirmed_at, expires_at,
retry_count, last_error, last_error_at
FROM SyncOperations
`
	var args []interface{}
	if zoneName != "" {
		query += " WHERE zone_name = ?"
		args = append(args, zoneName)
	}
	query += " ORDER BY created_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := hdb.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []*SyncOperationRecord
	for rows.Next() {
		op := &SyncOperationRecord{}
		var recordsJSON string
		var encrypted int
		var createdAt, sentAt, receivedAt, confirmedAt, expiresAt, lastErrorAt sql.NullInt64

		err := rows.Scan(
			&op.ID, &op.DistributionID, &op.ZoneName, &op.SyncType, &op.Direction,
			&op.SenderID, &op.ReceiverID, &recordsJSON, &op.Serial,
			&op.Transport, &encrypted, &op.Status, &op.StatusMessage,
			&createdAt, &sentAt, &receivedAt, &confirmedAt, &expiresAt,
			&op.RetryCount, &op.LastError, &lastErrorAt,
		)
		if err != nil {
			return nil, err
		}

		if recordsJSON != "" {
			if err := json.Unmarshal([]byte(recordsJSON), &op.Records); err != nil {
				log.Printf("failed to unmarshal records JSON, id=%d: %v", op.ID, err)
			}
		}

		op.Encrypted = encrypted == 1
		op.CreatedAt = unixToTime(createdAt)
		op.SentAt = unixToTime(sentAt)
		op.ReceivedAt = unixToTime(receivedAt)
		op.ConfirmedAt = unixToTime(confirmedAt)
		op.ExpiresAt = unixToTime(expiresAt)
		op.LastErrorAt = unixToTime(lastErrorAt)

		ops = append(ops, op)
	}

	return ops, nil
}

// ListSyncConfirmations retrieves confirmations, optionally filtered by distribution ID.
func (hdb *HsyncDB) ListSyncConfirmations(distributionID string, limit int) ([]*SyncConfirmationRecord, error) {
	hdb.Lock()
	defer hdb.Unlock()

	if limit < 0 {
		limit = 0
	}
	if limit > 10000 {
		limit = 10000
	}

	query := `
SELECT id, distribution_id, confirmer_id, status, message,
items_processed, signed_proof, confirmer_signature,
confirmed_at, received_at
FROM SyncConfirmations
`
	var args []interface{}
	if distributionID != "" {
		query += " WHERE distribution_id = ?"
		args = append(args, distributionID)
	}
	query += " ORDER BY confirmed_at DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := hdb.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var confs []*SyncConfirmationRecord
	for rows.Next() {
		c := &SyncConfirmationRecord{}
		var itemsJSON string
		var confirmedAt, receivedAt sql.NullInt64

		err := rows.Scan(
			&c.ID, &c.DistributionID, &c.ConfirmerID, &c.Status, &c.Message,
			&itemsJSON, &c.SignedProof, &c.ConfirmerSignature,
			&confirmedAt, &receivedAt,
		)
		if err != nil {
			return nil, err
		}

		if itemsJSON != "" {
			if err := json.Unmarshal([]byte(itemsJSON), &c.ItemsProcessed); err != nil {
				log.Printf("failed to unmarshal items JSON, id=%d: %v", c.ID, err)
			}
		}

		c.ConfirmedAt = unixToTime(confirmedAt)
		c.ReceivedAt = unixToTime(receivedAt)

		confs = append(confs, c)
	}

	return confs, nil
}

// ListTransportEvents retrieves transport events, optionally filtered by peer.
func (hdb *HsyncDB) ListTransportEvents(peerID string, limit int) ([]*HsyncTransportEvent, error) {
	hdb.Lock()
	defer hdb.Unlock()

	if limit < 0 {
		limit = 0
	}
	if limit > 10000 {
		limit = 10000
	}

	query := `
SELECT event_time, peer_id, zone_name, event_type, transport, direction,
success, error_code, error_message
FROM TransportEvents
`
	var args []interface{}
	if peerID != "" {
		query += " WHERE peer_id = ?"
		args = append(args, peerID)
	}
	query += " ORDER BY event_time DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := hdb.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*HsyncTransportEvent
	for rows.Next() {
		evt := &HsyncTransportEvent{}
		var eventTime sql.NullInt64
		var success int

		err := rows.Scan(
			&eventTime, &evt.PeerID, &evt.ZoneName, &evt.EventType, &evt.Transport, &evt.Direction,
			&success, &evt.ErrorCode, &evt.ErrorMessage,
		)
		if err != nil {
			return nil, err
		}

		evt.EventTime = unixToTime(eventTime)
		evt.Success = success == 1

		events = append(events, evt)
	}

	return events, nil
}

// GetAggregatedMetrics retrieves aggregated operational metrics.
func (hdb *HsyncDB) GetAggregatedMetrics() (*HsyncMetricsInfo, error) {
	hdb.Lock()
	defer hdb.Unlock()

	metrics := &HsyncMetricsInfo{}

	// Get totals from OperationalMetrics table
	row := hdb.DB.QueryRow(`
SELECT
COALESCE(SUM(syncs_sent), 0),
COALESCE(SUM(syncs_received), 0),
COALESCE(SUM(syncs_confirmed), 0),
COALESCE(SUM(syncs_failed), 0),
COALESCE(SUM(beats_sent), 0),
COALESCE(SUM(beats_received), 0),
COALESCE(SUM(beats_missed), 0),
COALESCE(AVG(avg_latency), 0),
COALESCE(MAX(max_latency), 0),
COALESCE(SUM(api_operations), 0),
COALESCE(SUM(dns_operations), 0)
FROM OperationalMetrics
`)

	err := row.Scan(
		&metrics.SyncsSent, &metrics.SyncsReceived, &metrics.SyncsConfirmed, &metrics.SyncsFailed,
		&metrics.BeatsSent, &metrics.BeatsReceived, &metrics.BeatsMissed,
		&metrics.AvgLatency, &metrics.MaxLatency,
		&metrics.APIOperations, &metrics.DNSOperations,
	)
	if err == sql.ErrNoRows {
		return metrics, nil
	}
	if err != nil {
		return metrics, err
	}

	return metrics, nil
}

// RecordMetrics records operational metrics for a time period.
func (hdb *HsyncDB) RecordMetrics(peerID, zoneName string, metrics *HsyncMetricsInfo) error {
	hdb.Lock()
	defer hdb.Unlock()

	// Round to minute for aggregation
	metricTime := time.Now().Truncate(time.Minute).Unix()

	_, err := hdb.DB.Exec(`
INSERT INTO OperationalMetrics (
metric_time, peer_id, zone_name,
syncs_sent, syncs_received, syncs_confirmed, syncs_failed,
beats_sent, beats_received, beats_missed,
avg_latency, max_latency,
api_operations, dns_operations
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(metric_time, peer_id, zone_name) DO UPDATE SET
syncs_sent = syncs_sent + excluded.syncs_sent,
syncs_received = syncs_received + excluded.syncs_received,
syncs_confirmed = syncs_confirmed + excluded.syncs_confirmed,
syncs_failed = syncs_failed + excluded.syncs_failed,
beats_sent = beats_sent + excluded.beats_sent,
beats_received = beats_received + excluded.beats_received,
beats_missed = beats_missed + excluded.beats_missed,
max_latency = MAX(max_latency, excluded.max_latency),
avg_latency = CASE WHEN (syncs_sent + syncs_received + syncs_confirmed + excluded.syncs_sent + excluded.syncs_received + excluded.syncs_confirmed) > 0 THEN ((avg_latency * (syncs_sent + syncs_received + syncs_confirmed)) + (excluded.avg_latency * (excluded.syncs_sent + excluded.syncs_received + excluded.syncs_confirmed))) / (syncs_sent + syncs_received + syncs_confirmed + excluded.syncs_sent + excluded.syncs_received + excluded.syncs_confirmed) ELSE excluded.avg_latency END,
api_operations = api_operations + excluded.api_operations,
dns_operations = dns_operations + excluded.dns_operations
`,
		metricTime, peerID, zoneName,
		metrics.SyncsSent, metrics.SyncsReceived, metrics.SyncsConfirmed, metrics.SyncsFailed,
		metrics.BeatsSent, metrics.BeatsReceived, metrics.BeatsMissed,
		metrics.AvgLatency, metrics.MaxLatency,
		metrics.APIOperations, metrics.DNSOperations,
	)
	return err
}
