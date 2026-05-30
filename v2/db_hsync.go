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
)

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
