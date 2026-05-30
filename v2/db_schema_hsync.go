/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database schema for HSYNC (multi-provider DNSSEC coordination).
 * Migrated from tdns/v2/db_schema_hsync.go — all methods now on
 * *HsyncDB instead of *tdns.KeyDB.
 *
 * Provides persistent storage for:
 * - Peer information (discovered agents, addresses, keys)
 * - Sync confirmations (operation tracking, audit trail)
 * - Zone-peer relationships
 * - Operational metrics
 * - Combiner edits and contributions
 */

package tdnsmp

import (
	"database/sql"
	"fmt"
	"log"
	"time"
)

// HsyncTables defines the database tables for HSYNC functionality.
// These are added to the KeyDB during initialization.
var HsyncTables = map[string]string{

	// SyncOperations tracks individual sync operations for audit and debugging.
	// Each row represents a sync operation (NS, DNSKEY, CDS, CSYNC, GLUE).
	"SyncOperations": `CREATE TABLE IF NOT EXISTS 'SyncOperations' (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		distribution_id   TEXT NOT NULL UNIQUE,

		-- Operation details
		zone_name         TEXT NOT NULL,
		sync_type         TEXT NOT NULL,              -- NS, DNSKEY, GLUE, CDS, CSYNC
		direction         TEXT NOT NULL,              -- outbound, inbound

		-- Participants
		sender_id         TEXT NOT NULL,
		receiver_id       TEXT NOT NULL,

		-- Payload
		records           TEXT,                        -- JSON array of RR strings
		serial            INTEGER,                     -- SOA serial at time of sync

		-- Transport used
		transport         TEXT,                        -- api, dns
		encrypted         INTEGER DEFAULT 0,           -- 1 if payload was encrypted

		-- Status tracking
		status            TEXT DEFAULT 'pending',      -- pending, sent, received, confirmed, failed, rejected
		status_message    TEXT,

		-- Timestamps
		created_at        INTEGER NOT NULL,
		sent_at           INTEGER,
		received_at       INTEGER,
		confirmed_at      INTEGER,
		expires_at        INTEGER,                     -- For replay protection

		-- Error tracking
		retry_count       INTEGER DEFAULT 0,
		last_error        TEXT,
		last_error_at     INTEGER
	)`,

	// SyncConfirmations stores detailed confirmations for sync operations.
	// Linked to SyncOperations via distribution_id.
	"SyncConfirmations": `CREATE TABLE IF NOT EXISTS 'SyncConfirmations' (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		distribution_id   TEXT NOT NULL,

		-- Confirmation source
		confirmer_id      TEXT NOT NULL,              -- Peer that sent the confirmation

		-- Status
		status            TEXT NOT NULL,              -- success, partial, failed, rejected
		message           TEXT,

		-- Detailed results (JSON)
		items_processed   TEXT,                        -- JSON: [{record_type, zone, status, details}]

		-- Proof (optional)
		signed_proof      TEXT,                        -- DNSSEC signatures from signer
		confirmer_signature TEXT,                      -- JWS signature from confirmer

		-- Timestamps
		confirmed_at      INTEGER NOT NULL,
		received_at       INTEGER NOT NULL,

		FOREIGN KEY(distribution_id) REFERENCES SyncOperations(distribution_id) ON DELETE CASCADE
	)`,

	// OperationalMetrics stores time-series metrics for monitoring.
	// Aggregated periodically for dashboard/alerting.
	"OperationalMetrics": `CREATE TABLE IF NOT EXISTS 'OperationalMetrics' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		metric_time     INTEGER NOT NULL,             -- Unix timestamp (rounded to minute)
		peer_id         TEXT,                          -- NULL for aggregate metrics
		zone_name       TEXT,                          -- NULL for aggregate metrics

		-- Communication metrics
		syncs_sent      INTEGER DEFAULT 0,
		syncs_received  INTEGER DEFAULT 0,
		syncs_confirmed INTEGER DEFAULT 0,
		syncs_failed    INTEGER DEFAULT 0,

		-- Heartbeat metrics
		beats_sent      INTEGER DEFAULT 0,
		beats_received  INTEGER DEFAULT 0,
		beats_missed    INTEGER DEFAULT 0,

		-- Latency (milliseconds)
		avg_latency     INTEGER,
		max_latency     INTEGER,

		-- Transport breakdown
		api_operations  INTEGER DEFAULT 0,
		dns_operations  INTEGER DEFAULT 0,

		UNIQUE(metric_time, peer_id, zone_name)
	)`,

	// TransportEvents logs transport-related events for debugging.
	// Useful for diagnosing connectivity issues.
	"TransportEvents": `CREATE TABLE IF NOT EXISTS 'TransportEvents' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time      INTEGER NOT NULL,
		peer_id         TEXT,
		zone_name       TEXT,

		-- Event details
		event_type      TEXT NOT NULL,                -- hello, beat, sync, relocate, confirm, error, state_change
		transport       TEXT,                          -- api, dns
		direction       TEXT,                          -- outbound, inbound

		-- Result
		success         INTEGER,                       -- 1 for success, 0 for failure
		error_code      TEXT,
		error_message   TEXT,

		-- Additional context (JSON)
		context         TEXT,

		-- Auto-cleanup: events older than 7 days can be purged
		expires_at      INTEGER
	)`,

	// CombinerPendingEdits stores agent UPDATEs awaiting manual approval.
	// Created when a zone has the mp-manual-approval option.
	"CombinerPendingEdits": `CREATE TABLE IF NOT EXISTS 'CombinerPendingEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		delivered_by    TEXT NOT NULL DEFAULT '',
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL
	)`,

	// CombinerApprovedEdits records edits that were approved by the operator.
	"CombinerApprovedEdits": `CREATE TABLE IF NOT EXISTS 'CombinerApprovedEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL,
		approved_at     INTEGER NOT NULL
	)`,

	// CombinerRejectedEdits records edits that were rejected by the operator.
	"CombinerRejectedEdits": `CREATE TABLE IF NOT EXISTS 'CombinerRejectedEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL,
		rejected_at     INTEGER NOT NULL,
		reason          TEXT NOT NULL
	)`,

	// CombinerPublishInstructions stores per-agent KEY/CDS publication instructions.
	// The combiner uses these to know which _signal names to maintain when NS records change.
	"CombinerPublishInstructions": `CREATE TABLE IF NOT EXISTS 'CombinerPublishInstructions' (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		zone              TEXT NOT NULL,
		sender_id         TEXT NOT NULL,
		key_rrs_json      TEXT NOT NULL DEFAULT '[]',
		cds_rrs_json      TEXT NOT NULL DEFAULT '[]',
		locations_json    TEXT NOT NULL DEFAULT '[]',
		published_ns_json TEXT NOT NULL DEFAULT '[]',
		updated_at        INTEGER NOT NULL,
		UNIQUE(zone, sender_id)
	)`,

	// CombinerContributions is a snapshot of the current per-agent contributions.
	// One row per RR. Used to restore AgentContributions on restart.
	"CombinerContributions": `CREATE TABLE IF NOT EXISTS 'CombinerContributions' (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		zone        TEXT NOT NULL,
		sender_id   TEXT NOT NULL,
		owner       TEXT NOT NULL,
		rrtype      INTEGER NOT NULL,
		rr          TEXT NOT NULL,
		updated_at  INTEGER NOT NULL,
		UNIQUE(zone, sender_id, owner, rrtype, rr)
	)`,

	// MPDnssecKeyStore holds DNSSEC keys for tdns-mp signer/agent (MP states and propagation columns).
	"MPDnssecKeyStore": `CREATE TABLE IF NOT EXISTS 'MPDnssecKeyStore' (
		id                        INTEGER PRIMARY KEY,
		zonename                  TEXT,
		state                     TEXT,
		keyid                     INTEGER,
		flags                     INTEGER,
		algorithm                 TEXT,
		creator                   TEXT,
		privatekey                TEXT,
		keyrr                     TEXT,
		comment                   TEXT,
		propagation_confirmed     INTEGER DEFAULT 0,
		propagation_confirmed_at  TEXT DEFAULT '',
		published_at              TEXT DEFAULT '',
		retired_at                TEXT DEFAULT '',
		UNIQUE (zonename, keyid)
	)`,
}

// HsyncIndexes defines indexes for the HSYNC tables.
var HsyncIndexes = []string{
	// SyncOperations indexes
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_zone ON SyncOperations(zone_name)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_status ON SyncOperations(status)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_created ON SyncOperations(created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_sender ON SyncOperations(sender_id)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_receiver ON SyncOperations(receiver_id)`,

	// SyncConfirmations indexes
	`CREATE INDEX IF NOT EXISTS idx_sync_confirm_distribution ON SyncConfirmations(distribution_id)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_confirm_status ON SyncConfirmations(status)`,

	// OperationalMetrics indexes
	`CREATE INDEX IF NOT EXISTS idx_metrics_time ON OperationalMetrics(metric_time)`,
	`CREATE INDEX IF NOT EXISTS idx_metrics_peer ON OperationalMetrics(peer_id)`,

	// TransportEvents indexes
	`CREATE INDEX IF NOT EXISTS idx_events_time ON TransportEvents(event_time)`,
	`CREATE INDEX IF NOT EXISTS idx_events_peer ON TransportEvents(peer_id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_type ON TransportEvents(event_type)`,
	`CREATE INDEX IF NOT EXISTS idx_events_expires ON TransportEvents(expires_at)`,

	// CombinerPendingEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_pending_edits_zone ON CombinerPendingEdits(zone)`,

	// CombinerApprovedEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_approved_edits_zone ON CombinerApprovedEdits(zone)`,

	// CombinerRejectedEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_rejected_edits_zone ON CombinerRejectedEdits(zone)`,

	// CombinerPublishInstructions indexes
	`CREATE INDEX IF NOT EXISTS idx_publish_instr_zone ON CombinerPublishInstructions(zone)`,

	// CombinerContributions indexes
	`CREATE INDEX IF NOT EXISTS idx_contributions_zone ON CombinerContributions(zone)`,
	`CREATE INDEX IF NOT EXISTS idx_contributions_zone_sender ON CombinerContributions(zone, sender_id)`,

	// MPDnssecKeyStore indexes (state filter is hot path for
	// GetDnssecKeysByState / foreign-key fetches).
	`CREATE INDEX IF NOT EXISTS idx_mp_dnskey_state ON MPDnssecKeyStore(state)`,
	`CREATE INDEX IF NOT EXISTS idx_mp_dnskey_zone_state ON MPDnssecKeyStore(zonename, state)`,
}

// validTableName checks that a table name contains only safe characters.
func validTableName(name string) bool {
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return len(name) > 0
}

// dbColumnExists checks whether a column exists in a table using PRAGMA table_info.
func dbColumnExists(db *sql.DB, table, column string) bool {
	if !validTableName(table) {
		return false
	}
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == column {
			return true
		}
	}
	return false
}

// migrateHsyncSchema applies schema migrations for existing databases.
// Currently handles the correlation_id → distribution_id rename (M41).
func (hdb *HsyncDB) migrateHsyncSchema() {
	migrations := []struct {
		table  string
		oldCol string
		newCol string
	}{
		{"SyncOperations", "correlation_id", "distribution_id"},
		{"SyncConfirmations", "correlation_id", "distribution_id"},
	}
	for _, m := range migrations {
		if dbColumnExists(hdb.DB, m.table, m.oldCol) && !dbColumnExists(hdb.DB, m.table, m.newCol) {
			_, err := hdb.DB.Exec(fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", m.table, m.oldCol, m.newCol))
			if err != nil {
				log.Printf("schema migration failed: %s.%s → %s: %v", m.table, m.oldCol, m.newCol, err)
			} else {
				log.Printf("schema migration applied: %s.%s → %s", m.table, m.oldCol, m.newCol)
			}
		}
	}
}

// InitHsyncTables initializes the HSYNC tables in the KeyDB.
// Call this during application startup after KeyDB is created.
func (hdb *HsyncDB) InitHsyncTables() error {
	hdb.Lock()
	defer hdb.Unlock()

	// Migrate existing tables before creating new ones
	hdb.migrateHsyncSchema()

	// Create tables
	for name, schema := range HsyncTables {
		_, err := hdb.DB.Exec(schema)
		if err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	// Create indexes
	for _, indexSQL := range HsyncIndexes {
		_, err := hdb.DB.Exec(indexSQL)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// InitCombinerEditTables initializes only the combiner edit tables.
// Call this on combiner startup — avoids creating agent-only HSYNC tables.
func (hdb *HsyncDB) InitCombinerEditTables() error {
	hdb.Lock()
	defer hdb.Unlock()

	combinerTables := []string{
		"CombinerPendingEdits",
		"CombinerApprovedEdits",
		"CombinerRejectedEdits",
		"CombinerContributions",
		"CombinerPublishInstructions",
	}

	for _, name := range combinerTables {
		schema, ok := HsyncTables[name]
		if !ok {
			return fmt.Errorf("table schema %q not found in HsyncTables", name)
		}
		if _, err := hdb.DB.Exec(schema); err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	combinerIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_pending_edits_zone ON CombinerPendingEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_approved_edits_zone ON CombinerApprovedEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_rejected_edits_zone ON CombinerRejectedEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_contributions_zone ON CombinerContributions(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_contributions_zone_sender ON CombinerContributions(zone, sender_id)`,
		`CREATE INDEX IF NOT EXISTS idx_publish_instr_zone ON CombinerPublishInstructions(zone)`,
	}

	for _, indexSQL := range combinerIndexes {
		if _, err := hdb.DB.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CleanupExpiredHsyncData removes expired data from HSYNC tables.
// Should be called periodically (e.g., daily).
func (hdb *HsyncDB) CleanupExpiredHsyncData() error {
	hdb.Lock()
	defer hdb.Unlock()

	now := time.Now().Unix()

	// Clean up expired transport events (older than 7 days)
	_, err := hdb.DB.Exec(`DELETE FROM TransportEvents WHERE expires_at < ?`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup transport events: %w", err)
	}

	// Clean up expired sync operations (older than 30 days)
	thirtyDaysAgo := now - (30 * 24 * 60 * 60)
	_, err = hdb.DB.Exec(`DELETE FROM SyncOperations WHERE created_at < ? AND status IN ('confirmed', 'failed', 'rejected')`, thirtyDaysAgo)
	if err != nil {
		return fmt.Errorf("failed to cleanup sync operations: %w", err)
	}

	// Clean up old metrics (older than 90 days)
	ninetyDaysAgo := now - (90 * 24 * 60 * 60)
	_, err = hdb.DB.Exec(`DELETE FROM OperationalMetrics WHERE metric_time < ?`, ninetyDaysAgo)
	if err != nil {
		return fmt.Errorf("failed to cleanup operational metrics: %w", err)
	}

	return nil
}
