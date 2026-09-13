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
	"github.com/miekg/dns"
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

	// MPKeyPropagation is the MP protocol state beside tdns's DnssecKeyStore,
	// where the signer's keys live: whether the peers have confirmed a key's
	// propagation, which gates its promotion to active. Keyed by zone and
	// key id like the keystore row it describes.
	"MPKeyPropagation": `CREATE TABLE IF NOT EXISTS 'MPKeyPropagation' (
		zonename      TEXT NOT NULL,
		keyid         INTEGER NOT NULL,
		confirmed     INTEGER DEFAULT 0,
		confirmed_at  TEXT DEFAULT '',
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

// dbTableExists reports whether a table exists.
func dbTableExists(db *sql.DB, table string) bool {
	if !validTableName(table) {
		return false
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// mpsignerCodepointToRegistry maps the algorithm numbers the signer's
// hand-written registrations used, up to the last release that carried them,
// to the registry codepoints every tdns binary uses now that mpsigner's
// registrations come from tdns-genalgs. Keys in the old store were minted
// under the left-hand numbers; the migration rewrites them. A number not in
// this table (the classical algorithms) is unchanged.
var mpsignerCodepointToRegistry = map[uint8]uint8{
	18:  199, // MLDSA44
	200: 202, // SLHDSA128S
	201: 203, // FALCON512
	202: 205, // MAYO1
	203: 209, // SNOVA24_5_4
	204: 212, // SQISIGN1
	205: 213, // QRUOV_Q31_L3 (no longer linked; migrated, not usable)
	209: 204, // FALCON1024
	// 206 MAYO2, 207 MAYO3, 208 MAYO5, 210 SNOVA37_17_2, 211 SNOVA25_8_3:
	// the same number on both sides.
}

// migratedMPKeystoreTable is where the old key table is parked after its rows
// have moved: kept for one start, dropped by the next.
const migratedMPKeystoreTable = "MPDnssecKeyStore_migrated"

// migrateMPKeystore moves the signer's keys from the retired MPDnssecKeyStore
// into tdns's DnssecKeyStore, where tdns signs with them, one-shot and
// fail-closed.
//
// Every row is copied with its state, timestamps and private half; its
// propagation columns go to the MPKeyPropagation side table; its DNSKEY is
// rewritten for the registry codepoint the algorithm has now, which changes
// the key tag and therefore the key id, and re-parsed. A foreign row keeps
// no private half. No row arrives active unless it left active: states are
// copied verbatim. The rows inserted are counted against the rows read, and
// on any mismatch, unparsable record or insert failure the whole transaction
// rolls back and the daemon refuses to start: a signer that came up on half
// its keys would serve a bogus zone. When the copy is verified the old table
// is renamed, so the next start finds nothing to migrate and drops it.
func (hdb *HsyncDB) migrateMPKeystore() error {
	if !dbTableExists(hdb.DB, "MPDnssecKeyStore") {
		if dbTableExists(hdb.DB, migratedMPKeystoreTable) {
			// The start after the migration: it came up on the new store,
			// so the parked copy has served its purpose.
			if _, err := hdb.DB.Exec("DROP TABLE " + migratedMPKeystoreTable); err != nil {
				lgSigner.Warn("dropping the migrated MP key table failed; leaving it", "table", migratedMPKeystoreTable, "err", err)
			} else {
				lgSigner.Info("dropped the migrated MP key table", "table", migratedMPKeystoreTable)
			}
		}
		return nil
	}
	if !dbTableExists(hdb.DB, "DnssecKeyStore") {
		return fmt.Errorf("MP key migration: DnssecKeyStore does not exist yet; the KeyDB must be initialized first")
	}

	type oldRow struct {
		zonename, state, algorithm, creator, privatekey, keyrr, comment string
		keyid, flags, confirmed                                         int
		confirmedAt, publishedAt, retiredAt                             string
	}
	rows, err := hdb.DB.Query(`SELECT zonename, state, keyid, flags, COALESCE(algorithm,''), COALESCE(creator,''), COALESCE(privatekey,''), COALESCE(keyrr,''), COALESCE(comment,''),
		COALESCE(propagation_confirmed,0), COALESCE(propagation_confirmed_at,''), COALESCE(published_at,''), COALESCE(retired_at,'') FROM MPDnssecKeyStore`)
	if err != nil {
		return fmt.Errorf("MP key migration: reading MPDnssecKeyStore: %w", err)
	}
	var old []oldRow
	for rows.Next() {
		var r oldRow
		if err := rows.Scan(&r.zonename, &r.state, &r.keyid, &r.flags, &r.algorithm, &r.creator, &r.privatekey, &r.keyrr, &r.comment,
			&r.confirmed, &r.confirmedAt, &r.publishedAt, &r.retiredAt); err != nil {
			rows.Close()
			return fmt.Errorf("MP key migration: scanning MPDnssecKeyStore: %w", err)
		}
		old = append(old, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("MP key migration: reading MPDnssecKeyStore: %w", err)
	}

	tx, err := hdb.DB.Begin()
	if err != nil {
		return fmt.Errorf("MP key migration: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	inserted := 0
	for _, r := range old {
		rr, err := dns.NewRR(r.keyrr)
		if err != nil {
			return fmt.Errorf("MP key migration: zone %s key %d: keyrr does not parse: %w", r.zonename, r.keyid, err)
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			return fmt.Errorf("MP key migration: zone %s key %d: keyrr is not a DNSKEY", r.zonename, r.keyid)
		}
		oldAlg := dnskey.Algorithm
		if newAlg, renumbered := mpsignerCodepointToRegistry[oldAlg]; renumbered && newAlg != oldAlg {
			dnskey.Algorithm = newAlg
		}
		keyrr := dnskey.String()
		if _, err := dns.NewRR(keyrr); err != nil {
			return fmt.Errorf("MP key migration: zone %s key %d: rewritten keyrr does not parse: %w", r.zonename, r.keyid, err)
		}
		keyid := dnskey.KeyTag()
		privatekey := r.privatekey
		if r.state == DnskeyStateForeign && privatekey != "" {
			lgSigner.Warn("MP key migration: a foreign key carried a private half; dropped", "zone", r.zonename, "keyid", r.keyid)
			privatekey = ""
		}
		if r.algorithm != "" {
			if _, known := dns.StringToAlgorithm[r.algorithm]; !known {
				lgSigner.Warn("MP key migration: algorithm is not linked into this binary; the key is migrated but cannot sign here",
					"zone", r.zonename, "keyid", keyid, "algorithm", r.algorithm)
			}
		}
		res, err := tx.Exec(`INSERT INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, comment, published_at, retired_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.zonename, r.state, keyid, r.flags, r.algorithm, r.creator, privatekey, keyrr, r.comment, r.publishedAt, r.retiredAt)
		if err != nil {
			return fmt.Errorf("MP key migration: zone %s key %d (was %d): insert into DnssecKeyStore: %w", r.zonename, keyid, r.keyid, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("MP key migration: zone %s key %d: insert affected %d rows, want 1", r.zonename, keyid, n)
		}
		inserted++
		if r.confirmed != 0 {
			if _, err := tx.Exec(`INSERT INTO MPKeyPropagation (zonename, keyid, confirmed, confirmed_at) VALUES (?, ?, 1, ?)
				ON CONFLICT(zonename, keyid) DO UPDATE SET confirmed=1, confirmed_at=excluded.confirmed_at`,
				r.zonename, keyid, r.confirmedAt); err != nil {
				return fmt.Errorf("MP key migration: zone %s key %d: propagation record: %w", r.zonename, keyid, err)
			}
		}
		if keyid != uint16(r.keyid) || dnskey.Algorithm != oldAlg {
			lgSigner.Info("MP key migration: key renumbered", "zone", r.zonename, "old_keyid", r.keyid, "new_keyid", keyid,
				"old_alg", oldAlg, "new_alg", dnskey.Algorithm, "state", r.state)
		}
	}
	if inserted != len(old) {
		return fmt.Errorf("MP key migration: %d rows read, %d inserted; refusing to start", len(old), inserted)
	}
	if _, err := tx.Exec("ALTER TABLE MPDnssecKeyStore RENAME TO " + migratedMPKeystoreTable); err != nil {
		return fmt.Errorf("MP key migration: renaming the old table: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("MP key migration: commit: %w", err)
	}
	committed = true
	lgSigner.Info("MP key migration: keys moved into DnssecKeyStore", "keys", inserted, "old_table", migratedMPKeystoreTable)
	return nil
}

// migrateHsyncSchema applies schema migrations for existing databases: the
// correlation_id → distribution_id rename (M41), and the move of the
// signer's keys into tdns's keystore (fail-closed, see migrateMPKeystore).
func (hdb *HsyncDB) migrateHsyncSchema() error {
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
	return hdb.migrateMPKeystore()
}

// InitHsyncTables initializes the HSYNC tables in the KeyDB.
// Call this during application startup after KeyDB is created.
func (hdb *HsyncDB) InitHsyncTables() error {
	hdb.Lock()
	defer hdb.Unlock()

	// Create tables
	for name, schema := range HsyncTables {
		_, err := hdb.DB.Exec(schema)
		if err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	// Migrate existing data. After the tables, because the key migration
	// writes into MPKeyPropagation, which may be new; before the indexes for
	// the same reason the rename wants the old table gone first.
	if err := hdb.migrateHsyncSchema(); err != nil {
		return err
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
