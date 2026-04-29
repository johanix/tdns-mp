/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor persistent event log: SQLite table for recording all zone
 * data modifications with timestamps and originator.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// AuditEvent represents one logged event in the auditor event log.
type AuditEvent struct {
	ID          int64     `json:"id"`
	Time        time.Time `json:"time"`
	Zone        string    `json:"zone"`
	Originator  string    `json:"originator"`
	DeliveredBy string    `json:"delivered_by"`
	EventType   string    `json:"event_type"`
	Summary     string    `json:"summary"`
	RRsAdded    int       `json:"rrs_added"`
	RRsRemoved  int       `json:"rrs_removed"`
	RRtypes     string    `json:"rrtypes"`
	Details     string    `json:"details"`
}

// InitAuditEventLogTable creates the AuditEventLog table and indexes.
func InitAuditEventLogTable(kdb *tdns.KeyDB) error {
	kdb.Lock()
	defer kdb.Unlock()

	schema := `CREATE TABLE IF NOT EXISTS AuditEventLog (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	time        TEXT NOT NULL,
	zone        TEXT NOT NULL,
	originator  TEXT NOT NULL,
	delivered_by TEXT DEFAULT '',
	event_type  TEXT NOT NULL,
	summary     TEXT NOT NULL,
	rrs_added   INTEGER DEFAULT 0,
	rrs_removed INTEGER DEFAULT 0,
	rrtypes     TEXT DEFAULT '',
	details     TEXT DEFAULT ''
)`
	if _, err := kdb.DB.Exec(schema); err != nil {
		return fmt.Errorf("failed to create AuditEventLog table: %w", err)
	}

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_audit_zone_time ON AuditEventLog(zone, time)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON AuditEventLog(time)`,
	}
	for _, idx := range indexes {
		if _, err := kdb.DB.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// InsertAuditEvent inserts a new event into the log.
func InsertAuditEvent(kdb *tdns.KeyDB, event *AuditEvent) error {
	kdb.Lock()
	defer kdb.Unlock()

	_, err := kdb.DB.Exec(
		`INSERT INTO AuditEventLog (time, zone, originator, delivered_by, event_type, summary, rrs_added, rrs_removed, rrtypes, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Time.UTC().Format(time.RFC3339),
		event.Zone,
		event.Originator,
		event.DeliveredBy,
		event.EventType,
		event.Summary,
		event.RRsAdded,
		event.RRsRemoved,
		event.RRtypes,
		event.Details,
	)
	return err
}

// QueryAuditEvents returns events matching the given filters.
// If zone is "", all zones are returned. If since is zero, no time filter.
// limit of 0 means no limit.
func QueryAuditEvents(kdb *tdns.KeyDB, zone string, since time.Time, limit int) ([]AuditEvent, error) {
	kdb.Lock()
	defer kdb.Unlock()

	query := `SELECT id, time, zone, originator, delivered_by, event_type, summary, rrs_added, rrs_removed, rrtypes, details FROM AuditEventLog WHERE 1=1`
	var args []interface{}

	if zone != "" {
		query += ` AND zone = ?`
		args = append(args, zone)
	}
	if !since.IsZero() {
		query += ` AND time >= ?`
		args = append(args, since.UTC().Format(time.RFC3339))
	}
	query += ` ORDER BY time DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := kdb.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var timeStr string
		if err := rows.Scan(&e.ID, &timeStr, &e.Zone, &e.Originator, &e.DeliveredBy, &e.EventType, &e.Summary, &e.RRsAdded, &e.RRsRemoved, &e.RRtypes, &e.Details); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		t, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			// Skip rows whose timestamp doesn't parse rather than
			// failing the whole query: one corrupt row should not
			// blind an admin to the rest of the log.
			lgAuditor.Warn("audit event has unparseable timestamp; skipping",
				"id", e.ID, "time", timeStr, "err", err)
			continue
		}
		e.Time = t
		events = append(events, e)
	}
	return events, rows.Err()
}

// ClearAuditEvents deletes events matching the given filters.
// `all=true` is mutually exclusive with `zone` / `olderThan`: an
// admin asking for both has very likely made a mistake and we'd
// rather error than silently wipe the whole table.
func ClearAuditEvents(kdb *tdns.KeyDB, zone string, olderThan time.Duration, all bool) (int64, error) {
	kdb.Lock()
	defer kdb.Unlock()

	var query string
	var args []interface{}

	if all {
		if zone != "" || olderThan > 0 {
			return 0, fmt.Errorf("ClearAuditEvents: all=true is mutually exclusive with zone or older_than")
		}
		query = `DELETE FROM AuditEventLog`
	} else if zone != "" && olderThan > 0 {
		cutoff := time.Now().Add(-olderThan)
		query = `DELETE FROM AuditEventLog WHERE zone = ? AND time < ?`
		args = append(args, zone, cutoff.UTC().Format(time.RFC3339))
	} else if zone != "" {
		query = `DELETE FROM AuditEventLog WHERE zone = ?`
		args = append(args, zone)
	} else if olderThan > 0 {
		cutoff := time.Now().Add(-olderThan)
		query = `DELETE FROM AuditEventLog WHERE time < ?`
		args = append(args, cutoff.UTC().Format(time.RFC3339))
	} else {
		return 0, fmt.Errorf("must specify zone, older_than, or all")
	}

	result, err := kdb.DB.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// StartAuditEventPruner runs a background goroutine that prunes old events.
func StartAuditEventPruner(ctx context.Context, kdb *tdns.KeyDB, retention, interval time.Duration) {
	if retention <= 0 || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				deleted, err := ClearAuditEvents(kdb, "", retention, false)
				if err != nil {
					lgAuditor.Error("event pruner failed", "err", err)
				} else if deleted > 0 {
					lgAuditor.Info("pruned old audit events", "deleted", deleted, "retention", retention)
				}
			}
		}
	}()
}
