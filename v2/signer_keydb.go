/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * Local copies of KeyDB signer functions, adapted from tdns/v2/keystore.go.
 * These operate on *tdns.KeyDB but live in tdns-mp to avoid cross-package calls.
 */
package tdnsmp

import (
	"database/sql"
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// GetDnssecKeysByState returns all DNSSEC keys in a given state, with lifecycle timestamps.
// If zone is empty, returns keys across all zones.
func GetDnssecKeysByState(hdb *HsyncDB, zone string, state string) ([]DnssecKeyWithTimestamps, error) {
	var query string
	var args []interface{}

	if zone == "" {
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM DnssecKeyStore WHERE state=?`
		args = []interface{}{state}
	} else {
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM DnssecKeyStore WHERE zonename=? AND state=?`
		args = []interface{}{zone, state}
	}

	rows, err := hdb.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("GetDnssecKeysByState: query failed: %w", err)
	}
	defer rows.Close()

	var entries []DnssecKeyWithTimestamps
	for rows.Next() {
		var zonename, algorithm, st, keyrr, publishedAtStr, retiredAtStr string
		var keyid, flags int
		if err := rows.Scan(&zonename, &keyid, &flags, &algorithm, &st, &keyrr, &publishedAtStr, &retiredAtStr); err != nil {
			return nil, fmt.Errorf("GetDnssecKeysByState: scan failed: %w", err)
		}

		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("GetDnssecKeysByState: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entry := DnssecKeyWithTimestamps{
			ZoneName:  zonename,
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     st,
			KeyRR:     keyrr,
		}

		if publishedAtStr != "" {
			if t, err := time.Parse(time.RFC3339, publishedAtStr); err == nil {
				entry.PublishedAt = &t
			}
		}
		if retiredAtStr != "" {
			if t, err := time.Parse(time.RFC3339, retiredAtStr); err == nil {
				entry.RetiredAt = &t
			}
		}

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetDnssecKeysByState: rows iteration failed: %w", err)
	}

	return entries, nil
}

// UpdateDnssecKeyState transitions a DNSSEC key to a new state and sets the
// appropriate lifecycle timestamp. When transitioning to "published", sets
// published_at. When transitioning to "retired", sets retired_at.
// Invalidates the cache for both old and new states.
func UpdateDnssecKeyState(hdb *HsyncDB, zonename string, keyid uint16, newstate string) error {
	tx, err := hdb.Begin("UpdateDnssecKeyState")
	if err != nil {
		return fmt.Errorf("error beginning transaction: %v", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	// Get the current state so we can invalidate the right cache entry
	var oldstate string
	err = tx.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&oldstate)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("key with keyid %d not found in zone %s", keyid, zonename)
		}
		return fmt.Errorf("error querying DnssecKeyStore: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	var res sql.Result
	switch newstate {
	case tdns.DnskeyStatePublished:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=?, published_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	case tdns.DnskeyStateRetired:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=?, retired_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	default:
		res, err = tx.Exec(`UPDATE DnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
			newstate, zonename, keyid)
	}

	if err != nil {
		return fmt.Errorf("error updating DnssecKeyStore: %v", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		err = fmt.Errorf("no rows updated for key %d in zone %s", keyid, zonename)
		return err
	}

	// Invalidate caches for both old and new states
	delete(hdb.KeystoreDnskeyCache, zonename+"+"+oldstate)
	delete(hdb.KeystoreDnskeyCache, zonename+"+"+newstate)

	lgSigner.Info("DNSKEY state updated", "zone", zonename, "keyid", keyid, "oldstate", oldstate, "newstate", newstate)
	return nil
}

// GenerateAndStageKey generates a new DNSSEC key and transitions it to the
// appropriate initial state (mpdist for MP zones, published otherwise).
func GenerateAndStageKey(hdb *HsyncDB, zone, creator string, alg uint8, keytype string, isMultiProvider bool) (uint16, error) {
	pkc, _, err := hdb.GenerateKeypair(zone, creator, tdns.DnskeyStateCreated, dns.TypeDNSKEY, alg, keytype, nil)
	if err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: key generation failed: %w", err)
	}

	keyid := pkc.KeyId

	var targetState string
	if isMultiProvider {
		targetState = tdns.DnskeyStateMpdist
	} else {
		targetState = tdns.DnskeyStatePublished
	}

	if err := UpdateDnssecKeyState(hdb, zone, keyid, targetState); err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: state transition to %s failed: %w", targetState, err)
	}

	lgSigner.Info("generated and staged DNSSEC key", "zone", zone, "keyid", keyid, "keytype", keytype, "state", targetState, "mp", isMultiProvider)
	return keyid, nil
}

// GetKeyInventory returns the complete DNSKEY inventory for a zone.
func GetKeyInventory(hdb *HsyncDB, zonename string) ([]KeyInventoryItem, error) {
	const inventorySql = `SELECT keyid, flags, algorithm, state, COALESCE(keyrr, '') FROM DnssecKeyStore WHERE zonename=?`

	rows, err := hdb.Query(inventorySql, zonename)
	if err != nil {
		return nil, fmt.Errorf("GetKeyInventory: query failed for zone %s: %w", zonename, err)
	}
	defer rows.Close()

	var entries []KeyInventoryItem
	for rows.Next() {
		var keyid, flags int
		var algorithm string
		var state, keyrr string
		if err := rows.Scan(&keyid, &flags, &algorithm, &state, &keyrr); err != nil {
			return nil, fmt.Errorf("GetKeyInventory: scan failed: %w", err)
		}
		alg, ok := dns.StringToAlgorithm[algorithm]
		if !ok {
			lgSigner.Warn("GetKeyInventory: unknown algorithm, skipping key", "zone", zonename, "keyid", keyid, "algorithm", algorithm)
			continue
		}
		entries = append(entries, KeyInventoryItem{
			KeyTag:    uint16(keyid),
			Algorithm: alg,
			Flags:     uint16(flags),
			State:     state,
			KeyRR:     keyrr,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetKeyInventory: rows iteration failed: %w", err)
	}

	return entries, nil
}

// SetPropagationConfirmed marks a DNSKEY as propagation-confirmed in the keystore.
func SetPropagationConfirmed(hdb *HsyncDB, zonename string, keyid uint16) error {
	const updateSql = `UPDATE DnssecKeyStore SET propagation_confirmed=1, propagation_confirmed_at=? WHERE zonename=? AND keyid=?`

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := hdb.Exec(updateSql, now, zonename, keyid)
	if err != nil {
		return fmt.Errorf("SetPropagationConfirmed: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("SetPropagationConfirmed: key %d not found in zone %s", keyid, zonename)
	}

	// Invalidate cache for published state (the key should be in published state)
	delete(hdb.KeystoreDnskeyCache, zonename+"+"+tdns.DnskeyStatePublished)
	lgSigner.Info("key marked as propagation confirmed", "keyid", keyid, "zone", zonename)
	return nil
}

// TransitionMpdistToPublished transitions a key from mpdist to published state.
// If the key is not in mpdist state, this is a no-op (returns nil).
func TransitionMpdistToPublished(hdb *HsyncDB, zonename string, keyid uint16) error {
	var currentState string
	err := hdb.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("TransitionMpdistToPublished: query failed: %w", err)
	}

	if currentState != tdns.DnskeyStateMpdist {
		lgSigner.Debug("TransitionMpdistToPublished: key not in mpdist, no-op", "zone", zonename, "keyid", keyid, "state", currentState)
		return nil
	}

	if err := UpdateDnssecKeyState(hdb, zonename, keyid, tdns.DnskeyStatePublished); err != nil {
		return fmt.Errorf("TransitionMpdistToPublished: %w", err)
	}

	lgSigner.Info("key transitioned mpdist->published", "zone", zonename, "keyid", keyid)
	return nil
}

// TransitionMpremoveToRemoved transitions a key from mpremove to removed state.
// If the key is not in mpremove state, this is a no-op (returns nil).
func TransitionMpremoveToRemoved(hdb *HsyncDB, zonename string, keyid uint16) error {
	var currentState string
	err := hdb.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("TransitionMpremoveToRemoved: query failed: %w", err)
	}

	if currentState != tdns.DnskeyStateMpremove {
		lgSigner.Debug("TransitionMpremoveToRemoved: key not in mpremove, no-op", "zone", zonename, "keyid", keyid, "state", currentState)
		return nil
	}

	if err := UpdateDnssecKeyState(hdb, zonename, keyid, tdns.DnskeyStateRemoved); err != nil {
		return fmt.Errorf("TransitionMpremoveToRemoved: %w", err)
	}

	lgSigner.Info("key transitioned mpremove->removed", "zone", zonename, "keyid", keyid)
	return nil
}
