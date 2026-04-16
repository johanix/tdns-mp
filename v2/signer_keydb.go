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
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM MPDnssecKeyStore WHERE state=?`
		args = []interface{}{state}
	} else {
		query = `SELECT zonename, keyid, flags, algorithm, state, COALESCE(keyrr, ''), COALESCE(published_at, ''), COALESCE(retired_at, '') FROM MPDnssecKeyStore WHERE zonename=? AND state=?`
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
	err = tx.QueryRow(`SELECT state FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&oldstate)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("key with keyid %d not found in zone %s", keyid, zonename)
		}
		return fmt.Errorf("error querying MPDnssecKeyStore: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	var res sql.Result
	switch newstate {
	case tdns.DnskeyStatePublished:
		res, err = tx.Exec(`UPDATE MPDnssecKeyStore SET state=?, published_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	case tdns.DnskeyStateRetired:
		res, err = tx.Exec(`UPDATE MPDnssecKeyStore SET state=?, retired_at=? WHERE zonename=? AND keyid=?`,
			newstate, now, zonename, keyid)
	default:
		res, err = tx.Exec(`UPDATE MPDnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
			newstate, zonename, keyid)
	}

	if err != nil {
		return fmt.Errorf("error updating MPDnssecKeyStore: %v", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		err = fmt.Errorf("no rows updated for key %d in zone %s", keyid, zonename)
		return err
	}

	delete(hdb.KeystoreDnskeyCache, zonename+"+"+oldstate)
	delete(hdb.KeystoreDnskeyCache, zonename+"+"+newstate)
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zonename, oldstate))
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zonename, newstate))

	lgSigner.Info("DNSKEY state updated", "zone", zonename, "keyid", keyid, "oldstate", oldstate, "newstate", newstate)
	return nil
}

// GenerateAndStageKey generates a new DNSSEC key and transitions it to the
// appropriate initial state (mpdist for MP zones, published otherwise).
func GenerateAndStageKey(hdb *HsyncDB, zone, creator string, alg uint8, keytype string, isMultiProvider bool) (uint16, error) {
	pkc, _, err := hdb.GenerateKeypairMP(zone, creator, tdns.DnskeyStateCreated, dns.TypeDNSKEY, alg, keytype, nil)
	if err != nil {
		return 0, fmt.Errorf("GenerateAndStageKey: key generation failed: %w", err)
	}

	keyid := pkc.KeyId

	var targetState string
	if isMultiProvider {
		targetState = DnskeyStateMpdist
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
	const inventorySql = `SELECT keyid, flags, algorithm, state, COALESCE(keyrr, '') FROM MPDnssecKeyStore WHERE zonename=?`

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
	const updateSql = `UPDATE MPDnssecKeyStore SET propagation_confirmed=1, propagation_confirmed_at=? WHERE zonename=? AND keyid=?`

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := hdb.Exec(updateSql, now, zonename, keyid)
	if err != nil {
		return fmt.Errorf("SetPropagationConfirmed: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("SetPropagationConfirmed: key %d not found in zone %s", keyid, zonename)
	}

	delete(hdb.KeystoreDnskeyCache, zonename+"+"+tdns.DnskeyStatePublished)
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zonename, tdns.DnskeyStatePublished))
	lgSigner.Info("key marked as propagation confirmed", "keyid", keyid, "zone", zonename)
	return nil
}

// TransitionMpdistToPublished transitions a key from mpdist to published state.
// If the key is not in mpdist state, this is a no-op (returns nil).
func TransitionMpdistToPublished(hdb *HsyncDB, zonename string, keyid uint16) error {
	var currentState string
	err := hdb.QueryRow(`SELECT state FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("TransitionMpdistToPublished: query failed: %w", err)
	}

	if currentState != DnskeyStateMpdist {
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
	err := hdb.QueryRow(`SELECT state FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("TransitionMpremoveToRemoved: query failed: %w", err)
	}

	if currentState != DnskeyStateMpremove {
		lgSigner.Debug("TransitionMpremoveToRemoved: key not in mpremove, no-op", "zone", zonename, "keyid", keyid, "state", currentState)
		return nil
	}

	if err := UpdateDnssecKeyState(hdb, zonename, keyid, tdns.DnskeyStateRemoved); err != nil {
		return fmt.Errorf("TransitionMpremoveToRemoved: %w", err)
	}

	lgSigner.Info("key transitioned mpremove->removed", "zone", zonename, "keyid", keyid)
	return nil
}

func mpDnssecCacheKey(zonename, state string) string {
	return zonename + "+mpdnssec+" + state
}

// GenerateKeypairMP stores generated KEY/DNSKEY material in MPDnssecKeyStore.
func (hdb *HsyncDB) GenerateKeypairMP(owner, creator, state string, rrtype uint16, alg uint8, keytype string, tx *tdns.Tx) (*tdns.PrivateKeyCache, string, error) {
	pkc, err := tdns.GenerateKeyMaterial(owner, rrtype, alg, keytype)
	if err != nil {
		return nil, "", err
	}

	const (
		addMPDnssecKeySql = `
INSERT OR REPLACE INTO MPDnssecKeyStore (zonename, state, keyid, algorithm, flags, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	)

	localtx := false
	if tx == nil {
		tx, err = hdb.Begin("GenerateKeypairMP")
		if err != nil {
			return nil, "", err
		}
		localtx = true
	}
	defer func() {
		if localtx {
			if err != nil {
				tx.Rollback()
			} else {
				tx.Commit()
			}
		}
	}()

	if state == "" {
		state = "active"
	}

	switch rrtype {
	case dns.TypeDNSKEY:
		flags := 257
		if keytype == "ZSK" {
			flags = 256
		}
		_, err = tx.Exec(addMPDnssecKeySql, owner, state, pkc.KeyId,
			dns.AlgorithmToString[pkc.Algorithm], flags, creator, pkc.PrivateKey, pkc.DnskeyRR.String())
	default:
		return nil, "", fmt.Errorf("GenerateKeypairMP: unsupported rrtype %d", rrtype)
	}
	if err != nil {
		return nil, "", err
	}

	return pkc, fmt.Sprintf("Generated new %s %s with keyid %d (initial state: %s)", owner, dns.TypeToString[rrtype], pkc.KeyId, state), nil
}

// GetDnssecKeysMP returns DNSSEC keys from MPDnssecKeyStore (tdns-mp signer table).
func GetDnssecKeysMP(hdb *HsyncDB, zonename, state string) (*tdns.DnssecKeys, error) {
	const fetchSql = `
SELECT keyid, flags, algorithm, privatekey, keyrr FROM MPDnssecKeyStore WHERE zonename=? AND state=?`

	cacheKey := mpDnssecCacheKey(zonename, state)
	if state == tdns.DnskeyStateActive {
		if dak, ok := hdb.KeystoreDnskeyCache[cacheKey]; ok {
			return dak, nil
		}
	}

	var dk tdns.DnssecKeys

	rows, err := hdb.Query(fetchSql, zonename, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var algorithm, privatekey, keyrrstr, logmsg string
	var flags, keyid int
	var keysfound bool

	for rows.Next() {
		err := rows.Scan(&keyid, &flags, &algorithm, &privatekey, &keyrrstr)
		if err != nil {
			if err == sql.ErrNoRows {
				return &dk, nil
			}
			return nil, err
		}

		keysfound = true

		_, alg, bindFormat, err := tdns.ParsePrivateKeyFromDB(privatekey, algorithm, keyrrstr)
		if err != nil {
			return nil, err
		}

		pkc, err := tdns.PrepareKeyCache(bindFormat, keyrrstr)
		if err != nil {
			return nil, err
		}

		if pkc.Algorithm != alg {
			return nil, fmt.Errorf("algorithm mismatch for key %s: stored=%d parsed=%d", keyrrstr, alg, pkc.Algorithm)
		}

		if (flags & 0x0001) != 0 {
			dk.KSKs = append(dk.KSKs, pkc)
			logmsg += fmt.Sprintf("%d (KSK) ", keyid)
		} else {
			dk.ZSKs = append(dk.ZSKs, pkc)
			logmsg += fmt.Sprintf("%d (ZSK) ", keyid)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if !keysfound {
		return &dk, nil
	}

	if len(dk.KSKs) == 0 {
		return &dk, nil
	}

	if len(dk.ZSKs) == 0 {
		dk.ZSKs = append(dk.ZSKs, dk.KSKs[0])
	}

	lgSigner.Debug("GetDnssecKeysMP returned keys", "zone", zonename, "state", state, "keys", logmsg)

	hdb.KeystoreDnskeyCache[cacheKey] = &dk

	return &dk, nil
}

// PromoteDnssecKeyMP updates key state in MPDnssecKeyStore.
func PromoteDnssecKeyMP(hdb *HsyncDB, zonename string, keyid uint16, oldstate, newstate string) (err error) {
	const getSql = `SELECT state FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`
	const updateSql = `UPDATE MPDnssecKeyStore SET state=? WHERE zonename=? AND keyid=? AND state=?`

	tx, err := hdb.Begin("PromoteDnssecKeyMP")
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			if commitErr := tx.Commit(); commitErr != nil {
				err = fmt.Errorf("commit failed: %w", commitErr)
			}
		}
	}()

	var currentState string
	err = tx.QueryRow(getSql, zonename, keyid).Scan(&currentState)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("key with keyid %d not found in zone %s", keyid, zonename)
		}
		return err
	}

	if currentState != oldstate {
		return fmt.Errorf("key with keyid %d in zone %s is not in state %s", keyid, zonename, oldstate)
	}

	res, err := tx.Exec(updateSql, newstate, zonename, keyid, oldstate)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows updated for key %d in zone %s", keyid, zonename)
	}

	delete(hdb.KeystoreDnskeyCache, zonename+"+"+oldstate)
	delete(hdb.KeystoreDnskeyCache, zonename+"+"+newstate)
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zonename, oldstate))
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zonename, newstate))

	return nil
}

func getDnssecKeyPropagationMP(hdb *HsyncDB, zonename string, keyid uint16) (bool, time.Time, error) {
	const querySql = `SELECT propagation_confirmed, propagation_confirmed_at FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`

	var confirmed int
	var confirmedAtStr string
	err := hdb.QueryRow(querySql, zonename, keyid).Scan(&confirmed, &confirmedAtStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, time.Time{}, fmt.Errorf("key %d not found in zone %s", keyid, zonename)
		}
		return false, time.Time{}, err
	}

	var confirmedAt time.Time
	if confirmedAtStr != "" {
		confirmedAt, _ = time.Parse(time.RFC3339, confirmedAtStr)
	}
	return confirmed != 0, confirmedAt, nil
}

func canPromoteMultiProviderMP(hdb *HsyncDB, zonename string, keyid uint16) bool {
	confirmed, confirmedAt, err := getDnssecKeyPropagationMP(hdb, zonename, keyid)
	if err != nil {
		lgSigner.Error("error checking propagation for multi-provider promotion", "keyid", keyid, "zone", zonename, "err", err)
		return false
	}

	if !confirmed {
		lgSigner.Debug("propagation not yet confirmed", "keyid", keyid, "zone", zonename)
		return false
	}

	elapsed := time.Since(confirmedAt)
	if elapsed < tdns.DefaultDnskeyTTL {
		lgSigner.Debug("propagation confirmed but TTL not expired", "keyid", keyid, "zone", zonename, "elapsed", elapsed.Truncate(time.Second), "ttl", tdns.DefaultDnskeyTTL)
		return false
	}

	lgSigner.Info("key eligible for multi-provider promotion", "keyid", keyid, "zone", zonename, "elapsed", elapsed.Truncate(time.Second), "ttl", tdns.DefaultDnskeyTTL)
	return true
}

func refreshActiveDnssecKeysMP(zd *tdns.ZoneData, hdb *HsyncDB, context string) (*tdns.DnssecKeys, error) {
	delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zd.ZoneName, tdns.DnskeyStateActive))
	delete(hdb.KeystoreDnskeyCache, zd.ZoneName+"+"+tdns.DnskeyStateActive)
	dak, err := GetDnssecKeysMP(hdb, zd.ZoneName, tdns.DnskeyStateActive)
	if err != nil {
		lgSigner.Error("failed to get DNSSEC active keys", "zone", zd.ZoneName, "context", context, "err", err)
		return nil, err
	}
	return dak, nil
}

// EnsureActiveDnssecKeysMP mirrors tdns.EnsureActiveDnssecKeys using MPDnssecKeyStore.
func EnsureActiveDnssecKeysMP(mpzd *MPZoneData, hdb *HsyncDB) (*tdns.DnssecKeys, error) {
	zd := mpzd.ZoneData
	if !zd.Options[tdns.OptOnlineSigning] && !zd.Options[tdns.OptInlineSigning] {
		return nil, fmt.Errorf("EnsureActiveDnssecKeysMP: zone %s does not allow signing", zd.ZoneName)
	}

	dak, err := GetDnssecKeysMP(hdb, zd.ZoneName, tdns.DnskeyStateActive)
	if err != nil {
		return nil, err
	}

	if len(dak.KSKs) > 0 && len(dak.ZSKs) > 0 {
		hasRealZSK := false
		for _, zsk := range dak.ZSKs {
			if zsk.DnskeyRR.Flags == 256 {
				hasRealZSK = true
				break
			}
		}
		if hasRealZSK {
			return dak, nil
		}
	}

	lgSigner.Info("no active DNSSEC keys available, will generate new keys", "zone", zd.ZoneName)

	dpk, err := GetDnssecKeysMP(hdb, zd.ZoneName, tdns.DnskeyStatePublished)
	if err != nil {
		return nil, err
	}

	if len(dpk.KSKs) > 0 || len(dpk.ZSKs) > 0 {
		lgSigner.Info("published DNSSEC keys available for promotion", "zone", zd.ZoneName)

		var promotedKskKeyId uint16
		multiProviderGating := zd.Options[tdns.OptMultiProvider]

		if len(dpk.KSKs) > 0 {
			promotedKskKeyId = dpk.KSKs[0].KeyId
			if multiProviderGating {
				if !canPromoteMultiProviderMP(hdb, zd.ZoneName, promotedKskKeyId) {
					lgSigner.Info("KSK not yet eligible for promotion (multi-provider gating)", "zone", zd.ZoneName, "keyid", promotedKskKeyId)
					promotedKskKeyId = 0
					goto skipKskPromotionMP
				}
			}
			err = PromoteDnssecKeyMP(hdb, zd.ZoneName, promotedKskKeyId, tdns.DnskeyStatePublished, tdns.DnskeyStateActive)
			if err != nil {
				return nil, err
			}
			lgSigner.Info("promoted published KSK to active", "zone", zd.ZoneName, "keyid", promotedKskKeyId)
		}
	skipKskPromotionMP:

		if len(dpk.ZSKs) > 0 && (len(dpk.KSKs) == 0 || dpk.ZSKs[0].KeyId != promotedKskKeyId) {
			zskKeyId := dpk.ZSKs[0].KeyId
			if multiProviderGating {
				if !canPromoteMultiProviderMP(hdb, zd.ZoneName, zskKeyId) {
					lgSigner.Info("ZSK not yet eligible for promotion (multi-provider gating)", "zone", zd.ZoneName, "keyid", zskKeyId)
					goto skipZskPromotionMP
				}
			}
			err = PromoteDnssecKeyMP(hdb, zd.ZoneName, zskKeyId, tdns.DnskeyStatePublished, tdns.DnskeyStateActive)
			if err != nil {
				return nil, err
			}
			lgSigner.Info("promoted published ZSK to active", "zone", zd.ZoneName, "keyid", zskKeyId)
		}
	skipZskPromotionMP:

		dak, err = GetDnssecKeysMP(hdb, zd.ZoneName, tdns.DnskeyStateActive)
		if err != nil {
			return nil, err
		}
	}

	if len(dak.KSKs) == 0 {
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zd.ZoneName, tdns.DnskeyStateActive))
		delete(hdb.KeystoreDnskeyCache, zd.ZoneName+"+"+tdns.DnskeyStateActive)
		_, msg, err := hdb.GenerateKeypairMP(zd.ZoneName, "ensure-active-keys", tdns.DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "KSK", nil)
		if err != nil {
			return nil, fmt.Errorf("EnsureActiveDnssecKeysMP: KSK: %w", err)
		}
		lgSigner.Info("generated KSK", "msg", msg)
		dak, err = refreshActiveDnssecKeysMP(zd, hdb, "after KSK generation")
		if err != nil {
			return nil, err
		}
	}

	realZSKCount := 0
	for _, zsk := range dak.ZSKs {
		if zsk.DnskeyRR.Flags == 256 {
			realZSKCount++
		}
	}

	if realZSKCount == 0 {
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(zd.ZoneName, tdns.DnskeyStateActive))
		delete(hdb.KeystoreDnskeyCache, zd.ZoneName+"+"+tdns.DnskeyStateActive)
		_, msg, err := hdb.GenerateKeypairMP(zd.ZoneName, "ensure-active-keys", tdns.DnskeyStateActive, dns.TypeDNSKEY, zd.DnssecPolicy.Algorithm, "ZSK", nil)
		if err != nil {
			return nil, fmt.Errorf("EnsureActiveDnssecKeysMP: ZSK: %w", err)
		}
		lgSigner.Info("generated ZSK", "msg", msg)
		dak, err = refreshActiveDnssecKeysMP(zd, hdb, "after ZSK generation")
		if err != nil {
			return nil, err
		}
	}

	if len(dak.KSKs) == 0 {
		return nil, fmt.Errorf("EnsureActiveDnssecKeysMP: no active KSK for zone %s", zd.ZoneName)
	}

	dak, err = refreshActiveDnssecKeysMP(zd, hdb, "before publishing")
	if err != nil {
		return nil, err
	}

	err = zd.PublishDnskeyRRs(dak)
	if err != nil {
		lgSigner.Warn("failed to publish DNSKEY RRs", "zone", zd.ZoneName, "err", err)
	}

	return dak, nil
}
