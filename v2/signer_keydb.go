/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * The signer's key seam.
 *
 * The keys live in tdns's DnssecKeyStore and tdns signs with them: the first
 * sign after the policy binds, every refresh's staged scope, the renewals of
 * its ResignerEngine, the standby maintenance and the timed transitions of
 * its key-state worker. What is MP's is the protocol between the states:
 * mpdist (a new key, served ahead of its promotion, awaiting the peers'
 * confirmation that it has propagated), mpremove (a retired key withdrawn
 * from the RRset, awaiting confirmation of the withdrawal), foreign (another
 * signer's DNSKEY, served here and never signing), and the propagation
 * record that gates a key's promotion to active. tdns learns the states
 * through its key lifecycle hooks (RegisterMPKeyLifecycleHooks) and attaches
 * no meaning to them beyond served or not served.
 */
package tdnsmp

import (
	"database/sql"
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// KeyInventoryItem and DnssecKeyWithTimestamps are tdns's: the inventory the
// KEYSTATE protocol carries is read from DnssecKeyStore.
type KeyInventoryItem = tdns.KeyInventoryItem
type DnssecKeyWithTimestamps = tdns.DnssecKeyWithTimestamps

// RegisterMPKeyLifecycleHooks installs the hooks that make tdns's keystore
// and key-state worker run the multi-provider key protocol for zones that
// carry the multi-provider option. Registered before tdns's MainInit, so the
// hooks are in place before any zone's first refresh. Zones without the
// option get tdns's defaults from every hook.
//
// The KeyDB is looked up at call time: it does not exist yet when this
// registers.
func RegisterMPKeyLifecycleHooks(conf *Config) {
	isMP := func(zd *tdns.ZoneData) bool {
		return zd != nil && zd.Options[tdns.OptMultiProvider]
	}
	keyDB := func() *tdns.KeyDB {
		if conf == nil || conf.Config == nil {
			return nil
		}
		return conf.Config.Internal.KeyDB
	}
	tdns.RegisterKeyLifecycleHooks(tdns.KeyLifecycleHooks{
		// A new standby key is served first and promoted only once the
		// peers confirm it has propagated.
		StagedState: func(zd *tdns.ZoneData) string {
			if isMP(zd) {
				return DnskeyStateMpdist
			}
			return ""
		},
		// A retired key leaves the RRset and waits for the peers to confirm
		// the withdrawal before it is removed.
		RetiredState: func(zd *tdns.ZoneData) string {
			if isMP(zd) {
				return DnskeyStateMpremove
			}
			return ""
		},
		// The propagation gate: confirmed by the peers, and the DNSKEY TTL
		// elapsed since.
		MayPromote: func(zd *tdns.ZoneData, keyid uint16) bool {
			if !isMP(zd) {
				return true
			}
			hdb := NewHsyncDB(keyDB())
			if hdb == nil {
				return false
			}
			return canPromoteMultiProviderMP(hdb, zd.ZoneName, keyid)
		},
		// tdns may mint an active key only for a zone with no key of that
		// role at all (the bootstrap); a zone whose keys are staged or gated
		// waits for them. Removed and foreign rows do not count: the former
		// are history, the latter are not ours.
		MayGenerate: func(zd *tdns.ZoneData, role string) bool {
			if !isMP(zd) {
				return true
			}
			kdb := keyDB()
			if kdb == nil {
				return false
			}
			n, err := countOwnKeysOfRole(kdb, zd.ZoneName, role)
			if err != nil {
				lgSigner.Error("MayGenerate: counting keys failed; not generating", "zone", zd.ZoneName, "role", role, "err", err)
				return false
			}
			return n == 0
		},
		// Every committed change is pushed to the agents as a fresh
		// inventory. Off the caller's goroutine: the caller may hold a
		// zone's lock (the publish path resolves keys under it), and the
		// push is network I/O with a timeout per agent.
		OnStateChange: func(zone string, keyid uint16, from, to string) {
			if tdns.Globals.App.Type != AppTypeMPSigner {
				return
			}
			zd, ok := tdns.Zones.Get(zone)
			if !ok || !isMP(zd) {
				return
			}
			lgSigner.Info("key state changed; pushing the inventory to the agents", "zone", zone, "keyid", keyid, "from", from, "to", to)
			go pushKeystateInventoryToAllAgents(conf, zone)
		},
	})
}

// countOwnKeysOfRole counts the zone's own keys of a role in any state but
// removed. A KSK is any key with the SEP bit, revoked ones (flags 385)
// included; a ZSK is flags 256.
func countOwnKeysOfRole(kdb *tdns.KeyDB, zone, role string) (int, error) {
	var n int
	var err error
	if role == "ZSK" {
		err = kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND flags=256 AND state NOT IN (?, ?)`,
			zone, tdns.DnskeyStateRemoved, DnskeyStateForeign).Scan(&n)
	} else {
		err = kdb.DB.QueryRow(`SELECT COUNT(*) FROM DnssecKeyStore WHERE zonename=? AND (flags & 1) = 1 AND state NOT IN (?, ?)`,
			zone, tdns.DnskeyStateRemoved, DnskeyStateForeign).Scan(&n)
	}
	return n, err
}

// GetKeyInventory returns the complete DNSKEY inventory for a zone -- every
// key in every state, foreign ones included -- from DnssecKeyStore.
func GetKeyInventory(hdb *HsyncDB, zonename string) ([]KeyInventoryItem, error) {
	return tdns.GetKeyInventory(hdb.KeyDB, zonename)
}

// --- Propagation: the MP-owned side table ---------------------------------
//
// Whether the peers have confirmed a key's propagation is MP protocol state,
// kept beside tdns's keystore rather than in it, keyed by zone and key id.

func keyState(hdb *HsyncDB, zonename string, keyid uint16) (string, bool, error) {
	var state string
	err := hdb.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&state)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return state, true, nil
}

// SetPropagationConfirmed records that the peers confirmed a DNSKEY's
// propagation.
func SetPropagationConfirmed(hdb *HsyncDB, zonename string, keyid uint16) error {
	if _, found, err := keyState(hdb, zonename, keyid); err != nil {
		return fmt.Errorf("SetPropagationConfirmed: %w", err)
	} else if !found {
		return fmt.Errorf("SetPropagationConfirmed: key %d not found in zone %s", keyid, zonename)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := hdb.Exec(`INSERT INTO MPKeyPropagation (zonename, keyid, confirmed, confirmed_at) VALUES (?, ?, 1, ?)
		ON CONFLICT(zonename, keyid) DO UPDATE SET confirmed=1, confirmed_at=excluded.confirmed_at`, zonename, keyid, now)
	if err != nil {
		return fmt.Errorf("SetPropagationConfirmed: %w", err)
	}
	lgSigner.Info("key marked as propagation confirmed", "keyid", keyid, "zone", zonename)
	return nil
}

func getDnssecKeyPropagationMP(hdb *HsyncDB, zonename string, keyid uint16) (bool, time.Time, error) {
	var confirmed int
	var confirmedAtStr string
	err := hdb.QueryRow(`SELECT confirmed, confirmed_at FROM MPKeyPropagation WHERE zonename=? AND keyid=?`, zonename, keyid).Scan(&confirmed, &confirmedAtStr)
	if err == sql.ErrNoRows {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	if confirmed == 0 {
		return false, time.Time{}, nil
	}
	// A confirmation whose time does not parse is not a confirmation: the
	// zero time would make the TTL look long elapsed and open the gate.
	confirmedAt, perr := time.Parse(time.RFC3339, confirmedAtStr)
	if perr != nil {
		return false, time.Time{}, fmt.Errorf("propagation confirmed_at %q for key %d in zone %s does not parse: %w", confirmedAtStr, keyid, zonename, perr)
	}
	return true, confirmedAt, nil
}

// canPromoteMultiProviderMP is the promotion gate: propagation confirmed by
// the peers, and the DNSKEY TTL elapsed since the confirmation.
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

// TransitionMpdistToPublished moves a key the peers confirmed from mpdist to
// published, through tdns's keystore. A key in any other state is left alone.
func TransitionMpdistToPublished(hdb *HsyncDB, zonename string, keyid uint16) error {
	state, found, err := keyState(hdb, zonename, keyid)
	if err != nil {
		return fmt.Errorf("TransitionMpdistToPublished: %w", err)
	}
	if !found || state != DnskeyStateMpdist {
		lgSigner.Debug("TransitionMpdistToPublished: key not in mpdist, no-op", "zone", zonename, "keyid", keyid, "state", state)
		return nil
	}
	if err := tdns.UpdateDnssecKeyState(hdb.KeyDB, zonename, keyid, tdns.DnskeyStatePublished); err != nil {
		return fmt.Errorf("TransitionMpdistToPublished: %w", err)
	}
	lgSigner.Info("key transitioned mpdist->published", "zone", zonename, "keyid", keyid)
	return nil
}

// TransitionMpremoveToRemoved moves a key whose withdrawal the peers
// confirmed from mpremove to removed, through tdns's keystore, and drops its
// propagation record.
func TransitionMpremoveToRemoved(hdb *HsyncDB, zonename string, keyid uint16) error {
	state, found, err := keyState(hdb, zonename, keyid)
	if err != nil {
		return fmt.Errorf("TransitionMpremoveToRemoved: %w", err)
	}
	if !found || state != DnskeyStateMpremove {
		lgSigner.Debug("TransitionMpremoveToRemoved: key not in mpremove, no-op", "zone", zonename, "keyid", keyid, "state", state)
		return nil
	}
	if err := tdns.UpdateDnssecKeyState(hdb.KeyDB, zonename, keyid, tdns.DnskeyStateRemoved); err != nil {
		return fmt.Errorf("TransitionMpremoveToRemoved: %w", err)
	}
	if _, err := hdb.Exec(`DELETE FROM MPKeyPropagation WHERE zonename=? AND keyid=?`, zonename, keyid); err != nil {
		lgSigner.Warn("TransitionMpremoveToRemoved: dropping the propagation record failed", "zone", zonename, "keyid", keyid, "err", err)
	}
	lgSigner.Info("key transitioned mpremove->removed", "zone", zonename, "keyid", keyid)
	return nil
}

// --- Foreign keys -----------------------------------------------------------

// syncForeignDNSKEYs records the other signers' DNSKEYs found in an incoming
// zone as foreign rows, served but never signing, and drops the rows for keys
// that are gone. In single-signer mode no foreign row is kept: whatever
// DNSKEYs the upstream carried are dropped by the publish, which rebuilds the
// RRset from the keystore. Reports whether the set changed.
func (mpzd *MPZoneData) syncForeignDNSKEYs(incoming *tdns.ZoneData, multiSigner bool) (bool, error) {
	kdb := mpzd.KeyDB
	if kdb == nil {
		return false, nil
	}
	zone := mpzd.ZoneName

	existing := map[uint16]bool{}
	rows, err := kdb.Query(`SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state=?`, zone, DnskeyStateForeign)
	if err != nil {
		return false, fmt.Errorf("syncForeignDNSKEYs: zone %s: query foreign keys: %w", zone, err)
	}
	for rows.Next() {
		var keyid int
		if err := rows.Scan(&keyid); err != nil {
			rows.Close()
			return false, fmt.Errorf("syncForeignDNSKEYs: zone %s: scan: %w", zone, err)
		}
		existing[uint16(keyid)] = true
	}
	rows.Close()

	local := map[uint16]bool{}
	rows, err = kdb.Query(`SELECT keyid FROM DnssecKeyStore WHERE zonename=? AND state!=?`, zone, DnskeyStateForeign)
	if err != nil {
		return false, fmt.Errorf("syncForeignDNSKEYs: zone %s: query local keys: %w", zone, err)
	}
	for rows.Next() {
		var keyid int
		if err := rows.Scan(&keyid); err != nil {
			rows.Close()
			return false, fmt.Errorf("syncForeignDNSKEYs: zone %s: scan: %w", zone, err)
		}
		local[uint16(keyid)] = true
	}
	rows.Close()

	var remote []dns.RR
	current := map[uint16]*dns.DNSKEY{}
	if multiSigner && incoming != nil {
		if rs, _ := incoming.RRsetForAnalysis(zone, dns.TypeDNSKEY); rs != nil {
			for _, rr := range rs.RRs {
				dnskey, ok := rr.(*dns.DNSKEY)
				if !ok {
					continue
				}
				if kt := dnskey.KeyTag(); !local[kt] {
					remote = append(remote, dns.Copy(rr))
					current[kt] = dnskey
				}
			}
		}
	}

	changed := false
	for kt, dnskey := range current {
		if existing[kt] {
			continue
		}
		alg := dns.AlgorithmToString[dnskey.Algorithm]
		if alg == "" {
			alg = fmt.Sprintf("%d", dnskey.Algorithm)
		}
		res, err := kdb.Exec(`INSERT OR IGNORE INTO DnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, 'foreign', '', ?)`,
			zone, DnskeyStateForeign, kt, dnskey.Flags, alg, dnskey.String())
		if err != nil {
			lgSigner.Error("failed to persist foreign DNSKEY", "zone", zone, "keytag", kt, "err", err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changed = true
			lgSigner.Info("persisted new foreign DNSKEY", "zone", zone, "keytag", kt, "flags", dnskey.Flags, "algorithm", alg)
		}
	}
	for kt := range existing {
		if _, still := current[kt]; still {
			continue
		}
		if _, err := kdb.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state=?`, zone, kt, DnskeyStateForeign); err != nil {
			lgSigner.Error("failed to delete stale foreign DNSKEY", "zone", zone, "keytag", kt, "err", err)
			continue
		}
		changed = true
		lgSigner.Info("removed stale foreign DNSKEY", "zone", zone, "keytag", kt)
	}
	mpzd.SetRemoteDNSKEYs(remote)
	return changed, nil
}

// triggerResign asks tdns's resigner to bring a zone's signatures and its
// DNSKEY RRset into line after a key-state change. A bounded wait rather
// than a drop: the periodic pass renews signatures by age, so a dropped
// request is not repaired by the next pass.
func triggerResign(conf *Config, zoneName string) {
	if conf == nil || conf.Config == nil {
		return
	}
	sendResignRequest(conf.Config.Internal.ResignQ, zoneName)
}

func sendResignRequest(q chan tdns.ResignRequest, zoneName string) {
	if q == nil {
		return
	}
	zd, exists := tdns.Zones.Get(zoneName)
	if !exists {
		lgSigner.Warn("zone not found for re-sign trigger", "zone", zoneName)
		return
	}
	select {
	case q <- tdns.ResignRequest{Zd: zd, Reason: tdns.ResignKeyStateChanged}:
		lgSigner.Debug("triggered re-sign", "zone", zoneName)
	case <-time.After(10 * time.Second):
		lgSigner.Error("ResignQ full for 10s, re-sign request lost", "zone", zoneName)
	}
}
