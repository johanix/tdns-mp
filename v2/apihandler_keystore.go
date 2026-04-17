/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Keystore API for tdns-mp: MPDnssecKeyStore + SIG(0) unchanged on KeyDB.
 */

package tdnsmp

import (
	"crypto"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// APIkeystoreMP handles POST /keystore for mpsigner/mpagent (MP DNSSEC table).
func (hdb *HsyncDB) APIkeystoreMP(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var kp tdns.KeystorePost
		err := decoder.Decode(&kp)
		if err != nil {
			lgApi.Warn("error decoding keystore post", "err", err)
		}

		lgApi.Debug("received /keystore request (MP)", "cmd", kp.Command, "subcmd", kp.SubCommand, "from", r.RemoteAddr)

		var resp *tdns.KeystoreResponse

		if hdb == nil || hdb.DB == nil {
			w.Header().Set("Content-Type", "application/json")
			resp = &tdns.KeystoreResponse{
				Error:    true,
				ErrorMsg: "HSYNC keystore database is not initialized",
				Time:     time.Now(),
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		tx, err := hdb.Begin("APIkeystoreMP")

		defer func() {
			if tx != nil {
				if err != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		if err != nil {
			lgApi.Error("hdb.Begin failed", "err", err)
			resp = &tdns.KeystoreResponse{
				Error:    true,
				ErrorMsg: err.Error(),
			}
			return
		}

		switch kp.Command {
		case "sig0-mgmt":
			resp, err = hdb.KeyDB.Sig0KeyMgmt(tx, kp)
			if err != nil {
				lgApi.Error("Sig0Mgmt failed", "err", err)
				resp = &tdns.KeystoreResponse{
					Error:    true,
					ErrorMsg: err.Error(),
				}
			}

		case "dnssec-mgmt":
			// Route based on zone type: MP zones use MPDnssecKeyStore,
			// non-MP zones use the regular tdns DnssecKeyStore.
			// Special case: "list" without a zone queries both tables.
			if kp.SubCommand == "list" && kp.Zone == "" {
				resp, err = hdb.listAllDnssecKeys(tx)
				if err != nil {
					lgApi.Error("listAllDnssecKeys failed", "err", err)
					resp = &tdns.KeystoreResponse{
						Error:    true,
						ErrorMsg: err.Error(),
					}
				}
			} else {
				zd, exists := tdns.Zones.Get(kp.Zone)
				if exists && zd.Options[tdns.OptMultiProvider] {
					resp, err = hdb.MPDnssecKeyMgmt(tx, kp)
					if err != nil {
						lgApi.Error("MPDnssecKeyMgmt failed", "err", err)
						resp = &tdns.KeystoreResponse{
							Error:    true,
							ErrorMsg: err.Error(),
						}
					}
				} else {
					resp, err = hdb.KeyDB.DnssecKeyMgmt(tx, kp)
					if err != nil {
						lgApi.Error("DnssecKeyMgmt failed", "err", err)
						resp = &tdns.KeystoreResponse{
							Error:    true,
							ErrorMsg: err.Error(),
						}
					}
				}
			}
			if err == nil && (kp.SubCommand == "rollover" || kp.SubCommand == "delete" || kp.SubCommand == "setstate" || kp.SubCommand == "clear") {
				triggerResign(conf, kp.Zone)
			}

		default:
			lgApi.Warn("unknown keystore command", "cmd", kp.Command)
			resp = &tdns.KeystoreResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Unknown command: %s", kp.Command),
			}
		}
	}
}

// MPDnssecKeyMgmt mirrors tdns.DnssecKeyMgmt for MPDnssecKeyStore.
func (hdb *HsyncDB) MPDnssecKeyMgmt(tx *tdns.Tx, kp tdns.KeystorePost) (*tdns.KeystoreResponse, error) {
	const (
		addDnskeySql = `
INSERT OR REPLACE INTO MPDnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		setStateDnskeySql = "UPDATE MPDnssecKeyStore SET state=? WHERE zonename=? AND keyid=?"
		getAllDnskeysSql  = `SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, propagation_confirmed, propagation_confirmed_at FROM MPDnssecKeyStore`
		getDnskeySql      = `
SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`
	)

	kdb := hdb.KeyDB
	var err error
	var resp = tdns.KeystoreResponse{Time: time.Now()}
	var res sql.Result

	switch kp.SubCommand {
	case "list":
		rows, err := tx.Query(getAllDnskeysSql)
		if err != nil {
			return nil, fmt.Errorf("error from tx.Query(%s): %v", getAllDnskeysSql, err)
		}
		defer rows.Close()

		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int
		var propConfirmed int
		var propConfirmedAt string

		tmp2 := map[string]tdns.DnssecKey{}
		for rows.Next() {
			err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr, &propConfirmed, &propConfirmedAt)
			if err != nil {
				return nil, fmt.Errorf("error from rows.Scan(): %v", err)
			}
			if len(privatekey) < 10 {
				privatekey = "ULTRA SECRET KEY"
			}
			mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
			dk := tdns.DnssecKey{
				Name:                   keyname,
				State:                  state,
				Flags:                  uint16(flags),
				Algorithm:              algorithm,
				Creator:                creator,
				PrivateKey:             "-***-",
				Keystr:                 keyrrstr,
				PropagationConfirmed:   propConfirmed != 0,
				PropagationConfirmedAt: time.Time{},
			}
			if propConfirmedAt != "" {
				dk.PropagationConfirmedAt, _ = time.Parse(time.RFC3339, propConfirmedAt)
			}
			tmp2[mapkey] = dk
		}
		resp.Dnskeys = tmp2
		resp.Msg = "Here are all the DNSSEC keys that we know"

	case "add":
		pkc := kp.PrivateKeyCache

		var privkey crypto.PrivateKey
		if pkc.K != nil {
			privkey = pkc.K
		} else {
			if pkc.KeyType == dns.TypeDNSKEY {
				bindFormat, err := tdns.PrivKeyToBindFormat(pkc.PrivateKey, dns.AlgorithmToString[pkc.Algorithm])
				if err != nil {
					return &resp, fmt.Errorf("failed to convert private key to BIND format: %v", err)
				}
				reconstructedPkc, err := tdns.PrepareKeyCache(bindFormat, pkc.DnskeyRR.String())
				if err != nil {
					return &resp, fmt.Errorf("failed to reconstruct private key: %v", err)
				}
				privkey = reconstructedPkc.K
			} else {
				return &resp, fmt.Errorf("unsupported key type for reconstruction: %d", pkc.KeyType)
			}
		}

		privkeyPEM, err := tdns.PrivateKeyToPEM(privkey)
		if err != nil {
			return &resp, fmt.Errorf("failed to convert private key to PEM: %v", err)
		}

		res, err = tx.Exec(addDnskeySql, pkc.DnskeyRR.Header().Name, kp.State, pkc.DnskeyRR.KeyTag(), pkc.DnskeyRR.Flags,
			dns.AlgorithmToString[pkc.Algorithm], "tdns-cli", privkeyPEM, pkc.DnskeyRR.String())
		if err != nil {
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, kp.State))

	case "generate":
		_, msg, genErr := hdb.GenerateKeypairMP(kp.Zone, "api-request", kp.State, dns.TypeDNSKEY, kp.Algorithm, kp.KeyType, tx)
		if genErr != nil {
			lgSigner.Error("GenerateKeypairMP failed", "err", genErr)
			resp.Error = true
			resp.ErrorMsg = genErr.Error()
		}
		resp.Msg = msg
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, kp.State))
		if genErr != nil {
			return &resp, genErr
		}

	case "setstate":
		// Capture the old state before the update so we can invalidate
		// both cache entries; otherwise GetDnssecKeysMP can serve a
		// stale key from the old-state slot.
		var oldState string
		row := tx.QueryRow(`SELECT state FROM MPDnssecKeyStore WHERE zonename=? AND keyid=?`, kp.Keyname, kp.Keyid)
		if scanErr := row.Scan(&oldState); scanErr != nil && scanErr != sql.ErrNoRows {
			return &resp, scanErr
		}
		res, err = tx.Exec(setStateDnskeySql, kp.State, kp.Keyname, kp.Keyid)
		if err != nil {
			return &resp, err
		}
		rows, _ := res.RowsAffected()
		if rows > 0 {
			resp.Msg = fmt.Sprintf("Updated %d rows", rows)
		} else {
			resp.Msg = fmt.Sprintf("Key with name \"%s\" and keyid %d not found.", kp.Keyname, kp.Keyid)
		}
		if oldState != "" && oldState != kp.State {
			delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+oldState)
			delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, oldState))
		}
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+kp.State)
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, kp.State))

	case "rollover":
		keytype := kp.KeyType
		if keytype == "" {
			keytype = "ZSK"
		}
		oldKeyid, newKeyid, err := RolloverKeyMP(hdb, kp.Zone, keytype, tx)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		resp.Msg = fmt.Sprintf("%s rollover for zone %s: active key %d retired, standby key %d now active", keytype, kp.Zone, oldKeyid, newKeyid)

	case "delete":
		row := tx.QueryRow(getDnskeySql, kp.Zone, kp.Keyid)

		var zone, state, algorithm, creator, privatekey, keyrr string
		var keyid, flags int
		err := row.Scan(&zone, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrr)
		if err != nil {
			if err == sql.ErrNoRows {
				return &resp, fmt.Errorf("key %s (keyid %d) not found", kp.Keyname, kp.Keyid)
			}
			return &resp, err
		}
		if uint16(keyid) != kp.Keyid || zone != kp.Zone {
			resp.Msg = fmt.Sprintf("key %s %d not found", kp.Keyname, kp.Keyid)
			return &resp, nil
		}

		targetState := DnskeyStateMpremove
		updateRes, err := tx.Exec(`UPDATE MPDnssecKeyStore SET state=? WHERE zonename=? AND keyid=?`,
			targetState, kp.Zone, kp.Keyid)
		if err != nil {
			return &resp, err
		}
		if rows, _ := updateRes.RowsAffected(); rows == 0 {
			return &resp, fmt.Errorf("no rows updated for key %d in zone %s", kp.Keyid, kp.Zone)
		}
		resp.Msg = fmt.Sprintf("Key %s (keyid %d) transitioned to %s", kp.Keyname, kp.Keyid, targetState)
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+state)
		delete(kdb.KeystoreDnskeyCache, kp.Keyname+"+"+targetState)
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, state))
		delete(hdb.KeystoreDnskeyCache, mpDnssecCacheKey(kp.Keyname, targetState))

	case "clear":
		if kp.Zone == "" {
			resp.Error = true
			resp.ErrorMsg = "zone is required for clear"
			return &resp, fmt.Errorf("zone is required for clear")
		}
		result, err := tx.Exec(`DELETE FROM MPDnssecKeyStore WHERE zonename=?`, kp.Zone)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = err.Error()
			return &resp, err
		}
		count, _ := result.RowsAffected()
		var keysToDelete []string
		for key := range kdb.KeystoreDnskeyCache {
			if strings.HasPrefix(key, kp.Zone+"+") {
				keysToDelete = append(keysToDelete, key)
			}
		}
		for _, key := range keysToDelete {
			delete(kdb.KeystoreDnskeyCache, key)
		}
		lgSigner.Info("all MP DNSSEC keys cleared", "zone", kp.Zone, "count", count)

		zd, zoneExists := tdns.Zones.Get(kp.Zone)
		if !zoneExists || zd.DnssecPolicy == nil {
			resp.Msg = fmt.Sprintf("Deleted all %d DNSSEC keys for zone %s. Zone not found or has no DNSSEC policy; no new keys generated.", count, kp.Zone)
			return &resp, nil
		}

		alg := zd.DnssecPolicy.Algorithm
		var generated []string

		zskPkc, _, err := hdb.GenerateKeypairMP(kp.Zone, "clear-regen", tdns.DnskeyStateActive, dns.TypeDNSKEY, alg, "ZSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active ZSK", "zone", kp.Zone, "err", err)
		} else {
			generated = append(generated, fmt.Sprintf("ZSK %d (active)", zskPkc.KeyId))
		}

		kskPkc, _, err := hdb.GenerateKeypairMP(kp.Zone, "clear-regen", tdns.DnskeyStateActive, dns.TypeDNSKEY, alg, "KSK", tx)
		if err != nil {
			lgSigner.Error("clear: failed to generate active KSK", "zone", kp.Zone, "err", err)
		} else {
			generated = append(generated, fmt.Sprintf("KSK %d (active)", kskPkc.KeyId))
		}

		resp.Msg = fmt.Sprintf("Deleted %d keys for zone %s. Generated: %s. Standby keys will follow via KeyStateWorker.",
			count, kp.Zone, strings.Join(generated, ", "))

	default:
		resp.Msg = fmt.Sprintf("Unknown keystore dnssec sub-command: %s", kp.SubCommand)
		resp.Error = true
		resp.ErrorMsg = resp.Msg
	}

	return &resp, nil
}

// listAllDnssecKeys queries both DnssecKeyStore and MPDnssecKeyStore
// and returns a merged result. Keys from the MP table get a "[mp]"
// suffix on the map key to distinguish them in the CLI output.
func (hdb *HsyncDB) listAllDnssecKeys(tx *tdns.Tx) (*tdns.KeystoreResponse, error) {
	resp := &tdns.KeystoreResponse{Time: time.Now()}
	allKeys := map[string]tdns.DnssecKey{}

	// 1. Non-MP keys from DnssecKeyStore
	const nonMPSql = `SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr FROM DnssecKeyStore`
	rows, err := tx.Query(nonMPSql)
	if err != nil {
		return nil, fmt.Errorf("listAllDnssecKeys: DnssecKeyStore query: %v", err)
	}
	for rows.Next() {
		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int
		if err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr); err != nil {
			rows.Close()
			return nil, fmt.Errorf("listAllDnssecKeys: DnssecKeyStore scan: %v", err)
		}
		mapkey := fmt.Sprintf("%s::%d", keyname, keyid)
		allKeys[mapkey] = tdns.DnssecKey{
			Name:       keyname,
			State:      state,
			Flags:      uint16(flags),
			Algorithm:  algorithm,
			Creator:    creator,
			PrivateKey: "-***-",
			Keystr:     keyrrstr,
		}
	}
	rows.Close()

	// 2. MP keys from MPDnssecKeyStore
	const mpSql = `SELECT zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr, propagation_confirmed, propagation_confirmed_at FROM MPDnssecKeyStore`
	rows, err = tx.Query(mpSql)
	if err != nil {
		return nil, fmt.Errorf("listAllDnssecKeys: MPDnssecKeyStore query: %v", err)
	}
	for rows.Next() {
		var keyname, state, algorithm, creator, privatekey, keyrrstr string
		var keyid, flags int
		var propConfirmed int
		var propConfirmedAt string
		if err := rows.Scan(&keyname, &state, &keyid, &flags, &algorithm, &creator, &privatekey, &keyrrstr, &propConfirmed, &propConfirmedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("listAllDnssecKeys: MPDnssecKeyStore scan: %v", err)
		}
		mapkey := fmt.Sprintf("%s::%d[mp]", keyname, keyid)
		dk := tdns.DnssecKey{
			Name:                 keyname,
			State:                state,
			Flags:                uint16(flags),
			Algorithm:            algorithm,
			Creator:              creator,
			PrivateKey:           "-***-",
			Keystr:               keyrrstr,
			PropagationConfirmed: propConfirmed != 0,
		}
		if propConfirmedAt != "" {
			dk.PropagationConfirmedAt, _ = time.Parse(time.RFC3339, propConfirmedAt)
		}
		allKeys[mapkey] = dk
	}
	rows.Close()

	resp.Dnskeys = allKeys
	resp.Msg = "DNSSEC keys from both DnssecKeyStore and MPDnssecKeyStore"
	return resp, nil
}
