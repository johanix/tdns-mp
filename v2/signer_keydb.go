/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * The signer's key seam.
 *
 * The keys live in tdns's DnssecKeyStore and tdns signs with them: the first
 * sign after the policy binds, every refresh's staged scope, the renewals of
 * its ResignerEngine. What is MP's is the protocol between the states, run
 * by tdns-mp's own key machine for every multi-provider zone (the
 * KeyLifecycleEngine; design S3 and S4a): mpdist (a new key, served ahead
 * of its promotion, awaiting the peers' confirmation that it has
 * propagated), mpremove (a retired key withdrawn from the RRset, awaiting
 * confirmation of the withdrawal), and foreign (another signer's DNSKEY,
 * served here and never signing). tdns attaches no meaning to the states
 * beyond served or not served, which the key columns say; the owner
 * registers the flags of its states (RegisterMPKeyLifecycleOwner). What is
 * left here is what the machine shares with the signer's zone handling: the
 * inventory, the foreign rows found in an incoming zone, and the resign
 * request.
 */
package tdnsmp

import (
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// KeyInventoryItem and DnssecKeyWithTimestamps are tdns's: the inventory the
// KEYSTATE protocol carries is read from DnssecKeyStore.
type KeyInventoryItem = tdns.KeyInventoryItem
type DnssecKeyWithTimestamps = tdns.DnssecKeyWithTimestamps

// GetKeyInventory returns the complete DNSKEY inventory for a zone -- every
// key in every state, foreign ones included -- from DnssecKeyStore.
func GetKeyInventory(hdb *HsyncDB, zonename string) ([]KeyInventoryItem, error) {
	return tdns.GetKeyInventory(hdb.KeyDB, zonename)
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
		// Through tdns's one insert, so the row carries pub from its state
		// and is served; a raw insert would leave the key out of the RRset
		// until the next open.
		if err := insertForeignKeyRow(kdb, zone, kt, dnskey, alg); err != nil {
			lgSigner.Error("failed to persist foreign DNSKEY", "zone", zone, "keytag", kt, "err", err)
			continue
		}
		changed = true
		lgSigner.Info("persisted new foreign DNSKEY", "zone", zone, "keytag", kt, "flags", dnskey.Flags, "algorithm", alg)
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

// sendResignRequest asks tdns's resigner to bring a zone's signatures and
// its DNSKEY RRset into line after a key-state change (the key machine's
// Wire.Resign, and the HSYNC path when the signer set changes). A bounded
// wait rather than a drop: the periodic pass renews signatures by age, so a
// dropped request is not repaired by the next pass.
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

// insertForeignKeyRow stores another provider's DNSKEY as a foreign row: served,
// never signing, no private half. Its own transaction, since the caller holds
// none.
func insertForeignKeyRow(kdb *tdns.KeyDB, zone string, keytag uint16, dnskey *dns.DNSKEY, alg string) error {
	tx, err := kdb.Begin("insertForeignKeyRow")
	if err != nil {
		return err
	}
	if err := tdns.InsertKeyRowTx(tx, tdns.KeyRow{
		Zone: zone, State: DnskeyStateForeign, Keyid: keytag, Flags: dnskey.Flags,
		Algorithm: alg, Creator: "foreign", KeyRR: dnskey.String(),
	}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
