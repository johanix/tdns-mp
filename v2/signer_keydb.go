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
// zone as foreign rows, served but never signing. others are the zone's
// other signers, as the HSYNCPARAM of the incoming zone names them. A row
// whose key the incoming zone lacks goes only when foreignKeyWithdrawn lets
// it: when the key states its provider's agent sent our agent, and our
// agent relayed here, no longer list the key, or when the zone owner no
// longer names that provider as a signer. One copy without another
// provider's key is neither, and a combiner that has just started may send
// such a copy (tdns-mp #207). Until then the row stays, served, and is
// looked at again when our agent next relays the other providers' key
// states (dropWithdrawnForeignDNSKEYs). In single-signer mode no foreign row is
// kept: whatever DNSKEYs the upstream carried are dropped by the publish,
// which rebuilds the RRset from the keystore. Reports whether the set
// changed.
func (mpzd *MPZoneData) syncForeignDNSKEYs(incoming *tdns.ZoneData, multiSigner bool, others []string) (bool, error) {
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
	var absent []uint16
	for kt := range existing {
		if _, still := current[kt]; !still {
			absent = append(absent, kt)
		}
	}
	var kept []uint16
	dropped := false
	switch {
	case !multiSigner:
		// no other signer: nothing keeps a foreign key
		kept, dropped = dropWithdrawnForeignRows(kdb, zone, absent, nil)
	case len(others) == 0:
		// other signers, and none of them named: whose relayed key states
		// to weigh is not known, so nothing is dropped
		kept = absent
	default:
		kept, dropped = dropWithdrawnForeignRows(kdb, zone, absent, others)
	}
	mpzd.setAbsentForeign(kept)
	mpzd.SetRemoteDNSKEYs(remote)
	return changed || dropped, nil
}

// dropWithdrawnForeignDNSKEYs looks again at the foreign rows that the last
// incoming zone lacked and that were kept, and drops the ones
// foreignKeyWithdrawn now lets go. Run when our agent relays the other
// providers' key states (KEYSTATE "foreign"): when a provider removes a key,
// the copy of the zone without it may reach this signer from our combiner
// before our agent relays the key states without it. Reports whether a row
// went.
func (mpzd *MPZoneData) dropWithdrawnForeignDNSKEYs(mp *MultiProviderConf) bool {
	kdb := mpzd.KeyDB
	if kdb == nil {
		return false
	}
	absent := mpzd.absentForeignKeys()
	if len(absent) == 0 {
		return false
	}
	others, signer := otherSignerLabels(mpzd, mp)
	if !signer {
		return false
	}
	kept, dropped := dropWithdrawnForeignRows(kdb, mpzd.ZoneName, absent, others)
	mpzd.setAbsentForeign(kept)
	return dropped
}

// dropWithdrawnForeignRows deletes the foreign rows among absent (key tags an
// incoming zone lacked) that foreignKeyWithdrawn lets go, by the relayed key
// states the key lifecycle keeps, and returns the ones it kept. With no
// other signer (others empty) every row goes. Without the relayed key states
// (no table yet, a read that fails) every row is kept.
func dropWithdrawnForeignRows(kdb *tdns.KeyDB, zone string, absent []uint16, others []string) (kept []uint16, dropped bool) {
	if len(absent) == 0 {
		return nil, false
	}
	word := map[uint16]foreignSaid{}
	if len(others) > 0 {
		var err error
		if word, err = readForeignWord(kdb, zone); err != nil {
			lgSigner.Warn("the other providers' relayed key states could not be read; the foreign DNSKEYs the incoming zone lacks are kept",
				"zone", zone, "keytags", absent, "err", err)
			return absent, false
		}
	}
	for _, kt := range absent {
		withdrawn, why := foreignKeyWithdrawn(word, kt, others)
		if !withdrawn {
			lgSigner.Info("kept another signer's DNSKEY that the incoming zone lacks", "zone", zone, "keytag", kt, "why", why)
			kept = append(kept, kt)
			continue
		}
		if _, err := kdb.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state=?`, zone, kt, DnskeyStateForeign); err != nil {
			lgSigner.Error("failed to delete withdrawn foreign DNSKEY", "zone", zone, "keytag", kt, "err", err)
			kept = append(kept, kt)
			continue
		}
		dropped = true
		lgSigner.Info("removed withdrawn foreign DNSKEY", "zone", zone, "keytag", kt, "why", why)
	}
	return kept, dropped
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
