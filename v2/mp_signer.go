/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP zone signing: SignZone, extractRemoteDNSKEYs, PublishDnskeyRRs
 * on *MPZoneData. Handles modes 2-4 (multi-provider signing).
 * Mode 1 (single-signer, no MP) stays in tdns.
 */

package tdnsmp

import (
	"fmt"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SignZone signs an MP zone. Modes 2-4 only.
//   - Mode 2: single-signer MP — strip remote, sign with local keys
//   - Mode 4: multi-signer — extract remote DNSKEYs, merge, sign
//
// Mode 3 (non-signer) is gated by not enabling OptInlineSigning
// in HSYNC analysis, so SetupZoneSigning never fires for mode 3.
func (mpzd *MPZoneData) SignZone(hdb *HsyncDB, force bool) (int, error) {
	zd := mpzd.ZoneData

	if !zd.Options[tdns.OptOnlineSigning] && !zd.Options[tdns.OptInlineSigning] {
		return 0, fmt.Errorf("SignZone: zone %s should not be signed here", zd.ZoneName)
	}

	// Mode selection using MPOptions
	if mpzd.MPOptions[tdns.OptMultiSigner] {
		// Mode 4: extract remote DNSKEYs before PublishDnskeyRRs
		// overwrites the DNSKEY RRset with local keys only.
		if err := mpzd.extractRemoteDNSKEYs(hdb); err != nil {
			lgSigner.Warn("error extracting remote DNSKEYs, proceeding without", "zone", zd.ZoneName, "err", err)
		}
		lgSigner.Info("multi-signer mode (mode 4)", "zone", zd.ZoneName, "remote_dnskeys", len(mpzd.GetRemoteDNSKEYs()))
	} else {
		// Mode 2: single-signer MP — strip remote
		mpzd.SetRemoteDNSKEYs(nil)
		lgSigner.Info("single-signer multi-provider mode (mode 2)", "zone", zd.ZoneName)
	}

	dak, err := EnsureActiveDnssecKeysMP(mpzd, hdb)
	if err != nil {
		lgSigner.Error("failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "err", err)
		return 0, err
	}

	newrrsigs := 0

	if !zd.Options[tdns.OptBlackLies] {
		err = zd.GenerateNsecChainWithDak(dak)
		if err != nil {
			return 0, err
		}
	}

	MaybeSignRRset := func(rrset core.RRset, zone string) (core.RRset, bool) {
		resigned, err := zd.SignRRset(&rrset, zone, dak, force)
		if err != nil {
			name, rrtype := "<empty>", "<empty>"
			if len(rrset.RRs) > 0 {
				h := rrset.RRs[0].Header()
				name = h.Name
				rrtype = dns.TypeToString[uint16(h.Rrtype)]
			}
			lgSigner.Error("failed to sign RRset", "name", name, "rrtype", rrtype, "zone", zd.ZoneName, "err", err)
		}
		if resigned {
			newrrsigs++
		}
		return rrset, resigned
	}

	names, err := zd.GetOwnerNames()
	if err != nil {
		return 0, err
	}
	sort.Strings(names)

	err = mpzd.PublishDnskeyRRs(hdb, dak)
	if err != nil {
		return 0, err
	}

	var delegations []string
	for _, name := range names {
		if name == zd.ZoneName {
			continue
		}
		owner, err := zd.GetOwner(name)
		if err != nil {
			return 0, err
		}
		if owner == nil {
			continue
		}
		if _, exist := owner.RRtypes.Get(dns.TypeNS); exist {
			delegations = append(delegations, name)
		}
	}

	lgSigner.Debug("zone delegations", "zone", zd.ZoneName, "delegations", delegations)

	var signed, zoneResigned bool
	for _, name := range names {
		owner, err := zd.GetOwner(name)
		if err != nil {
			return 0, err
		}
		if owner == nil {
			continue
		}

		for _, rrt := range owner.RRtypes.Keys() {
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
			if rrt == dns.TypeRRSIG {
				continue
			}
			if rrt == dns.TypeNS && name != zd.ZoneName {
				continue // don't sign delegations
			}
			var wasglue bool
			if rrt == dns.TypeA || rrt == dns.TypeAAAA {
				for _, del := range delegations {
					if strings.HasSuffix(name, del) {
						lgSigner.Debug("not signing glue record", "zone", zd.ZoneName, "name", name, "rrtype", dns.TypeToString[uint16(rrt)], "delegation", del)
						wasglue = true
						continue
					}
				}
			}
			if wasglue {
				continue
			}
			rrset, signed = MaybeSignRRset(rrset, zd.ZoneName)
			owner.RRtypes.Set(rrt, rrset)

			if signed {
				zoneResigned = true
			}
		}
	}

	if zoneResigned {
		_, err := zd.BumpSerial()
		if err != nil {
			lgSigner.Error("failed to bump SOA serial", "zone", zd.ZoneName, "err", err)
			return 0, err
		}
	}

	return newrrsigs, nil
}

// extractRemoteDNSKEYs identifies foreign DNSKEYs in the zone by
// comparing against local keys in the KeyDB. Foreign keys are stored
// on mpzd.MP.RemoteDNSKEYs and persisted to the KeyDB with state='foreign'.
// Only called in mode 4 (multi-signer).
func (mpzd *MPZoneData) extractRemoteDNSKEYs(hdb *HsyncDB) error {
	zd := mpzd.ZoneData

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return fmt.Errorf("extractRemoteDNSKEYs: zone %s: cannot get apex: %v", zd.ZoneName, err)
	}

	dnskeyRRset, exists := apex.RRtypes.Get(dns.TypeDNSKEY)
	if !exists || len(dnskeyRRset.RRs) == 0 {
		lgSigner.Debug("no DNSKEY RRset in zone (normal for fresh zones)", "zone", zd.ZoneName)
		mpzd.SetRemoteDNSKEYs(nil)
		return nil
	}

	// Get all local keys to identify what's ours
	localKeyTags := make(map[uint16]bool)
	for _, state := range []string{tdns.DnskeyStateCreated, DnskeyStateMpdist, DnskeyStateMpremove, tdns.DnskeyStatePublished, tdns.DnskeyStateStandby, tdns.DnskeyStateActive, tdns.DnskeyStateRetired, tdns.DnskeyStateRemoved} {
		dak, err := GetDnssecKeysMP(hdb, zd.ZoneName, state)
		if err != nil {
			continue
		}
		for _, k := range dak.KSKs {
			localKeyTags[k.DnskeyRR.KeyTag()] = true
		}
		for _, k := range dak.ZSKs {
			localKeyTags[k.DnskeyRR.KeyTag()] = true
		}
	}

	// Get existing foreign keys from the DB (to detect removals).
	// Close the iterator immediately after scanning so the subsequent
	// Exec writes don't contend with the open SQLite read cursor.
	const fetchForeignSql = `SELECT keyid FROM MPDnssecKeyStore WHERE zonename=? AND state='foreign'`
	rows, err := hdb.Query(fetchForeignSql, zd.ZoneName)
	if err != nil {
		return fmt.Errorf("extractRemoteDNSKEYs: zone %s: error querying foreign keys: %v", zd.ZoneName, err)
	}
	existingForeign := make(map[uint16]bool)
	for rows.Next() {
		var keyid int
		if err := rows.Scan(&keyid); err != nil {
			rows.Close()
			return fmt.Errorf("extractRemoteDNSKEYs: zone %s: error scanning foreign key row: %v", zd.ZoneName, err)
		}
		existingForeign[uint16(keyid)] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("extractRemoteDNSKEYs: zone %s: row iteration error: %v", zd.ZoneName, err)
	}
	rows.Close()

	// Identify foreign keys: any DNSKEY not in our local set
	var remote []dns.RR
	currentForeign := make(map[uint16]*dns.DNSKEY)
	for _, rr := range dnskeyRRset.RRs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		kt := dnskey.KeyTag()
		if !localKeyTags[kt] {
			remote = append(remote, dns.Copy(rr))
			currentForeign[kt] = dnskey
		}
	}

	// Persist new foreign keys to KeyDB
	const insertForeignSql = `INSERT OR IGNORE INTO MPDnssecKeyStore (zonename, state, keyid, flags, algorithm, creator, privatekey, keyrr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	for kt, dnskey := range currentForeign {
		res, err := hdb.Exec(insertForeignSql, zd.ZoneName, DnskeyStateForeign, kt, dnskey.Flags,
			dns.AlgorithmToString[dnskey.Algorithm], "foreign", "", dnskey.String())
		if err != nil {
			lgSigner.Error("failed to persist foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "err", err)
		} else if n, _ := res.RowsAffected(); n > 0 {
			lgSigner.Info("persisted new foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "flags", dnskey.Flags, "algorithm", dns.AlgorithmToString[dnskey.Algorithm])
		}
	}

	// Remove stale foreign keys from DB
	const deleteForeignSql = `DELETE FROM MPDnssecKeyStore WHERE zonename=? AND keyid=? AND state='foreign'`
	for kt := range existingForeign {
		if _, stillPresent := currentForeign[kt]; !stillPresent {
			lgSigner.Info("removing stale foreign DNSKEY from KeyDB", "zone", zd.ZoneName, "keytag", kt)
			_, err := hdb.Exec(deleteForeignSql, zd.ZoneName, kt)
			if err != nil {
				lgSigner.Error("failed to delete stale foreign DNSKEY", "zone", zd.ZoneName, "keytag", kt, "err", err)
			}
		}
	}

	if len(remote) > 0 || len(existingForeign) > 0 {
		lgSigner.Info("foreign DNSKEY summary", "zone", zd.ZoneName, "in_zone", len(currentForeign), "in_db", len(existingForeign), "persisted", len(currentForeign))
	}

	mpzd.SetRemoteDNSKEYs(remote)
	return nil
}

// PublishDnskeyRRs publishes local + remote DNSKEYs into the zone's
// DNSKEY RRset. Shadows the tdns version by adding the remote DNSKEY
// merge for multi-signer mode 4.
func (mpzd *MPZoneData) PublishDnskeyRRs(hdb *HsyncDB, dak *tdns.DnssecKeys) error {
	zd := mpzd.ZoneData

	if !zd.Options[tdns.OptAllowUpdates] && !zd.Options[tdns.OptOnlineSigning] && !zd.Options[tdns.OptInlineSigning] {
		return fmt.Errorf("zone %s does not allow updates or signing", zd.ZoneName)
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return err
	}
	if apex == nil {
		return fmt.Errorf("PublishDnskeyRRs: zone apex %q not found", zd.ZoneName)
	}

	var publishkeys []dns.RR
	for _, ksk := range dak.KSKs {
		zd.Logger.Printf("PublishDnskeyRRs: ksk: %v", ksk.DnskeyRR.String())
		publishkeys = append(publishkeys, dns.RR(&ksk.DnskeyRR))
	}
	for _, zsk := range dak.ZSKs {
		zd.Logger.Printf("PublishDnskeyRRs: zsk: %v", zsk.DnskeyRR.String())
		if zsk.DnskeyRR.Flags == 257 {
			continue
		}
		publishkeys = append(publishkeys, dns.RR(&zsk.DnskeyRR))
	}

	zd.Logger.Printf("PublishDnskeyRRs: there are %d active KSKs and %d active ZSKs", len(dak.KSKs), len(dak.ZSKs))

	const fetchZoneDnskeysSql = `
SELECT keyid, flags, algorithm, keyrr FROM MPDnssecKeyStore WHERE zonename=? AND (state='mpdist' OR state='published' OR state='standby' OR state='retired' OR state='foreign')`

	rows, err := hdb.Query(fetchZoneDnskeysSql, zd.ZoneName)
	if err != nil {
		lgSigner.Error("PublishDnskeyRRs: error querying DNSKEY store", "zone", zd.ZoneName, "err", err)
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var keyid, flags, algorithm string
		var keyrr string
		err = rows.Scan(&keyid, &flags, &algorithm, &keyrr)
		if err != nil {
			lgSigner.Error("PublishDnskeyRRs: error scanning DNSKEY row", "err", err)
			return err
		}

		rr, err := dns.NewRR(keyrr)
		if err != nil {
			lgSigner.Error("PublishDnskeyRRs: error creating dns.RR from keyrr", "err", err)
			return err
		}
		if _, ok := rr.(*dns.DNSKEY); !ok {
			lgSigner.Error("PublishDnskeyRRs: parsed RR is not a DNSKEY", "rrtype", dns.TypeToString[rr.Header().Rrtype], "keyrr", keyrr)
			continue
		}
		publishkeys = append(publishkeys, rr)
	}
	if err = rows.Err(); err != nil {
		lgSigner.Error("PublishDnskeyRRs: rows iteration error", "err", err)
		return err
	}

	// Multi-signer mode 4: merge remote DNSKEYs
	remoteDNSKEYs := mpzd.GetRemoteDNSKEYs()
	if len(remoteDNSKEYs) > 0 {
		for _, rk := range remoteDNSKEYs {
			dup := false
			for _, pk := range publishkeys {
				if dns.IsDuplicate(rk, pk) {
					dup = true
					break
				}
			}
			if !dup {
				publishkeys = append(publishkeys, rk)
			}
		}
		zd.Logger.Printf("PublishDnskeyRRs: merged remote DNSKEYs (multi-signer mode 4), total keys: %d", len(publishkeys))
	}

	dnskeys := core.RRset{
		Name:   zd.ZoneName,
		RRtype: dns.TypeDNSKEY,
		RRs:    publishkeys,
	}
	apex.RRtypes.Set(dns.TypeDNSKEY, dnskeys)

	return nil
}
