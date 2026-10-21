/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// What this agent holds of a zone's SIG(0) key (step 7b, decision 18).
//
// The zone's key is the one its parent trusts, and every voting member
// holds it. It is read from the KEY records at the apex of the agent's copy
// of the zone, and from the active local keys, read with a query of their
// own on the keystore: tdns's GetSig0Keys keeps the first row it reads and
// warns of the others.
//
//   - The zone publishes one KEY: the zone's key is the active local key whose
//     KEY record is that one, compared as zoneTakesKey compares.
//   - The zone publishes none: a key rolled at the parent need not be
//     published (design 4.1). The zone's key is then the active key tdns
//     signs with, the first row of the store's query that GetSig0Keys makes;
//     the others are retired.
//   - The zone publishes several: no local key is the zone's key. The agent
//     holds none, imports nothing, retires nothing, and the leader makes no
//     key; an operator has to bring the apex to one KEY.

// sig0Row is one active SIG(0) key of the keystore.
type sig0Row struct {
	keyid      uint16
	algorithm  string
	privatekey string
	keyrr      string
	key        *dns.KEY
}

// zoneKey is what readZoneKey found.
type zoneKey struct {
	published []*dns.KEY
	active    []sig0Row
	held      *sig0Row // the zone's key, when this agent holds it
}

// several: the apex carries more than one KEY.
func (z *zoneKey) several() bool { return len(z.published) > 1 }

// others are the active keys that are not the zone's key.
func (z *zoneKey) others() []sig0Row {
	if z.held == nil {
		return nil
	}
	var out []sig0Row
	for _, r := range z.active {
		if r.keyid != z.held.keyid {
			out = append(out, r)
		}
	}
	return out
}

// sameKey: same flags, protocol, algorithm and public key.
func sameKey(a, b *dns.KEY) bool {
	return a != nil && b != nil && a.Flags == b.Flags && a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

// publishedKeys is the KEY RRset at the apex of the agent's copy of the zone.
// A zone that has not loaded here publishes nothing.
func publishedKeys(zone ZoneName) []*dns.KEY {
	apex := zoneApex(zone)
	if apex == nil {
		return nil
	}
	var out []*dns.KEY
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs {
		if k, ok := rr.(*dns.KEY); ok {
			out = append(out, k)
		}
	}
	return out
}

// activeSig0Rows reads the zone's active SIG(0) keys from the keystore, every
// row, with no cache.
func activeSig0Rows(kdb *tdns.KeyDB, zone ZoneName) ([]sig0Row, error) {
	rows, err := kdb.Query(`SELECT keyid, algorithm, privatekey, keyrr FROM Sig0KeyStore WHERE zonename=? AND state=?`,
		dns.Fqdn(string(zone)), tdns.Sig0StateActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sig0Row
	for rows.Next() {
		var r sig0Row
		var keyid int
		if err := rows.Scan(&keyid, &r.algorithm, &r.privatekey, &r.keyrr); err != nil {
			return nil, err
		}
		r.keyid = uint16(keyid)
		if rr, err := dns.NewRR(r.keyrr); err == nil {
			if k, ok := rr.(*dns.KEY); ok {
				r.key = k
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// firstActiveSig0Key is name's first active key, the one tdns signs with
// (GetSig0Keys), read with a query of its own: tdns's cache of those keys is
// a map with no lock (johanix/tdns#943), which only the syncher's goroutine
// reads here (signingKeyCached). Nil when there is none.
func firstActiveSig0Key(kdb *tdns.KeyDB, name string) (*sig0Row, error) {
	active, err := activeSig0Rows(kdb, ZoneName(name))
	if err != nil || len(active) == 0 || active[0].key == nil {
		return nil, err
	}
	return &active[0], nil
}

// readZoneKey reads what this agent holds of the zone's SIG(0) key.
func readZoneKey(kdb *tdns.KeyDB, zone ZoneName) (*zoneKey, error) {
	z := &zoneKey{published: publishedKeys(zone)}
	active, err := activeSig0Rows(kdb, zone)
	if err != nil {
		return nil, err
	}
	z.active = active
	switch {
	case z.several():
	case len(z.published) == 1:
		for i := range active {
			if sameKey(active[i].key, z.published[0]) {
				z.held = &active[i]
				break
			}
		}
	case len(active) > 0:
		// tdns signs with the first row its own query of the store reads
		// (GetSig0Keys, on a cache miss): the same query, so the same row.
		// tdns's cache is not read here: a map tdns keeps no lock around,
		// and this runs on goroutines other than the one tdns signs on.
		z.held = &active[0]
	}
	return z, nil
}

// keystoreBusy: tdns's KeyDB refuses a transaction while another is open,
// with this text and no sentinel error.
func keystoreBusy(err error) bool {
	return err != nil && strings.Contains(err.Error(), "transaction already in progress")
}

// keystoreRetries is how many times a keystore change that found another
// transaction open is tried again, and how long apart, growing.
const keystoreRetries = 8

const keystoreRetryStep = 25 * time.Millisecond

// sig0KeyMgmtRetried is Sig0KeyMgmt, tried again while the keystore is busy
// with another transaction.
func sig0KeyMgmtRetried(kdb *tdns.KeyDB, kp tdns.KeystorePost) (*tdns.KeystoreResponse, error) {
	var resp *tdns.KeystoreResponse
	var err error
	for try := 0; try < keystoreRetries; try++ {
		resp, err = kdb.Sig0KeyMgmt(nil, kp)
		if err == nil && resp != nil && resp.Error && strings.Contains(resp.ErrorMsg, "transaction already in progress") {
			err = fmt.Errorf("%s", resp.ErrorMsg)
		}
		if !keystoreBusy(err) {
			return resp, err
		}
		time.Sleep(time.Duration(try+1) * keystoreRetryStep)
	}
	return resp, err
}

// retireOtherActiveKeys keeps exactly one active SIG(0) key for the zone, the
// zone's key: tdns signs with the first active row GetSig0Keys reads, and
// BootstrapSig0KeyWithParent uploads it. Every other active key is retired,
// not deleted. It reports whether the zone's key is now the only active one,
// read back from the keystore; a retire that fails leaves it not held. A
// cache of tdns's that still holds a retired key (tdns #943: it is cleared
// before the keystore's commit) is cleared by the syncher before it signs
// (signingKeyCached), on its own goroutine: the cache is a map tdns keeps no
// lock around.
func retireOtherActiveKeys(kdb *tdns.KeyDB, zone ZoneName, z *zoneKey) (bool, error) {
	if z == nil || z.held == nil {
		return false, nil
	}
	keep := z.held.keyid
	for _, r := range z.others() {
		resp, err := sig0KeyMgmtRetried(kdb, tdns.KeystorePost{
			Command:    "sig0-mgmt",
			SubCommand: "setstate",
			Keyname:    dns.Fqdn(string(zone)),
			Keyid:      r.keyid,
			State:      tdns.Sig0StateRetired,
		})
		if err == nil && resp != nil && resp.Error {
			err = fmt.Errorf("%s", resp.ErrorMsg)
		}
		if err != nil {
			return false, fmt.Errorf("retiring SIG(0) key %d of %s: %w", r.keyid, zone, err)
		}
		lgAgent.Info("an active SIG(0) key that is not the zone's key is retired", "zone", zone, "keyid", r.keyid, "kept", keep)
	}
	active, err := activeSig0Rows(kdb, zone)
	if err != nil {
		return false, err
	}
	if len(active) != 1 || active[0].keyid != keep {
		return false, nil
	}
	return true, nil
}

// bootstrapKey is the key the operator's parentsync-bootstrap polls with
// the parent: the zone's key, and only while it is the only active key, as
// the leader's set-up has it (publishZoneKey). tdns's bootstrap uploads the
// first active key, so with another one active it could bootstrap a key the
// zone does not publish. refusal says why there is none.
func bootstrapKey(kdb *tdns.KeyDB, zone ZoneName) (*sig0Row, string) {
	zk, err := readZoneKey(kdb, zone)
	switch {
	case err != nil:
		return nil, fmt.Sprintf("the SIG(0) keys of zone %s cannot be read: %v", zone, err)
	case zk.several():
		return nil, fmt.Sprintf("zone %s publishes several SIG(0) KEYs; an operator has to leave one", zone)
	case zk.held == nil || zk.held.key == nil:
		return nil, fmt.Sprintf("this agent does not hold the SIG(0) key of zone %s", zone)
	case len(zk.active) != 1:
		return nil, fmt.Sprintf("zone %s has %d active SIG(0) keys; tdns would bootstrap the first, not necessarily the zone's key", zone, len(zk.active))
	}
	return zk.held, ""
}
