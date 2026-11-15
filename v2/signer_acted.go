/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * What a signer handed nothing last acted by, on disk, so that a restart
 * keeps it (tdns-mp #357). A signer that waits for its agent's hand-over
 * takes no change of roles from its copy (rule 5). Held in memory only, a
 * restart forgot the sets, and its first load took its roles from its copy,
 * which may be a serial its agent refused (design 3.1).
 *
 * TEMPORARY, until P5 (tdns-mp #146). A first load with nothing kept still
 * takes its roles from its copy, so a signer whose very first load sees a
 * refused copy still takes the role. tdns binds a zone's DNSSEC policy only at
 * its first load with inline-signing on, and nothing binds one later, so a
 * signer that does not sign then could never start. Once a policy can be bound
 * when signing starts, no first load takes a role from its copy, there is
 * nothing to keep, and this file and the table MPSignerActed go.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	tdns "github.com/johanix/tdns/v2"
)

// signerActedStore are the sets each zone's signer last acted by with nothing
// handed. A zone is here from its first load until its first hand-over.
type signerActedStore struct {
	mu    sync.Mutex
	hdb   *HsyncDB         // nil: in memory only
	zones map[string]Roles // canonicalName -> the sets
}

// signerActed is the signer's store, set by its initialisation; nil on every
// other daemon.
var signerActed atomic.Pointer[signerActedStore]

// loadSignerActed reads the sets kept on disk, at the signer's start.
func loadSignerActed(hdb *HsyncDB) (*signerActedStore, error) {
	s := &signerActedStore{hdb: hdb, zones: map[string]Roles{}}
	if hdb == nil {
		return s, nil
	}
	hdb.Lock()
	defer hdb.Unlock()
	if _, err := hdb.DB.Exec(HsyncTables["MPSignerActed"]); err != nil {
		return nil, fmt.Errorf("the MPSignerActed table: %w", err)
	}
	rows, err := hdb.DB.Query(`SELECT zonename, sets FROM MPSignerActed`)
	if err != nil {
		return nil, fmt.Errorf("reading the sets the signer last acted by: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var zone, sets string
		if err := rows.Scan(&zone, &sets); err != nil {
			return nil, fmt.Errorf("reading the sets the signer last acted by: %w", err)
		}
		var r Roles
		if err := json.Unmarshal([]byte(sets), &r); err != nil {
			return nil, fmt.Errorf("the sets the signer last acted by for %s: %w", zone, err)
		}
		s.zones[zone] = r
	}
	return s, rows.Err()
}

// get is what is kept for the zone.
func (s *signerActedStore) get(zone string) (Roles, bool) {
	if s == nil {
		return Roles{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.zones[canonicalName(zone)]
	return r, ok
}

// keep keeps r for a zone with nothing kept, on disk first. Waiting, the
// signer's sets do not change, so what is kept stands until a hand-over.
func (s *signerActedStore) keep(zone string, r Roles) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := canonicalName(zone)
	if _, kept := s.zones[key]; kept {
		return nil
	}
	if s.hdb != nil {
		js, err := json.Marshal(r)
		if err != nil {
			return err
		}
		s.hdb.Lock()
		_, err = s.hdb.DB.Exec(`INSERT INTO MPSignerActed (zonename, sets) VALUES (?, ?)`, key, string(js))
		s.hdb.Unlock()
		if err != nil {
			return fmt.Errorf("keeping the sets the signer acts by for %s: %w", zone, err)
		}
	}
	s.zones[key] = r
	return nil
}

// drop forgets what is kept for the zone: it holds a hand-over now.
func (s *signerActedStore) drop(zone string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := canonicalName(zone)
	if _, kept := s.zones[key]; !kept {
		return nil
	}
	if s.hdb != nil {
		s.hdb.Lock()
		_, err := s.hdb.DB.Exec(`DELETE FROM MPSignerActed WHERE zonename=?`, key)
		s.hdb.Unlock()
		if err != nil {
			return fmt.Errorf("dropping the sets the signer acted by for %s: %w", zone, err)
		}
	}
	delete(s.zones, key)
	return nil
}

// signerLastActed is what the signer last acted by for the zone, with kept
// its data: that data when a load or a hand-over computed it, or what is kept
// on disk. False when it has acted by none yet: its first load.
func signerLastActed(zone string, kept *MPdata) (Roles, bool) {
	if kept.computed() {
		return kept.Sets, true
	}
	return signerActed.Load().get(zone)
}

// restoreSignerActed gives the zone, before its first load, the data of the
// sets kept, in place of the config parse's stub, so that a copy that drops
// this provider leaves its roles as they were. Sets that do not name this
// provider leave the stub: they give it no role, and signerLastActed finds
// them.
func (mpzd *MPZoneData) restoreSignerActed(mp *MultiProviderConf) {
	r, ok := signerActed.Load().get(mpzd.ZoneName)
	if !ok {
		return
	}
	if _, handed := actingHeld.Load().roles(mpzd.ZoneName); handed {
		return
	}
	label := labelOfIdentity(r, ourHsyncIdentities(mp))
	if label == "" {
		return
	}
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	d := &MPdata{
		OurLabel:     label,
		WeAreSigner:  has(r.Signing, label),
		OtherSigners: len(othersIn(r.KeySigners, label)),
		ZoneSigned:   len(r.Signing) > 0,
		Sets:         r,
		Options:      map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	d.WeAreProvider = has(r.Servers, label) || d.WeAreSigner
	mpzd.MP.MPdata = d
}
