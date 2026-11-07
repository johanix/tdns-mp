/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Data access layer for the ZoneDataReplaceOrigin table.
 * Persists the replace-order guard (ZoneDataRepo.lastReplace) so a restart
 * still rejects an older REPLACE (tdns-mp #249).
 */

package tdnsmp

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// SaveReplaceOrigin upserts the origin of the last applied REPLACE for
// (zone, agentID, rrtype).
func SaveReplaceOrigin(hdb *HsyncDB, zone, agentID string, rrtype uint16, origin replaceOrigin) error {
	hdb.Lock()
	defer hdb.Unlock()

	_, err := hdb.DB.Exec(`
		INSERT INTO ZoneDataReplaceOrigin (zone, agent_id, rrtype, origin_time, dist_id, under, has_under)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zone, agent_id, rrtype) DO UPDATE SET
			origin_time = excluded.origin_time,
			dist_id = excluded.dist_id,
			under = excluded.under,
			has_under = excluded.has_under`,
		zone, agentID, rrtype, origin.Time.UnixNano(), origin.DistID, origin.Under, origin.HasUnder)
	if err != nil {
		return fmt.Errorf("SaveReplaceOrigin: upsert: %w", err)
	}
	return nil
}

// LoadAllReplaceOrigins loads every ZoneDataReplaceOrigin row into the same
// key shape ZoneDataRepo.lastReplace uses: "zone|agent|RRTYPE".
func LoadAllReplaceOrigins(hdb *HsyncDB) (map[string]replaceOrigin, error) {
	hdb.Lock()
	defer hdb.Unlock()

	rows, err := hdb.DB.Query(`SELECT zone, agent_id, rrtype, origin_time, dist_id, under, has_under FROM ZoneDataReplaceOrigin`)
	if err != nil {
		return nil, fmt.Errorf("LoadAllReplaceOrigins: query: %w", err)
	}
	defer rows.Close()

	result := make(map[string]replaceOrigin)
	for rows.Next() {
		var zone, agentID, distID string
		var rrtype uint16
		var originTime int64
		var under uint32
		var hasUnder bool
		if err := rows.Scan(&zone, &agentID, &rrtype, &originTime, &distID, &under, &hasUnder); err != nil {
			return nil, fmt.Errorf("LoadAllReplaceOrigins: scan: %w", err)
		}
		key := zone + "|" + agentID + "|" + dns.TypeToString[rrtype]
		result[key] = replaceOrigin{Time: time.Unix(0, originTime), DistID: distID, Under: under, HasUnder: hasUnder}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("LoadAllReplaceOrigins: rows: %w", err)
	}
	return result, nil
}
