/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Data access layer for the ZoneDataReplaceOrigin and CombinerReplaceOrigin
 * tables. Persists the replace-order guards (ZoneDataRepo.lastReplace on
 * the agent, combinerReplaceOrigins on the combiner) so a restart still
 * rejects an older REPLACE (tdns-mp #249).
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
	return saveReplaceOriginIn(hdb, "ZoneDataReplaceOrigin", zone, agentID, rrtype, origin)
}

// LoadAllReplaceOrigins loads every ZoneDataReplaceOrigin row into the same
// key shape ZoneDataRepo.lastReplace uses: "zone|agent|RRTYPE".
func LoadAllReplaceOrigins(hdb *HsyncDB) (map[string]replaceOrigin, error) {
	return loadReplaceOriginsFrom(hdb, "ZoneDataReplaceOrigin")
}

// SaveCombinerReplaceOrigin is SaveReplaceOrigin for the combiner's guard.
func SaveCombinerReplaceOrigin(hdb *HsyncDB, zone, senderID string, rrtype uint16, origin replaceOrigin) error {
	return saveReplaceOriginIn(hdb, "CombinerReplaceOrigin", zone, senderID, rrtype, origin)
}

// DeleteCombinerReplaceOrigin removes the combiner's guard row for (zone,
// senderID, rrtype): the place a REPLACE that was not applied took, with
// none held before it.
func DeleteCombinerReplaceOrigin(hdb *HsyncDB, zone, senderID string, rrtype uint16) error {
	hdb.Lock()
	defer hdb.Unlock()
	if _, err := hdb.DB.Exec(`DELETE FROM CombinerReplaceOrigin WHERE zone = ? AND agent_id = ? AND rrtype = ?`, zone, senderID, rrtype); err != nil {
		return fmt.Errorf("delete replace origin in CombinerReplaceOrigin: %w", err)
	}
	return nil
}

// LoadCombinerReplaceOrigins is LoadAllReplaceOrigins for the combiner's
// guard, in the key shape of combinerReplaceOrigins: "zone|sender|RRTYPE".
func LoadCombinerReplaceOrigins(hdb *HsyncDB) (map[string]replaceOrigin, error) {
	return loadReplaceOriginsFrom(hdb, "CombinerReplaceOrigin")
}

// saveReplaceOriginIn upserts origin into table, one of the two above.
func saveReplaceOriginIn(hdb *HsyncDB, table, zone, agentID string, rrtype uint16, origin replaceOrigin) error {
	hdb.Lock()
	defer hdb.Unlock()

	_, err := hdb.DB.Exec(`
		INSERT INTO `+table+` (zone, agent_id, rrtype, origin_time, dist_id, under, has_under)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zone, agent_id, rrtype) DO UPDATE SET
			origin_time = excluded.origin_time,
			dist_id = excluded.dist_id,
			under = excluded.under,
			has_under = excluded.has_under`,
		zone, agentID, rrtype, origin.Time.UnixNano(), origin.DistID, origin.Under, origin.HasUnder)
	if err != nil {
		return fmt.Errorf("save replace origin in %s: upsert: %w", table, err)
	}
	return nil
}

// loadReplaceOriginsFrom loads every row of table, keyed "zone|agent|RRTYPE".
func loadReplaceOriginsFrom(hdb *HsyncDB, table string) (map[string]replaceOrigin, error) {
	hdb.Lock()
	defer hdb.Unlock()

	rows, err := hdb.DB.Query(`SELECT zone, agent_id, rrtype, origin_time, dist_id, under, has_under FROM ` + table)
	if err != nil {
		return nil, fmt.Errorf("load replace origins from %s: query: %w", table, err)
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
			return nil, fmt.Errorf("load replace origins from %s: scan: %w", table, err)
		}
		key := zone + "|" + agentID + "|" + dns.TypeToString[rrtype]
		result[key] = replaceOrigin{Time: time.Unix(0, originTime), DistID: distID, Under: under, HasUnder: hasUnder}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load replace origins from %s: rows: %w", table, err)
	}
	return result, nil
}
