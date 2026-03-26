/*
 * Copyright (c) Johan Stenstam, <johani@johani.org>
 *
 * Local copy of InitCombinerEditTables, adapted from tdns/v2/db_schema_hsync.go.
 */
package tdnsmp

import (
	"fmt"

	tdns "github.com/johanix/tdns/v2"
)

// InitCombinerEditTables initializes only the combiner edit tables.
// Call this on combiner startup — avoids creating agent-only HSYNC tables.
func InitCombinerEditTables(kdb *tdns.KeyDB) error {
	kdb.Lock()
	defer kdb.Unlock()

	combinerTables := []string{
		"CombinerPendingEdits",
		"CombinerApprovedEdits",
		"CombinerRejectedEdits",
		"CombinerContributions",
		"CombinerPublishInstructions",
		"OutgoingSerials",
	}

	for _, name := range combinerTables {
		schema, ok := tdns.HsyncTables[name]
		if !ok {
			return fmt.Errorf("table schema %q not found in HsyncTables", name)
		}
		if _, err := kdb.DB.Exec(schema); err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	combinerIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_pending_edits_zone ON CombinerPendingEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_approved_edits_zone ON CombinerApprovedEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_rejected_edits_zone ON CombinerRejectedEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_contributions_zone ON CombinerContributions(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_contributions_zone_sender ON CombinerContributions(zone, sender_id)`,
		`CREATE INDEX IF NOT EXISTS idx_publish_instr_zone ON CombinerPublishInstructions(zone)`,
	}

	for _, indexSQL := range combinerIndexes {
		if _, err := kdb.DB.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}
