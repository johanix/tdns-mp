/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import tdns "github.com/johanix/tdns/v2"

// ParentSyncAfterKeyPublication is the MP-enhanced version that adds
// leader election gating. Only the elected leader bootstraps keys
// with the parent. The base version in tdns has no leader checks.
//
// If leadership is lost mid-retry inside the base version's loop,
// the attempt still executes. This is acceptable: a duplicate
// bootstrap is harmless, and leadership loss mid-loop is rare.
func (conf *Config) ParentSyncAfterKeyPublication(zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	lem := conf.InternalMp.LeaderElectionManager

	// Only the leader should bootstrap.
	if lem != nil && !lem.IsLeader(zone) {
		lg.Info("ParentSyncAfterKeyPublication: not the leader, skipping", "zone", zone)
		return
	}

	// Delegate to the base version which handles IMR wait,
	// HSYNCPARAM check, KeyState inquiry, and bootstrap.
	conf.Config.ParentSyncAfterKeyPublication(tdns.ZoneName(zone), keyName, keyid, algorithm)
}
