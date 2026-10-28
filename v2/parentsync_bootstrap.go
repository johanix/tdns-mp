/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"

	tdns "github.com/johanix/tdns/v2"
)

// ParentSyncAfterKeyPublication is the MP-enhanced version that adds
// leader election gating. Only the elected leader bootstraps keys
// with the parent. The base version in tdns has no leader checks.
//
// The poll is a run of the zone (delegationSyncRun), so that what ends the
// zone's work with its parent ends the poll too, from any of its waits: the
// owner's take-over, and a refresh after which this agent no longer takes
// part in the zone (followParentSyncParam). tdns's poll stops by itself only
// at the owner's take-over. The run is taken first, and the checks come
// after it, so that a refresh that lands between the two is not missed.
//
// A poll that returns because its run was cancelled is started again when
// this agent takes part in the zone by then: a record set OFF and back ON
// during a wait would otherwise get no new poll until a later refresh. A
// poll that returns for any other reason is not: the parent trusts the key,
// the poll gave up, or a poll for the key already runs (tdns holds one per
// key, and a new call while the slot is held would spin).
//
// A lead lost to another agent while the poll runs cancels its run
// (stopRunsOfLostLead), from any of its waits: a former leader does not
// bootstrap the key after the new leader has. The poll is not started
// again: the next pass finds this agent no leader.
func (conf *Config) ParentSyncAfterKeyPublication(ctx context.Context, zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	for {
		runCtx, done := conf.delegationSyncRun(ctx, string(zone))
		if !conf.keyPollOnce(ctx, runCtx, zone, keyName, keyid, algorithm) {
			done()
			return
		}
		done()
	}
}

// keyPollOnce runs the poll once, under the run runCtx, and says whether it
// is to be started again: whether the run was cancelled while ctx lives.
func (conf *Config) keyPollOnce(ctx, runCtx context.Context, zone ZoneName, keyName string, keyid uint16, algorithm uint8) (again bool) {
	lem := conf.InternalMp.LeaderElectionManager

	// Only the leader should bootstrap.
	if lem != nil && !lem.IsLeader(zone) {
		lg.Info("ParentSyncAfterKeyPublication: not the leader, skipping", "zone", zone)
		return false
	}
	if !conf.stillParticipates(string(zone)) {
		lgElect.Info("the key poll is not started: this agent takes no part in the zone", "zone", zone)
		return false
	}
	// Nor while the zone is frozen (plan S6): the take-up when the
	// transition is done starts it (takeUp)
	if held, why := conf.syncHeld(string(zone), syncOther); held {
		lgElect.Info("the key poll is not started during the transition", "zone", zone, "phase", why)
		return false
	}
	// The option says whether this agent may sync the zone at all: the
	// zone's records name it, and HSYNCPARAM says parentsync=agent
	// (followParentSyncParam).
	if zd, ok := Zones.Get(string(zone)); ok && ownerSyncsDelegation(zd.ZoneData) {
		lgElect.Info("the key poll is not started: the zone's parentsync option is off", "zone", zone)
		return false
	}

	// Delegate to the base version which handles IMR wait,
	// HSYNCPARAM check, KeyState inquiry, and bootstrap.
	if poll := conf.InternalMp.keyPoll; poll != nil {
		poll(runCtx, zone, keyName, keyid, algorithm)
	} else {
		conf.Config.ParentSyncAfterKeyPublication(runCtx, tdns.ZoneName(zone), keyName, keyid, algorithm)
	}
	return runCtx.Err() != nil && ctx.Err() == nil
}
