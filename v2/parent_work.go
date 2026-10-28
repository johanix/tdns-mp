/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The leader's work towards a zone's parent, as the thaw reads it (design
 * 3.2, plan S7). Every path to the parent runs on a context of the zone's
 * own, the run that delegationSyncRun gives it: a sync, an UPDATE that tdns
 * retries, the key's poll and its bootstrap, the operator's
 * parentsync-bootstrap. The leader thaws only once nothing is in flight
 * there; at the thaw's turn, and when its group's leader is invalidated, it
 * cancels what is left. A hand-over of the lead ends the work as before
 * (delegationSyncZoneLeft, stopRunsOfLostLead), and so does the owner's
 * taking the sync over (delegationSyncOwnerSyncs).
 */
package tdnsmp

import (
	"strings"
)

// parentWorkCancelled is the cause of a run cancelled by cancelParentWork:
// a sync it stops is owed until the transition is done, not retried as a
// failure.
type parentWorkCancelled struct{ why string }

func (p parentWorkCancelled) Error() string { return "parent work for the zone cancelled: " + p.why }

// parentWorkUnderWay is what the leader has in flight towards the zone's
// parent (design 3.2): a sync under way (its run, the key's poll among
// them), a key's poll about to start, a NOTIFY held back, or an ask of the
// chain scheduled, the check of the parent after a NOTIFY or the retry of a
// failed sync. "" when nothing is.
func (conf *Config) parentWorkUnderWay(zone string) string {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	runs := len(c.runs[zone])
	ch := c.zones[zone]
	held := ch != nil && ch.hold != nil
	waiting := ch != nil && ch.waiting
	c.mu.Unlock()
	polls, _, _ := conf.InternalMp.keyPolls.state(ZoneName(zone))
	var what []string
	switch {
	case runs > 0:
		what = append(what, "a sync in flight")
	case polls > 0:
		what = append(what, "a key poll")
	}
	switch {
	case held:
		what = append(what, "a NOTIFY held")
	case waiting:
		what = append(what, "a check of the parent scheduled")
	}
	return strings.Join(what, ", ")
}

// cancelParentWork ends the leader's work towards the zone's parent: every
// run is cancelled, with why as its cause, and the chain is dropped as
// delegationSyncNotLeading drops it, its held NOTIFY and its scheduled asks
// with it. Each run leaves its list when it has returned.
func (conf *Config) cancelParentWork(zone, why string) {
	c := &conf.InternalMp.delegationSyncChains
	cause := parentWorkCancelled{why: why}
	c.mu.Lock()
	_, chained := c.zones[zone]
	c.endChainLocked(zone)
	runs := 0
	for _, run := range c.runs[zone] {
		if run.cancelFor != nil {
			run.cancelFor(cause)
		} else {
			run.cancel()
		}
		runs++
	}
	c.mu.Unlock()
	if chained || runs > 0 {
		lg.Info("parent work for the zone cancelled", "zone", zone, "why", why, "syncs", runs)
	}
}

// cancelGroupParentWork cancels the parent work of every zone of a group
// whose leader is invalidated: a sync that tdns still retries, for up to
// 75 s, goes out from nobody's lead.
func (conf *Config) cancelGroupParentWork(zones []ZoneName) {
	for _, zone := range zones {
		conf.cancelParentWork(string(zone), "the group's leader is invalidated")
	}
}
