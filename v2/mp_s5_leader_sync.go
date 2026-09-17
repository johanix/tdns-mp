/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Arrow 2's trigger (key lifecycle ownership design §4.1, Q2; test plan
 * T5.4, T5.8): the zone's DS set reaches the parent through the elected
 * leader's delegation sync. The sync itself compares the parent's DS
 * with the owner's DS intent and sends the difference, and sends nothing
 * when there is none; what was missing is somebody asking for it when
 * the DS set changes with nothing else changing (a KSK that becomes
 * standby, a DS withdrawn, another provider's word arriving), and when
 * the leadership moves.
 */
package tdnsmp

import (
	"sort"

	tdns "github.com/johanix/tdns/v2"
)

// requestDelegationSync asks the delegation syncher to bring the parent in
// line with the zone, if this agent is the zone's elected leader (with no
// election manager there is nobody else to be it). The request is an
// explicit sync: analysis first, an update only for a difference, so
// asking twice sends once. It does not wait: the caller is an engine's
// loop. Reports whether a request was queued.
func (conf *Config) requestDelegationSync(zone string, why string) bool {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil || mpzd.DelegationSyncQ == nil {
		return false
	}
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil && !lem.IsLeader(ZoneName(zone)) {
		lgEngine.Debug("not the delegation sync leader; the leader syncs the parent", "zone", zone, "why", why)
		return false
	}
	select {
	case mpzd.DelegationSyncQ <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: zone, ZoneData: mpzd.ZoneData}:
		lgEngine.Info("delegation sync requested", "zone", zone, "why", why)
		return true
	default:
		lgEngine.Warn("the delegation sync queue is full; the request is dropped, the next change asks again", "zone", zone, "why", why)
		return false
	}
}

// sameDSIntent: both unknown, or both known with the same DS records.
func sameDSIntent(a, b tdns.DSIntent) bool {
	if a.Known != b.Known || len(a.Set) != len(b.Set) {
		return false
	}
	as, bs := make([]string, len(a.Set)), make([]string, len(b.Set))
	for i := range a.Set {
		as[i], bs[i] = a.Set[i].String(), b.Set[i].String()
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
