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
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// delegationSyncRetryDelay and delegationSyncRetries bound what happens
// when the syncher's queue is full: the request is tried again after the
// delay, that many times, and then given up with a warning (the next
// change of the DS set, or an election, asks anew).
var (
	delegationSyncRetryDelay = 30 * time.Second
	delegationSyncRetries    = 5
)

// requestDelegationSync asks the delegation syncher to bring the parent in
// line with the zone, if the zone syncs with its parent through its agents
// (parentsync=agent) and this agent is the zone's elected leader (with no
// election manager there is nobody else to be it). The request is an
// explicit sync: analysis first, an update only for a difference, so
// asking twice sends once. It does not wait: the callers are engines'
// loops. ctx is the asking engine's: a retry that comes due after it has
// ended asks for nothing. Reports whether a request was queued now.
func (conf *Config) requestDelegationSync(ctx context.Context, zone string, why string) bool {
	return conf.requestDelegationSyncAttempt(ctx, zone, why, 0)
}

func (conf *Config) requestDelegationSyncAttempt(ctx context.Context, zone string, why string, attempt int) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil || mpzd.DelegationSyncQ == nil {
		return false
	}
	if !mpzd.Options[tdns.OptParentSync] {
		lgEngine.Debug("the zone does not sync with its parent through its agents; no delegation sync asked for", "zone", zone, "why", why)
		return false
	}
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil && !lem.IsLeader(ZoneName(zone)) {
		lgEngine.Debug("not the delegation sync leader; the leader syncs the parent", "zone", zone, "why", why)
		return false
	}
	if queueExplicitDelegationSync(mpzd) {
		lgEngine.Info("delegation sync requested", "zone", zone, "why", why, "attempt", attempt+1)
		return true
	}
	if attempt >= delegationSyncRetries {
		lgEngine.Warn("the delegation sync queue stayed full; the request is given up, the next change of the DS set or an election asks again", "zone", zone, "why", why, "attempts", attempt+1)
		return false
	}
	lgEngine.Warn("the delegation sync queue is full; asking again shortly", "zone", zone, "why", why, "attempt", attempt+1, "in", delegationSyncRetryDelay)
	time.AfterFunc(delegationSyncRetryDelay, func() { conf.requestDelegationSyncAttempt(ctx, zone, why, attempt+1) })
	return false
}

// queueExplicitDelegationSync puts an explicit sync on the zone's queue
// without waiting for room.
func queueExplicitDelegationSync(mpzd *MPZoneData) bool {
	select {
	case mpzd.DelegationSyncQ <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: mpzd.ZoneName, ZoneData: mpzd.ZoneData}:
		return true
	default:
		return false
	}
}

// sameDSIntent: both unknown, or both known with the same DS records, by
// what a DS is (key tag, algorithm, digest type, digest), not by how the
// record prints: a TTL is not a change of the DS set.
func sameDSIntent(a, b tdns.DSIntent) bool {
	if a.Known != b.Known || len(a.Set) != len(b.Set) {
		return false
	}
	key := func(rr dns.RR) string {
		if ds, ok := rr.(*dns.DS); ok {
			return fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		}
		return rr.String()
	}
	as, bs := make([]string, len(a.Set)), make([]string, len(b.Set))
	for i := range a.Set {
		as[i], bs[i] = key(a.Set[i]), key(b.Set[i])
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
