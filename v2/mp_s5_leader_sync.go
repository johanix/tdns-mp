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
	"sync"
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

// delegationSyncRetryPolicy is the delay and the bound of one request's
// retries, read once when the request is made: the retries run from timer
// callbacks, which must not read variables a test may be restoring.
type delegationSyncRetryPolicy struct {
	delay   time.Duration
	retries int
}

// requestDelegationSync asks the delegation syncher to bring the parent in
// line with the zone, if the zone syncs with its parent through its agents
// (parentsync=agent) and this agent is the zone's elected leader (with no
// election manager there is nobody else to be it). The request is an
// explicit sync: analysis first, an update only for a difference, so
// asking twice sends once. It does not wait: the callers are engines'
// loops. ctx is the asking engine's: a retry that comes due after it has
// ended asks for nothing. Reports whether a request was queued now.
func (conf *Config) requestDelegationSync(ctx context.Context, zone string, why string) bool {
	return conf.requestDelegationSyncAttempt(ctx, zone, why, 0,
		delegationSyncRetryPolicy{delay: delegationSyncRetryDelay, retries: delegationSyncRetries})
}

func (conf *Config) requestDelegationSyncAttempt(ctx context.Context, zone string, why string, attempt int, policy delegationSyncRetryPolicy) bool {
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
	if attempt >= policy.retries {
		lgEngine.Warn("the delegation sync queue stayed full; the request is given up, the next change of the DS set or an election asks again", "zone", zone, "why", why, "attempts", attempt+1)
		return false
	}
	lgEngine.Warn("the delegation sync queue is full; asking again shortly", "zone", zone, "why", why, "attempt", attempt+1, "in", policy.delay)
	time.AfterFunc(policy.delay, func() { conf.requestDelegationSyncAttempt(ctx, zone, why, attempt+1, policy) })
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

// A sync that fails is asked again. The parent may refuse the leader's
// update for a reason that passes by itself: the commonest is a SIG(0) key
// it knows and has not finished verifying ("known, but not yet trusted"),
// which is what the first sync after a new key always meets. The syncher
// used to drop such a request, and then nothing asked again until the DS
// set changed or an election was held, so the parent stayed without the
// DS set for as long as the keys stayed as they were.
//
// One chain of retries per zone, with growing delays, ended by a sync that
// succeeds, by losing the leadership, or by the bound (then the next change
// of the DS set, or an election, asks anew).
var delegationSyncFailureDelays = []time.Duration{
	30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
	8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute,
}

type delegationSyncFailures struct {
	mu      sync.Mutex
	attempt map[string]int  // zone -> failures seen in this chain
	waiting map[string]bool // zone -> a retry is scheduled and has not fired
}

// delegationSyncFailed notes a failed sync of a zone and schedules the next
// ask, unless one is scheduled already. delays is read once per call: the
// retry runs from a timer callback.
func (conf *Config) delegationSyncFailed(ctx context.Context, zone string, cause error) {
	conf.delegationSyncFailedWith(ctx, zone, cause, delegationSyncFailureDelays)
}

func (conf *Config) delegationSyncFailedWith(ctx context.Context, zone string, cause error, delays []time.Duration) {
	f := &conf.InternalMp.delegationSyncFailures
	f.mu.Lock()
	if f.attempt == nil {
		f.attempt, f.waiting = map[string]int{}, map[string]bool{}
	}
	if f.waiting[zone] {
		f.mu.Unlock()
		return
	}
	n := f.attempt[zone]
	if n >= len(delays) {
		delete(f.attempt, zone)
		f.mu.Unlock()
		lgEngine.Warn("the delegation sync keeps failing; given up until the DS set changes or an election is held", "zone", zone, "failures", n+1, "last", cause)
		return
	}
	f.attempt[zone] = n + 1
	f.waiting[zone] = true
	f.mu.Unlock()
	delay := delays[n]
	lgEngine.Warn("the delegation sync failed; asking again", "zone", zone, "failure", n+1, "in", delay, "cause", cause)
	time.AfterFunc(delay, func() {
		f.mu.Lock()
		delete(f.waiting, zone)
		f.mu.Unlock()
		if !conf.requestDelegationSync(ctx, zone, "the last delegation sync failed") {
			// The ask was not queued now: not the leader any more, the
			// zone gone, the engine ended, or the syncher's queue full
			// (the ask retries the queue by itself for a while). This
			// chain ends here: whoever leads now has its own, and a sync
			// that fails after a queued retry starts a new chain from the
			// first delay.
			conf.delegationSyncSucceeded(zone)
		}
	})
}

// delegationSyncSucceeded ends a zone's chain of retries: the next failure
// starts from the first delay again.
func (conf *Config) delegationSyncSucceeded(zone string) {
	f := &conf.InternalMp.delegationSyncFailures
	f.mu.Lock()
	delete(f.attempt, zone)
	f.mu.Unlock()
}

// mpLeaderSync: the request is for a multi-provider zone that syncs with its
// parent through its agents, which is the sync requestDelegationSync asks
// for and the one whose failure is asked again.
func mpLeaderSync(conf *Config, ds tdns.DelegationSyncRequest) bool {
	return conf != nil && ds.ZoneData != nil && ds.ZoneData.Options[tdns.OptMultiProvider] && ds.ZoneData.Options[tdns.OptParentSync]
}

// noteKeyInventory records an inventory the zone's signer sent, whichever
// way it came: pushed by the signer when a key changed, or as the answer to
// this agent's own request (at its start, at a refresh). Both must feed the
// same things, and the second did not: its snapshot lost the Owned mark, it
// never reached the owner, and it asked for nothing. An agent that had
// restarted therefore had no DS set until the signer's keys next changed,
// and the sync an election asks for found no opinion about the DS and
// called the parent in sync.
//
// The agent's DS-intent provider answers from the latest inventory (design
// §4.1, arrow 2); a DS set that is known and not what it was goes to the
// parent through the leader's delegation sync, whatever else did or did not
// change (T5.4). An unknown set asks for nothing: the sync leaves the
// parent's DS alone then anyway. Only an inventory from a signer that runs
// the zone's key lifecycle states the DS set: the syncher's DS intent is the
// owner's for such a zone alone, so for any other the request would find
// nothing to act on. What the DS set was counts only if the inventory before
// this one came from an owning signer too: a zone that has just been taken
// had no DS set the syncher would act on, whatever its keys were, so the
// take asks for a sync even with every key as it was. The same holds for
// the first inventory after a start: there is no inventory before it.
func (conf *Config) noteKeyInventory(ctx context.Context, zd *MPZoneData, msg *KeystateInventoryMsg) {
	if conf == nil || zd == nil || msg == nil {
		return
	}
	snap := &KeyInventorySnapshot{
		SenderID:  msg.SenderID,
		Zone:      msg.Zone,
		Inventory: msg.Inventory,
		Owned:     msg.Owned,
		Received:  time.Now(),
	}
	prev := zd.GetLastKeyInventory()
	zd.SetLastKeyInventory(snap)
	o := conf.InternalMp.KeyLifecycleOwner
	if o == nil {
		return
	}
	var before tdns.DSIntent
	if prev != nil && prev.Owned {
		before, _ = o.DSIntent(zd.ZoneData, dns.SHA256)
	}
	o.SetInventory(msg.Zone, snap)
	if after, err := o.DSIntent(zd.ZoneData, dns.SHA256); msg.Owned && err == nil && after.Known && !sameDSIntent(before, after) {
		conf.requestDelegationSync(ctx, msg.Zone, "the zone's DS set changed")
	}
}
