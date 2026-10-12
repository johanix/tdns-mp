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

// A sync that goes to the parent as a NOTIFY is asked again too, for
// another reason: it is not known to have done anything. The answer to an
// UPDATE is the parent's word on the change. A NOTIFY only asks the parent
// to come and look. The parent scans the zone's nameservers some time
// later, and finds nothing to do if they do not serve the change yet. Seen
// on a test fleet: the leader, a provider that does not sign the zone, sent
// NOTIFY(CDS) in the second the signer created the CDS; the parent scanned,
// found no change, and the sync counted as done with no DS at the parent.
// A NOTIFY(CSYNC) that is early in the same way makes the parent refuse, or
// apply the NS set from before the change and stay one change behind.
//
// So after a NOTIFY the leader looks at the parent again: it asks for the
// explicit sync once more after a delay. That sync analyses the parent
// first and sends only for a difference, so the ask is the check, and the
// NOTIFY is repeated only while the parent still differs. The delays grow,
// to about an hour in all: the zone's nameservers need seconds to a minute
// to serve a change, and the parent then needs to scan. The chain is ended
// by an analysis that finds the parent in sync, by losing the leadership,
// or by the bound (then the next change of the delegation's data, or an
// election, asks anew).
var delegationSyncNotifyDelays = []time.Duration{
	30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute,
	8 * time.Minute, 15 * time.Minute, 30 * time.Minute,
}

// delegationSyncChains is what the leader keeps of each zone's sync between
// two asks: one chain per zone, whether the last sync failed or went out as
// a NOTIFY, and so at most one ask waiting per zone.
type delegationSyncChains struct {
	mu    sync.Mutex
	zones map[string]*delegationSyncChain
}

type delegationSyncChain struct {
	failures int    // syncs that failed, in a row
	rechecks int    // checks of the parent scheduled after a NOTIFY, in this chain
	notified string // the last NOTIFY sent that no analysis has seen at the parent ("CSYNC", "CDS", "CSYNC, CDS")
	waiting  bool   // an ask is scheduled and has not fired
	ask      int    // the number of the ask that waits: one that fires with another number was replaced
}

// of returns the zone's chain, a new one if it has none. The caller holds mu.
func (c *delegationSyncChains) of(zone string) *delegationSyncChain {
	if c.zones == nil {
		c.zones = map[string]*delegationSyncChain{}
	}
	ch := c.zones[zone]
	if ch == nil {
		ch = &delegationSyncChain{}
		c.zones[zone] = ch
	}
	return ch
}

// delegationSyncAskAfter schedules the zone's one waiting ask: the explicit
// sync, after the delay. The caller has marked the chain as waiting and
// given the ask its number, under the lock.
func (conf *Config) delegationSyncAskAfter(ctx context.Context, zone string, ask int, delay time.Duration, why string) {
	c := &conf.InternalMp.delegationSyncChains
	time.AfterFunc(delay, func() {
		c.mu.Lock()
		ch := c.zones[zone]
		if ch == nil || ch.ask != ask {
			c.mu.Unlock()
			return
		}
		ch.waiting = false
		c.mu.Unlock()
		if !conf.requestDelegationSync(ctx, zone, why) {
			// The ask was not queued now: not the leader any more, the
			// zone gone, the engine ended, or the syncher's queue full
			// (the ask retries the queue by itself for a while). This
			// chain ends here: whoever leads now has its own, and a sync
			// that fails, or sends a NOTIFY, after a queued retry starts a
			// new chain from the first delay.
			conf.delegationSyncSucceeded(zone)
		}
	})
}

// delegationSyncFailed notes a failed sync of a zone and schedules the next
// ask, unless one is scheduled already. delays is read once per call: the
// retry runs from a timer callback.
func (conf *Config) delegationSyncFailed(ctx context.Context, zone string, cause error) {
	conf.delegationSyncFailedWith(ctx, zone, cause, delegationSyncFailureDelays)
}

func (conf *Config) delegationSyncFailedWith(ctx context.Context, zone string, cause error, delays []time.Duration) {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.of(zone)
	if ch.waiting {
		c.mu.Unlock()
		return
	}
	n := ch.failures
	if n >= len(delays) {
		delete(c.zones, zone)
		c.mu.Unlock()
		lgEngine.Warn("the delegation sync keeps failing; given up until the DS set changes or an election is held", "zone", zone, "failures", n+1, "last", cause)
		return
	}
	ch.failures, ch.waiting = n+1, true
	ch.ask++
	ask := ch.ask
	c.mu.Unlock()
	delay := delays[n]
	lgEngine.Warn("the delegation sync failed; asking again", "zone", zone, "failure", n+1, "in", delay, "cause", cause)
	conf.delegationSyncAskAfter(ctx, zone, ask, delay, "the last delegation sync failed")
}

// delegationSyncNotified is for a sync that SyncZoneDelegation carried out
// without error: if it went to the parent as a NOTIFY, for a zone whose
// leader this agent is, it schedules the look at the parent that decides
// whether the sync is done, and reports true. The caller then does not book
// the sync as done and does not tell the peers. delays is read once per
// call, as for a failure.
func (conf *Config) delegationSyncNotified(ctx context.Context, ds tdns.DelegationSyncRequest, msg string) bool {
	sent := notifiesSent(msg)
	if sent == "" || !mpLeaderSync(conf, ds) {
		return false
	}
	conf.delegationSyncNotifiedWith(ctx, ds.ZoneName, sent, delegationSyncNotifyDelays)
	return true
}

func (conf *Config) delegationSyncNotifiedWith(ctx context.Context, zone string, sent string, delays []time.Duration) {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.of(zone)
	ch.notified, ch.failures = sent, 0
	n := ch.rechecks
	// A NOTIFY while a check waits did not come from the chain: its own ask
	// has not fired. A new change, or an election, asked in between. The
	// check that waits was timed for an earlier NOTIFY, so it is replaced by
	// the same check timed for this one, by the first delay: the parent is
	// then looked at neither seconds after a NOTIFY nor half an hour after a
	// change. The count of checks stays as it is. Only the chain's own asks
	// move it towards the bound, so a trigger that comes again and again (an
	// election, at every renewal of the lease) does not keep the chain from
	// ending.
	retimed := ch.waiting && n > 0 && len(delays) > 0
	if !retimed && n >= len(delays) {
		delete(c.zones, zone)
		c.mu.Unlock()
		lgEngine.Warn("the parent still differs from the zone after the last check, and a last NOTIFY has been sent; given up until the delegation's data changes or an election is held", "zone", zone, "notify", sent, "checks", n)
		return
	}
	delay := delays[0]
	if !retimed {
		delay = delays[n]
		ch.rechecks = n + 1
	}
	check := ch.rechecks
	ch.waiting = true
	ch.ask++
	ask := ch.ask
	c.mu.Unlock()
	lgEngine.Info("the delegation sync went to the parent as a NOTIFY; checking the parent again", "zone", zone, "notify", sent, "check", check, "in", delay)
	conf.delegationSyncAskAfter(ctx, zone, ask, delay, "a NOTIFY was sent to the parent, which is checked again")
}

// delegationSyncSucceeded ends a zone's chain: the next failure, or the next
// NOTIFY, starts from the first delay again. An ask that still waits is left
// to fire; it finds a chain with nothing in it. Returned are the NOTIFY the
// chain had sent and the number of checks it had asked for, for the caller
// that ends the chain because the parent was found in sync.
func (conf *Config) delegationSyncSucceeded(zone string) (notified string, rechecks int) {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := c.zones[zone]
	if ch == nil {
		return "", 0
	}
	notified, rechecks = ch.notified, ch.rechecks
	if ch.waiting {
		ch.failures, ch.rechecks, ch.notified = 0, 0, ""
	} else {
		delete(c.zones, zone)
	}
	return notified, rechecks
}

// delegationSyncInSync is for an analysis that found the parent in sync with
// the zone. It ends the zone's chain. If the chain had sent a NOTIFY, this
// is when that sync is done, so the peers are told now, once; a sync that
// never sent anything tells them nothing, as before.
func (conf *Config) delegationSyncInSync(zone string) {
	sent, checks := conf.delegationSyncSucceeded(zone)
	if sent == "" {
		return
	}
	lgEngine.Info("the parent is in sync with the zone after the NOTIFY", "zone", zone, "notify", sent, "checks", checks)
	go notifyPeersParentSyncDone(conf, zone, dns.RcodeToString[dns.RcodeSuccess],
		fmt.Sprintf("the parent is in sync with zone %s after NOTIFY(%s)", zone, sent))
}

// delegationSyncNotifyMarker starts the message of a sync that tdns sent as
// a NOTIFY (SyncZoneDelegationViaNotify); the NOTIFY types follow it, up to
// the closing bracket.
const delegationSyncNotifyMarker = "SyncZoneDelegationViaNotify: Sent NOTIFY("

// notifiesSent reads from the message of a sync which NOTIFYs it handed to
// the notifier: "CSYNC", "CDS" or "CSYNC, CDS", and "" for a sync that went
// as an UPDATE or through the API, or that sent nothing. The message is the
// only place where SyncZoneDelegation says which scheme carried the sync:
// the rcode is NOERROR either way, and the update result is as empty after
// a NOTIFY as after an API call. The words are tdns's, not a contract; a
// test runs the real sync and fails if they change.
func notifiesSent(msg string) string {
	rest, ok := strings.CutPrefix(msg, delegationSyncNotifyMarker)
	if !ok {
		return ""
	}
	types, _, ok := strings.Cut(rest, ")")
	if !ok {
		return ""
	}
	return types
}

// mpLeaderSync: the request is for a multi-provider zone that syncs with its
// parent through its agents, which is the sync requestDelegationSync asks
// for, and the one whose failure is asked again and whose NOTIFY is checked
// at the parent.
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
	computedBefore := conf.computedDSIntentOr(msg.Zone)
	o.SetInventory(msg.Zone, snap)
	if after, err := o.DSIntent(zd.ZoneData, dns.SHA256); msg.Owned && err == nil && after.Known && !sameDSIntent(before, after) {
		conf.requestDelegationSync(ctx, msg.Zone, "the zone's DS set changed")
	}
	if !msg.Owned {
		// our signer signs the zone without owning it: this inventory is
		// our provider's share of the computed DS set (Amendment 2)
		conf.noteComputedDSSet(ctx, msg.Zone, computedBefore)
	}
}
