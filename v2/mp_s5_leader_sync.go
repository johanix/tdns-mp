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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
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
// loops. ctx is the asking engine's: a retry ends with it, and asks for
// nothing after it has ended. Reports whether a request was queued now.
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
	conf.delegationSyncAfter(ctx, policy.delay, func() { conf.requestDelegationSyncAttempt(ctx, zone, why, attempt+1, policy) })
	return false
}

// delegationSyncAfter runs f once d has passed, for the engine whose ctx is
// given: a retry of a full queue, a chain's ask, the end of a hold and the
// word that a hold still waits are scheduled this way. When the ctx ends
// first, f does not run and nothing is left waiting. What is scheduled is
// counted until it has returned (delegationSyncChains.timers), so that the
// end of an engine can be waited for (waitDelegationSyncTimers).
func (conf *Config) delegationSyncAfter(ctx context.Context, d time.Duration, f func()) {
	var stopped <-chan struct{}
	if ctx != nil {
		if ctx.Err() != nil {
			return
		}
		stopped = ctx.Done()
	}
	conf.InternalMp.delegationSyncChains.timers.Go(func() {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-stopped:
			return
		}
		if ctx != nil && ctx.Err() != nil {
			return // both were ready, and the select took the timer
		}
		f()
	})
}

// waitDelegationSyncTimers returns once nothing that delegationSyncAfter
// scheduled is waiting or running. Once the engines' ctx has ended, that is
// at once, or when what is running has returned: a test's rig waits for it
// before it puts back the settings and the logger the test replaced.
func (conf *Config) waitDelegationSyncTimers() {
	conf.InternalMp.delegationSyncChains.timers.Wait()
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

// Before the NOTIFY leaves at all, the leader waits as well. The check
// repairs a NOTIFY that was early; the wait makes it early less often, so
// that the parent is not asked to scan for nothing. A NOTIFY that anything
// but the chain's own check causes (a change of the DS set, a refresh that
// found a delegation change, an election, an operator's request) is held
// for the zone's wait: the largest propagation delay among the providers
// that serve the zone, each of which announces its own in gossip
// (delegationNotifyWait). The data may have changed just now, and the
// nameservers need that long from now. The chain's own check sends at
// once: the change is old by then. Only the NOTIFY is held. The sync has
// run, an UPDATE is not delayed, and the syncher does not wait.
//
// A NOTIFY(CSYNC) waits for one thing more, and first: the zone's CSYNC,
// which the leader makes and sends to every provider, must have every
// provider's final confirmation (mp_s5_leader_csync.go). The zone's wait is
// counted from the last of them.

// delegationSyncChains is what the leader keeps of each zone's sync between
// two asks: one chain per zone, whether the last sync failed or went out as
// a NOTIFY, and so at most one thing scheduled per zone: an ask, or the end
// of a hold.
type delegationSyncChains struct {
	mu    sync.Mutex
	zones map[string]*delegationSyncChain
	asks  int // the number last given to something scheduled, for any zone
	// csyncs is the CSYNC this agent made for each zone it leads, kept apart
	// from the chains: a chain ends and starts over, and the CSYNC of a
	// difference is made once
	csyncs map[string]*delegationCsync
	// timers counts what is scheduled for later, for every zone, until it
	// has returned (delegationSyncAfter)
	timers sync.WaitGroup
	// runs holds a cancel for each leader sync under way, per zone, until it
	// has returned (delegationSyncRun)
	runs  map[string]map[uint64]context.CancelFunc
	runID uint64
}

type delegationSyncChain struct {
	failures int                   // syncs that failed, in a row
	rechecks int                   // checks of the parent scheduled after a NOTIFY, in this chain
	notified string                // the last NOTIFY that left and that no analysis has seen at the parent ("CSYNC", "CDS", "CSYNC, CDS")
	waiting  bool                  // an ask, or the end of a hold, is scheduled and has not fired
	ask      int                   // the number of what is scheduled: a timer that fires with another number was replaced
	hold     *delegationNotifyHold // the NOTIFYs that are held back, while a hold runs
}

// delegationNotifyHold is a zone's NOTIFYs on their way to the parent, held
// back until the zone's nameservers have had time to serve the change.
type delegationNotifyHold struct {
	notifies []tdns.NotifyRequest // one per NOTIFY type
	diff     string               // the difference between the zone and the parent that they are for
	retimed  bool                 // a check waited when the hold began: the check after the hold is that one
	// awaiting: the hold has no end yet. It waits for the providers' final
	// confirmations of the zone's CSYNC (csync is that record), and the
	// zone's wait starts when the last one is in. out and delays are what
	// the release needs then.
	awaiting bool
	csync    string
	out      chan tdns.NotifyRequest
	delays   []time.Duration
}

// delegationNotifies is what one sync handed over for the notifier, and what
// it takes to let it go.
type delegationNotifies struct {
	requests []tdns.NotifyRequest
	diff     string                  // what the sync was to bring to the parent (delegationDifference)
	out      chan tdns.NotifyRequest // the notifier's queue
	wait     time.Duration           // the zone's wait (delegationNotifyWait)
	largest  string                  // the provider whose propagation delay the wait is
}

// delegationCheck is the look at the parent that follows a NOTIFY, or the
// bound in its place.
type delegationCheck struct {
	ask   int
	n     int // which check of the chain, or how many there were at the bound
	delay time.Duration
	bound bool
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

// schedule marks the chain as waiting for something new and gives that its
// number. The numbers are not a chain's own: a timer left behind by a chain
// that has ended must not match the chain that follows it. The caller holds
// mu.
func (c *delegationSyncChains) schedule(ch *delegationSyncChain) int {
	c.asks++
	ch.waiting, ch.ask = true, c.asks
	return ch.ask
}

// delegationSyncAskAfter schedules the zone's one waiting ask: the explicit
// sync, after the delay. The caller has marked the chain as waiting and
// given the ask its number, under the lock.
func (conf *Config) delegationSyncAskAfter(ctx context.Context, zone string, ask int, delay time.Duration, why string) {
	c := &conf.InternalMp.delegationSyncChains
	conf.delegationSyncAfter(ctx, delay, func() {
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
	ch.failures = n + 1
	ask := c.schedule(ch)
	c.mu.Unlock()
	delay := delays[n]
	lgEngine.Warn("the delegation sync failed; asking again", "zone", zone, "failure", n+1, "in", delay, "cause", cause)
	conf.delegationSyncAskAfter(ctx, zone, ask, delay, "the last delegation sync failed")
}

// delegationSyncNotified takes over the NOTIFYs that a sync of a zone this
// agent leads handed over for the notifier (syncDelegation). They go on to
// the notifier at once, or after the zone's wait, and the look at the parent
// that decides whether the sync is done is scheduled from when they leave.
// The caller does not book the sync as done and does not tell the peers.
// Reported is whether they are held, or that the sync has failed after all:
// a provider has rejected the zone's CSYNC, and a NOTIFY(CSYNC) for a record
// that not every provider serves is not sent. delays is read once per call,
// as for a failure.
func (conf *Config) delegationSyncNotified(ctx context.Context, zone string, sent delegationNotifies) (held bool, failed error) {
	sent.wait, sent.largest = conf.delegationNotifyWait(zone)
	return conf.delegationSyncNotifiedWith(ctx, zone, sent, delegationSyncNotifyDelays)
}

func (conf *Config) delegationSyncNotifiedWith(ctx context.Context, zone string, sent delegationNotifies, delays []time.Duration) (held bool, failed error) {
	c := &conf.InternalMp.delegationSyncChains
	every := delegationCsyncAwaitedEvery
	c.mu.Lock()
	ch := c.of(zone)
	// The sync was the chain's own if a NOTIFY of the chain's is out and
	// nothing of the chain's is scheduled: its check, or the retry of a
	// check that failed, has fired, and this is the sync it asked for. Any
	// other sync was asked for by something else.
	own := !ch.waiting && ch.notified != ""
	leave, retimed := sent.requests, ch.waiting && ch.rechecks > 0
	if ch.hold != nil {
		// NOTIFYs are held already. These join them, one per type, the newer
		// in the place of the older.
		leave, retimed = mergeNotifies(ch.hold.notifies, sent.requests), ch.hold.retimed
	}
	types := notifyTypes(leave)
	// A NOTIFY(CSYNC) is for the CSYNC this leader made and sent to the
	// zone's providers. It does not leave before each of them has given its
	// final confirmation, and not at all if one has rejected the record.
	if cur := c.csyncs[zone]; cur != nil && !own && slices.ContainsFunc(leave, func(req tdns.NotifyRequest) bool { return req.RRtype == dns.TypeCSYNC }) {
		if cur.failed != nil {
			// rejected before the sync handed its NOTIFY over: the next
			// ask makes and distributes a new one
			cause := cur.failed
			delete(c.csyncs, zone)
			if ch.hold != nil {
				ch.hold, ch.waiting = nil, false
			}
			c.mu.Unlock()
			return false, cause
		}
		if !cur.confirmed {
			// A hold with no end yet. Nothing is timed here: the zone's
			// wait is counted from the last confirmation
			// (delegationCsyncProgress). The count of failures stays, so
			// that a CSYNC that is rejected again and again is asked for at
			// growing intervals.
			same := ch.hold != nil && ch.hold.awaiting && ch.hold.csync == cur.record
			ch.hold = &delegationNotifyHold{notifies: leave, diff: sent.diff, retimed: retimed,
				awaiting: true, csync: cur.record, out: sent.out, delays: delays}
			if same {
				c.mu.Unlock()
				return true, nil
			}
			ask := c.schedule(ch)
			awaited := slices.Clone(cur.awaited)
			c.mu.Unlock()
			lgEngine.Info("a NOTIFY to the parent waits for the providers' confirmations of the zone's CSYNC", "zone", zone, "notify", types, "serial", cur.serial, "awaited", awaited)
			conf.delegationCsyncAwaitedAfter(ctx, zone, ask, every)
			return true, nil
		}
	}
	ch.failures = 0
	if !own && sent.wait > 0 {
		// The wait runs from the change. A sync that found the same
		// difference as the one the hold is for brings no change (an
		// election, an operator's request), and the hold ends when it was
		// going to: a wait that every such sync started anew would never
		// end where they come more often than the wait is long.
		restart := ch.hold == nil || ch.hold.diff != sent.diff
		ch.hold = &delegationNotifyHold{notifies: leave, diff: sent.diff, retimed: retimed}
		if !restart {
			c.mu.Unlock()
			return true, nil
		}
		ask := c.schedule(ch)
		c.mu.Unlock()
		lgEngine.Info("a NOTIFY to the parent is held until the zone's nameservers have had time to serve the change", "zone", zone, "notify", types, "wait", sent.wait, "largest", sent.largest)
		conf.delegationSyncReleaseAfter(ctx, zone, ask, sent, delays)
		return true, nil
	}
	ch.hold = nil
	check := c.notifyLeft(zone, ch, types, retimed, delays)
	c.mu.Unlock()
	forwardNotifies(ctx, sent.out, leave)
	conf.delegationSyncCheckAfter(ctx, zone, types, check)
	return false, nil
}

// notifyLeft books a NOTIFY as on its way to the parent and decides on the
// check that follows it. The caller holds mu.
func (c *delegationSyncChains) notifyLeft(zone string, ch *delegationSyncChain, types string, retimed bool, delays []time.Duration) delegationCheck {
	ch.notified = types
	n := ch.rechecks
	// A NOTIFY while a check waited did not come from the chain: its own ask
	// had not fired. A new change, or an election, asked in between. The
	// check that waited was timed for an earlier NOTIFY, so it is replaced by
	// the same check timed for this one, by the first delay: the parent is
	// then looked at neither seconds after a NOTIFY nor half an hour after a
	// change. The count of checks stays as it is. Only the chain's own asks
	// move it towards the bound, so a trigger that comes again and again (an
	// election, at every renewal of the lease) does not keep the chain from
	// ending.
	retimed = retimed && n > 0 && len(delays) > 0
	if !retimed && n >= len(delays) {
		delete(c.zones, zone)
		return delegationCheck{n: n, bound: true}
	}
	delay := delays[0]
	if !retimed {
		delay = delays[n]
		ch.rechecks = n + 1
	}
	return delegationCheck{ask: c.schedule(ch), n: ch.rechecks, delay: delay}
}

// delegationSyncCheckAfter says and schedules what notifyLeft decided.
func (conf *Config) delegationSyncCheckAfter(ctx context.Context, zone string, types string, check delegationCheck) {
	if check.bound {
		lgEngine.Warn("the parent still differs from the zone after the last check, and a last NOTIFY has been sent; given up until the delegation's data changes or an election is held", "zone", zone, "notify", types, "checks", check.n)
		return
	}
	lgEngine.Info("the delegation sync went to the parent as a NOTIFY; checking the parent again", "zone", zone, "notify", types, "check", check.n, "in", check.delay)
	conf.delegationSyncAskAfter(ctx, zone, check.ask, check.delay, "a NOTIFY was sent to the parent, which is checked again")
}

// delegationSyncReleaseAfter schedules the end of a zone's hold: what is
// held then goes on to the notifier, if this agent still leads the zone and
// the engine still runs, and the first check is timed from there. The
// caller has given the hold its number, under the lock.
func (conf *Config) delegationSyncReleaseAfter(ctx context.Context, zone string, ask int, sent delegationNotifies, delays []time.Duration) {
	c := &conf.InternalMp.delegationSyncChains
	conf.delegationSyncAfter(ctx, sent.wait, func() {
		stopped := ctx != nil && ctx.Err() != nil
		leads := conf.leadsZone(zone)
		c.mu.Lock()
		ch := c.zones[zone]
		if ch == nil || ch.ask != ask || ch.hold == nil || ch.hold.awaiting {
			c.mu.Unlock()
			return
		}
		if stopped || !leads {
			c.mu.Unlock()
			conf.delegationSyncNotLeading(zone, stopped)
			return
		}
		hold := ch.hold
		ch.hold, ch.waiting = nil, false
		types := notifyTypes(hold.notifies)
		check := c.notifyLeft(zone, ch, types, hold.retimed, delays)
		c.mu.Unlock()
		forwardNotifies(ctx, sent.out, hold.notifies)
		lgEngine.Info("the held NOTIFY has left for the parent", "zone", zone, "notify", types, "held", sent.wait)
		conf.delegationSyncCheckAfter(ctx, zone, types, check)
	})
}

// delegationSyncNotLeading ends the zone's chain on an agent that does not
// lead the zone any more: whoever leads now has its own. A NOTIFY that is
// still held is dropped, and said to be unless the engine is stopping. What
// is remembered of the CSYNC this agent made goes too: the next leader makes
// its own.
func (conf *Config) delegationSyncNotLeading(zone string, quiet bool) {
	if hold := conf.endDelegationSyncChain(zone); hold != nil && !quiet {
		lgEngine.Info("the held NOTIFY is dropped: this agent no longer leads the zone", "zone", zone, "notify", notifyTypes(hold.notifies))
	}
}

// delegationSyncOwnerSyncs ends the zone's chain when the zone's owner has
// taken its delegation sync over (followParentSyncParam): no agent sends
// anything to the parent now. A NOTIFY that is still held is dropped. An
// ask, a check or the end of a hold that is still scheduled finds no chain
// when it fires, and does nothing. What is remembered of the CSYNC this
// agent made goes too: the agent that leads when the sync comes back to the
// agents makes its own. A sync under way is stopped: an UPDATE that tdns is
// still retrying is not sent again.
func (conf *Config) delegationSyncOwnerSyncs(zone string) {
	if hold := conf.endDelegationSyncChain(zone); hold != nil {
		lgEngine.Info("the held NOTIFY is dropped: the zone's owner syncs its delegation", "zone", zone, "notify", notifyTypes(hold.notifies))
	}
	if n := conf.stopDelegationSyncRuns(zone); n > 0 {
		lgEngine.Info("the delegation sync under way is stopped: the zone's owner syncs its delegation", "zone", zone, "syncs", n)
	}
}

// delegationSyncRun gives a leader sync of the zone a context of its own,
// which delegationSyncOwnerSyncs cancels when the zone's owner takes the sync
// over. A sync can sit in tdns's UPDATE retry loop for a minute or more after
// a REFUSED, and the loop asks only its context whether to go on. done ends
// the run.
func (conf *Config) delegationSyncRun(ctx context.Context, zone string) (runCtx context.Context, done func()) {
	c := &conf.InternalMp.delegationSyncChains
	runCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	if c.runs == nil {
		c.runs = map[string]map[uint64]context.CancelFunc{}
	}
	if c.runs[zone] == nil {
		c.runs[zone] = map[uint64]context.CancelFunc{}
	}
	c.runID++
	id := c.runID
	c.runs[zone][id] = cancel
	c.mu.Unlock()
	return runCtx, func() {
		c.mu.Lock()
		delete(c.runs[zone], id)
		if len(c.runs[zone]) == 0 {
			delete(c.runs, zone)
		}
		c.mu.Unlock()
		cancel()
	}
}

// stopDelegationSyncRuns cancels the zone's leader syncs under way, and says
// how many there were. Each leaves the list when it has returned.
func (conf *Config) stopDelegationSyncRuns(zone string) int {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cancel := range c.runs[zone] {
		cancel()
	}
	return len(c.runs[zone])
}

// delegationSyncGivenBack runs the leader's setup when the zone's HSYNCPARAM
// gives the delegation sync back to the agents (followParentSyncParam) and
// this agent leads the zone. While the owner synced it, an election or a lease
// renewal skipped the setup (onLeaderElected), so a leader elected then has no
// SIG(0) key for the zone, and nothing would ask for a sync until the next
// renewal. The setup is what an election runs: the key, then a sync. An agent
// that does not lead runs nothing; the leader's own refresh runs it. At a
// zone's first load there is no leader yet, and the election runs it.
func (conf *Config) delegationSyncGivenBack(zone string) {
	lem := conf.InternalMp.LeaderElectionManager
	if lem == nil || lem.onLeaderElected == nil || !lem.IsLeader(ZoneName(zone)) {
		return
	}
	lgEngine.Info("the zone's delegation sync is the agents' again, and this agent leads it: running the leader's setup", "zone", zone)
	go func() {
		if err := lem.onLeaderElected(ZoneName(zone)); err != nil {
			lgEngine.Error("the leader's setup failed after the delegation sync came back to the agents", "zone", zone, "err", err)
		}
	}()
}

// endDelegationSyncChain forgets the zone's chain and its CSYNC, and returns
// the hold the chain had, if any.
func (conf *Config) endDelegationSyncChain(zone string) *delegationNotifyHold {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[zone]
	delete(c.zones, zone)
	delete(c.csyncs, zone)
	c.mu.Unlock()
	if ch == nil {
		return nil
	}
	return ch.hold
}

// ownerSyncsDelegation: the zone is a multi-provider zone whose owner syncs
// its delegation with the parent, not its agents: its HSYNCPARAM does not
// say parentsync=agent (followParentSyncParam).
func ownerSyncsDelegation(zd *tdns.ZoneData) bool {
	return zd != nil && zd.Options[tdns.OptMultiProvider] && !zd.Options[tdns.OptParentSync]
}

// leadsZone: this agent leads the zone's delegation sync. With no election
// manager there is nobody else to.
func (conf *Config) leadsZone(zone string) bool {
	lem := conf.InternalMp.LeaderElectionManager
	return lem == nil || lem.IsLeader(ZoneName(zone))
}

// delegationSyncSucceeded ends a zone's chain: the next failure, or the next
// NOTIFY, starts from the first delay again. An ask that still waits is left
// to fire; it finds a chain with nothing in it. A NOTIFY that is still held
// is dropped: the parent has the delegation without it. Returned are the
// NOTIFY the chain had sent and the number of checks it had asked for, for
// the caller that ends the chain because the parent was found in sync.
func (conf *Config) delegationSyncSucceeded(zone string) (notified string, rechecks int) {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[zone]
	if ch == nil {
		c.mu.Unlock()
		return "", 0
	}
	notified, rechecks = ch.notified, ch.rechecks
	hold := ch.hold
	if hold != nil {
		// what is scheduled is the end of this hold, and finds no chain
		ch.hold, ch.waiting = nil, false
	}
	if ch.waiting {
		ch.failures, ch.rechecks, ch.notified = 0, 0, ""
	} else {
		delete(c.zones, zone)
	}
	c.mu.Unlock()
	if hold != nil {
		lgEngine.Info("the held NOTIFY is dropped: the parent does not need it any more", "zone", zone, "notify", notifyTypes(hold.notifies))
	}
	return notified, rechecks
}

// delegationSyncInSync is for an analysis that found the parent in sync with
// the zone. It ends the zone's chain. If the chain had sent a NOTIFY, this
// is when that sync is done, so the peers are told now, once; a sync that
// never sent anything tells them nothing, as before.
func (conf *Config) delegationSyncInSync(zone string) {
	// The difference the zone's CSYNC was made for is gone. The same
	// difference at a later time is a new change, and gets a new CSYNC.
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	delete(c.csyncs, zone)
	c.mu.Unlock()
	sent, checks := conf.delegationSyncSucceeded(zone)
	if sent == "" {
		return
	}
	lgEngine.Info("the parent is in sync with the zone after the NOTIFY", "zone", zone, "notify", sent, "checks", checks)
	go notifyPeersParentSyncDone(conf, zone, dns.RcodeToString[dns.RcodeSuccess],
		fmt.Sprintf("the parent is in sync with zone %s after NOTIFY(%s)", zone, sent))
}

// delegationNotifyWait is how long a NOTIFY to the zone's parent is held:
// the largest propagation delay among this agent's own and those of the
// providers that serve the zone (HSYNCPARAM servers=), each of which
// announces its own in the gossip of its beats. A serving provider that
// announces none, or has not been heard yet, neither lowers nor raises the
// wait. A provider that only signs, an auditor and a member with no role
// have no nameservers to wait for. Also returned is the provider whose
// value the wait is.
//
// The wait has a ceiling (delegationNotifyWaitMax): one provider that
// announces a very large value would otherwise hold every leader's NOTIFY
// that long. A NOTIFY that leaves before the slowest provider serves the
// change costs one NOTIFY: the checks that follow send it again.
func (conf *Config) delegationNotifyWait(zone string) (wait time.Duration, largest string) {
	wait, largest = conf.delegationNotifyWaitAnnounced(zone)
	if ceiling := delegationNotifyWaitMax(); wait > ceiling {
		// with the ceiling at zero the operator has switched the hold off:
		// nothing to tell
		if _, told := notifyWaitCeilingTold.LoadOrStore(fmt.Sprintf("%s %s %s", largest, wait, ceiling), ceiling > 0); !told && ceiling > 0 {
			lgEngine.Warn("a provider's propagation delay is above the ceiling of the wait before a NOTIFY; the NOTIFY is held for the ceiling",
				"provider", largest, "announced", wait, "ceiling", ceiling, "setting", notifyWaitMaxKey)
		}
		wait = ceiling
	}
	return wait, largest
}

// notifyWaitMaxKey is the agent's setting for the ceiling of the wait before
// a NOTIFY, and defaultNotifyWaitMax what it is when unset.
const (
	notifyWaitMaxKey     = "delegationsync.notify-wait-max"
	defaultNotifyWaitMax = 10 * time.Minute
)

// notifyWaitCeilingTold: the provider, value and ceiling already warned of,
// so that the warning comes once and not at every NOTIFY.
var notifyWaitCeilingTold sync.Map

// delegationNotifyWaitMax is the longest a NOTIFY is held, whatever the
// providers announce. Zero is a setting: no NOTIFY is held. A value that is
// negative, or positive and below a second (a number written without a unit
// is read as nanoseconds), is refused and the default is used.
func delegationNotifyWaitMax() time.Duration {
	if !viper.IsSet(notifyWaitMaxKey) {
		return defaultNotifyWaitMax
	}
	d := viper.GetDuration(notifyWaitMaxKey)
	if d == 0 {
		return 0
	}
	if d < time.Second {
		if _, told := notifyWaitCeilingTold.LoadOrStore(fmt.Sprintf("refused %s", d), true); !told {
			lgEngine.Error("the ceiling of the wait before a NOTIFY is not a usable duration (write a unit, as in 10m); the default is used",
				"setting", notifyWaitMaxKey, "read_as", d, "default", defaultNotifyWaitMax)
		}
		return defaultNotifyWaitMax
	}
	return d
}

// delegationNotifyWaitAnnounced is the wait as the providers' announcements
// give it, before the ceiling.
func (conf *Config) delegationNotifyWaitAnnounced(zone string) (wait time.Duration, largest string) {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.GossipStateTable == nil {
		return 0, ""
	}
	gst := ar.GossipStateTable
	us := dns.Fqdn(gst.LocalID)
	wait, largest = gst.PropagationDelay(), us
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return wait, largest
	}
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return wait, largest
	}
	byLabel := mpzd.hsync3IdentitiesByLabel()
	var unknown []string
	for _, label := range hp.GetServers() {
		id := byLabel[normalizeHSYNC3Label(label)]
		if id == "" || id == us {
			continue
		}
		d, known := gst.AnnouncedPropagationDelay(id)
		if !known {
			unknown = append(unknown, id)
			continue
		}
		if d > wait {
			wait, largest = d, id
		}
	}
	if len(unknown) > 0 {
		lgEngine.Debug("the propagation delay of some of the zone's serving providers is not known; the wait before a NOTIFY is that of the others", "zone", zone, "unknown", unknown, "wait", wait)
	}
	return wait, largest
}

// delegationDifference names what a sync was to bring to the parent: the
// records to add and those to remove. Two syncs with the same difference
// found the zone and the parent as they were.
func delegationDifference(dss tdns.DelegationSyncStatus) string {
	return differenceOf(dss.NsAdds, dss.NsRemoves, dss.AAdds, dss.ARemoves, dss.AAAAAdds, dss.AAAARemoves, dss.DSAdds, dss.DSRemoves)
}

// delegationNSDifference is the part of the difference that a CSYNC tells
// the parent about: the NS set and the glue, not the DS set. Empty when they
// do not differ.
func delegationNSDifference(dss tdns.DelegationSyncStatus) string {
	return differenceOf(dss.NsAdds, dss.NsRemoves, dss.AAdds, dss.ARemoves, dss.AAAAAdds, dss.AAAARemoves)
}

// differenceOf names a difference by its records: sets to add and sets to
// remove, in turn.
func differenceOf(sets ...[]dns.RR) string {
	var parts []string
	for i, rrs := range sets {
		op := "+"
		if i%2 == 1 {
			op = "-"
		}
		for _, rr := range rrs {
			parts = append(parts, op+rr.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// notifyTypes names NOTIFYs as the log does: "CSYNC", "CDS", "CSYNC, CDS".
func notifyTypes(notifies []tdns.NotifyRequest) string {
	types := make([]string, len(notifies))
	for i, req := range notifies {
		types[i] = dns.TypeToString[req.RRtype]
	}
	return strings.Join(types, ", ")
}

// mergeNotifies keeps one NOTIFY per type, a newer one in the place of the
// older.
func mergeNotifies(held, newer []tdns.NotifyRequest) []tdns.NotifyRequest {
	out := slices.Clone(held)
	for _, req := range newer {
		if i := slices.IndexFunc(out, func(h tdns.NotifyRequest) bool { return h.RRtype == req.RRtype }); i >= 0 {
			out[i] = req
		} else {
			out = append(out, req)
		}
	}
	return out
}

// forwardNotifies hands NOTIFYs to the notifier as tdns's own sync does: it
// waits for room, and gives up when the engine stops.
func forwardNotifies(ctx context.Context, out chan tdns.NotifyRequest, notifies []tdns.NotifyRequest) {
	if out == nil {
		return
	}
	var stopped <-chan struct{}
	if ctx != nil {
		stopped = ctx.Done()
	}
	for _, req := range notifies {
		select {
		case out <- req:
		case <-stopped:
			return
		}
	}
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
