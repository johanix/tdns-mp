/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Parent sync (design 5.5, plan S20): the runner for a change of parentsync.
 * The option and P3's hook follow the step's ParentSync (S3), so they change
 * at the steps below, never at the thaw or at a refresh.
 *
 * From agent to owner, the leader under V, in order, each confirmed:
 *
 *  1. Waiting for an emergency rollover, every provider withdraws its CDS and
 *     CSYNC: each combiner stops applying them, each signer stops serving a
 *     CDS through its DS engine (Roles.CDSWithdrawn).
 *  2. Their TTL passes.
 *  3. The agents' SIG(0) key is deleted at the parent by an update that key
 *     signs. At a parent that takes NOTIFY only, or after a failure, the
 *     owner is told to delete it, and the step goes on.
 *  4. Every agent stops syncing (ParentSync=owner: followParentSyncParam),
 *     and each combiner stops applying the agents' KEY.
 *
 * Then "done", once the leader has nothing in flight. The owner writes to the
 * parent only after it.
 *
 * From owner to agent, one step, the transition's first: every agent turns
 * the option on, and the leader takes the zone up as at an arrival
 * (onZoneJoined): the key's set-up, then the explicit sync, which looks at the
 * parent first and sends only the difference. The step is done when the KEY
 * is published and every recipient has confirmed it, or the zone uses no key.
 * The key is offered to the parent only then; the parent's trust stays owed
 * under keyPending, not under the transition.
 *
 * The plan is made from what is in place: the sets held and the steps taken,
 * so a new leader plans the same steps from the stamps it took. What the
 * parent said is kept in memory only: a new leader, or one restarted, looks
 * again.
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func init() {
	registerStepRunner(stepRunner{name: "parent sync taken up", kind: stepTakeUp, steps: parentSyncTakeUpSteps})
	registerStepRunner(stepRunner{name: "parent sync handed over", kind: stepHandOver, steps: parentSyncHandOverSteps})
}

// The keys of the runner's steps.
const (
	parentSyncCDSKey    = "parentsync cds"
	parentSyncTTLKey    = "parentsync ttl"
	parentSyncKeyKey    = "parentsync key"
	parentSyncStopKey   = "parentsync stop"
	parentSyncTakeUpKey = "parentsync take-up"
)

// takeUpAskEvery is how often the take-up's step asks the leader's set-up
// again while no KEY is booked: the set-up may have found no key to publish,
// and a restart forgets what it published.
const takeUpAskEvery = time.Minute

// cdsTTLUnknown, in seconds, stands for the TTL of a CDS and CSYNC that the
// leader cannot read from its copy, a zone not loaded here yet. The owner writes
// to the parent after this wait, so it does not read as no TTL at all.
const cdsTTLUnknown = 3600

// servesNoCDS: a part handed r serves no CDS of its own.
func servesNoCDS(r Roles) bool {
	return r.CDSWithdrawn || r.ParentSync != core.HsyncParentSyncAgent
}

// parentSyncGoesTo: the transition gives the parent sync to `to`: the sets
// held still say otherwise, or the step named key is taken already.
func (p planView) parentSyncGoesTo(to uint8, key string) bool {
	if p.to == nil || p.to.ParentSync != to {
		return false
	}
	return p.held.ParentSync != to || slices.Contains(p.taken, key)
}

func parentSyncHandOverSteps(p planView) []plannedStep {
	if !p.parentSyncGoesTo(core.HsyncParentSyncOwner, parentSyncCDSKey) {
		return nil
	}
	ttl := time.Duration(p.held.CDSTTL) * time.Second
	return []plannedStep{
		{
			key: parentSyncCDSKey, what: "parent sync to the owner: step 1 (the CDS and CSYNC withdrawn)", keys: true,
			sets: func(held Roles) Roles {
				held.CDSWithdrawn = true
				if p.conf != nil {
					held.CDSTTL = p.conf.servedCDSTTL(p.zone)
				}
				return held
			},
		},
		{
			key: parentSyncTTLKey, what: "parent sync to the owner: step 2 (their TTL)",
			wait: func(_ *Config, _ string, since time.Time) string {
				if until := since.Add(ttl); time.Now().Before(until) {
					return "the TTL of the CDS and CSYNC, until " + until.UTC().Format(time.RFC3339)
				}
				return ""
			},
		},
		{
			key: parentSyncKeyKey, what: "parent sync to the owner: step 3 (the agents' key deleted at the parent)",
			wait: func(conf *Config, zone string, _ time.Time) string { return conf.agentsKeyWait(zone) },
		},
		{
			key: parentSyncStopKey, what: "parent sync to the owner: step 4 (every agent stops syncing)",
			sets: func(held Roles) Roles {
				held.ParentSync = core.HsyncParentSyncOwner
				return held
			},
			start: func(_ *Config, zone string) { lg.Info("parent sync handed to the owner", "zone", zone) },
			wait:  func(conf *Config, zone string, _ time.Time) string { return conf.parentWorkUnderWay(zone) },
		},
	}
}

func parentSyncTakeUpSteps(p planView) []plannedStep {
	if !p.parentSyncGoesTo(core.HsyncParentSyncAgent, parentSyncTakeUpKey) {
		return nil
	}
	return []plannedStep{{
		key: parentSyncTakeUpKey, what: "parent sync to the agents: the zone taken up",
		sets: func(held Roles) Roles {
			held.ParentSync = core.HsyncParentSyncAgent
			return held
		},
		start: func(_ *Config, zone string) { lg.Info("parent sync taken up by the agents", "zone", zone) },
		wait:  func(conf *Config, zone string, _ time.Time) string { return conf.takeUpWait(zone) },
	}}
}

// servedCDSTTL is the largest TTL of the CDS, CDNSKEY and CSYNC this agent's
// copy of the zone serves; 0 with none. A copy that cannot be read says nothing
// of them: cdsTTLUnknown.
func (conf *Config) servedCDSTTL(zone string) uint32 {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return cdsTTLUnknown
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return cdsTTLUnknown
	}
	var ttl uint32
	for _, rrtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeCSYNC} {
		if rrset, ok := apex.RRtypes.Get(rrtype); ok {
			for _, rr := range rrset.RRs {
				ttl = max(ttl, rr.Header().Ttl)
			}
		}
	}
	return ttl
}

// --- The book ---

// parentSyncBook is what this agent has carried out of a change of
// parentsync, per zone.
type parentSyncBook struct {
	mu         sync.Mutex
	zones      map[string]*parentSyncZone // by zone, folded
	goroutines sync.WaitGroup
}

type parentSyncZone struct {
	running      bool      // a try runs in the background
	keyDone      bool      // step 3: the parent's word is in, or the owner is told
	told         string    // what the owner has to do at the parent
	asked        time.Time // when the take-up last asked the leader's set-up
	noKey        bool      // the zone's parent takes no UPDATE: no KEY to wait for
	keyConfirmed bool      // every recipient has confirmed the take-up's KEY
}

func (b *parentSyncBook) zone(zone string) *parentSyncZone {
	if b.zones == nil {
		b.zones = map[string]*parentSyncZone{}
	}
	key := canonicalName(zone)
	z := b.zones[key]
	if z == nil {
		z = &parentSyncZone{}
		b.zones[key] = z
	}
	return z
}

// with runs f on the zone's entry, under the book's lock.
func (b *parentSyncBook) with(zone string, f func(z *parentSyncZone)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f(b.zone(zone))
}

// try runs f in the background, unless one runs for the zone.
func (b *parentSyncBook) try(zone string, f func()) {
	b.mu.Lock()
	z := b.zone(zone)
	if z.running {
		b.mu.Unlock()
		return
	}
	z.running = true
	b.goroutines.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.goroutines.Done()
		defer b.with(zone, func(z *parentSyncZone) { z.running = false })
		f()
	}()
}

// wait is for a test: every try has ended.
func (b *parentSyncBook) wait() { b.goroutines.Wait() }

func (b *parentSyncBook) tellOwner(zone, what string) {
	b.with(zone, func(z *parentSyncZone) { z.told = what })
}

// ownerTold is what the owner has been told to do at the parent; it stands
// until the agents take the sync up again.
func (b *parentSyncBook) ownerTold(zone string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if z := b.zones[canonicalName(zone)]; z != nil {
		return z.told
	}
	return ""
}

// transitionDone drops what the zone's transition kept here, but what the
// owner was told.
func (b *parentSyncBook) transitionDone(zone string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if z := b.zones[canonicalName(zone)]; z != nil {
		*z = parentSyncZone{running: z.running, told: z.told}
	}
}

// turnCtx is what a step's own work at the parent runs under: the turns' own.
func (conf *Config) turnCtx() context.Context {
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ctx != nil {
		return b.ctx
	}
	return context.Background()
}

// --- Step 3 ---

// agentsKeyWait is what step 3 waits for: this leader's try at the parent, in
// the background, as a wait may not block the turn. A new leader, or one
// restarted, tries again, and finds what the parent trusts now.
func (conf *Config) agentsKeyWait(zone string) string {
	b := &conf.InternalMp.parentSyncs
	done := false
	b.with(zone, func(z *parentSyncZone) { done = z.keyDone })
	if done {
		return ""
	}
	b.try(zone, func() {
		conf.deleteAgentsKey(conf.turnCtx(), ZoneName(zone))
		b.with(zone, func(z *parentSyncZone) { z.keyDone = true })
		conf.askThaw(zone)
	})
	return "the parent's word on the agents' SIG(0) key"
}

// deleteAgentsKey deletes at the parent what the agents hold that it trusts:
// the retired keys, then the zone's key, which signs them all, its own delete
// last. A roll under way ends first, as a member's keys would: what it left
// at the parent is among them. What cannot be deleted the owner is told of.
func (conf *Config) deleteAgentsKey(ctx context.Context, zone ZoneName) {
	b := &conf.InternalMp.parentSyncs
	tell := func(keyids []uint16, why error) {
		what := "the zone's owner has to delete the agents' SIG(0) key at the parent"
		if len(keyids) > 0 {
			what = fmt.Sprintf("the parent may still trust the agents' SIG(0) key %v: the zone's owner has to delete it", keyids)
		}
		b.tellOwner(string(zone), what)
		lg.Warn("the agents' SIG(0) key is not deleted at the parent: the zone's owner has to delete it", "zone", zone, "keyids", keyids, "why", why)
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		tell(nil, errors.New("no keystore for the zone"))
		return
	}
	r, err := loadRoll(kdb, zone)
	if err != nil {
		tell(nil, fmt.Errorf("the zone's roll cannot be read: %w", err))
		return
	}
	if r != nil {
		conf.endRollHere(kdb, r, "the parent sync goes to the zone's owner")
	}
	_ = conf.keySetupLocked(zone, func() error {
		zk, err := readZoneKey(kdb, zone)
		if err != nil {
			tell(nil, fmt.Errorf("the zone's keys cannot be read: %w", err))
			return nil
		}
		if zk.held == nil || zk.held.key == nil {
			switch {
			case zk.several():
				tell(keyTags(zk.published), errors.New("the zone publishes several KEYs"))
			case len(zk.published) > 0:
				tell(keyTags(zk.published), errors.New("this agent holds no key the zone publishes"))
			}
			return nil
		}
		if uses, known := conf.zoneKeyUse(ctx, zone); known && !uses {
			tell([]uint16{zk.held.keyid}, errors.New("the parent takes no UPDATE"))
			return nil
		}
		retired, err := sig0Rows(kdb, zone, tdns.Sig0StateRetired)
		if err != nil {
			tell([]uint16{zk.held.keyid}, fmt.Errorf("the zone's retired keys cannot be read: %w", err))
			return nil
		}
		retired = slices.DeleteFunc(retired, func(old sig0Row) bool {
			return old.key == nil || old.keyid == zk.held.keyid || (old.parentState != 0 && old.parentState != edns0.KeyStateTrusted)
		})
		var failed []uint16
		var why error
		for _, k := range append(retired, *zk.held) {
			state, err := conf.rollParentOf().keyState(ctx, zone, k.keyid)
			if err == nil && state != edns0.KeyStateTrusted {
				tdns.UpdateParentState(kdb, string(zone), k.keyid, state)
				continue
			}
			if err := conf.deleteKeyAtParent(ctx, zone, k.key, zk.held); err != nil {
				failed, why = append(failed, k.keyid), err
				continue
			}
			tdns.UpdateParentState(kdb, string(zone), k.keyid, edns0.KeyStateUnknown)
			lg.Info("the agents' SIG(0) key is deleted at the parent", "zone", zone, "keyid", k.keyid, "signer", zk.held.keyid)
		}
		if len(failed) > 0 {
			tell(failed, why)
		}
		return nil
	})
}

// --- The take-up ---

// parentSyncTakenUp: the zone's transition has taken the step that gives the
// parent sync to the agents. From there until "done" the leader's sync and its
// key's publication and offers are a step's own (design 6): they pass the
// freeze.
func (conf *Config) parentSyncTakenUp(zone string) bool {
	return conf.InternalMp.Instructions.tookStep(zone, parentSyncTakeUpKey)
}

// takeUpKEYUnconfirmed: the step that takes the parent sync up is taken, and
// not every recipient has confirmed its KEY: every nameserver serves the KEY
// before it is offered.
func (conf *Config) takeUpKEYUnconfirmed(zone string) bool {
	if !conf.parentSyncTakenUp(zone) {
		return false
	}
	confirmed := false
	conf.InternalMp.parentSyncs.with(zone, func(z *parentSyncZone) { confirmed = z.keyConfirmed })
	return !confirmed
}

// askTakeUp has the leader take the zone up as at an arrival, in the
// background, at most every takeUpAskEvery.
func (conf *Config) askTakeUp(zone string) {
	b := &conf.InternalMp.parentSyncs
	due := false
	b.with(zone, func(z *parentSyncZone) {
		if due = time.Since(z.asked) >= takeUpAskEvery; due {
			z.asked = time.Now()
		}
	})
	if !due {
		return
	}
	b.try(zone, func() {
		z := ZoneName(zone)
		if uses, known := conf.zoneKeyUse(conf.turnCtx(), z); known && !uses {
			b.with(zone, func(z *parentSyncZone) { z.noKey = true })
		}
		lem := conf.InternalMp.LeaderElectionManager
		if lem == nil || lem.onZoneJoined == nil {
			return
		}
		if err := lem.onZoneJoined(z); err != nil {
			lg.Warn("taking the zone up failed, the step asks again", "zone", zone, "err", err)
		}
		conf.askThaw(zone)
	})
}

// takeUpWait is what the take-up's step waits for: the KEY published and
// confirmed by every recipient, or a zone that uses no key. Once it is, the
// key is offered to the parent; the parent's trust is not waited for.
func (conf *Config) takeUpWait(zone string) string {
	const published = "the zone's KEY to be published"
	b := &conf.InternalMp.parentSyncs
	z := ZoneName(zone)
	noKey := false
	b.with(zone, func(z *parentSyncZone) { noKey = z.noKey })
	if noKey {
		return ""
	}
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return published
	}
	st, booked := tm.rollKEYs.state(z)
	if !booked {
		conf.askTakeUp(zone)
		return published
	}
	awaited, err := conf.rollKEYAwaited(z, st)
	if err != nil {
		tm.rollKEYs.forget(z)
		lg.Warn("the zone's KEY was not taken, the step publishes it again", "zone", zone, "err", err)
		b.with(zone, func(z *parentSyncZone) { z.asked = time.Time{} })
		conf.askTakeUp(zone)
		return published
	}
	if len(awaited) > 0 {
		return "the zone's KEY confirmed by " + strings.Join(awaited, ", ")
	}
	if !conf.offerTakenUpKey(zone) {
		return "the zone's key to be offered"
	}
	return ""
}

// offerTakenUpKey offers the zone's key to the parent, once: every recipient
// has confirmed its KEY. It reports whether the key has been offered; a key
// that cannot be read now is not, and the step asks again. The mark comes
// before the poll, which asks for it (takeUpKEYUnconfirmed).
func (conf *Config) offerTakenUpKey(zone string) bool {
	if !conf.takeUpKEYUnconfirmed(zone) {
		return true
	}
	z := ZoneName(zone)
	kdb := conf.zoneKeyDB(z)
	if kdb == nil {
		return false
	}
	zk, err := readZoneKey(kdb, z)
	if err != nil || zk.held == nil || zk.held.key == nil {
		return false
	}
	conf.InternalMp.parentSyncs.with(zone, func(z *parentSyncZone) { z.keyConfirmed = true })
	conf.launchKeyPoll(conf.turnCtx(), nil, z, zone, zk.held.keyid, zk.held.key.Algorithm)
	return true
}
