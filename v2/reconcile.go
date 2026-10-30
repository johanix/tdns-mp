/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The reconciliation (design 3.3, plan S12). From the thaw until "done" the
 * leader of the zone's group under the active serial V carries out what V
 * calls for, one step at a time. The parts keep the sets they hold until the
 * leader's first step: step 0, the sets held at the thaw. The leader plans
 * the steps from what is in place: additions first, then role changes, then
 * removals (design 5), each from the runner of its kind (S16 to S21 register
 * them), and last, that every voting member's combiner and signer hold V.
 * Until a runner exists a transition has only its last step: the judge
 * refuses every kind of change that has none (S4).
 *
 * A step travels in the leader's stamp, with its sets per purpose and their
 * digest, and the removals under way. Every agent keeps it on disk, hands
 * its parts the step's sets, and tells in its own stamp once both its parts
 * hold it. The leader goes on once every voting member under V tells, first
 * hand, that it holds the step; a member with no role, on its way in or out,
 * is waited for up to multi-provider.transitions.no-role-timeout, and a
 * leaving member that has not confirmed a step for leaving-timeout is
 * excused. When the last step is held the leader says "done", first hand,
 * and every agent ends the transition on its word.
 */
package tdnsmp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// InstrStep is a step of the reconciliation as an agent holds it; its wire
// form is package hsync's.
type InstrStep = hsync.InstrStep

// InstrRemoval is a removal under way as a stamp tells it.
type InstrRemoval = hsync.InstrRemoval

// --- The kinds of change and their runners (design 5) ---

// stepKind orders the steps of a transition that changes several things
// (design 5): additions first, then role changes, then removals.
type stepKind int

const (
	stepAddition stepKind = iota
	stepRoleChange
	stepRemoval
)

// stepRunner is the steps of one kind of change: what a transition needs of
// it, planned from what is in place. S16 to S21 register theirs at init
// (registerStepRunner).
type stepRunner struct {
	name  string
	kind  stepKind
	steps func(p planView) []plannedStep
	// holds is whether this agent's own part of the step it holds is done,
	// beyond its parts holding the step's sets: S18a's newcomer, whose
	// servers serve the zone from its upstream. It is asked at every
	// agent, of every step; nil for nothing more.
	holds func(conf *Config, zone string, step InstrStep) bool
	// status is what the step held waits for, as this agent's status shows
	// it (S18a: a newcomer's nameservers); "" for nothing. Nil for none.
	status func(conf *Config, zone string, step heldStep, now time.Time) string
}

// stepRunners are the runners registered, in the order they were.
var stepRunners []stepRunner

// registerStepRunner adds a kind of change's runner. Called at init only.
func registerStepRunner(r stepRunner) {
	stepRunners = append(stepRunners, r)
}

// planView is what a runner plans from: the two readings (from is nil where
// this agent does not hold it), the sets the parts hold at the current
// step, the removals under way, the leaving members excused (by identity,
// folded), and the keys of the steps taken.
type planView struct {
	zone     string
	from, to *Instructions
	held     Roles
	removals []Removal
	excused  map[string]bool
	taken    []string
}

// plannedStep is one step of a runner's.
type plannedStep struct {
	// key names the step across plans and leaders: each is taken once.
	key  string
	what string // what it does, for the status and the log
	kind stepKind
	// provider is the provider the step concerns, by identity.
	provider string
	// keys: a DS or DNSKEY step, which waits for an emergency rollover
	// (design 3.3).
	keys bool
	// leaverNS: a leaving provider's NS step, which comes before any
	// addition's DNSKEY step once its provider is excused (design 5).
	leaverNS bool
	// sets are the sets once the step is taken, from those held before it;
	// removals the removals under way. Nil keeps them.
	sets     func(held Roles) Roles
	removals func(held []Removal) []Removal
	// start is the leader's own action when it takes the step (a
	// withdrawal, a sync: S16, S17b); wait what else the step waits for
	// before it is held, since it was taken ("" for nothing). Nil for none.
	start func(conf *Config, zone string)
	wait  func(conf *Config, zone string, since time.Time) string
}

// lastStepKey is the key of every transition's last step.
const lastStepKey = "last"

// planSteps is the transition's steps in order, the steps taken among them:
// each registered runner's, by kind; a leaving provider's NS step moved
// before the first addition's DNSKEY or DS step once its provider is
// excused (design 5); and last, that every voting member's combiner and
// signer hold V.
func planSteps(p planView) []plannedStep {
	var steps []plannedStep
	for _, kind := range []stepKind{stepAddition, stepRoleChange, stepRemoval} {
		for _, r := range stepRunners {
			if r.kind != kind {
				continue
			}
			for _, st := range r.steps(p) {
				st.kind = kind
				steps = append(steps, st)
			}
		}
	}
	steps = excusedNSFirst(steps, p.excused, p.taken)
	to := p.to
	return append(steps, plannedStep{
		key:  lastStepKey,
		what: fmt.Sprintf("every voting member's combiner and signer hold %d", to.Serial),
		sets: func(Roles) Roles { return rolesFor(to, to, 0) },
	})
}

// excusedNSFirst moves the NS step of each excused leaving provider before
// the first addition's DNSKEY or DS step not taken: a new signer's DNSKEY
// must not wait for a member that cannot confirm (design 5).
func excusedNSFirst(steps []plannedStep, excused map[string]bool, taken []string) []plannedStep {
	first := slices.IndexFunc(steps, func(st plannedStep) bool {
		return st.kind == stepAddition && st.keys && !slices.Contains(taken, st.key)
	})
	if first < 0 {
		return steps
	}
	for i := first + 1; i < len(steps); i++ {
		st := steps[i]
		if !st.leaverNS || !excused[canonicalName(st.provider)] {
			continue
		}
		steps = slices.Insert(slices.Delete(steps, i, i+1), first, st)
		first++
	}
	return steps
}

// --- The step in the store ---

// heldStep is the step a zone's store holds, as its stamp tells it.
type heldStep struct {
	InstrStep
	sets Roles
	at   time.Time
}

// stepDigest is the digest of a step's sets: the first 8 octets of SHA-256
// over their JSON, as 16 hex digits. Every agent of a zone runs the same
// build (no mixed versions), so the same sets give the same JSON.
func stepDigest(sets Roles) (json.RawMessage, string, error) {
	raw, err := json.Marshal(sets)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])[:16], nil
}

// stepHeldLocked is z's step, false when it holds no step's sets. Called
// with the store's lock held.
func (z *zoneSerials) stepHeldLocked() (heldStep, bool) {
	if z.Sets == nil {
		return heldStep{}, false
	}
	var sets Roles
	if err := json.Unmarshal(z.Sets, &sets); err != nil {
		return heldStep{}, false
	}
	_, digest, err := stepDigest(sets)
	if err != nil {
		return heldStep{}, false
	}
	return heldStep{
		InstrStep: InstrStep{Number: z.Step, Of: z.StepOf, What: z.StepWhat, Sets: slices.Clone(z.Sets), Digest: digest, Taken: slices.Clone(z.Taken)},
		sets:      sets,
		at:        z.StepAt,
	}, true
}

// stepSets are the sets the parts hold at the zone's step, while this agent
// holds one; false at rest, or while it holds no step's sets.
func (s *InstructionStore) stepSets(zone string) (Roles, bool) {
	if s == nil {
		return Roles{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	if z == nil || !z.Enforced || z.Active == nil {
		return Roles{}, false
	}
	st, ok := z.stepHeldLocked()
	return st.sets, ok
}

// pending: a transition to the zone's active serial may be under way here
// and this agent holds no step's sets (zoneSerials.Pending): it hands its
// parts nothing new until it has the leader's step (design 3.3).
func (s *InstructionStore) pending(zone string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	return z != nil && z.Enforced && z.Pending
}

var errStepNotActive = errors.New("the step is not for the active serial")

// setStep keeps st as the zone's step, with the removals under way it
// names: the leader's own when it takes a step, a member's from the
// leader's stamp. It is refused when the zone's active serial is not
// active, or when the step's sets do not give its digest. A step kept
// already changes nothing.
func (s *InstructionStore) setStep(zone string, active SerialDigest, st InstrStep, removals []Removal) error {
	var sets Roles
	if err := json.Unmarshal(st.Sets, &sets); err != nil {
		return fmt.Errorf("zone %s: step %d's sets do not decode: %w", zone, st.Number, err)
	}
	raw, digest, err := stepDigest(sets)
	if err != nil {
		return err
	}
	if digest != st.Digest {
		return fmt.Errorf("zone %s: step %d's sets give digest %s, not %s", zone, st.Number, digest, st.Digest)
	}
	return s.update(zone, func(z *zoneSerials) error {
		if z.Active == nil || !z.Enforced || z.Active.SerialDigest != active {
			return fmt.Errorf("zone %s: %w (%s)", zone, errStepNotActive, active)
		}
		if old, ok := z.stepHeldLocked(); !ok || old.Number != st.Number || old.Digest != st.Digest {
			z.StepAt = time.Now()
		}
		z.Step, z.Sets, z.StepOf, z.StepWhat, z.Taken, z.Pending = st.Number, raw, st.Of, st.What, slices.Clone(st.Taken), false
		kept := make([]Removal, 0, len(removals))
		for _, r := range removals {
			r.Identity = canonicalName(r.Identity)
			if i := slices.IndexFunc(z.Removals, func(o Removal) bool { return o.Label == r.Label && core.EqualNames(o.Identity, r.Identity) }); i >= 0 {
				r.Since = z.Removals[i].Since
			}
			if r.Since.IsZero() {
				r.Since = time.Now()
			}
			r.Step = st.Number
			kept = append(kept, r)
		}
		if len(kept) == 0 {
			kept = nil
		}
		z.Removals = kept
		return nil
	})
}

// excuse keeps a leaving member excused for the rest of the zone's
// transition (design 3.2): the planner plans it as excused from then on.
func (s *InstructionStore) excuse(zone, member string) error {
	return s.update(zone, func(z *zoneSerials) error {
		if !z.reconciling() || slices.ContainsFunc(z.Excused, func(e string) bool { return core.EqualNames(e, member) }) {
			return errToldUnchanged
		}
		z.Excused = append(z.Excused, canonicalName(member))
		return nil
	})
}

// reconcileInputs is what the reconciliation reads of the store for a zone.
type reconcileInputs struct {
	name        string
	active      heldSerial
	from        *heldSerial
	newer       *heldSerial // the highest serial held above the active one
	step        heldStep
	hasStep     bool
	removals    []Removal
	excused     []string
	enforced    bool
	reconciling bool
}

// reconcileInputs is what the store holds of zone, the zone named in any
// case; false when it holds no active serial for it.
func (s *InstructionStore) reconcileInputs(zone string) (reconcileInputs, bool) {
	if s == nil {
		return reconcileInputs{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, z := s.zoneLocked(zone)
	if z == nil || z.Active == nil {
		return reconcileInputs{}, false
	}
	in := reconcileInputs{name: name, active: *z.Active, removals: slices.Clone(z.Removals),
		excused: slices.Clone(z.Excused), enforced: z.Enforced, reconciling: z.reconciling()}
	if z.From != nil {
		f := *z.From
		in.from = &f
	}
	if n := len(z.Held); n > 0 {
		h := z.Held[n-1]
		in.newer = &h
	}
	in.step, in.hasStep = z.stepHeldLocked()
	return in, true
}

// stampStepLocked adds to st what this agent tells of its reconciliation:
// that it reconciles, the step it holds and the removals under way. Called
// with the store's lock held.
func (z *zoneSerials) stampStepLocked(st *InstrStamp) {
	if !z.Enforced {
		return
	}
	st.Reconciling = z.reconciling()
	if step, ok := z.stepHeldLocked(); ok {
		w := step.InstrStep
		st.Step = &w
	}
	for _, r := range z.Removals {
		st.Removals = append(st.Removals, InstrRemoval{Label: r.Label, Identity: r.Identity, NSNames: slices.Clone(r.NSNames), Step: r.Step})
	}
}

// removalsOf are a stamp's removals as the store keeps them.
func removalsOf(rs []InstrRemoval) []Removal {
	var out []Removal
	for _, r := range rs {
		out = append(out, Removal{Label: r.Label, Identity: r.Identity, NSNames: slices.Clone(r.NSNames), Step: r.Step})
	}
	return out
}

// noRoleMember: id is a member of the zone with no role under its active
// serial, on its way in or out (design 4): an ON record in none of the
// lists, or a provider whose removal is under way. A distribution waits for
// it only up to multi-provider.transitions.no-role-timeout.
func noRoleMember(zone ZoneName, id AgentId) bool {
	in := instructionsFor(zone)
	switch st := zoneStanding(in, string(id)); {
	case in == nil, st == standingVoting, st == standingAuditor:
		return false
	case st == standingNoRole:
		return true
	}
	_, ok := instrStore.Load().removal(dns.Fqdn(string(zone)), "", string(id))
	return ok
}

// --- The parts ---

// holdsStep: this agent holds the zone's step at the active serial sd: both
// its parts hold the step's sets, and every runner's own part of it is done
// here. Its stamp tells it (StepHeld).
func (conf *Config) holdsStep(zone string, sd SerialDigest, step InstrStep) bool {
	if !conf.partsHold(zone, sd, step.Number) {
		return false
	}
	for _, r := range stepRunners {
		if r.holds != nil && !r.holds(conf, zone, step) {
			return false
		}
	}
	return true
}

// partsHold: this agent's combiner and signer both hold what it hands them
// for the zone at the active serial sd and the step: its combiner by its
// confirmation, its signer by its inventory (plan S10, S11). An agent that
// hands neither part anything holds nothing.
func (conf *Config) partsHold(zone string, sd SerialDigest, step int) bool {
	t, ts := conf.InternalMp.Handover, conf.InternalMp.SignerHandover
	if t == nil && ts == nil {
		return false
	}
	return (t == nil || t.holds(zone, sd, step)) && (ts == nil || ts.holds(zone, sd, step))
}

// holds: the part holds what this agent wants it to act by for the zone,
// and that is the active serial sd at the step.
func (t *handoverTracker) holds(zone string, sd SerialDigest, step int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	z := t.zones[handoverKey(zone)]
	return z != nil && z.want != nil && z.want.Serial == sd.Serial && z.want.Digest == sd.Digest && z.want.Step == step && z.want.sameAs(z.held)
}

// --- The turn ---

// reconcileBook is what the agent and the auditor keep of their zones'
// reconciliations in memory: per zone, since when each leaving member has
// owed a step's confirmation, and the lines logged once.
type reconcileBook struct {
	mu    sync.Mutex
	zones map[string]*zoneReconcile // by zone, folded
}

type zoneReconcile struct {
	owing map[string]time.Time // by member, folded: when the first step it has not confirmed was taken
	said  map[string]bool
}

func (b *reconcileBook) zone(zone string) *zoneReconcile {
	if b.zones == nil {
		b.zones = map[string]*zoneReconcile{}
	}
	zr := b.zones[zone]
	if zr == nil {
		zr = &zoneReconcile{owing: map[string]time.Time{}, said: map[string]bool{}}
		b.zones[zone] = zr
	}
	return zr
}

// sayOnce reports whether the zone's line keyed by key is logged for the
// first time.
func (b *reconcileBook) sayOnce(zone, key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	zr := b.zone(zone)
	if zr.said[key] {
		return false
	}
	zr.said[key] = true
	return true
}

// forget drops what the book keeps of the zone: its transition is done.
func (b *reconcileBook) forget(zone string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.zones, zone)
}

// reconcileTurn is the zone's reconciliation, at its turn (thawTurn): the
// leader under the active serial takes the next step, or says "done", once
// the step it holds is held; every other agent takes the leader's step and
// its "done" from the leader's stamp.
func (conf *Config) reconcileTurn(zone string, now time.Time) {
	s := conf.InternalMp.Instructions
	in, ok := s.reconcileInputs(zone)
	if !ok || !in.enforced || !in.reconciling || conf.MpConfig() == nil {
		return
	}
	key := canonicalName(in.name)
	if in.newer != nil && conf.InternalMp.reconciles.sayOnce(key, fmt.Sprintf("newer %d", in.newer.Serial)) {
		lg.Info("a newer serial of the zone's instructions waits until the transition is done", "zone", in.name, "serial", in.newer.Serial)
	}
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	told := t.firstHand(key)
	if !conf.leadsReconciliation(in) {
		conf.followStep(in, told)
		return
	}
	v := conf.reconcileView(in, told, now)
	if v.adopt != nil {
		conf.takeFrom(in, v.adopt, "the furthest step a voting member holds")
		return
	}
	for _, id := range v.excuse {
		if err := s.excuse(in.name, id); err == nil {
			lg.Info("a leaving member that has not confirmed a step is excused", "zone", in.name, "member", id, "step", in.step.Number, "since", v.owing[id].Format(time.TimeOnly))
		}
	}
	for _, id := range v.timedOut {
		if conf.InternalMp.reconciles.sayOnce(key, fmt.Sprintf("timed out %d %s", in.step.Number, id)) {
			lg.Warn("a member with no role did not confirm in time, going on", "zone", in.name, "member", id, "what", "step "+fmt.Sprint(in.step.Number))
		}
	}
	if len(v.excuse) > 0 {
		return // planned again, as excused, at the next turn
	}
	switch {
	case v.done:
		conf.transitionDone(in.name, in.active.Serial)
		return
	case len(v.waits) > 0 || v.next == nil:
		return
	}
	if v.rollover != "" {
		if conf.InternalMp.reconciles.sayOnce(key, "rollover "+v.next.key) {
			lg.Info("a DS or DNSKEY step waits for an emergency rollover", "zone", in.name, "step", in.step.Number+1, "provider", v.rollover)
		}
		return
	}
	conf.takeStep(in, *v.next, v.of)
}

// leadsReconciliation: this agent carries out the zone's reconciliation: it
// leads the zone's group under the active serial, or the zone is in no
// group and this agent is its only voting member (design 3.3). The leader
// under V is never a provider that V takes away (design 3.2).
func (conf *Config) leadsReconciliation(in reconcileInputs) bool {
	local := AgentId(dns.Fqdn(conf.MpConfig().Identity))
	_, voters, _ := participantsOf(in.active.Reading)
	switch {
	case !isAmong(voters, local):
		return false
	case len(voters) == 1:
		return true
	}
	lem := conf.InternalMp.LeaderElectionManager
	return lem != nil && lem.IsLeader(ZoneName(in.name))
}

// reconcileView is what the leader's turn sees of the zone's step.
type reconcileView struct {
	adopt    *toldStamp // a voting member's stamp whose step is further than the one held here
	waits    []string   // whom and what the step held waits for
	timedOut []string   // members with no role that did not confirm in time
	excuse   []string   // leaving members to excuse now
	owing    map[string]time.Time
	next     *plannedStep // the next step to take; nil with none
	of       int          // the steps planned, taken ones included
	rollover string       // the voting member whose emergency rollover holds the next step, a DS or DNSKEY one
	done     bool         // the last step is held
}

// reconcileView is what the leader's turn sees of the zone at now: a
// further step that a voting member tells, to take first; else whom the
// step held waits for, and the next step. Its only side effect is the
// book's count of what each leaving member owes.
func (conf *Config) reconcileView(in reconcileInputs, told map[string]toldStamp, now time.Time) reconcileView {
	mp := conf.MpConfig()
	local := dns.Fqdn(mp.Identity)
	_, votersV, _ := participantsOf(in.active.Reading)
	var votersN []string
	if in.from != nil {
		_, votersN, _ = participantsOf(in.from.Reading)
	}
	var v reconcileView

	// A step further than this agent's, told first hand by a voting member
	// under V: a new leader, or one that lost its store, plans again from
	// what is in place (design 3.3). With none held here it waits until
	// every other voting member under V has been heard.
	var unheard []string
	for _, id := range votersV {
		if core.EqualNames(id, local) {
			continue
		}
		st, ok := told[canonicalName(id)]
		switch {
		case !ok:
			unheard = append(unheard, id)
		case st.Known && st.Active == in.active.Serial && st.ActiveDigest == in.active.Digest && st.Step != nil &&
			(!in.hasStep || st.Step.Number > in.step.Number) && (v.adopt == nil || st.Step.Number > v.adopt.Step.Number):
			c := st
			v.adopt = &c
		}
	}
	// a leader that holds no step's sets takes none until every other
	// voting member under V is heard: one not heard may tell a further step
	if !in.hasStep && len(unheard) > 0 {
		v.adopt = nil
		for _, id := range unheard {
			v.waits = append(v.waits, id+" (not heard)")
		}
		return v
	}
	if v.adopt != nil {
		return v
	}

	held, removals := in.step.sets, in.removals
	if !in.hasStep {
		// nothing in place is known but V: a leader that knew its active
		// serial by the members' word, with no step told
		held = rolesFor(in.active.Reading, in.active.Reading, 0)
	}
	excused := map[string]bool{}
	for _, id := range in.excused {
		excused[canonicalName(id)] = true
	}
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	if zt := b.zones[canonicalName(in.name)]; zt != nil && zt.agreed == in.active.SerialDigest {
		maps.Copy(excused, zt.excused)
	}
	b.mu.Unlock()

	// With no step held there is nothing to confirm: the first is taken.
	if in.hasStep {
		conf.stepWaits(in, told, votersN, votersV, removals, excused, now, &v)
	}

	var from *Instructions
	if in.from != nil {
		from = in.from.Reading
	}
	plan := planSteps(planView{zone: in.name, from: from, to: in.active.Reading, held: held, removals: removals, excused: excused, taken: in.step.Taken})
	var cur *plannedStep
	if n := len(in.step.Taken); n > 0 {
		if i := slices.IndexFunc(plan, func(st plannedStep) bool { return st.key == in.step.Taken[n-1] }); i >= 0 {
			cur = &plan[i]
		}
	}
	if cur != nil && cur.wait != nil {
		if w := cur.wait(conf, in.name, in.step.at); w != "" {
			v.waits = append(v.waits, w)
		}
	}
	untaken := slices.DeleteFunc(slices.Clone(plan), func(st plannedStep) bool { return slices.Contains(in.step.Taken, st.key) })
	v.of = len(in.step.Taken) + len(untaken)
	switch {
	case len(untaken) > 0:
		v.next = &untaken[0]
		if v.next.keys {
			v.rollover = conf.emergencyRollover(in, told, excused)
		}
	default:
		v.done = len(v.waits) == 0
	}
	return v
}

// stepWaits adds to v whom the step held waits for: this agent's parts;
// every other voting member under V, without a time-out; a member with no
// role under V that is heard, up to no-role-timeout from the step (design
// 4): a newcomer whose agent is not running holds nothing up. A leaving
// member (voting under N and not under V, or one whose removal is under
// way) has no role too, and once it has not confirmed a step for
// leaving-timeout it is excused (design 3.2). The auditor is not waited
// for. A member holds the step when its first-hand stamp tells the active
// serial, the step by number and digest, and that both its parts hold it.
func (conf *Config) stepWaits(in reconcileInputs, told map[string]toldStamp, votersN, votersV []string, removals []Removal, excused map[string]bool, now time.Time, v *reconcileView) {
	mp := conf.MpConfig()
	local := dns.Fqdn(mp.Identity)
	timeout, noRole := leavingTimeoutFor(mp), noRoleTimeoutFor(mp)
	holds := func(st toldStamp) bool {
		if !st.Known || st.Active != in.active.Serial || st.ActiveDigest != in.active.Digest {
			return false
		}
		// one at rest at V, done with the transition or at rest since it
		// first knew V, holds V's lists in its parts: past every step, and it
		// takes no step any more
		if !st.Reconciling {
			return true
		}
		return st.StepHeld && st.Step != nil && st.Step.Number == in.step.Number && st.Step.Digest == in.step.Digest
	}
	if !conf.holdsStep(in.name, in.active.SerialDigest, in.step.InstrStep) {
		v.waits = append(v.waits, local+" (its combiner and signer)")
	}
	leaving := map[string]bool{}
	for _, id := range votersN {
		// one that is the auditor under V is not leaving: the auditor is not
		// waited for, and its stamps never tell a step held
		if !isAmong(votersV, AgentId(id)) && zoneStanding(in.active.Reading, id) != standingAuditor {
			leaving[canonicalName(id)] = true
		}
	}
	for _, r := range removals {
		leaving[canonicalName(r.Identity)] = true
	}
	var noRoleIDs []string
	for _, rec := range in.active.Reading.Records {
		if zoneStanding(in.active.Reading, rec.Identity) == standingNoRole && !leaving[canonicalName(rec.Identity)] {
			noRoleIDs = append(noRoleIDs, rec.Identity)
		}
	}
	rb := &conf.InternalMp.reconciles
	rb.mu.Lock()
	zr := rb.zone(canonicalName(in.name))
	v.owing = maps.Clone(zr.owing)
	for _, id := range votersV {
		if core.EqualNames(id, local) {
			continue
		}
		if st, ok := told[canonicalName(id)]; !ok || !holds(st) {
			v.waits = append(v.waits, id)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(leaving)) {
		if excused[id] || core.EqualNames(id, local) {
			continue
		}
		st, heard := told[id]
		if heard && holds(st) {
			delete(zr.owing, id)
			continue
		}
		// since the first step it has not confirmed was taken
		since, ok := zr.owing[id]
		if !ok {
			since = in.step.at
			zr.owing[id] = since
		}
		v.owing[id] = since
		if now.Sub(since) >= timeout {
			v.excuse = append(v.excuse, id)
			continue
		}
		fresh := heard && now.Sub(st.heard) <= timeout
		switch {
		case !fresh:
		case now.Sub(in.step.at) < noRole:
			v.waits = append(v.waits, id+" (leaving)")
		default:
			v.timedOut = append(v.timedOut, id)
		}
	}
	for _, id := range noRoleIDs {
		st, heard := told[canonicalName(id)]
		if !heard || now.Sub(st.heard) > timeout || holds(st) {
			continue
		}
		if now.Sub(in.step.at) < noRole {
			v.waits = append(v.waits, id+" (no role)")
		} else {
			v.timedOut = append(v.timedOut, id)
		}
	}
	rb.mu.Unlock()
}

// emergencyRollover names a voting member under V, this agent included,
// whose rollover is under way and not paused only on excused members (S5a's
// predicate; design 3.2, 3.3); "" for none.
func (conf *Config) emergencyRollover(in reconcileInputs, told map[string]toldStamp, excused map[string]bool) string {
	local := dns.Fqdn(conf.MpConfig().Identity)
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	if t != nil && t.rollover != nil && t.rollover(in.name) && !pausedOn(t.waitsOnOf(in.name), in.active.Reading, excused) {
		return local
	}
	_, votersV, _ := participantsOf(in.active.Reading)
	for _, id := range votersV {
		if core.EqualNames(id, local) {
			continue
		}
		if st, ok := told[canonicalName(id)]; ok && st.Rollover && !pausedOn(st.WaitsOn, in.active.Reading, excused) {
			return id
		}
	}
	return ""
}

// takeStep has the leader take st, the step after the one held: its sets
// and removals are kept, its stamp tells them, its own parts are handed
// them (onSetsChanged), and its own action runs.
func (conf *Config) takeStep(in reconcileInputs, st plannedStep, of int) {
	held, removals := in.step.sets, in.removals
	if !in.hasStep {
		held = rolesFor(in.active.Reading, in.active.Reading, 0)
	}
	if st.sets != nil {
		held = st.sets(held)
	}
	if st.removals != nil {
		removals = st.removals(removals)
	}
	raw, digest, err := stepDigest(held)
	if err != nil {
		lg.Error("the step's sets could not be made", "zone", in.name, "err", err)
		return
	}
	next := InstrStep{Number: in.step.Number + 1, Of: of, What: st.what, Sets: raw, Digest: digest, Taken: append(slices.Clone(in.step.Taken), st.key)}
	if err := conf.InternalMp.Instructions.setStep(in.name, in.active.SerialDigest, next, removals); err != nil {
		lg.Error("the step could not be kept", "zone", in.name, "step", next.Number, "err", err)
		return
	}
	lg.Info("transition step sent", "zone", in.name, "step", next.Number, "what", st.what)
	if mpzd, ok := Zones.Get(in.name); ok && mpzd != nil {
		conf.onSetsChanged(mpzd, true)
	}
	if st.start != nil {
		st.start(conf, in.name)
	}
}

// takeFrom keeps the step a member's stamp tells, with its removals, as
// this agent's, and hands its parts the step's sets.
func (conf *Config) takeFrom(in reconcileInputs, st *toldStamp, why string) {
	if err := conf.InternalMp.Instructions.setStep(in.name, in.active.SerialDigest, *st.Step, removalsOf(st.Removals)); err != nil {
		lg.Warn("a step a member tells is not taken", "zone", in.name, "step", st.Step.Number, "member", st.identity, "err", err)
		return
	}
	lg.Info("taking the zone's step from a member", "zone", in.name, "step", st.Step.Number, "member", st.identity, "why", why)
	if mpzd, ok := Zones.Get(in.name); ok && mpzd != nil {
		conf.onSetsChanged(mpzd, true)
	}
}

// followStep is the turn of an agent that does not lead the zone's
// reconciliation: it takes the step the leader's first-hand stamp tells at
// the same active serial, when it is further than its own or names other
// sets, and ends the transition when the leader's stamp tells it done. An
// agent that knows no leader and does not vote under the active serial
// (the auditor) takes the furthest a voting member tells, and "done" from
// any of them.
func (conf *Config) followStep(in reconcileInputs, told map[string]toldStamp) {
	same := func(st toldStamp) bool {
		return st.Known && st.Active == in.active.Serial && st.ActiveDigest == in.active.Digest
	}
	var src []toldStamp
	var leader AgentId
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, _ = lem.ZoneLeader(ZoneName(in.name))
	}
	if st, ok := told[canonicalName(string(leader))]; leader != "" && ok {
		src = append(src, st)
	} else if !votesIn(in.active.Reading, AgentId(conf.MpConfig().Identity)) {
		_, voters, _ := participantsOf(in.active.Reading)
		for _, id := range voters {
			if st, ok := told[canonicalName(id)]; ok {
				src = append(src, st)
			}
		}
	}
	var best *toldStamp
	for i := range src {
		st := src[i]
		if !same(st) {
			continue
		}
		if !st.Reconciling {
			conf.transitionDone(in.name, in.active.Serial)
			return
		}
		if st.Step != nil && (best == nil || st.Step.Number > best.Step.Number) {
			best = &src[i]
		}
	}
	if best == nil {
		return
	}
	if in.hasStep && (best.Step.Number < in.step.Number || best.Step.Number == in.step.Number && best.Step.Digest == in.step.Digest) {
		return
	}
	conf.takeFrom(in, best, "the leader's step")
}

// transitionDone ends the zone's transition here (design 3.3): the store
// drops the from-serial, the step and the removals; the parts are handed
// the active serial's sets at rest; the freeze's end releases what the zone
// kept (onFreeze); and a newer serial that waited is judged and agreed at
// the next turn.
func (conf *Config) transitionDone(zone string, serial uint32) {
	if err := conf.InternalMp.Instructions.Done(zone); err != nil {
		lg.Error("the transition could not be marked done", "zone", zone, "serial", serial, "err", err)
		return
	}
	conf.InternalMp.reconciles.forget(canonicalName(zone))
	lg.Info("transition done", "zone", zone, "serial", serial)
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
		conf.onSetsChanged(mpzd, true)
	}
	conf.askThaw(zone)
}

// reconcileLine is the zone's reconciliation as the status shows it: the
// step held here and what it waits for, and a newer serial that waits for
// "done"; "" when the zone does not reconcile here.
func (conf *Config) reconcileLine(zone string, now time.Time) string {
	in, ok := conf.InternalMp.Instructions.reconcileInputs(zone)
	if !ok || !in.enforced || !in.reconciling || conf.MpConfig() == nil {
		return ""
	}
	head := fmt.Sprintf("reconciling to %d", in.active.Serial)
	if in.from != nil {
		head = fmt.Sprintf("reconciling %d->%d", in.from.Serial, in.active.Serial)
	}
	var line string
	switch {
	case !in.hasStep:
		line = head + ": waiting for the leader's step"
	case in.step.Number == 0:
		line = head + ": step 0 (the sets held)"
	default:
		line = fmt.Sprintf("%s: step %d of %d", head, in.step.Number, in.step.Of)
		if in.step.What != "" {
			line += " (" + in.step.What + ")"
		}
	}
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	if conf.leadsReconciliation(in) {
		v := conf.reconcileView(in, t.firstHand(canonicalName(in.name)), now)
		switch {
		case v.adopt != nil:
			line += fmt.Sprintf(", taking step %d from %s", v.adopt.Step.Number, v.adopt.identity)
		case len(v.waits) > 0:
			line += ", waiting for " + strings.Join(v.waits, ", ")
		case v.rollover != "":
			line += ", the next step waits for an emergency rollover at " + v.rollover
		}
	} else if in.hasStep && in.step.Number == 0 {
		line += ", waiting for the leader's first step"
	}
	for _, r := range stepRunners {
		if r.status == nil || !in.hasStep {
			continue
		}
		if s := r.status(conf, in.name, in.step, now); s != "" {
			line += ", " + s
		}
	}
	if in.newer != nil {
		line += fmt.Sprintf("; %d held, waits until done", in.newer.Serial)
	}
	return line
}
