/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The thaw (design 3.2, plan S7). The leader of the zone's group under its
 * active serial N makes the serial agreed on, V, active once every other
 * voting member under N tells, first hand and fresh, that it holds N active
 * and agrees on V with its signer's hold confirmed, its own signer has
 * confirmed the hold, no rollover is under way, payload encryption is on at
 * every voting member, and nothing of the leader's is in flight towards the
 * parent. Its stamp then tells the thaw, and every other member makes V
 * active on the first first-hand telling of it from the leader or from a
 * voting member under V. A leaving voting member whose telling has not
 * counted for multi-provider.transitions.leaving-timeout is excused. The
 * reconciliation that follows, until "done", is reconcile.go's (S12).
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// thawBook is what the agent and the auditor keep of their zones' thaws, in
// memory: per zone what the thaw's conditions have seen, the zones whose
// turn is asked, and the serials asked of a member.
type thawBook struct {
	mu      sync.Mutex
	zones   map[string]*zoneThaw // by zone, folded
	pending map[string]bool      // the zones whose turn is asked (askThaw)
	wake    chan struct{}
	fetched map[string]time.Time // the instructions RFIs asked, by zone, serial, digest and member
	gate    map[string]bool      // the excusals from a group's gate logged, by group and member
	// turn: one turn at a time, of any zone (thawTurn)
	turn sync.Mutex
}

// zoneThaw is what the thaw of one zone has seen, for the serial agreed on
// it names: when each member's telling last met the thaw's first two
// conditions, every agent seen as the zone's leader with its lease, and
// the leaving members excused.
type zoneThaw struct {
	agreed  SerialDigest
	met     map[string]time.Time // by member, folded
	leases  map[string]time.Time // by leader, folded
	excused map[string]bool      // by member, folded
	warned  time.Time            // the last warning that a leaving leader holds the zone
	refused map[uint32]bool      // the serials told active that this agent refuses, logged
	thawed  *thawMark
}

// thawMark is the last thaw made active here: its target, who told it, and
// when.
type thawMark struct {
	to uint32
	by string
	at time.Time
}

func (b *thawBook) zone(zone string) *zoneThaw {
	if b.zones == nil {
		b.zones = map[string]*zoneThaw{}
	}
	zt := b.zones[zone]
	if zt == nil {
		zt = &zoneThaw{}
		b.zones[zone] = zt
	}
	return zt
}

// forAgreed is zt, its marks started over when the serial agreed on moved:
// the excusal time counts from when this agent first holds the serial
// agreed on.
func (zt *zoneThaw) forAgreed(v SerialDigest) *zoneThaw {
	if zt.agreed != v {
		zt.agreed = v
		zt.met, zt.leases, zt.excused = map[string]time.Time{}, map[string]time.Time{}, map[string]bool{}
	}
	return zt
}

// thawInputs is what the thaw reads of the store for one zone.
type thawInputs struct {
	name        string
	active      heldSerial
	agreed      *heldSerial
	ownerError  string
	reconciling bool
	enforced    bool
}

// thawInputs is what the store holds of zone, the zone named in any case;
// false when it holds no active serial for it.
func (s *InstructionStore) thawInputs(zone string) (thawInputs, bool) {
	if s == nil {
		return thawInputs{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, z := s.zoneLocked(zone)
	if z == nil || z.Active == nil {
		return thawInputs{}, false
	}
	in := thawInputs{name: name, active: *z.Active, ownerError: z.OwnerError,
		reconciling: z.reconciling(), enforced: z.Enforced}
	if a := z.agreeing(); a != nil {
		c := *a
		in.agreed = &c
	}
	return in, true
}

// thawView is what the thaw of a zone waits for, as this agent sees it.
type thawView struct {
	zone     string // the store's name for it
	from, to SerialDigest
	leads    bool     // this agent thaws the zone
	parent   string   // the leader's work in flight towards the parent; "" for none
	waits    []string // whom and what else the thaw waits for
	excused  []string // the leaving members excused
	held     string   // a heard leaving leader that renews its lease and holds the zone
	noLeader string   // the zone's leader is lost and is not leaving
}

// ready: this agent thaws the zone now.
func (v thawView) ready() bool {
	return v.leads && v.parent == "" && len(v.waits) == 0
}

// line is the view as the status shows it.
func (v thawView) line() string {
	var parts []string
	switch {
	case v.held != "":
		parts = append(parts, "held by "+v.held+", the leader, which leaves and renews its lease; its operator must stop it")
	case v.noLeader != "":
		parts = append(parts, "no leader ("+v.noLeader+"); waiting for it or for the owner to remove it")
	}
	waits := slices.Clone(v.waits)
	if v.parent != "" {
		waits = append(waits, "the parent ("+v.parent+")")
	}
	if len(waits) > 0 {
		parts = append(parts, "waiting for "+strings.Join(waits, ", "))
	}
	parts = append(parts, v.excused...)
	if len(parts) == 0 {
		if v.leads {
			return "agreeing: thawing"
		}
		return "agreeing: every voting member agrees, waiting for the leader's thaw"
	}
	return "agreeing: " + strings.Join(parts, "; ")
}

// thawView is what the thaw of zone waits for at now (design 3.2); false
// when the zone agrees on nothing here: it keeps no enforced active serial,
// agrees on no serial above it, holds an owner error, or its transition is
// not done (one transition at a time, design 3.3).
func (conf *Config) thawView(zone string, now time.Time) (thawView, bool) {
	in, ok := conf.InternalMp.Instructions.thawInputs(zone)
	if !ok || !in.enforced || in.agreed == nil || in.ownerError != "" || in.reconciling {
		return thawView{}, false
	}
	mp := conf.MpConfig()
	if mp == nil {
		return thawView{}, false
	}
	local := dns.Fqdn(mp.Identity)
	timeout := leavingTimeoutFor(mp)
	v := thawView{zone: in.name, from: in.active.SerialDigest, to: in.agreed.SerialDigest}
	_, votersN, _ := participantsOf(in.active.Reading)
	_, votersV, _ := participantsOf(in.agreed.Reading)
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	told := t.firstHand(canonicalName(in.name))
	lem := conf.InternalMp.LeaderElectionManager
	ar := conf.InternalMp.AgentRegistry
	heard := map[string]bool{}
	for _, id := range slices.Concat(votersN, votersV) {
		heard[canonicalName(id)] = ar != nil && ar.isAgentOperational(AgentId(id))
	}
	var leader AgentId
	var expiry time.Time
	if lem != nil {
		leader, expiry = lem.zoneLease(ZoneName(in.name))
	}

	// No voting member under N: each voting member under V makes V active
	// when every voting member under V tells V (design 3.2).
	if len(votersN) == 0 {
		v.leads = isAmong(votersV, AgentId(local))
		if !v.leads {
			return v, true
		}
		if !t.encrypts() {
			v.waits = append(v.waits, local+" (payload encryption off)")
		}
		for _, id := range votersV {
			if core.EqualNames(id, local) {
				continue
			}
			st, ok := told[canonicalName(id)]
			switch {
			case !ok || now.Sub(st.heard) > timeout:
				v.waits = append(v.waits, id+" (not heard)")
			case st.Error != "":
				v.waits = append(v.waits, id+" (owner error)")
			case !(st.Known && st.Active == v.to.Serial && st.ActiveDigest == v.to.Digest) && !(st.Agreeing == v.to.Serial && st.AgreeingDigest == v.to.Digest):
				v.waits = append(v.waits, fmt.Sprintf("%s (agrees on %d)", id, st.Agreeing))
			case !st.encrypted:
				v.waits = append(v.waits, id+" (payload encryption off)")
			}
		}
		return v, true
	}

	switch {
	case !isAmong(votersN, AgentId(local)):
	case len(votersN) == 1:
		v.leads = true // the zone's only voting member, in no group
	case lem != nil:
		v.leads = lem.IsLeader(ZoneName(in.name))
	}

	b := &conf.InternalMp.thaws
	b.mu.Lock()
	zt := b.zone(canonicalName(in.name)).forAgreed(v.to)
	if leader != "" {
		zt.leases[canonicalName(string(leader))] = expiry
	}

	// Each other voting member's telling: whether it meets the thaw's first
	// two conditions, and why not. A leaving one whose telling has not met
	// them for the configured time is excused, its rollover flag with them.
	type member struct {
		id      string
		st      toldStamp
		heard   bool // a stamp of the zone has been heard from it
		tells   string
		rolling bool
	}
	var members []member
	excused := map[string]bool{}
	for _, id := range votersN {
		if core.EqualNames(id, local) {
			continue
		}
		m := member{id: id}
		m.st, m.heard = told[canonicalName(id)]
		m.tells = tellsAgreement(m.st, m.heard, now, timeout, v.from, v.to)
		m.rolling = m.tells == "" && m.st.Rollover
		key := canonicalName(id)
		if m.tells == "" && !m.rolling {
			zt.met[key] = now
		}
		leaving := !isAmong(votersV, AgentId(id))
		if leaving && (m.tells != "" || m.rolling) {
			since := in.agreed.Since
			if met := zt.met[key]; met.After(since) {
				since = met
			}
			expiry, led := zt.leases[key]
			switch {
			case now.Sub(since) < timeout:
			case led && !now.After(expiry):
				// a leaving leader is excused only once its lease has run
				// out here; a heard one that renews it holds the zone
				if heard[key] {
					v.held = id
				}
			default:
				excused[key] = true
				if !zt.excused[key] {
					zt.excused[key] = true
					lg.Info("a leaving voting member is excused", "zone", in.name, "member", id, "since", since.Format(time.TimeOnly), "why", strings.TrimSpace(m.tells+" "+rollingWord(m.rolling)))
				}
				v.excused = append(v.excused, fmt.Sprintf("%s excused (leaving, no telling that counts since %s)", id, since.Format(time.TimeOnly)))
				continue
			}
		}
		members = append(members, m)
	}
	for k := range zt.excused {
		if !excused[k] {
			delete(zt.excused, k)
		}
	}
	warn := v.held != "" && now.Sub(zt.warned) >= time.Hour
	if warn {
		zt.warned = now
	}
	leases := maps.Clone(zt.leases)
	b.mu.Unlock()
	if warn {
		lg.Warn("a leaving leader holds the zone: it renews its lease and its telling does not count", "zone", in.name, "member", v.held)
	}

	// This agent's own: its signer's hold, its provider's rollover, its
	// payload encryption, and as the leader its work at the parent.
	if isAmong(votersN, AgentId(local)) {
		if !conf.holdConfirmed(in.name) {
			v.waits = append(v.waits, local+" (no hold yet)")
		}
		if t != nil && t.rollover != nil && t.rollover(in.name) && !pausedOn(t.waitsOnOf(in.name), in.active.Reading, excused) {
			v.waits = append(v.waits, local+" (rollover under way)")
		}
		if !t.encrypts() {
			v.waits = append(v.waits, local+" (payload encryption off)")
		}
	}
	for _, m := range members {
		switch {
		case m.tells != "":
			v.waits = append(v.waits, m.id+" ("+m.tells+")")
		case m.rolling && !pausedOn(m.st.WaitsOn, in.active.Reading, excused):
			v.waits = append(v.waits, m.id+" (rollover under way)")
		case !m.st.encrypted:
			v.waits = append(v.waits, m.id+" (payload encryption off)")
		}
	}
	// A voting member under V that does not vote under N tells nothing the
	// thaw waits for but its payload encryption (rule 4).
	for _, id := range votersV {
		if core.EqualNames(id, local) || isAmong(votersN, AgentId(id)) {
			continue
		}
		if st, ok := told[canonicalName(id)]; !ok || !st.encrypted {
			v.waits = append(v.waits, id+" (payload encryption off)")
		}
	}
	if v.leads {
		v.parent = conf.parentWorkUnderWay(in.name)
	} else if lem != nil {
		if _, ok := lem.ZoneLeader(ZoneName(in.name)); !ok {
			v.noLeader = lostLeader(leases, votersV, heard, told)
		}
	}
	return v, true
}

// tellsAgreement is why a member's latest first-hand stamp st does not
// tell what the thaw needs: active from and agreeing on to, by serial and
// digest, its active serial known, no owner error, its signer's hold, heard
// within timeout (rule 4). "" when it does. Its rollover is read apart.
func tellsAgreement(st toldStamp, heard bool, now time.Time, timeout time.Duration, from, to SerialDigest) string {
	switch {
	case !heard:
		return "not heard"
	case now.Sub(st.heard) > timeout:
		return "not heard since " + st.heard.Format(time.TimeOnly)
	case st.Error != "":
		return "owner error"
	case !st.Known || st.ActiveDigest == "":
		return "tells no active serial"
	case st.Active != from.Serial || st.ActiveDigest != from.Digest:
		return fmt.Sprintf("tells %d", st.Active)
	case st.Agreeing == to.Serial && st.AgreeingDigest == to.Digest:
	case st.Refused != "" && st.Newest == to.Serial:
		return fmt.Sprintf("refuses %d: %s", to.Serial, st.Refused)
	case st.AgreeingDigest == "":
		return "agrees on nothing"
	default:
		return fmt.Sprintf("agrees on %d", st.Agreeing)
	}
	if !st.Hold {
		return "no hold yet"
	}
	return ""
}

func rollingWord(rolling bool) string {
	if rolling {
		return "rollover under way"
	}
	return ""
}

// pausedOn: a rollover that waits only on the confirmations of excused
// members (WaitsOn, plan S11, by the labels under the active serial in)
// counts as paused, not under way (design 3.2). With nothing named it is
// under way.
func pausedOn(waitsOn []string, in *Instructions, excused map[string]bool) bool {
	if len(waitsOn) == 0 || in == nil {
		return false
	}
	for _, label := range waitsOn {
		r, ok := in.record(label)
		if !ok || !excused[canonicalName(r.Identity)] {
			return false
		}
	}
	return true
}

// waitsOnOf is whom this provider's rollover waits on (S11's WaitsOn); none
// where the agent knows none.
func (t *stampTable) waitsOnOf(zone string) []string {
	if t == nil || t.waitsOn == nil {
		return nil
	}
	return t.waitsOn(zone)
}

// lostLeader names the zone's last leader seen here when it is not heard
// and not leaving, with when it was last heard: the group stays without a
// leader until it is heard again or the owner removes it (design 3.2,
// membership 4.3). "" otherwise.
func lostLeader(leases map[string]time.Time, votersV []string, heard map[string]bool, told map[string]toldStamp) string {
	var last string
	var at time.Time
	for id, expiry := range leases {
		if last == "" || expiry.After(at) {
			last, at = id, expiry
		}
	}
	if last == "" || heard[last] || !isAmong(votersV, AgentId(last)) {
		return ""
	}
	since := "never"
	if st, ok := told[last]; ok {
		since = st.heard.Format(time.TimeOnly)
	}
	return dns.Fqdn(last) + " not heard since " + since
}

// encrypts: payload encryption is on at this agent.
func (t *stampTable) encrypts() bool { return t != nil && t.crypto }

// askThaw asks the zone's turn (thawTurn) when there is something for it to
// do: the zone agrees on a serial here, or a member tells an active serial
// above this agent's, or a serial agreed on above what it holds. The worker
// (runThaws) takes it; asked again before it does, it is taken once.
func (conf *Config) askThaw(zone string) {
	if !conf.thawWanted(zone) {
		return
	}
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	if b.pending == nil {
		b.pending = map[string]bool{}
		b.wake = make(chan struct{}, 1)
	}
	b.pending[canonicalName(zone)] = true
	wake := b.wake
	b.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

// thawWanted: the zone's turn has something to do; for a zone whose active
// serial this agent does not know, always: the restart rule (S9).
func (conf *Config) thawWanted(zone string) bool {
	if conf.InternalMp.Instructions.activeUnknown(zone) {
		return true
	}
	in, ok := conf.InternalMp.Instructions.thawInputs(zone)
	if !ok || !in.enforced {
		return false
	}
	if in.agreed != nil || in.reconciling {
		return true
	}
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	for _, st := range t.firstHand(canonicalName(zone)) {
		if st.Known && st.ActiveDigest != "" && CompareSerial(st.Active, in.active.Serial) > 0 ||
			st.AgreeingDigest != "" && CompareSerial(st.Agreeing, in.active.Serial) > 0 {
			return true
		}
	}
	return false
}

// thawRound asks the turn of every zone the store keeps, at every beat
// round: a member's excusal comes with time, not with a telling.
func (conf *Config) thawRound() {
	s := conf.InternalMp.Instructions
	if s == nil {
		return
	}
	s.mu.Lock()
	zones := slices.Collect(maps.Keys(s.zones))
	s.mu.Unlock()
	for _, zone := range zones {
		conf.askThaw(zone)
	}
}

// runThaws takes the turns asked (askThaw), one zone at a time, until ctx
// ends.
func (conf *Config) runThaws(ctx context.Context) {
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	if b.pending == nil {
		b.pending = map[string]bool{}
		b.wake = make(chan struct{}, 1)
	}
	wake := b.wake
	b.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
		b.mu.Lock()
		zones := slices.Sorted(maps.Keys(b.pending))
		clear(b.pending)
		b.mu.Unlock()
		for _, zone := range zones {
			conf.thawTurn(zone)
		}
	}
}

// thawTurn is the zone's turn: with no active serial known here, the
// restart rule's (knowActive, S9); otherwise a transition under way goes on
// (the reconciliation's turn, plan S12), the leader thaws it when it is
// ready, and cancels its parent work when that is all the thaw waits for
// (design 3.2: at the thaw's turn); every agent makes active a serial a
// member tells first hand (activateOnTellings), and fetches a serial agreed
// on that it lacks.
func (conf *Config) thawTurn(zone string) {
	b := &conf.InternalMp.thaws
	b.turn.Lock()
	defer b.turn.Unlock()
	if conf.InternalMp.Instructions.activeUnknown(zone) {
		conf.knowActive(zone)
		return
	}
	conf.reconcileTurn(zone, time.Now())
	if v, ok := conf.thawView(zone, time.Now()); ok && v.leads {
		switch {
		case v.ready():
			conf.thaw(v)
			return
		case v.parent != "" && len(v.waits) == 0 && v.held == "":
			conf.cancelParentWork(v.zone, "the thaw's turn")
		}
	}
	conf.activateOnTellings(zone)
	conf.fetchAgreed(zone)
}

// thaw makes the serial agreed on active, by this agent's own word: the
// leader's, the only voting member's, or a voting member's under V when no
// member votes under N.
func (conf *Config) thaw(v thawView) {
	lg.Info("thawing the zone", "zone", v.zone, "from", v.from.Serial, "to", v.to.Serial)
	if err := conf.activate(v.zone, Thaw{From: v.from, To: v.to}, dns.Fqdn(conf.MpConfig().Identity)); err != nil {
		lg.Error("the thaw failed", "zone", v.zone, "from", v.from.Serial, "to", v.to.Serial, "err", err)
	}
}

// activate makes the thaw's target the zone's active serial, written before
// it is told (Activate), and runs what follows from it: the zone moves to
// its group under the new serial (onActiveChanged), the parts are handed V
// with the sets they hold, step 0 (onSetsChanged), and every voting member
// this agent never asked is asked (askUnasked). The reconciliation follows
// (reconcileTurn).
func (conf *Config) activate(zone string, th Thaw, by string) error {
	s := conf.InternalMp.Instructions
	before := s.activeReading(zone)
	if err := s.Activate(zone, th); err != nil {
		return err
	}
	lg.Info("the zone's active instructions are now", "zone", zone, "serial", th.To.Serial, "by", by)
	conf.InternalMp.CatchUp.activeChanged(ZoneName(zone))
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	b.zone(canonicalName(zone)).thawed = &thawMark{to: th.To.Serial, by: by, at: time.Now()}
	b.mu.Unlock()
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
		mpzd.onActiveChanged(conf.InternalMp.MPTransport, before, s.activeReading(zone))
		conf.onSetsChanged(mpzd, true)
		// with the provider data the new serial gives: a member never
		// asked is asked now (plan S15)
		conf.InternalMp.CatchUp.askUnasked(ZoneName(zone))
	}
	conf.askThaw(zone)
	return nil
}

// activateOnTellings makes a serial active on the first first-hand stamp
// that tells it active, from the zone's leader or from a voting member
// under it, provided this agent holds it (design 3.2). The stamp's last
// thaw names the pair: a member behind its from-serial moves straight to
// the target, judging the thaw's own pair, and fetches the from-serial when
// it lacks it. A member that does not hold the target starts nothing and
// fetches it. A serial this agent refuses is never made active.
func (conf *Config) activateOnTellings(zone string) {
	s := conf.InternalMp.Instructions
	in, ok := s.thawInputs(zone)
	if !ok || !in.enforced {
		return
	}
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	var leader AgentId
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, _ = lem.ZoneLeader(ZoneName(in.name))
	}
	told := t.firstHand(canonicalName(in.name))
	for _, key := range slices.Sorted(maps.Keys(told)) {
		st := told[key]
		id := st.identity
		if !st.Known || st.ActiveDigest == "" || CompareSerial(st.Active, in.active.Serial) <= 0 {
			continue
		}
		to := SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}
		reading := s.readingAt(in.name, to)
		if reading == nil {
			// asked only of the leader or a voting member under the active
			// serial: a member with no vote is not trusted with the
			// owner's instructions
			if core.EqualNames(id, string(leader)) || votesIn(in.active.Reading, AgentId(id)) {
				conf.fetchInstructions(in.name, to, id, "a member tells it active")
			}
			continue
		}
		if !core.EqualNames(id, string(leader)) && !votesIn(reading, AgentId(id)) {
			continue
		}
		th := st.Thaw
		if th == nil || th.To != to {
			continue
		}
		switch c := CompareSerial(in.active.Serial, th.From.Serial); {
		case c > 0, c == 0 && in.active.SerialDigest != th.From:
			continue
		case c < 0 && s.readingAt(in.name, th.From) == nil:
			conf.fetchInstructions(in.name, th.From, id, "the thaw's from-serial")
			continue
		}
		err := conf.activate(in.name, *th, id)
		if err == nil {
			return
		}
		b := &conf.InternalMp.thaws
		b.mu.Lock()
		zt := b.zone(canonicalName(in.name))
		if zt.refused == nil {
			zt.refused = map[uint32]bool{}
		}
		first := !zt.refused[to.Serial]
		zt.refused[to.Serial] = true
		b.mu.Unlock()
		if first {
			lg.Warn("a serial a member tells active is not made active here", "zone", in.name, "serial", to.Serial, "member", id, "err", err)
		}
	}
}

// fetchAgreed asks a voting member that tells a serial agreed on above
// every serial this agent holds for it (design 3.1, decision 94).
func (conf *Config) fetchAgreed(zone string) {
	s := conf.InternalMp.Instructions
	in, ok := s.thawInputs(zone)
	if !ok || !in.enforced {
		return
	}
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	told := t.firstHand(canonicalName(in.name))
	for _, key := range slices.Sorted(maps.Keys(told)) {
		st := told[key]
		id := st.identity
		if st.AgreeingDigest == "" || CompareSerial(st.Agreeing, in.active.Serial) <= 0 || !votesIn(in.active.Reading, AgentId(id)) {
			continue
		}
		if in.agreed != nil && CompareSerial(st.Agreeing, in.agreed.Serial) <= 0 {
			continue
		}
		sd := SerialDigest{Serial: st.Agreeing, Digest: st.AgreeingDigest}
		if s.readingAt(in.name, sd) == nil {
			conf.fetchInstructions(in.name, sd, id, "a voting member agrees on it")
		}
	}
}

// fetchInstructions asks member for the zone's instructions at sd, an RFI
// CONFIG of subtype "instructions", at most once a minute for the same
// serial and member, and keeps the answer when its records give sd (Hold).
// The agent and the auditor ask: both keep serials (rule 3) and have the
// RFI's waiters. An auditor whose transfer skipped a thaw's from-serial
// gets it from a member, as no transfer brings it any more.
func (conf *Config) fetchInstructions(zone string, sd SerialDigest, member, why string) {
	ar, msgQs := conf.InternalMp.AgentRegistry, conf.InternalMp.MsgQs
	if app := tdns.Globals.App.Type; (app != AppTypeMPAgent && app != AppTypeMPAuditor) || ar == nil || ar.LocalAgent == nil || msgQs == nil {
		return
	}
	key := fmt.Sprintf("%s %d %s %s", canonicalName(zone), sd.Serial, sd.Digest, canonicalName(member))
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	if b.fetched == nil {
		b.fetched = map[string]time.Time{}
	}
	if time.Since(b.fetched[key]) < fetchInterval {
		b.mu.Unlock()
		return
	}
	b.fetched[key] = time.Now()
	b.mu.Unlock()
	lg.Info("asking a member for a serial of the zone's instructions this agent lacks", "zone", zone, "serial", sd.Serial, "member", member, "why", why)
	go func() {
		agent, err := ar.GetAgentInfo(AgentId(dns.Fqdn(member)))
		if err != nil {
			lg.Warn("the member asked for the zone's instructions is not known here", "zone", zone, "member", member, "err", err)
			return
		}
		resp, err := requestConfigWith(ar, agent, zone, "instructions", instructionsAsk(sd), msgQs)
		switch {
		case err != nil:
			return // requestConfigWith said why
		case resp == nil:
			return // the time-out is logged
		}
		in, err := instructionsAnswered(zone, sd, resp.ConfigData)
		if err != nil {
			lg.Warn("a member's answer with the zone's instructions is not taken", "zone", zone, "serial", sd.Serial, "member", member, "err", err)
			return
		}
		switch err := conf.InternalMp.Instructions.Hold(zone, in); {
		case err == nil:
			lg.Info("a serial of the zone's instructions is held, fetched from a member", "zone", zone, "serial", sd.Serial, "member", member)
		case errors.Is(err, errHeldAlready):
		default:
			lg.Warn("a serial of the zone's instructions fetched from a member is not kept", "zone", zone, "serial", sd.Serial, "member", member, "err", err)
			return
		}
		conf.askThaw(zone)
	}()
}

// instructionsAsk is the instructions RFI's records: the serial and digest
// asked for.
func instructionsAsk(sd SerialDigest) map[string][]string {
	return map[string][]string{"_serial": {strconv.FormatUint(uint64(sd.Serial), 10)}, "_digest": {sd.Digest}}
}

// instructionsAsked is the serial and digest an instructions RFI asks for.
func instructionsAsked(records map[string][]string) (SerialDigest, error) {
	serial, err := strconv.ParseUint(parseString(records, "_serial"), 10, 32)
	digest := parseString(records, "_digest")
	if err != nil || digest == "" {
		return SerialDigest{}, fmt.Errorf("the request names no serial and digest")
	}
	return SerialDigest{Serial: uint32(serial), Digest: digest}, nil
}

// instructionsAnswer is the answer to an instructions RFI: the instructions
// at a serial as HSYNC3 and HSYNCPARAM records in presentation form, the
// hand-over's form (plan S10).
func instructionsAnswer(zone string, in *Instructions) map[string]string {
	records, _ := json.Marshal(in.instructionRecords(zone))
	return map[string]string{
		"serial":  strconv.FormatUint(uint64(in.Serial), 10),
		"digest":  in.Digest(),
		"records": string(records),
	}
}

// instructionsAnswered reads an answer to an instructions RFI, checked
// against the serial and digest asked for.
func instructionsAnswered(zone string, sd SerialDigest, data map[string]string) (*Instructions, error) {
	if why := data[configRefusedKey]; why != "" {
		return nil, fmt.Errorf("refused: %s", why)
	}
	var records []string
	if err := json.Unmarshal([]byte(data["records"]), &records); err != nil {
		return nil, fmt.Errorf("its records do not decode: %w", err)
	}
	in, err := readInstructionRecords(dns.Fqdn(zone), records)
	if err != nil {
		return nil, fmt.Errorf("its records do not read: %w", err)
	}
	if in == nil || in.Serial != sd.Serial || in.Digest() != sd.Digest {
		return nil, fmt.Errorf("its records do not give %s", sd)
	}
	return in, nil
}

// instructionsLine is the zone's instructions in one line, with its
// transition (thawLine), as the auditor's zone page shows them.
func (conf *Config) instructionsLine(zone string) string {
	st := conf.InternalMp.Instructions.Status(zone)
	if st != nil {
		st.Thaw = conf.thawLine(zone)
	}
	return st.Line()
}

// thawLine is the zone's transition as the status shows it: what the
// restart rule waits for while the active serial is not known (S9), its
// reconciliation's step and what it waits for (plan S12), what the
// agreement waits for, when the last transition was done here, or the
// last thaw made active here; "" with none.
func (conf *Config) thawLine(zone string) string {
	now := time.Now()
	if v, ok := conf.restartView(zone, now); ok {
		return v.line()
	}
	if line := conf.reconcileLine(zone, now); line != "" {
		return line
	}
	if v, ok := conf.thawView(zone, now); ok {
		return v.line()
	}
	if st := conf.InternalMp.Instructions.Status(zone); st != nil && st.Active != nil && !st.DoneAt.IsZero() {
		return fmt.Sprintf("at %d, done since %s", st.Active.Serial, st.DoneAt.Format(time.TimeOnly))
	}
	b := &conf.InternalMp.thaws
	b.mu.Lock()
	defer b.mu.Unlock()
	zt := b.zones[canonicalName(zone)]
	if zt == nil || zt.thawed == nil {
		return ""
	}
	return fmt.Sprintf("thawed to %d at %s by %s", zt.thawed.to, zt.thawed.at.Format(time.TimeOnly), zt.thawed.by)
}

// gateExcused are the members the gate of the group leaves out (design
// 3.2): a leaving voting member excused in a zone of the group, for as long
// as it is not heard, so that the group can elect without it. It affects
// every zone of the group. The excusal ends when it is heard again.
func (conf *Config) gateExcused(groupHash string) []string {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.ProviderGroupManager == nil {
		return nil
	}
	pg := ar.ProviderGroupManager.GetGroup(groupHash)
	if pg == nil {
		return nil
	}
	// An excusal counts while its zone agrees on the serial it was made
	// for: a thaw, a refusal or the owner's newer serial ends it.
	agreed := make(map[string]SerialDigest, len(pg.Zones))
	for _, zone := range pg.Zones {
		if in, ok := conf.InternalMp.Instructions.thawInputs(string(zone)); ok && in.agreed != nil {
			agreed[canonicalName(string(zone))] = in.agreed.SerialDigest
		}
	}
	b := &conf.InternalMp.thaws
	var out []string
	b.mu.Lock()
	for _, zone := range pg.Zones {
		key := canonicalName(string(zone))
		zt := b.zones[key]
		if a, ok := agreed[key]; !ok || zt == nil || zt.agreed != a {
			continue
		}
		for id := range zt.excused {
			if !slices.Contains(out, id) && !ar.isAgentOperational(AgentId(dns.Fqdn(id))) {
				out = append(out, id)
			}
		}
	}
	if b.gate == nil {
		b.gate = map[string]bool{}
	}
	logged := map[string]bool{}
	for _, id := range out {
		key := groupHash + " " + id
		logged[key] = true
		if !b.gate[key] {
			lg.Info("a leaving voting member is excused from the group's gate", "group", shortHash(groupHash), "member", id)
		}
	}
	for key := range b.gate {
		if strings.HasPrefix(key, groupHash+" ") && !logged[key] {
			delete(b.gate, key)
		}
	}
	maps.Copy(b.gate, logged)
	b.mu.Unlock()
	slices.Sort(out)
	return out
}

// withoutExcused is voters without the members excused, compared as
// canonical names. An excusal never leaves no voter: a gate with nobody to
// wait for would open by itself, and stay open when a voter came back.
func withoutExcused(voters, excused []string) []string {
	if len(excused) == 0 {
		return voters
	}
	kept := slices.DeleteFunc(slices.Clone(voters), func(v string) bool { return isAmong(excused, AgentId(v)) })
	if len(kept) == 0 {
		return voters
	}
	return kept
}
