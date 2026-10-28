/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The hand-over (design 3.5 and rule 5, plan S10): an agent hands its
 * combiner the serial of the owner's instructions it acts by, those
 * instructions as records, and the current step's sets, and the combiner
 * acts by what it was handed, not by its own copy of the zone. So a
 * combiner whose copy lags its agent's judges nothing by the old copy
 * (tdns-mp #235). This file holds the object and the agent's side: what it
 * wants its combiner to act by, what the combiner holds, the hand-over in
 * flight, and what waits until the combiner holds it. The combiner's side
 * is combiner_acting.go.
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ActingHandover is what an agent hands its combiner for one zone: the
// serial it acts by with its digest, its instructions as HSYNC3 and
// HSYNCPARAM records in presentation form (instructionRecords), and the
// current step's sets per purpose, each provider by label and identity. It
// rides on an update with no operations, through the confirmed queue.
type ActingHandover struct {
	Zone    string   `json:"zone"`
	Serial  uint32   `json:"serial"`
	Digest  string   `json:"digest"`
	Records []string `json:"records,omitempty"` // none: the zone has no instructions any more
	// The order key, with Serial: the newest serial the agent holds, the
	// phase and the step (S12 fills the steps). Made breaks a tie between
	// two hand-overs of one key that hand different things.
	Newest uint32    `json:"newest"`
	Phase  string    `json:"phase,omitempty"`
	Step   int       `json:"step,omitempty"`
	Sets   Roles     `json:"sets"`
	Made   time.Time `json:"made"`
	// Reset: the agent forgot the zone's serials (rule 3's forget command)
	// and the combiner takes this whatever serial it holds.
	Reset bool `json:"reset,omitempty"`
	// Refresh asks the combiner to refresh the zone from its upstream (the
	// fetch down the provider's chain, design 3.1; S5a asks for it).
	Refresh bool `json:"refresh,omitempty"`
}

// String names the hand-over by its serial, digest and step, for the log
// and the status.
func (h *ActingHandover) String() string {
	if h == nil {
		return "nothing"
	}
	if len(h.Records) == 0 {
		return "no instructions"
	}
	s := fmt.Sprintf("%d (%s)", h.Serial, h.Digest)
	if h.Step > 0 {
		s += fmt.Sprintf(", step %d", h.Step)
	}
	return s
}

// phaseRank orders two hand-overs of one pair of serials: a step of the
// reconciliation comes before the transition's "done" (S12).
func phaseRank(phase string) int {
	if phase == PhaseReconciling {
		return 0
	}
	return 1
}

// sameAs: h and o hand the same serial, instructions, phase, step and sets.
// When either was made, and its flags, do not count.
func (h *ActingHandover) sameAs(o *ActingHandover) bool {
	if h == nil || o == nil {
		return h == o
	}
	if h.Serial != o.Serial || h.Digest != o.Digest || h.Newest != o.Newest || h.Phase != o.Phase || h.Step != o.Step || len(h.Records) != len(o.Records) {
		return false
	}
	// The sets as they travel: a set that is empty and one that is nil
	// are the same set.
	a, _ := json.Marshal(h.Sets)
	b, _ := json.Marshal(o.Sets)
	return bytes.Equal(a, b)
}

// olderThan: h is below held by the order key (the active serial, the
// newest, the phase and the step), or of the same key, handing something
// else, and made before it. A serial in RFC 1982's undefined half of the
// one held is not newer. A hand-over after a forget, or of no instructions,
// is judged by when it was made alone: the agent's serials started again.
func (h *ActingHandover) olderThan(held *ActingHandover) bool {
	switch {
	case held == nil:
		return false
	case h.Reset || len(h.Records) == 0:
		return h.Made.Before(held.Made)
	case h.Serial != held.Serial:
		return CompareSerial(h.Serial, held.Serial) != 1
	case h.Newest != held.Newest:
		return CompareSerial(h.Newest, held.Newest) != 1
	case phaseRank(h.Phase) != phaseRank(held.Phase):
		return phaseRank(h.Phase) < phaseRank(held.Phase)
	case h.Step != held.Step:
		return h.Step < held.Step
	case h.sameAs(held):
		return false
	}
	return h.Made.Before(held.Made)
}

// signingProviders are the zone's signing set as a set of providers: those
// signers= names, then those leaving it (#275), each with the identity of
// its ON record ("" for none).
func (mpzd *MPZoneData) signingProviders() []Provider {
	set := mpzd.signingSet()
	out := []Provider{}
	for _, label := range mpzd.signingLabels() {
		out = append(out, Provider{Label: label, Identity: set[label]})
	}
	return out
}

// actingSets are the sets a hand-over carries for the zone as mpzd reads
// it: its roles, with the key, DS and signing sets its signing set (#275).
func (mpzd *MPZoneData) actingSets() Roles {
	r := mpzd.roles()
	signing := mpzd.signingProviders()
	r.KeySigners, r.DSSigners, r.Signing = signing, slices.Clone(signing), slices.Clone(signing)
	return r
}

// wantedHandover is what this agent wants its combiner to act by for the
// zone: the instructions it acts by (until S7 its copy's, S3's rule), the
// store's newest serial, phase and step, and the step's sets. Until S13 the
// sets of whose DNSKEYs and DS are published, and of who signs, are the
// zone's signing set, signers= with the providers leaving it (#275): so the
// other providers' combiners keep a leaving signer's DNSKEYs and CDS while
// it signs on, until the owner removes its HSYNC3 record. Nil for a zone
// that is not loaded here or not multi-provider; one with no records for a
// zone whose instructions are gone (the end of multi-provider service).
func (conf *Config) wantedHandover(zone string) *ActingHandover {
	zone = dns.Fqdn(zone)
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || !mpzd.Options[tdns.OptMultiProvider] || !mpzd.Ready {
		return nil
	}
	h := &ActingHandover{Zone: zone, Phase: PhaseSteady, Made: time.Now()}
	in := mpzd.instructions()
	if in == nil {
		return h
	}
	h.Serial, h.Digest, h.Records, h.Newest = in.Serial, in.Digest(), in.instructionRecords(zone), in.Serial
	h.Sets = mpzd.actingSets()
	if st := conf.InternalMp.Instructions.Status(zone); st != nil {
		h.Phase = st.Phase
		if st.Newest != nil && CompareSerial(st.Newest.Serial, h.Newest) == 1 {
			h.Newest = st.Newest.Serial
		}
	}
	_, _, h.Step = instrStore.Load().transition(zone)
	return h
}

// handoverTracker is the agent's side of the hand-over, per zone (plan S10):
// the hand-over it wants its combiner to act by, what the combiner holds,
// the hand-over in flight, and the updates that wait until the combiner
// holds what this agent wants. Every send to the combiner passes its gate
// (EnqueueForCombiner). Nil on every role but the agent's.
type handoverTracker struct {
	mu    sync.Mutex
	zones map[string]*zoneHandover
	// sent are the updates let through to the combiner, by distribution,
	// until their final word, with the hand-over the combiner held then.
	sent map[string]*sentUpdate
	// enqueue puts a message on the queue to the combiner, past the gate.
	enqueue func(zone ZoneName, update *ZoneUpdate, distID string) (string, error)
	self    AgentId
}

type zoneHandover struct {
	want *ActingHandover // what the combiner is to act by
	held *ActingHandover // what it holds, by its confirmation or its answer to an own read; nil: not known
	// The hand-over in flight: its distribution, what it hands, and when it
	// went on the queue.
	flightID string
	flight   *ActingHandover
	flightAt time.Time
	heldAt   time.Time // when the combiner was last known to hold want
	waiting  []waitingUpdate
	reset    bool // the zone's serials were forgotten: the next hand-over says so
}

type waitingUpdate struct {
	zone   ZoneName // as the caller named it
	update *ZoneUpdate
	distID string
}

type sentUpdate struct {
	zone   ZoneName // as the caller named it
	update *ZoneUpdate
	under  *ActingHandover
	at     time.Time
}

// handoverMaxWaiting is how many updates may wait for a zone's hand-over:
// as many as the queue to the combiner takes. Beyond that the send fails,
// as it does when the queue is full.
const handoverMaxWaiting = 10000

// handoverResend is how long a hand-over may be in flight unconfirmed
// before the ticker hands over again; the queue gives a message up long
// before.
const handoverResend = 5 * time.Minute

func newHandoverTracker(self AgentId, enqueue func(ZoneName, *ZoneUpdate, string) (string, error)) *handoverTracker {
	return &handoverTracker{zones: map[string]*zoneHandover{}, sent: map[string]*sentUpdate{}, enqueue: enqueue, self: self}
}

// handOver makes h what the combiner is to act by for its zone, and sends it
// unless the combiner holds it or it is in flight already.
func (t *handoverTracker) handOver(h *ActingHandover) {
	if t == nil || h == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(h.Zone)
	z.want = h
	send := t.dueLocked(z, false)
	t.mu.Unlock()
	t.send(send)
}

// handoverSend is a hand-over due, with the distribution it goes under.
type handoverSend struct {
	h      *ActingHandover
	distID string
}

// dueLocked is the hand-over to send for z now, nil when none is due: the
// combiner holds what is wanted, or it is in flight (unless again, a
// resend, which the ticker and a combiner's start ask for).
func (t *handoverTracker) dueLocked(z *zoneHandover, again bool) *handoverSend {
	if z.want == nil || z.want.sameAs(z.held) {
		return nil
	}
	if !again && z.want.sameAs(z.flight) {
		return nil
	}
	h := *z.want
	h.Made = time.Now()
	h.Reset = z.reset
	h.Refresh = false
	z.flight, z.flightID, z.flightAt = &h, transport.GenerateDistributionID(), time.Now()
	return &handoverSend{h: &h, distID: z.flightID}
}

// send puts the hand-over on the queue to the combiner, ahead of nothing
// that waits for it: the queue sends one recipient's messages in order. One
// that could not be queued is in flight no more, and the ticker sends it.
func (t *handoverTracker) send(hs *handoverSend) {
	if hs == nil {
		return
	}
	h := hs.h
	if _, err := t.enqueue(ZoneName(h.Zone), &ZoneUpdate{Zone: ZoneName(h.Zone), AgentId: t.self, Acting: h}, hs.distID); err != nil {
		lgEngine.Warn("the hand-over to the combiner could not be queued; tried again on the ticker", "zone", h.Zone, "serial", h.Serial, "err", err)
		t.mu.Lock()
		if z := t.zone(h.Zone); z.flightID == hs.distID {
			z.flightID, z.flight = "", nil
		}
		t.mu.Unlock()
		return
	}
	lgEngine.Info("handing the combiner the serial it acts by", "zone", h.Zone, "handover", h.String(), "distrib", hs.distID)
}

func (t *handoverTracker) zone(zone string) *zoneHandover {
	key := handoverKey(zone)
	z := t.zones[key]
	if z == nil {
		z = &zoneHandover{}
		t.zones[key] = z
	}
	return z
}

// gate is EnqueueForCombiner's check: nothing goes to the combiner under a
// serial and step it has not confirmed holding (plan S10). An update for a
// zone whose combiner does not hold what this agent wants waits, in order,
// and goes out when it does (waiting true). One that goes out now is noted,
// with what the combiner holds, for the rule on its final word
// (confirmation). A zone this agent has handed nothing yet, such as one not
// loaded, is not held up.
func (t *handoverTracker) gate(zone ZoneName, update *ZoneUpdate, distID string) (waiting bool, err error) {
	if t == nil || update == nil || update.Acting != nil {
		return false, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	z := t.zones[handoverKey(string(zone))]
	if z == nil || z.want == nil {
		return false, nil
	}
	if !z.want.sameAs(z.held) {
		if len(z.waiting) >= handoverMaxWaiting {
			return false, fmt.Errorf("%d updates for zone %s wait for the combiner to hold serial %d", len(z.waiting), zone, z.want.Serial)
		}
		z.waiting = append(z.waiting, waitingUpdate{zone: zone, update: update, distID: distID})
		lgEngine.Debug("an update waits until the combiner holds the serial this agent acts by", "zone", zone, "distrib", distID, "serial", z.want.Serial)
		return true, nil
	}
	t.sent[distID] = &sentUpdate{zone: zone, update: update, under: z.held, at: time.Now()}
	return false, nil
}

// confirmation is the combiner's final word on a distribution, before it
// goes on (OnConfirmationReceived). The word on a hand-over is the
// tracker's alone: a success means the combiner holds it, and what waited
// goes out, in order; anything else is a refusal, and the combiner's own
// read says what it holds. A refusal or an "ignored" of an update sent
// while the combiner held another serial than this agent now wants is not
// final: the update is sent again, under the serial wanted. handled says
// the word goes no further.
func (t *handoverTracker) confirmation(distID string, status transport.ConfirmStatus) (handled bool) {
	if t == nil || status == transport.ConfirmPending {
		return t != nil && t.isHandover(distID)
	}
	t.mu.Lock()
	for zone, z := range t.zones {
		if z.flightID != distID {
			continue
		}
		h := z.flight
		z.flightID, z.flight = "", nil
		if status != transport.ConfirmSuccess {
			z.held = nil
			t.mu.Unlock()
			lgEngine.Warn("the combiner refused the hand-over; its own read says what it holds", "zone", zone, "handover", h.String(), "status", status.String())
			return true
		}
		z.held, z.heldAt, z.reset = h, time.Now(), false
		var release []waitingUpdate
		if z.want.sameAs(h) {
			release, z.waiting = z.waiting, nil
		}
		// the agent may want something else by now, and not have sent it
		// while this was in flight
		send := t.dueLocked(z, false)
		t.mu.Unlock()
		lgEngine.Info("the combiner acts by the serial handed", "zone", zone, "handover", h.String(), "released", len(release))
		for _, w := range release {
			if _, err := t.enqueueThrough(w.zone, w.update, w.distID); err != nil {
				lgEngine.Error("an update that waited for the combiner's hand-over could not be queued", "zone", zone, "distrib", w.distID, "err", err)
			}
		}
		t.send(send)
		return true
	}
	s := t.sent[distID]
	if s == nil {
		t.mu.Unlock()
		return false
	}
	delete(t.sent, distID)
	z := t.zones[handoverKey(string(s.zone))]
	stale := z != nil && z.want != nil && !z.want.sameAs(s.under)
	t.mu.Unlock()
	switch status {
	case transport.ConfirmFailed, transport.ConfirmRejected, transport.ConfirmIgnored, transport.ConfirmPartial:
	default:
		return false
	}
	if !stale {
		return false
	}
	lgEngine.Info("the combiner's word on an update sent under another serial is not final: sending it again", "zone", s.zone, "distrib", distID, "status", status.String(), "sentUnder", s.under.String())
	if _, err := t.enqueueThrough(s.zone, s.update, distID); err != nil {
		lgEngine.Error("an update the combiner judged under another serial could not be sent again", "zone", s.zone, "distrib", distID, "err", err)
		return false
	}
	return true
}

// enqueueThrough sends an update through the gate, as EnqueueForCombiner.
func (t *handoverTracker) enqueueThrough(zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
	if waiting, err := t.gate(zone, update, distID); waiting || err != nil {
		return distID, err
	}
	return t.enqueue(zone, update, distID)
}

func (t *handoverTracker) isHandover(distID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, z := range t.zones {
		if z.flightID == distID {
			return true
		}
	}
	return false
}

// learned is what the combiner holds for the zone by its answer to an own
// read (EDITS): nothing, or what it was handed. A combiner that holds what
// this agent wants gets nothing again, and what waited goes out.
func (t *handoverTracker) learned(zone string, held *ActingHandover) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	z.held = held
	var release []waitingUpdate
	if z.want != nil && z.want.sameAs(held) {
		z.heldAt = time.Now()
		release, z.waiting = z.waiting, nil
	}
	send := t.dueLocked(z, false)
	t.mu.Unlock()
	for _, w := range release {
		if _, err := t.enqueueThrough(w.zone, w.update, w.distID); err != nil {
			lgEngine.Error("an update that waited for the combiner's hand-over could not be queued", "zone", zone, "distrib", w.distID, "err", err)
		}
	}
	t.send(send)
}

// combinerStarted: the combiner reports a start. What it held before is
// not known now, so every zone is handed over again.
func (t *handoverTracker) combinerStarted() {
	if t == nil {
		return
	}
	t.mu.Lock()
	var sends []*handoverSend
	for _, z := range t.zones {
		z.held = nil
		sends = append(sends, t.dueLocked(z, true))
	}
	t.mu.Unlock()
	for _, hs := range sends {
		t.send(hs)
	}
}

// forgot: the operator forgot the zone's serials here (rule 3). The next
// hand-over says so, and the combiner takes it whatever serial it holds.
func (t *handoverTracker) forgot(zone string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	z.reset, z.held = true, nil
	t.mu.Unlock()
}

// tick hands over again where the combiner does not hold what is wanted and
// nothing has been in flight for handoverResend, and forgets what was sent a
// day ago and never answered: the queue has given it up by then.
func (t *handoverTracker) tick() {
	if t == nil {
		return
	}
	t.mu.Lock()
	var sends []*handoverSend
	for _, z := range t.zones {
		if z.flight == nil || time.Since(z.flightAt) > handoverResend {
			sends = append(sends, t.dueLocked(z, true))
		}
	}
	for id, s := range t.sent {
		if time.Since(s.at) > noteMaxAge {
			delete(t.sent, id)
		}
	}
	t.mu.Unlock()
	for _, hs := range sends {
		t.send(hs)
	}
}

// statusLine is what this agent knows of its combiner's hand-over for the
// zone, for `agent parentsync status`; "" for a zone it hands nothing.
func (t *handoverTracker) statusLine(zone string) string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	z := t.zones[handoverKey(zone)]
	if z == nil || z.want == nil {
		return ""
	}
	if z.want.sameAs(z.held) {
		return fmt.Sprintf("acting by %s, as handed; known since %s", z.held, z.heldAt.Format(time.TimeOnly))
	}
	line := fmt.Sprintf("handing it %s", z.want)
	if z.held != nil {
		line += fmt.Sprintf("; it acts by %s", z.held)
	}
	if z.flight != nil {
		line += fmt.Sprintf("; in flight since %s", z.flightAt.Format(time.TimeOnly))
	}
	if n := len(z.waiting); n > 0 {
		line += fmt.Sprintf("; %d updates wait for it", n)
	}
	return line
}

// handOverToCombiner hands the agent's combiner what the agent wants it to
// act by for the zone: at every refresh, the first load's included, and
// whenever the sets change (onSetsChanged).
func (conf *Config) handOverToCombiner(zone string) {
	t := conf.InternalMp.Handover
	if t == nil {
		return
	}
	t.handOver(conf.wantedHandover(zone))
}

// startHandovers sets up the agent's side of the hand-over when the agent
// names a combiner: the tracker, which every send to the combiner passes
// (EnqueueForCombiner), and its slow ticker.
func (conf *Config) startHandovers(ctx context.Context, tm *MPTransportBridge) {
	mp := conf.MpConfig()
	if tm == nil || mp == nil || !conf.namesCombiner() {
		return
	}
	t := newHandoverTracker(AgentId(mp.Identity), tm.enqueueToCombiner)
	conf.InternalMp.Handover, tm.handover = t, t
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.tick()
			}
		}
	}()
}

// fromCombiner: the STATUS-UPDATE's sender is this agent's combiner.
func (conf *Config) fromCombiner(sender string) bool {
	tm := conf.InternalMp.MPTransport
	return tm != nil && tm.combinerID != "" && core.EqualNames(dns.Fqdn(sender), dns.Fqdn(string(tm.combinerID)))
}
