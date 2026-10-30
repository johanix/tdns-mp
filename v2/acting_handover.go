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
 * is combiner_acting.go. The agent hands its signer the same object (plan
 * S11), whose side is signer_acting.go.
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

// wantedHandover is what this agent wants its combiner to act by for the
// zone: the instructions it acts by (its active ones, S3's rule), the
// store's newest serial, phase and step, and the step's sets per purpose
// (plan S13), with the hold while the zone is frozen (S6, folded in by S11):
// a leaving provider stays in each set until its step for that set, so the
// other providers' combiners keep its DNSKEYs and CDS, and its own signer
// signs on, until then (design 5.2). Nil for a zone
// that is not loaded here or not multi-provider, and for one whose active
// serial this agent does not know (S9); one with no records for a zone
// whose instructions are gone (the end of multi-provider service). Nil too
// while a transition may be under way and this agent holds no step's sets:
// its parts get nothing new until the leader's stamp gives it the step
// (design 3.3, plan S12).
func (conf *Config) wantedHandover(zone string) *ActingHandover {
	zone = dns.Fqdn(zone)
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || !mpzd.Options[tdns.OptMultiProvider] || !mpzd.Ready || conf.InternalMp.Instructions.pending(zone) {
		return nil
	}
	if conf.InternalMp.Instructions.activeUnknown(zone) {
		return nil // nothing new until the active serial is known (design 3.3, 3.4)
	}
	h := &ActingHandover{Zone: zone, Phase: PhaseSteady, Made: time.Now()}
	in := mpzd.instructions()
	if in == nil {
		return h
	}
	h.Serial, h.Digest, h.Records, h.Newest = in.Serial, in.Digest(), in.instructionRecords(zone), in.Serial
	h.Sets = mpzd.roles()
	h.Sets.Hold = len(conf.zoneFrozen(zone)) > 0
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
//
// The agent keeps a second one for its signer (plan S11; toSigner): the
// same hand-over goes as a KEYSTATE signal "acting", sent off the caller's
// goroutine, and what the signer holds comes in its inventories, in order
// (learned). Nothing waits for the signer: its gate and its confirmations
// are the combiner's alone.
type handoverTracker struct {
	mu    sync.Mutex
	zones map[string]*zoneHandover
	// sent are the updates let through to the combiner, by distribution,
	// until their final word, with the hand-over the combiner held then.
	sent map[string]*sentUpdate
	// enqueue puts a message on the queue to the combiner, past the gate;
	// for the signer, it sends the hand-over.
	enqueue  func(zone ZoneName, update *ZoneUpdate, distID string) (string, error)
	self     AgentId
	toSigner bool
	// onHeld is told a zone whose part has come to hold what this agent
	// wants it to act by: its step may be held now (plan S12). Nil: none.
	onHeld func(zone string)
}

// resendAfter is how long a hand-over may be in flight before the ticker
// sends it again: handoverResend for the combiner, which confirms it;
// signerHandoverResend for the signer, which does not.
func (t *handoverTracker) resendAfter() time.Duration {
	if t.toSigner {
		return signerHandoverResend
	}
	return handoverResend
}

// part is the part the tracker hands over to, for the log.
func (t *handoverTracker) part() string {
	if t.toSigner {
		return "signer"
	}
	return "combiner"
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
	draining bool      // an update that waited is being queued (drain)
	reset    bool      // the zone's serials were forgotten: a hand-over says so until one that does is confirmed
	resetAt  time.Time // when they were forgotten
}

type waitingUpdate struct {
	zone    ZoneName // as the caller named it
	update  *ZoneUpdate
	distID  string
	removed []string // what the combiner removed on a word that was not final
}

type sentUpdate struct {
	zone    ZoneName // as the caller named it
	update  *ZoneUpdate
	under   *ActingHandover
	at      time.Time
	removed []string // as waitingUpdate's
}

// handoverMaxWaiting is how many updates may wait for a zone's hand-over:
// as many as the queue to the combiner takes. Beyond that the send fails,
// as it does when the queue is full.
const handoverMaxWaiting = 10000

// handoverResend is how long a hand-over may be in flight unconfirmed
// before the ticker hands over again; the queue gives a message up long
// before.
const handoverResend = 5 * time.Minute

// signerHandoverResend is the same for the signer, which confirms nothing:
// a hand-over no inventory since has said it holds goes again after it. The
// KEYSTATE's own confirmation says only that it arrived, and a signal
// dropped on the signer's full queue has one too.
const signerHandoverResend = 30 * time.Second

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
// To the signer it goes off the caller's goroutine, which may be a
// refresh's: the send waits for the signer's answer.
func (t *handoverTracker) send(hs *handoverSend) {
	if hs == nil {
		return
	}
	if t.toSigner {
		go t.deliver(hs)
		return
	}
	t.deliver(hs)
}

func (t *handoverTracker) deliver(hs *handoverSend) {
	h := hs.h
	if _, err := t.enqueue(ZoneName(h.Zone), &ZoneUpdate{Zone: ZoneName(h.Zone), AgentId: t.self, Acting: h}, hs.distID); err != nil {
		lgEngine.Warn("the hand-over to the "+t.part()+" could not be sent; tried again on the ticker", "zone", h.Zone, "serial", h.Serial, "err", err)
		t.mu.Lock()
		if z := t.zone(h.Zone); z.flightID == hs.distID {
			z.flightID, z.flight = "", nil
		}
		t.mu.Unlock()
		return
	}
	lgEngine.Info("handing the "+t.part()+" the serial it acts by", "zone", h.Zone, "handover", h.String(), "distrib", hs.distID)
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
// and goes out when it does (waiting true); so does one that would overtake
// updates still waiting. One that goes out now is noted, with what the
// combiner holds, for the rule on its final word (confirmation). A zone
// this agent has handed nothing yet, such as one not loaded, is not held
// up.
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
	if !z.want.sameAs(z.held) || z.draining || len(z.waiting) > 0 {
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
// final, and nor is one from a combiner that says it acts by another
// serial than the one the update was sent under (acting, plan S8): the
// update is sent again, under the serial wanted. What the combiner removed
// in such a word is gone whatever the serial, and its answer to the update
// sent again cannot name it, since it no longer holds it: the removed
// records are kept with the update and returned with the final word, which
// names them (carried). handled says the word goes no further.
func (t *handoverTracker) confirmation(distID string, status transport.ConfirmStatus, acting *ActingStamp, removed []string) (handled bool, carried []string) {
	if t == nil || status == transport.ConfirmPending {
		return t != nil && t.isHandover(distID), nil
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
			return true, nil
		}
		// a forget is told until a hand-over that tells it is confirmed
		z.held, z.heldAt, z.reset = h, time.Now(), z.reset && !h.Reset
		waiting := len(z.waiting)
		// the agent may want something else by now, and not have sent it
		// while this was in flight
		send := t.dueLocked(z, false)
		t.mu.Unlock()
		lgEngine.Info("the combiner acts by the serial handed", "zone", zone, "handover", h.String(), "waiting", waiting)
		t.drain(zone)
		t.send(send)
		t.told(zone)
		return true, nil
	}
	s := t.sent[distID]
	if s == nil {
		t.mu.Unlock()
		return false, nil
	}
	delete(t.sent, distID)
	z := t.zones[handoverKey(string(s.zone))]
	stale := z != nil && z.want != nil && (!z.want.sameAs(s.under) || acting != nil && !acting.names(s.under))
	t.mu.Unlock()
	switch status {
	case transport.ConfirmFailed, transport.ConfirmRejected, transport.ConfirmIgnored, transport.ConfirmPartial:
	default:
		return false, s.removed
	}
	if !stale {
		return false, s.removed
	}
	lgEngine.Info("the combiner's word on an update sent under another serial is not final: sending it again", "zone", s.zone, "distrib", distID, "status", status.String(), "sentUnder", s.under.String())
	// it waits behind what waits already, and goes out as they do
	key := handoverKey(string(s.zone))
	t.mu.Lock()
	z = t.zone(key)
	z.waiting = append(z.waiting, waitingUpdate{zone: s.zone, update: s.update, distID: distID, removed: append(slices.Clip(s.removed), removed...)})
	t.mu.Unlock()
	t.drain(key)
	return true, nil
}

// unsent forgets an update the gate let through and the queue then
// refused: no final word on it will come.
func (t *handoverTracker) unsent(distID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.sent, distID)
	t.mu.Unlock()
}

// drain queues the updates that wait for the zone, in order, once the
// combiner holds what this agent wants. Each is noted as sent before it is
// queued, under what the combiner holds; while one is being queued every
// new update waits behind it (gate). One the queue refuses stays first, and
// the ticker drains again.
func (t *handoverTracker) drain(zone string) {
	if t == nil {
		return
	}
	key := handoverKey(zone)
	for {
		t.mu.Lock()
		z := t.zones[key]
		if z == nil || z.draining || len(z.waiting) == 0 || z.want == nil || !z.want.sameAs(z.held) {
			t.mu.Unlock()
			return
		}
		w := z.waiting[0]
		z.draining = true
		t.sent[w.distID] = &sentUpdate{zone: w.zone, update: w.update, under: z.held, at: time.Now(), removed: w.removed}
		t.mu.Unlock()
		_, err := t.enqueue(w.zone, w.update, w.distID)
		t.mu.Lock()
		z.draining = false
		if err != nil {
			delete(t.sent, w.distID)
			t.mu.Unlock()
			lgEngine.Warn("an update that waited for the combiner's hand-over could not be queued; tried again on the ticker", "zone", zone, "distrib", w.distID, "err", err)
			return
		}
		z.waiting = z.waiting[1:]
		t.mu.Unlock()
	}
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
// read (EDITS): nothing, or what it was handed. An answer older than what
// a confirmation said since is kept out: the combiner's hand-overs only go
// forward, and its start report says when it lost them. A combiner that
// holds what this agent wants gets nothing again, and what waited goes out.
//
// For the signer it is what its latest inventory says it holds: taken as
// it is, since its inventories are recorded in order (noteKeyInventory) and
// one that names nothing is the signer saying it lost what it held (plan
// S11). A signer that holds nothing holds a hand-over of no instructions.
func (t *handoverTracker) learned(zone string, held *ActingHandover) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	if !t.toSigner && z.held != nil && (held == nil || held.olderThan(z.held)) {
		t.mu.Unlock()
		lgEngine.Debug("an answer older than the combiner's confirmation, not taken", "zone", zone, "answer", held.String(), "held", z.held.String())
		return
	}
	if t.toSigner && held == nil && z.want != nil && len(z.want.Records) == 0 {
		held = z.want
	}
	z.held = held
	holds := z.want != nil && z.want.sameAs(held)
	if holds {
		z.heldAt = time.Now()
	}
	// the signer confirms nothing: a forget is told until an inventory
	// says it holds a hand-over, made since, that told it
	if t.toSigner && held != nil && held.Reset && !held.Made.Before(z.resetAt) {
		z.reset = false
	}
	send := t.dueLocked(z, false)
	t.mu.Unlock()
	t.drain(zone)
	t.send(send)
	if holds {
		t.told(zone)
	}
}

// told tells onHeld that the part holds what is wanted for the zone.
func (t *handoverTracker) told(zone string) {
	if t.onHeld != nil {
		t.onHeld(zone)
	}
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

// again: the part is to say again what it holds for the zone. The combiner
// holds no hand-over for it, and says so every minute until it does (its
// start report's repeat); or the signer is to confirm its hold for the
// serial the zone agrees on now (onFreeze, plan S6). The zone is handed over
// again; what the part holds for the others stands.
func (t *handoverTracker) again(zone string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	z.held = nil
	send := t.dueLocked(z, true)
	t.mu.Unlock()
	t.send(send)
}

// letHoldGo: the zone's freeze has ended. A zone this agent hands nothing
// any more, as one that left the configuration, is handed what was wanted
// last without the hold, so that its signer's key machine is not held for
// ever (plan S6).
func (t *handoverTracker) letHoldGo(zone string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zones[handoverKey(zone)]
	if z == nil || z.want == nil || !z.want.Sets.Hold {
		t.mu.Unlock()
		return
	}
	h := *z.want
	h.Sets.Hold = false
	z.want = &h
	send := t.dueLocked(z, false)
	t.mu.Unlock()
	t.send(send)
}

// holdLast: this agent knows no active serial for the zone, so it hands
// its parts nothing new (design 3.3, 3.4), and nothing new starts at its
// signer either (the project owner, 2026-10-29): the signer is handed what
// it holds, or failing that what this agent last wanted it to hold, with
// the hold set and its sets as they are. Nothing when neither carries
// instructions: a signer that holds nothing acts by nothing (rule 5), and
// its inventory says what it holds when it has something (learned).
func (t *handoverTracker) holdLast(zone string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	base := z.held
	if base == nil {
		base = z.want
	}
	if base == nil || len(base.Records) == 0 {
		t.mu.Unlock()
		return
	}
	h := *base
	h.Sets.Hold = true
	if h.sameAs(z.want) {
		t.mu.Unlock()
		return
	}
	z.want = &h
	send := t.dueLocked(z, false)
	t.mu.Unlock()
	t.send(send)
}

// holdHeld: the part holds what is wanted for the zone, and that carries
// the hold.
func (t *handoverTracker) holdHeld(zone string) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	z := t.zones[handoverKey(zone)]
	return z != nil && z.want != nil && z.want.Sets.Hold && z.want.sameAs(z.held)
}

// forgot: the operator forgot the zone's serials here (rule 3). The next
// hand-over says so, and the combiner takes it whatever serial it holds.
func (t *handoverTracker) forgot(zone string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	z := t.zone(zone)
	z.reset, z.resetAt, z.held = true, time.Now(), nil
	t.mu.Unlock()
}

// tick hands over again where the part does not hold what is wanted and
// nothing has been in flight for resendAfter, drains what still waits,
// and forgets what was sent a day ago and never answered: the queue has
// given it up by then.
func (t *handoverTracker) tick() {
	if t == nil {
		return
	}
	t.mu.Lock()
	var sends []*handoverSend
	var drains []string
	for key, z := range t.zones {
		// a failed send to the combiner goes again at once; to the signer,
		// as an unanswered one: its inventory at its start asks sooner
		failed := z.flight == nil && !t.toSigner
		if failed || time.Since(z.flightAt) > t.resendAfter() {
			sends = append(sends, t.dueLocked(z, true))
		}
		if len(z.waiting) > 0 {
			drains = append(drains, key)
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
	for _, key := range drains {
		t.drain(key)
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

// handOverToParts hands the agent's combiner and its signer what the
// agent wants them to act by for the zone: at every refresh, the first
// load's included, and whenever the sets change (onSetsChanged).
func (conf *Config) handOverToParts(zone string) {
	t, ts := conf.InternalMp.Handover, conf.InternalMp.SignerHandover
	if t == nil && ts == nil {
		return
	}
	h := conf.wantedHandover(zone)
	t.handOver(h)
	// frozen and handed nothing new: the active serial is not known (S9),
	// or no step's sets are held yet (S12)
	if s := conf.InternalMp.Instructions; h == nil && (s.activeUnknown(zone) || s.pending(zone)) {
		ts.holdLast(zone)
		return
	}
	ts.handOver(h)
}

// startHandovers sets up the agent's side of the hand-over: when the agent
// names a combiner, the tracker every send to the combiner passes
// (EnqueueForCombiner); when it names a signer, the signer's (plan S11);
// and their tickers.
func (conf *Config) startHandovers(ctx context.Context, tm *MPTransportBridge) {
	mp := conf.MpConfig()
	if tm == nil || mp == nil {
		return
	}
	var trackers []*handoverTracker
	if conf.namesCombiner() {
		t := newHandoverTracker(AgentId(mp.Identity), tm.enqueueToCombiner)
		t.onHeld = conf.askThaw
		conf.InternalMp.Handover, tm.handover = t, t
		trackers = append(trackers, t)
	}
	if tm.signerID != "" {
		t := newHandoverTracker(AgentId(mp.Identity), tm.sendActingToSigner)
		t.toSigner, t.onHeld = true, conf.askThaw
		conf.InternalMp.SignerHandover = t
		trackers = append(trackers, t)
	}
	for _, t := range trackers {
		go t.run(ctx)
	}
}

// run ticks the tracker five times in each resendAfter, so a hand-over due
// goes again within a fifth of it: the combiner's every minute.
func (t *handoverTracker) run(ctx context.Context) {
	ticker := time.NewTicker(t.resendAfter() / 5)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.tick()
		}
	}
}

// fromCombiner: the STATUS-UPDATE's sender is this agent's combiner.
func (conf *Config) fromCombiner(sender string) bool {
	tm := conf.InternalMp.MPTransport
	return tm != nil && tm.combinerID != "" && core.EqualNames(dns.Fqdn(sender), dns.Fqdn(string(tm.combinerID)))
}
