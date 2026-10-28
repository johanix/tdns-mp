/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Plan S10, the agent's side: it hands its combiner what it acts by, and
// sends it nothing under a serial the combiner has not confirmed holding.

// handedQueue is what a tracker put on the queue to the combiner, in order.
type handedQueue struct {
	mu   sync.Mutex
	msgs []handedMsg
}

type handedMsg struct {
	distID string
	update *ZoneUpdate
}

func (q *handedQueue) enqueue(_ ZoneName, u *ZoneUpdate, distID string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.msgs = append(q.msgs, handedMsg{distID: distID, update: u})
	return distID, nil
}

func (q *handedQueue) take() []handedMsg {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.msgs
	q.msgs = nil
	return out
}

func newTestTracker() (*handoverTracker, *handedQueue) {
	q := &handedQueue{}
	return newHandoverTracker(actUs, q.enqueue), q
}

// wantOf is a hand-over of serial for zone, its sets naming signers.
func wantOf(zone string, serial uint32, signers ...string) *ActingHandover {
	h := &ActingHandover{Zone: zone, Serial: serial, Digest: "d", Records: []string{"x"}, Newest: serial, Phase: PhaseSteady, Made: time.Now()}
	for _, s := range signers {
		h.Sets.KeySigners = append(h.Sets.KeySigners, Provider{Label: s, Identity: "agent." + s + ".example."})
	}
	return h
}

func update(zone string) *ZoneUpdate {
	return &ZoneUpdate{Zone: ZoneName(zone), Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}}
}

// The one hand-over in a batch of queued messages.
func handoverIn(t *testing.T, msgs []handedMsg) handedMsg {
	t.Helper()
	var found []handedMsg
	for _, m := range msgs {
		if m.update.Acting != nil {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d hand-overs queued, want one: %+v", len(found), msgs)
	}
	return found[0]
}

// Nothing goes to the combiner under a serial it has not confirmed holding:
// an update waits behind the hand-over in flight; a zone the agent has handed
// nothing yet is not held up.
func TestTheAgentSendsNothingToItsCombinerUnderASerialItDoesNotHold(t *testing.T) {
	const zone = "gate.acting.example."
	tr, q := newTestTracker()
	if waiting, err := tr.gate(ZoneName(zone), update(zone), "u0"); waiting || err != nil {
		t.Fatalf("a zone handed nothing yet held an update: waiting=%v err=%v", waiting, err)
	}
	tr.handOver(wantOf(zone, 7, "alpha"))
	handoverIn(t, q.take())
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u1"); !waiting {
		t.Error("an update went to the combiner under a serial it has not confirmed holding")
	}
	if waiting, _ := tr.gate(ZoneName("other."+zone), update("other."+zone), "u2"); waiting {
		t.Error("an update of another zone waits for this zone's hand-over")
	}
	if line := tr.statusLine(zone); line == "" {
		t.Error("the status says nothing of the hand-over in flight")
	}
}

// When the combiner confirms the hand-over, what waited goes out in the
// order it was sent.
func TestWhatWaitedForTheCombinerGoesOutInOrderWhenItHolds(t *testing.T) {
	const zone = "order.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 7, "alpha"))
	h := handoverIn(t, q.take())
	for _, id := range []string{"u1", "u2", "u3"} {
		tr.gate(ZoneName(zone), update(zone), id)
	}
	if len(q.take()) != 0 {
		t.Fatal("updates went out before the combiner confirmed the hand-over")
	}
	if !tr.confirmation(h.distID, transport.ConfirmSuccess) {
		t.Error("the hand-over's confirmation went on past the tracker")
	}
	var got []string
	for _, m := range q.take() {
		got = append(got, m.distID)
	}
	if len(got) != 3 || got[0] != "u1" || got[1] != "u2" || got[2] != "u3" {
		t.Errorf("released %v, want u1 u2 u3 in order", got)
	}
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u4"); waiting {
		t.Error("an update waits though the combiner holds the serial")
	}
}

// A refused hand-over is not taken as held: the gate stays shut and the
// ticker hands over again; once confirmed, nothing is handed again.
func TestTheAgentHandsAgainUntilItsCombinerHolds(t *testing.T) {
	const zone = "again.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 7, "alpha"))
	first := handoverIn(t, q.take())
	tr.confirmation(first.distID, transport.ConfirmFailed)
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u1"); !waiting {
		t.Error("an update went out after the combiner refused the hand-over")
	}
	tr.tick()
	second := handoverIn(t, q.take())
	if second.distID == first.distID {
		t.Error("the hand-over went again under the refused distribution")
	}
	tr.confirmation(second.distID, transport.ConfirmSuccess)
	q.take()
	tr.tick()
	for _, m := range q.take() {
		if m.update.Acting != nil {
			t.Error("the ticker handed over again what the combiner holds")
		}
	}
}

// The combiner's answer to an own read says what it holds: the agent hands
// nothing it holds, and hands what it lacks.
func TestTheAgentLearnsWhatItsCombinerHoldsFromTheOwnRead(t *testing.T) {
	const zone = "learned.acting.example."
	tr, q := newTestTracker()
	want := wantOf(zone, 7, "alpha")
	tr.learned(zone, want)
	tr.handOver(want)
	if msgs := q.take(); len(msgs) != 0 {
		t.Errorf("the combiner holds what is wanted, and the agent sent %d messages", len(msgs))
	}
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u1"); waiting {
		t.Error("an update waits though the own read says the combiner holds the serial")
	}

	const behind = "behind.acting.example."
	tr.handOver(wantOf(behind, 8, "alpha"))
	first := handoverIn(t, q.take())
	tr.gate(ZoneName(behind), update(behind), "u2")
	tr.learned(behind, wantOf(behind, 8, "alpha"))
	got := q.take()
	if len(got) != 1 || got[0].distID != "u2" {
		t.Errorf("the own read says the combiner holds the serial: released %+v, want u2", got)
	}
	tr.confirmation(first.distID, transport.ConfirmSuccess)
	tr.learned(behind, wantOf(behind, 7, "alpha"))
	handoverIn(t, q.take())
}

// A refusal or an "ignored" of an update sent while the combiner held
// another serial than the agent now wants is not final: it goes again, under
// the serial wanted. One under the serial wanted is final.
func TestACombinerRefusalUnderAnotherSerialIsSentAgain(t *testing.T) {
	const zone = "resend.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 7, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess)

	tr.gate(ZoneName(zone), update(zone), "under7")
	tr.gate(ZoneName(zone), update(zone), "final")
	if tr.confirmation("final", transport.ConfirmRejected) {
		t.Error("a refusal under the serial wanted was not final")
	}

	tr.handOver(wantOf(zone, 8, "alpha", "beta")) // #235: the agent now has beta a signer
	eight := handoverIn(t, q.take())
	if !tr.confirmation("under7", transport.ConfirmRejected) {
		t.Fatal("the combiner's refusal under serial 7 was taken as final")
	}
	if len(q.take()) != 0 {
		t.Error("the update went again before the combiner holds serial 8")
	}
	tr.confirmation(eight.distID, transport.ConfirmSuccess)
	if got := q.take(); len(got) != 1 || got[0].distID != "under7" {
		t.Errorf("after serial 8 is held, sent %+v, want the update again", got)
	}
	if tr.confirmation("under7", transport.ConfirmSuccess) {
		t.Error("the update's success under serial 8 went no further")
	}
}

// The combiner's start report: every zone is handed over again, whatever it
// held.
func TestTheCombinersStartHandsEveryZoneAgain(t *testing.T) {
	tr, q := newTestTracker()
	for _, z := range []string{"one.acting.example.", "two.acting.example."} {
		tr.handOver(wantOf(z, 3, "alpha"))
		tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess)
	}
	tr.combinerStarted()
	n := 0
	for _, m := range q.take() {
		if m.update.Acting != nil {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d zones handed over after the combiner's start, want 2", n)
	}
}

// After a forget the next hand-over says so, and goes even at a lower serial.
func TestAForgetHandsOverWithReset(t *testing.T) {
	const zone = "forget.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 9, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess)
	tr.forgot(zone)
	tr.handOver(wantOf(zone, 2, "alpha"))
	if h := handoverIn(t, q.take()).update.Acting; !h.Reset || h.Serial != 2 {
		t.Errorf("after the forget the agent hands %+v, want serial 2 marked reset", h)
	}
}

// The order key: the active serial by RFC 1982, then the newest, a step of
// the reconciliation before its "done", the step; a tie by when it was made.
func TestTheHandOversOrderKey(t *testing.T) {
	now := time.Now()
	held := &ActingHandover{Serial: 8, Digest: "a", Records: []string{"x"}, Newest: 9, Phase: PhaseAgreeing, Made: now}
	at := func(f func(h *ActingHandover)) *ActingHandover { h := *held; f(&h); return &h }
	for name, c := range map[string]struct {
		h     *ActingHandover
		older bool
	}{
		"a lower serial":            {at(func(h *ActingHandover) { h.Serial = 7 }), true},
		"a higher serial":           {at(func(h *ActingHandover) { h.Serial = 9 }), false},
		"across the wrap":           {at(func(h *ActingHandover) { h.Serial, h.Newest = 1, 1 }), true},
		"the undefined half":        {at(func(h *ActingHandover) { h.Serial = 8 + 1<<31 }), true},
		"a lower newest":            {at(func(h *ActingHandover) { h.Newest = 8 }), true},
		"a step before done":        {at(func(h *ActingHandover) { h.Phase, h.Step = PhaseReconciling, 3 }), true},
		"the same, made earlier":    {at(func(h *ActingHandover) { h.Made = now.Add(-time.Hour) }), false},
		"another digest, earlier":   {at(func(h *ActingHandover) { h.Digest, h.Made = "b", now.Add(-time.Hour) }), true},
		"another digest, later":     {at(func(h *ActingHandover) { h.Digest, h.Made = "b", now.Add(time.Hour) }), false},
		"a reset at a lower serial": {at(func(h *ActingHandover) { h.Serial, h.Reset, h.Made = 2, true, now.Add(time.Second) }), false},
		"an old reset":              {at(func(h *ActingHandover) { h.Serial, h.Reset, h.Made = 2, true, now.Add(-time.Second) }), true},
	} {
		if got := c.h.olderThan(held); got != c.older {
			t.Errorf("%s: older %v, want %v", name, got, c.older)
		}
	}
	reconciling := at(func(h *ActingHandover) { h.Phase, h.Step = PhaseReconciling, 2 })
	if !at(func(h *ActingHandover) { h.Phase, h.Step = PhaseReconciling, 1 }).olderThan(reconciling) {
		t.Error("step 1 is not older than step 2")
	}
}

// The hand-over travels on the sync wrapper, and arrives whole.
func TestTheHandOverTravelsOnTheSyncWrapper(t *testing.T) {
	const zone = "wire.acting.example."
	h := handoverFor(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha"`)...)
	msg, err := syncAppMessage(&PeerSyncRequest{SenderID: actUs, Zone: zone, MessageType: "update", DistributionID: "d1", Acting: h}, "combiner.alpha.example.")
	if err != nil {
		t.Fatal(err)
	}
	var payload DnsSyncPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Acting.sameAs(h) {
		t.Errorf("the combiner reads %+v, handed %+v", payload.Acting, h)
	}
	plain, _ := syncAppMessage(&PeerSyncRequest{SenderID: actUs, Zone: zone, MessageType: "update", DistributionID: "d2"}, "combiner.alpha.example.")
	var raw map[string]any
	if err := json.Unmarshal(plain.Payload, &raw); err != nil {
		t.Fatal(err)
	}
	if _, there := raw["acting"]; there {
		t.Error("an update with no hand-over carries the field")
	}
}

// tdns-mp #235, on the wire: the agent's combiner holds serial 7, in which
// the peer is no signer. The peer's DNSKEY arrives and goes to the combiner,
// which rejects it; meanwhile the agent hands it serial 8, in which the peer
// signs. The rejection is not final: the sender gets no answer from it, the
// key goes again once the combiner confirms 8, and the sender's answer is
// the combiner's word on that.
func TestTransportBoundary_TheCombinerConfirmsAHandOver(t *testing.T) {
	r := receivingRig(t, "boundary.acting.example.")
	z := r.mpzd.ZoneName
	signer := AgentId(r.peer.Identity)
	tr := newHandoverTracker(AgentId(r.us.Identity), r.us.Bridge.enqueueToCombiner)
	r.us.Bridge.handover, r.conf.InternalMp.Handover = tr, tr
	t.Cleanup(func() { r.us.Bridge.handover, r.conf.InternalMp.Handover = nil, nil })

	before := r.combinerDists()
	tr.handOver(wantOf(z, 7, "us"))
	h7 := r.newCombinerDist(before, 5*time.Second)
	if h7 == "" {
		t.Fatal("the hand-over did not go on the queue to the combiner")
	}
	r.combinerTakes(h7)

	key := testDnskey(t, z, 256)
	rec := key.String()
	d1 := nextDistributionID()
	r.receivesAt(t, string(signer), d1, time.Now(), nil, core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{rec}})
	toCombiner := r.heldBy(t, signer, dns.TypeDNSKEY, rec).DistributionID
	waitUntil(t, "the key did not go to the combiner, which holds serial 7", func() bool { return r.combinerDists()[toCombiner] })

	before = r.combinerDists()
	tr.handOver(wantOf(z, 8, "us", "peer"))
	h8 := r.newCombinerDist(before, 5*time.Second)
	if h8 == "" {
		t.Fatal("the hand-over of serial 8 did not go on the queue")
	}
	r.rejects(rigCombiner, toCombiner, rec, "DNSKEY rejected: sender is not a signer")
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		c, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
		if !ok {
			break
		}
		if c.DistributionID == d1 && c.Status != "PENDING" {
			t.Fatalf("the combiner's refusal under serial 7 reached the sender: %+v", *c)
		}
	}
	if r.combinerDists()[toCombiner] {
		t.Fatal("the key went again before the combiner holds serial 8")
	}

	r.combinerTakes(h8)
	waitUntil(t, "the key did not go again once the combiner holds serial 8", func() bool { return r.combinerDists()[toCombiner] })
	r.confirms(rigCombiner, toCombiner, rec)
	if c := r.answered(t, d1); !slices.Contains(c.AppliedRecords, rec) {
		t.Errorf("after the combiner took the key under serial 8, the sender got %+v", *c)
	}
}

// The combiner's start report, a STATUS-UPDATE from the agent's own
// combiner, hands every zone over again; one from anyone else does nothing.
func TestACombinerStartReportHandsEveryZoneAgain(t *testing.T) {
	const zone = "report.acting.example."
	tr, q := newTestTracker()
	conf := &Config{}
	conf.InternalMp.Handover = tr
	conf.InternalMp.MPTransport = &MPTransportBridge{combinerID: "combiner.alpha.example."}
	e := &HsyncDataEngine{conf: conf}
	tr.handOver(wantOf(zone, 3, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess)

	e.handleStatusUpdate(context.Background(), &StatusUpdateMsg{SenderID: "agent.beta.example.", Zone: ".", SubType: "combiner-start"})
	if msgs := q.take(); len(msgs) != 0 {
		t.Errorf("a start report from another than the combiner handed over %d times", len(msgs))
	}
	e.handleStatusUpdate(context.Background(), &StatusUpdateMsg{SenderID: "COMBINER.alpha.example", Zone: ".", SubType: "combiner-start"})
	handoverIn(t, q.take())
}
