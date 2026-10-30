/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
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
	mu     sync.Mutex
	msgs   []handedMsg
	refuse bool // the queue refuses every update but a hand-over
}

type handedMsg struct {
	distID string
	update *ZoneUpdate
}

func (q *handedQueue) enqueue(_ ZoneName, u *ZoneUpdate, distID string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.refuse && u.Acting == nil {
		return "", errors.New("the queue is full")
	}
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
	if handled, _ := tr.confirmation(h.distID, transport.ConfirmSuccess, nil, nil); !handled {
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
	tr.confirmation(first.distID, transport.ConfirmFailed, nil, nil)
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u1"); !waiting {
		t.Error("an update went out after the combiner refused the hand-over")
	}
	tr.tick()
	second := handoverIn(t, q.take())
	if second.distID == first.distID {
		t.Error("the hand-over went again under the refused distribution")
	}
	tr.confirmation(second.distID, transport.ConfirmSuccess, nil, nil)
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
	tr.confirmation(first.distID, transport.ConfirmSuccess, nil, nil)
	// an answer from before the confirmation, older than it, is not taken:
	// nothing is handed again and nothing waits
	tr.learned(behind, wantOf(behind, 7, "alpha"))
	tr.learned(behind, nil)
	if msgs := q.take(); len(msgs) != 0 {
		t.Errorf("an answer older than the confirmation made the agent send %d messages", len(msgs))
	}
	if waiting, _ := tr.gate(ZoneName(behind), update(behind), "u3"); waiting {
		t.Error("an answer older than the confirmation holds updates back")
	}
}

// A refusal or an "ignored" of an update sent while the combiner held
// another serial than the agent now wants is not final: it goes again, under
// the serial wanted. One under the serial wanted is final.
func TestACombinerRefusalUnderAnotherSerialIsSentAgain(t *testing.T) {
	const zone = "resend.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 7, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)

	tr.gate(ZoneName(zone), update(zone), "under7")
	tr.gate(ZoneName(zone), update(zone), "final")
	if handled, _ := tr.confirmation("final", transport.ConfirmRejected, nil, nil); handled {
		t.Error("a refusal under the serial wanted was not final")
	}

	tr.handOver(wantOf(zone, 8, "alpha", "beta")) // #235: the agent now has beta a signer
	eight := handoverIn(t, q.take())
	if handled, _ := tr.confirmation("under7", transport.ConfirmRejected, nil, nil); !handled {
		t.Fatal("the combiner's refusal under serial 7 was taken as final")
	}
	if len(q.take()) != 0 {
		t.Error("the update went again before the combiner holds serial 8")
	}
	tr.confirmation(eight.distID, transport.ConfirmSuccess, nil, nil)
	if got := q.take(); len(got) != 1 || got[0].distID != "under7" {
		t.Errorf("after serial 8 is held, sent %+v, want the update again", got)
	}
	if handled, _ := tr.confirmation("under7", transport.ConfirmSuccess, nil, nil); handled {
		t.Error("the update's success under serial 8 went no further")
	}
}

// A refusal from a combiner that says it acts by another serial than the one
// the update was sent under is not final either (plan S8): the update goes
// again, under the serial wanted. One that names the serial sent under is
// final.
func TestACombinerRefusalActingByAnotherSerialIsSentAgain(t *testing.T) {
	const zone = "acting.resend.example."
	tr, q := newTestTracker()
	seven := wantOf(zone, 7, "alpha")
	tr.handOver(seven)
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)

	tr.gate(ZoneName(zone), update(zone), "final")
	if handled, _ := tr.confirmation("final", transport.ConfirmRejected, actingStampOf(seven), nil); handled {
		t.Error("a refusal acting by the serial sent under was not final")
	}
	tr.gate(ZoneName(zone), update(zone), "other")
	if handled, _ := tr.confirmation("other", transport.ConfirmRejected, &ActingStamp{Serial: 6, Digest: "x"}, nil); !handled {
		t.Fatal("a refusal acting by another serial was taken as final")
	}
	if got := q.take(); len(got) != 1 || got[0].distID != "other" {
		t.Errorf("sent %+v, want the update again", got)
	}
}

// The combiner's start report: every zone is handed over again, whatever it
// held.
func TestTheCombinersStartHandsEveryZoneAgain(t *testing.T) {
	tr, q := newTestTracker()
	for _, z := range []string{"one.acting.example.", "two.acting.example."} {
		tr.handOver(wantOf(z, 3, "alpha"))
		tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)
	}
	tr.combinerStarted()
	var zones []string
	for _, m := range q.take() {
		if m.update.Acting != nil {
			zones = append(zones, m.update.Acting.Zone)
		}
	}
	slices.Sort(zones)
	if !slices.Equal(zones, []string{"one.acting.example.", "two.acting.example."}) {
		t.Errorf("handed over %v after the combiner's start, want both zones once", zones)
	}
}

// An update the gate let through and the queue then refused is forgotten:
// no word on it comes, and none is waited for.
func TestAnUpdateTheQueueRefusesIsNotKeptAsSent(t *testing.T) {
	const zone = "unsent.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 4, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u1"); waiting {
		t.Fatal("the update waits though the combiner holds what is wanted")
	}
	tr.unsent("u1")
	tr.mu.Lock()
	_, kept := tr.sent["u1"]
	tr.mu.Unlock()
	if kept {
		t.Error("an update the queue refused is kept as sent")
	}
}

// The repeat of the combiner's start report names a zone it waits for: that
// zone is handed over again, and the others' updates are not held up.
func TestACombinerWaitsReportHandsThatZoneAlone(t *testing.T) {
	tr, q := newTestTracker()
	for _, z := range []string{"one.acting.example.", "two.acting.example."} {
		tr.handOver(wantOf(z, 3, "alpha"))
		tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)
	}
	tr.again("one.acting.example.")
	if h := handoverIn(t, q.take()).update.Acting; h.Zone != "one.acting.example." {
		t.Errorf("handed over %s, want the zone the combiner waits for", h.Zone)
	}
	if waiting, _ := tr.gate("two.acting.example.", update("two.acting.example."), "u1"); waiting {
		t.Error("another zone's update waits for the hand-over of the zone the combiner waits for")
	}
}

// An update that waited and that the queue refuses is not lost: it stays
// first, what comes after it waits behind it, and the ticker sends them in
// order once the queue takes them.
func TestAnUpdateTheQueueRefusesOnReleaseIsSentByTheTicker(t *testing.T) {
	const zone = "refused.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 4, "alpha"))
	hand := handoverIn(t, q.take())
	tr.gate(ZoneName(zone), update(zone), "u1")
	q.refuse = true
	tr.confirmation(hand.distID, transport.ConfirmSuccess, nil, nil)
	if msgs := q.take(); len(msgs) != 0 {
		t.Fatalf("the queue refuses, yet %d messages were queued", len(msgs))
	}
	if waiting, _ := tr.gate(ZoneName(zone), update(zone), "u2"); !waiting {
		t.Error("a new update overtakes one that still waits")
	}
	q.refuse = false
	tr.tick()
	got := q.take()
	if len(got) != 2 || got[0].distID != "u1" || got[1].distID != "u2" {
		t.Errorf("the ticker sent %+v, want u1 then u2", got)
	}
}

// A forget while the same hand-over is in flight is not lost with its
// confirmation: the next hand-over says it.
func TestAForgetDuringAFlightIsToldByTheNextHandOver(t *testing.T) {
	const zone = "forgetflight.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 9, "alpha"))
	flight := handoverIn(t, q.take())
	tr.forgot(zone)
	tr.handOver(wantOf(zone, 9, "alpha"))
	if msgs := q.take(); len(msgs) != 0 {
		t.Fatalf("the same hand-over was sent again while in flight: %d", len(msgs))
	}
	tr.confirmation(flight.distID, transport.ConfirmSuccess, nil, nil)
	tr.handOver(wantOf(zone, 2, "alpha"))
	if h := handoverIn(t, q.take()).update.Acting; !h.Reset || h.Serial != 2 {
		t.Errorf("after the forget the agent hands %+v, want serial 2 marked reset", h)
	}
}

// After a forget the next hand-over says so, and goes even at a lower serial.
func TestAForgetHandsOverWithReset(t *testing.T) {
	const zone = "forget.acting.example."
	tr, q := newTestTracker()
	tr.handOver(wantOf(zone, 9, "alpha"))
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)
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

// removalRig is the receiving rig with the agent's hand-over tracker, the
// combiner acting by serial 7, and two NS records of the zone's.
func removalRig(t *testing.T, zone string) (r *notifyRig, tr *handoverTracker, rec1, rec2 string) {
	t.Helper()
	r = receivingRig(t, zone)
	tr = newHandoverTracker(AgentId(r.us.Identity), r.us.Bridge.enqueueToCombiner)
	r.us.Bridge.handover, r.conf.InternalMp.Handover = tr, tr
	t.Cleanup(func() { r.us.Bridge.handover, r.conf.InternalMp.Handover = nil, nil })
	before := r.combinerDists()
	tr.handOver(wantOf(zone, 7, "us"))
	h7 := r.newCombinerDist(before, 5*time.Second)
	if h7 == "" {
		t.Fatal("the hand-over did not go on the queue to the combiner")
	}
	r.combinerTakes(h7)
	var recs []string
	for _, ns := range []string{"ns1", "ns2"} {
		rr, err := dns.NewRR(zone + " 3600 IN NS " + ns + ".removal.example.")
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rr.String())
	}
	return r, tr, recs[0], recs[1]
}

// removedUnderSeven has the update toCombiner, which deletes rec1 and adds
// rec2, answered by the combiner at serial 7 while 8 is wanted: rec1
// removed, rec2 refused. Once it holds 8 the update goes again, and the
// combiner takes rec2 and names no removal: it no longer holds rec1.
func (r *notifyRig) removedUnderSeven(t *testing.T, tr *handoverTracker, toCombiner, rec1, rec2 string) {
	t.Helper()
	waitUntil(t, "the update did not go to the combiner", func() bool { return r.combinerDists()[toCombiner] })
	before := r.combinerDists()
	tr.handOver(wantOf(r.mpzd.ZoneName, 8, "us", "peer"))
	h8 := r.newCombinerDist(before, 5*time.Second)
	if h8 == "" {
		t.Fatal("the hand-over of serial 8 did not go on the queue")
	}
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(toCombiner, rigCombiner, transport.ConfirmPartial, r.mpzd.ZoneName,
		nil, []string{rec1}, []transport.RejectedItemDTO{{Record: rec2, Reason: "refused at serial 7"}}, nil, false, ""))
	r.combinerTakes(h8)
	waitUntil(t, "the update did not go again once the combiner holds serial 8", func() bool { return r.combinerDists()[toCombiner] })
	r.confirms(rigCombiner, toCombiner, rec2)
}

// removalOf is rec1's state as the agent's data engine tracks it, once it
// is removed or after a while: the engine takes a command before the
// confirmations queued ahead of it.
func (r *notifyRig) removalOf(t *testing.T, agent AgentId, rec1 string) string {
	t.Helper()
	state := "not tracked"
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end) && state != RRStateRemoved.String(); time.Sleep(10 * time.Millisecond) {
		for _, info := range r.repo(t)[agent][dns.TypeNS] {
			if info.RR == rec1 {
				state = info.State
			}
		}
	}
	return state
}

// What the combiner removed in a word that is not final is gone whatever
// the serial, and its answer to the update sent again cannot name it: it no
// longer holds the record. The final word names it (plan S8; the word that
// is not final is S10's). Here the update is the peer's, which the agent
// forwards: the peer's final confirmation names rec1 as removed.
func TestTransportBoundary_ACombinersRemovalUnderAnotherSerialIsNamedInTheFinalWord(t *testing.T) {
	r, tr, rec1, rec2 := removalRig(t, "removal.acting.example.")
	peer := AgentId(r.peer.Identity)
	d1 := nextDistributionID()
	r.receivesAt(t, string(peer), d1, time.Now(), nil, core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{rec1}})
	first := r.heldBy(t, peer, dns.TypeNS, rec1).DistributionID
	waitUntil(t, "rec1 did not go to the combiner", func() bool { return r.combinerDists()[first] })
	r.confirms(rigCombiner, first, rec1)
	r.answered(t, d1)

	d2 := nextDistributionID()
	r.receivesAt(t, string(peer), d2, time.Now(), nil, core.RROperation{Operation: "delete", RRtype: "NS", Records: []string{rec1}},
		core.RROperation{Operation: "add", RRtype: "NS", Records: []string{rec2}})
	r.removedUnderSeven(t, tr, r.heldBy(t, peer, dns.TypeNS, rec2).DistributionID, rec1, rec2)
	if c := r.answered(t, d2); !slices.Contains(c.RemovedRecords, rec1) {
		t.Errorf("the peer's final confirmation: %+v, want rec1 named as removed", *c)
	}
}

// The same for the agent's own update: its removal of rec1, which the peer
// confirms too, is confirmed, not left pending for good.
func TestTransportBoundary_ACombinersRemovalOfAnOwnRecordUnderAnotherSerialIsConfirmed(t *testing.T) {
	r, tr, rec1, rec2 := removalRig(t, "own.removal.acting.example.")
	us, peer := AgentId(r.us.Identity), r.peer.Identity
	own := func(ops ...core.RROperation) {
		answer := make(chan *AgentMsgResponse, 1)
		r.us.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(r.mpzd.ZoneName), AgentId: us, UpdateType: "local",
			Update: &ZoneUpdate{Zone: ZoneName(r.mpzd.ZoneName), AgentId: us, Operations: ops}, Response: answer}
		if a, ok := recvWithin(answer, 10*time.Second); !ok || a.Error {
			t.Fatalf("the agent's own update: %+v", a)
		}
	}
	own(core.RROperation{Operation: "add", RRtype: "NS", Records: []string{rec1}})
	first := r.heldBy(t, us, dns.TypeNS, rec1).DistributionID
	waitUntil(t, "rec1 did not go to the combiner", func() bool { return r.combinerDists()[first] })
	r.confirms(rigCombiner, first, rec1)
	r.confirms(peer, first, rec1)

	own(core.RROperation{Operation: "delete", RRtype: "NS", Records: []string{rec1}},
		core.RROperation{Operation: "add", RRtype: "NS", Records: []string{rec2}})
	toCombiner := r.heldBy(t, us, dns.TypeNS, rec2).DistributionID
	r.removedUnderSeven(t, tr, toCombiner, rec1, rec2)
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(toCombiner, peer, transport.ConfirmSuccess, r.mpzd.ZoneName,
		[]string{rec2}, []string{rec1}, nil, nil, false, ""))
	if st := r.removalOf(t, us, rec1); st != RRStateRemoved.String() {
		t.Errorf("rec1's removal here: %s, want removed", st)
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
	tr.confirmation(handoverIn(t, q.take()).distID, transport.ConfirmSuccess, nil, nil)

	e.handleStatusUpdate(context.Background(), &StatusUpdateMsg{SenderID: "agent.beta.example.", Zone: ".", SubType: "combiner-start"})
	if msgs := q.take(); len(msgs) != 0 {
		t.Errorf("a start report from another than the combiner handed over %d times", len(msgs))
	}
	e.handleStatusUpdate(context.Background(), &StatusUpdateMsg{SenderID: "COMBINER.alpha.example", Zone: ".", SubType: "combiner-start"})
	handoverIn(t, q.take())
}
