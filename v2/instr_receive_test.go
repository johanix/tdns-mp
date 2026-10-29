package tdnsmp

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Messages between serials (design rule 6, plan S8), on the freeze rig:
// the agent of provider a, at serial 41, receives provider b's
// distributions, made under 41, 42 or 40, and answers them.

// receiveRig is the freeze rig with what rule 6 needs: the confirmations
// the agent sends, its stamps, its activation wired to the data engine's
// queue, a leader, and its transport able to ask a sender's standing.
type receiveRig struct {
	*freezeRig
	lem     *LeaderElectionManager
	mu      sync.Mutex
	answers []*RemoteConfirmationDetail
}

func newReceiveRig(t *testing.T, zone string) *receiveRig {
	t.Helper()
	r := &receiveRig{freezeRig: newFreezeRig(t, zone)}
	msgQs := r.conf.InternalMp.MsgQs
	msgQs.OnRemoteConfirmationReady = func(d *RemoteConfirmationDetail) {
		r.mu.Lock()
		r.answers = append(r.answers, d)
		r.mu.Unlock()
	}
	tm := r.conf.InternalMp.MPTransport
	tm.msgQs, tm.LocalID = msgQs, roleA
	tm.getZone = func(name string) (*tdns.ZoneData, bool) {
		mpzd, ok := Zones.Get(name)
		if !ok {
			return nil, false
		}
		return mpzd.ZoneData, true
	}
	tm.stamps = newStampTable(roleA, r.store, 1, false, nil)
	r.store.onActive = func(zone string) { r.conf.askActivated(ZoneName(zone)) }
	r.lem = NewLeaderElectionManager(roleA, time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	r.conf.InternalMp.LeaderElectionManager = r.lem
	t.Cleanup(r.lem.hooks.Wait)
	return r
}

// leads makes who the zone's leader, as an election names it.
func (r *receiveRig) leads(who AgentId) {
	le := &LeaderElection{Zone: ZoneName(r.zone)}
	r.lem.noteLeaderLocked(le, who, time.Now())
	le.Leader, le.LeaderExpiry = who, time.Now().Add(time.Hour)
	r.lem.mu.Lock()
	r.lem.elections[ZoneName(r.zone)] = le
	r.lem.mu.Unlock()
}

var stampSeq atomic.Uint64

// msgStampAt is a sender's stamp, active at in.
func msgStampAt(in *Instructions) *MsgStamp {
	return &MsgStamp{Epoch: 1, Seq: stampSeq.Add(1), InstrStamp: InstrStamp{Known: true,
		Active: in.Serial, ActiveDigest: in.Digest(), Newest: in.Serial, NewestDigest: in.Digest()}}
}

// bNS is a replace of provider b's NS records.
func (r *receiveRig) bNS(names ...string) core.RROperation {
	op := core.RROperation{Operation: "replace", RRtype: "NS"}
	for _, n := range names {
		op.Records = append(op.Records, r.ns(n))
	}
	return op
}

// fromB is b's distribution distID, made under under (nil: no stamp),
// handled by the data engine's remote case. It returns the engine's answer.
func (r *receiveRig) fromB(distID string, under *Instructions, ops ...core.RROperation) *AgentMsgResponse {
	r.t.Helper()
	var ms *MsgStamp
	if under != nil {
		ms = msgStampAt(under)
	}
	resp := make(chan *AgentMsgResponse, 1)
	r.conf.applyRemoteUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleB, UpdateType: "remote",
		Update:            &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleB, Operations: ops},
		OriginatingDistID: distID, OriginatingInstr: ms, Mechanism: "DNS", OriginatingTime: time.Now(), DeliveredBy: roleB,
		Response: resp}, r.conf.InternalMp.MsgQs)
	select {
	case a := <-resp:
		return a
	default:
		r.t.Fatal("the data engine gave the update no answer")
	}
	return nil
}

// nsOf is agent's NS records as the data holds them.
func (r *receiveRig) nsOf(agent AgentId) []string {
	var out []string
	if ar, ok := r.zdr.Get(ZoneName(r.zone)); ok {
		if od, ok := ar.Get(agent); ok {
			if rrset, ok := od.RRtypes.Get(dns.TypeNS); ok {
				for _, rr := range rrset.RRs {
					out = append(out, rr.(*dns.NS).Ns)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// answered is what the agent answered the distribution, in order.
func (r *receiveRig) answered(distID string) []*RemoteConfirmationDetail {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*RemoteConfirmationDetail
	for _, a := range r.answers {
		if a.OriginatingDistID == distID {
			out = append(out, a)
		}
	}
	return out
}

// cmds are the data engine's commands queued, taken off its queue.
func (r *receiveRig) cmds() []string {
	var out []string
	for {
		select {
		case c := <-r.conf.InternalMp.MsgQs.SynchedDataCmd:
			out = append(out, c.Cmd)
		default:
			return out
		}
	}
}

func (r *receiveRig) kept() []keptEntry { return r.conf.InternalMp.Kept.entries(r.zone, listKept) }

// activated has the data engine handle what waits for the active serial.
func (r *receiveRig) activated() {
	r.conf.instrActivated(context.Background(), r.zdr, ZoneName(r.zone))
}

func TestAMessageMadeUnderTheSameActiveSerialIsTaken(t *testing.T) {
	r := newReceiveRig(t, "same.receive.example.")
	r.agree() // taken also while the zone agrees
	if a := r.fromB("d1", r.n, r.bNS("ns1.b.example.")); a.Error {
		t.Fatalf("the engine's answer: %+v", a)
	}
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns1.b.example."}) {
		t.Errorf("b's NS in the data: %v", got)
	}
	if len(r.kept()) != 0 || len(r.answered("d1")) != 0 {
		t.Errorf("kept %v, answered %v: want it taken, its answer the combiner's", r.kept(), r.answered("d1"))
	}
	if r.sent()[freezeCombiner] != 1 {
		t.Errorf("queued %v: want the update handed to the combiner", r.sent())
	}
}

func TestAMessageMadeUnderAHigherSerialIsKeptAndAcknowledged(t *testing.T) {
	r := newReceiveRig(t, "higher.receive.example.")
	a := r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	want := "kept: this agent acts by serial 41, the message was made under 42"
	if a.Error || a.Msg != want {
		t.Errorf("the engine's answer: %+v", a)
	}
	if got := r.nsOf(roleB); len(got) != 0 {
		t.Errorf("b's NS reached the data: %v", got)
	}
	if r.sent()[freezeCombiner] != 0 {
		t.Error("a kept update was handed to the combiner")
	}
	if k := r.kept(); len(k) != 1 || k[0].Distribution != "d1" || k[0].Update.Sender != roleB || k[0].Update.Instr.Active != 42 {
		t.Fatalf("the kept list: %+v", k)
	}
	if got := r.answered("d1"); len(got) != 1 || got[0].Status != "PENDING" || got[0].Message != want || got[0].OriginatingSender != roleB {
		t.Errorf("the answers: %+v, want one PENDING that says why", got)
	}
}

func TestAMessageIsKeptWhileTheActiveSerialIsNotKnown(t *testing.T) {
	r := newReceiveRig(t, "unknown.receive.example.")
	if err := r.store.update(r.zone, func(z *zoneSerials) error { z.Active = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	r.cmds()
	r.fromB("d1", r.n, r.bNS("ns1.b.example."))
	if got := r.answered("d1"); len(got) != 1 || got[0].Message != "kept: this agent does not know its active serial yet, the message was made under 41" {
		t.Errorf("the answers: %+v", got)
	}
	if len(r.kept()) != 1 {
		t.Errorf("the kept list: %+v", r.kept())
	}
}

// A message whose sender tells no active serial is taken as before, by an
// agent that knows its own; one that knows none keeps it, and takes it at
// the release (TestACatchUpAnswerIsKeptWhileTheActiveSerialIsUnknown, S9).
func TestAMessageWithNoStampIsTaken(t *testing.T) {
	r := newReceiveRig(t, "nostamp.receive.example.")
	r.fromB("d1", nil, r.bNS("ns1.b.example."))
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns1.b.example."}) || len(r.kept()) != 0 {
		t.Errorf("b's NS %v, kept %v", got, r.kept())
	}
}

func TestAKeptMessageIsTakenWhenTheActiveSerialCatchesUp(t *testing.T) {
	r := newReceiveRig(t, "caught.receive.example.")
	r.agree()
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	r.done()
	if got := r.cmds(); !slices.Contains(got, "instr-activated") {
		t.Fatalf("the activation asked the data engine for %v, want instr-activated", got)
	}
	r.activated()
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns1.b.example."}) {
		t.Errorf("b's NS in the data after the release: %v", got)
	}
	if len(r.kept()) != 0 {
		t.Errorf("the kept list after the release: %+v", r.kept())
	}
	if r.sent()[freezeCombiner] != 1 {
		t.Errorf("queued %v: want the released update handed to the combiner", r.sent())
	}
}

func TestAKeptMessageIsRefusedWhenTheActiveSerialPassesIt(t *testing.T) {
	r := newReceiveRig(t, "passed.receive.example.")
	r.agree()
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	w := freezeAt(t, 43, "w", "a,b", "")
	r.store.Note(r.zone, w, nil)
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(w)}); err != nil {
		t.Fatal(err)
	}
	r.activated()
	got := r.answered("d1")
	if n := len(got); n != 2 || got[n-1].Status != "REJECTED" || !strings.HasPrefix(got[n-1].Message, staleInstructions+":") {
		t.Fatalf("the answers: %+v, want the PENDING and then a stale refusal", got)
	}
	if len(r.kept()) != 0 || len(r.nsOf(roleB)) != 0 {
		t.Errorf("kept %v, b's NS %v", r.kept(), r.nsOf(roleB))
	}
}

// A message made under a higher serial than the one activated stays kept,
// and those made under the one activated are taken past it, in order.
func TestAKeptMessageAboveTheActivatedSerialStays(t *testing.T) {
	r := newReceiveRig(t, "stays.receive.example.")
	r.agree()
	w := freezeAt(t, 43, "w", "a,b", "")
	r.fromB("d1", w, r.bNS("ns1.b.example."))
	r.fromB("d2", r.v, r.bNS("ns2.b.example."))
	r.done()
	r.activated()
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns2.b.example."}) {
		t.Errorf("b's NS: %v, want the one made under 42", got)
	}
	if k := r.kept(); len(k) != 1 || k[0].Distribution != "d1" {
		t.Errorf("the kept list: %+v, want the one made under 43", k)
	}
}

func TestAStaleMessageIsRefusedWithTheReceiversStamp(t *testing.T) {
	r := newReceiveRig(t, "stale.receive.example.")
	old := freezeAt(t, 40, "o", "a,b", "")
	r.fromB("d1", old, r.bNS("ns1.b.example."))
	got := r.answered("d1")
	want := "stale-instructions: made under older instructions: this agent acts by serial 41, the message was made under 40"
	if len(got) != 1 || got[0].Status != "REJECTED" || got[0].Message != want {
		t.Fatalf("the answers: %+v", got)
	}
	// the stamp goes on in confirmOn, as on every confirmation (S5b)
	if ms := confirmStamp(r.conf.InternalMp.MPTransport.stamps.confirmAppFor(r.zone)); ms == nil || ms.Active != 41 {
		t.Errorf("the receiver's stamp on its confirmation: %+v", ms)
	}
}

func TestAStaleRefusalIsAFinalConfirmationNotATransportRefusal(t *testing.T) {
	r := newReceiveRig(t, "final.receive.example.")
	old := freezeAt(t, 40, "o", "a,b", "")
	a := r.fromB("d1", old, r.bNS("ns1.b.example."))
	if a.Error {
		t.Errorf("the engine's answer is an error: %+v", a)
	}
	if got := r.answered("d1"); len(got) != 1 || got[0].Status != "REJECTED" {
		t.Errorf("the answers: %+v, want one final REJECTED", got)
	}
	if len(r.nsOf(roleB)) != 0 || len(r.kept()) != 0 || r.sent()[freezeCombiner] != 0 {
		t.Error("a stale message was stored, kept or passed on")
	}
}

func TestAResentKeptMessageIsKeptOnce(t *testing.T) {
	r := newReceiveRig(t, "once.receive.example.")
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	if k := r.kept(); len(k) != 1 {
		t.Errorf("the kept list: %+v, want one entry", k)
	}
	if got := r.answered("d1"); len(got) != 2 || got[1].Status != "PENDING" {
		t.Errorf("the answers: %+v, want a PENDING for each send", got)
	}
}

// A kept CSYNC is judged by the leader the zone has at its release: the
// leader rule is asked then.
func TestAKeptMessageIsJudgedByTheInstructionsActiveAtRelease(t *testing.T) {
	r := newReceiveRig(t, "judged.receive.example.")
	r.leads(roleB)
	r.agree()
	op, _ := csyncOp(r.zone, 1000)
	r.fromB("d1", r.v, op)
	r.leads(roleA)
	r.done()
	r.activated()
	got := r.answered("d1")
	if n := len(got); n != 2 || got[n-1].Status != "REJECTED" || !strings.Contains(got[n-1].Message, "delegation sync leader") {
		t.Fatalf("the answers: %+v, want the PENDING and then the leader rule's refusal", got)
	}
}

// The sender may no longer send for the zone at the release: refused.
func TestAKeptMessageFromASenderThatMayNotSendIsRefusedAtRelease(t *testing.T) {
	r := newReceiveRig(t, "standing.receive.example.")
	r.agree()
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	r.conf.InternalMp.MPTransport.getZone = func(string) (*tdns.ZoneData, bool) { return nil, false }
	r.done()
	r.activated()
	got := r.answered("d1")
	if n := len(got); n != 2 || got[n-1].Status != "REJECTED" || !strings.HasPrefix(got[n-1].Message, "refused at its release") {
		t.Fatalf("the answers: %+v", got)
	}
	if len(r.nsOf(roleB)) != 0 {
		t.Errorf("b's NS: %v", r.nsOf(roleB))
	}
}

// The kept list survives a restart, and is released after it.
func TestTheKeptListSurvivesARestart(t *testing.T) {
	r := newReceiveRig(t, "restart.receive.example.")
	r.agree()
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	r.load()
	r.store.onActive = func(zone string) { r.conf.askActivated(ZoneName(zone)) }
	k := r.kept()
	if len(k) != 1 || k[0].Update.Sender != roleB || k[0].Update.Instr == nil || k[0].Update.Instr.Active != 42 || k[0].Update.Mechanism != "DNS" {
		t.Fatalf("the kept list after a restart: %+v", k)
	}
	r.done()
	r.activated()
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns1.b.example."}) {
		t.Errorf("b's NS after the release: %v", got)
	}
}

// Others' kept distributions are released at the activation, before this
// agent's own owed changes at "done" (design 3.3).
func TestKeptRemoteUpdatesDoNotWaitBehindOwedLocalOnes(t *testing.T) {
	r := newReceiveRig(t, "order.receive.example.")
	r.agree()
	r.edit("ns1.a.example.") // owed
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	r.cmds()
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Done(r.zone); err != nil {
		t.Fatal(err)
	}
	if got := r.cmds(); len(got) < 2 || got[0] != "instr-activated" || !slices.Contains(got[1:], "instr-done") {
		t.Errorf("the data engine was asked for %v, want instr-activated before instr-done", got)
	}
}

func TestTheKeptDistributionsAreShownInTheStatus(t *testing.T) {
	r := newReceiveRig(t, "status.receive.example.")
	r.agree()
	r.fromB("d1", r.v, r.bNS("ns1.b.example."))
	if _, kept := r.conf.freezeLines(r.zone); kept != "1 distribution of another agent's" {
		t.Errorf("kept here: %q", kept)
	}
}

// --- at the sender ---

// sentToB records the stamp of a send of distID to b, at in.
func (r *receiveRig) sentToB(distID string, in *Instructions) {
	r.conf.InternalMp.MPTransport.stamps.sent(distID, roleB, r.zone, msgStampAt(in))
}

func TestAConfirmationIsAlwaysTaken(t *testing.T) {
	r := newReceiveRig(t, "taken.sender.example.")
	tm := r.conf.InternalMp.MPTransport
	r.sentToB("d1", r.n)
	if tm.notYetFrom("d1", roleB, transport.ConfirmSuccess, msgStampAt(r.v)) {
		t.Error("a success from a peer at another serial is not taken")
	}
	if tm.notYetFrom("d1", roleB, transport.ConfirmPending, msgStampAt(r.v)) {
		t.Error("a PENDING from a peer at another serial is not taken")
	}
	if tm.notYetFrom("d1", roleB, transport.ConfirmRejected, msgStampAt(r.n)) {
		t.Error("a rejection from a peer at the send's serial is not final")
	}
	if tm.notYetFrom("d2", roleB, transport.ConfirmRejected, msgStampAt(r.v)) {
		t.Error("a rejection of a send with no stamp recorded is not final")
	}
	if tm.notYetFrom("d1", roleB, transport.ConfirmRejected, nil) {
		t.Error("a rejection with no stamp is not final")
	}
	tm.TrackDnskeyPropagation(ZoneName(r.zone), "d1", []uint16{7}, nil, []AgentId{roleB})
	tm.ProcessDnskeyConfirmation("d1", roleB, "SUCCESS", nil, nil)
	if _, open := tm.pendingDnskeyPropagations["d1"]; open {
		t.Error("a success did not settle the key's propagation")
	}
}

func TestTheAuditorConfirmsWhateverTheStamp(t *testing.T) {
	var got *RemoteConfirmationDetail
	msgQs := &MsgQs{OnRemoteConfirmationReady: func(d *RemoteConfirmationDetail) { got = d }}
	old := freezeAt(t, 40, "o", "a,b", "")
	msg := &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{DistributionID: "d1", Instr: msgStampAt(old),
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{"auditor.receive.example. 3600 IN NS ns1.b.example."}}}}}
	auditorConfirms(msgQs, msg, roleB, "auditor.receive.example.")
	if got == nil || got.Status != "SUCCESS" {
		t.Errorf("the auditor's confirmation: %+v", got)
	}
}

func TestARequestIsAnsweredWhateverItsStamp(t *testing.T) {
	r := newReceiveRig(t, "request.receive.example.")
	ar := r.conf.InternalMp.AgentRegistry
	updates := make(chan *SynchedDataUpdate, 1)
	cmds := make(chan *SynchedDataCmd, 1)
	old := freezeAt(t, 40, "o", "a,b", "")
	ar.MsgHandler(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgRfi, RfiType: "SYNC", OriginatorID: roleB,
		Zone: ZoneName(r.zone), Instr: msgStampAt(old), CatchUp: &CatchUp{Request: "r1", Reason: "start"}}}, updates, cmds)
	select {
	case c := <-cmds:
		if c.Cmd != "resync-targeted" || c.TargetAgent != roleB {
			t.Errorf("the request asked for %+v", c)
		}
	default:
		t.Error("a request stamped with an older serial was not answered")
	}
}

func TestARejectionFromAPeerAtAnotherSerialIsNotFinal(t *testing.T) {
	r := newReceiveRig(t, "rejected.sender.example.")
	tm := r.conf.InternalMp.MPTransport
	r.sentToB("d1", r.n)
	tm.TrackDnskeyPropagation(ZoneName(r.zone), "d1", []uint16{7}, nil, []AgentId{roleB})
	notYet := tm.notYetFrom("d1", roleB, transport.ConfirmRejected, msgStampAt(r.v))
	if !notYet {
		t.Fatal("a rejection from a peer at another serial reads as final")
	}
	tm.processDnskeyConfirmation("d1", roleB, "REJECTED", nil, nil, []RejectedItemInfo{{Record: "x", Reason: staleInstructions}}, notYet)
	prop := tm.pendingDnskeyPropagations["d1"]
	if prop == nil || prop.ExpectedAgents[roleB] || prop.Rejected || len(prop.Results[roleB]) != 0 {
		t.Errorf("the key's propagation after a \"not yet\": %+v, want it pending for b", prop)
	}
}

func TestAnIgnoredFromAPeerAtAnotherSerialIsNotFinal(t *testing.T) {
	r := newReceiveRig(t, "ignored.sender.example.")
	tm := r.conf.InternalMp.MPTransport
	r.sentToB("d1", r.n)
	tm.TrackDnskeyPropagation(ZoneName(r.zone), "d1", []uint16{7}, nil, []AgentId{roleB})
	tm.pendingDnskeyPropagations["d1"].Signing = map[AgentId]bool{roleB: true}
	notYet := tm.notYetFrom("d1", roleB, transport.ConfirmIgnored, msgStampAt(r.v))
	tm.processDnskeyConfirmation("d1", roleB, "IGNORED", nil, nil, nil, notYet)
	if prop := tm.pendingDnskeyPropagations["d1"]; prop == nil || len(prop.Results[roleB]) != 0 {
		t.Errorf("the key's propagation after a \"not yet\": %+v, want it pending for b", prop)
	}
	// what the records' tracking takes of it: nothing it rejected or ignored
	rec := r.ns("ns1.b.example.")
	tracked := r.zdr.getOrCreateTracking(ZoneName(r.zone), roleA, dns.TypeNS)
	rr, _ := dns.NewRR(rec)
	r.zdr.markAddPending(tracked, rr, "d1", time.Now())
	r.zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: "d1", Zone: ZoneName(r.zone), Source: roleB, Status: "IGNORED",
		IgnoredRecords: []string{rr.String()}, NotYet: true}, r.conf.InternalMp.MsgQs)
	if st := tracked.Tracked[0].State; st != RRStatePending {
		t.Errorf("the record's state after a \"not yet\": %v, want pending", st)
	}
}

func TestTheOldSendIsNotResentByTheQueue(t *testing.T) {
	r := newReceiveRig(t, "settled.sender.example.")
	tm := r.conf.InternalMp.MPTransport
	if err := tm.EnqueueForSpecificAgent(ZoneName(r.zone), roleB, &ZoneUpdate{Zone: ZoneName(r.zone)}, "d1"); err != nil {
		t.Fatal(err)
	}
	settleQueuedMessage(r.queue, "d1", roleB, transport.ConfirmRejected)
	if r.sent()[roleB] != 0 {
		t.Error("the queue still holds a send its peer answered \"not yet\"")
	}
}

// d1 is a's NS edit, sent to b under 41; b answers it under 42.
func (r *receiveRig) notYetFromB(answerUnder *Instructions) string {
	r.t.Helper()
	tm := r.conf.InternalMp.MPTransport
	r.edit("ns1.a.example.")
	var distID string
	for _, m := range r.queue.GetPendingMessages() {
		if m.RecipientID == roleB {
			distID = m.DistributionID
		}
	}
	if distID == "" {
		r.t.Fatal("the edit was not sent to b")
	}
	r.sentToB(distID, r.n)
	settleQueuedMessage(r.queue, distID, roleB, transport.ConfirmRejected)
	if !tm.notYetFrom(distID, roleB, transport.ConfirmRejected, msgStampAt(answerUnder)) {
		r.t.Fatal("b's answer under another serial reads as final")
	}
	tm.noteNotYet(ZoneName(r.zone), roleB, distID, msgStampAt(answerUnder))
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	return distID
}

// resent: an update is queued again for b under distID.
func (r *receiveRig) resent(distID string) bool {
	return slices.ContainsFunc(r.queue.GetPendingMessages(), func(m transport.PendingMessageInfo) bool {
		return m.RecipientID == roleB && m.DistributionID == distID
	})
}

func TestAfterActivationOwnContributionsGoAgainToThosePeers(t *testing.T) {
	r := newReceiveRig(t, "again.sender.example.")
	distID := r.notYetFromB(r.v)
	r.activated() // still at 41: b is ahead, nothing goes
	if r.resent(distID) {
		t.Fatal("sent again before this agent caught up with b")
	}
	r.agree()
	r.done()
	r.activated()
	if !r.resent(distID) {
		t.Fatalf("not sent again to b after the activation; queued %v", r.sent())
	}
	if len(r.conf.InternalMp.MPTransport.notYets.forZone(ZoneName(r.zone))) != 0 {
		t.Error("the book still holds what was sent again")
	}
	// what goes is a complete replace per type, with no catch_up: the
	// complete answer's operations
	var names []string
	for _, op := range r.conf.catchUpOperations(r.zdr, ZoneName(r.zone), roleA) {
		if op.RRtype != "NS" || op.Operation != "replace" {
			continue
		}
		for _, rec := range op.Records {
			if rr, err := dns.NewRR(rec); err == nil {
				names = append(names, rr.(*dns.NS).Ns)
			}
		}
	}
	if !slices.Equal(names, []string{"ns1.a.example."}) {
		t.Errorf("a's NS as sent again: %v", names)
	}
}

func TestANotYetThatArrivesAfterActivationIsSentAgainAtOnce(t *testing.T) {
	r := newReceiveRig(t, "atonce.sender.example.")
	r.agree()
	r.done()
	r.cmds()
	// a's edit went out under 41 before the thaw; b answers under 42
	distID := r.notYetFromB(r.v)
	if got := r.cmds(); !slices.Contains(got, "instr-activated") {
		t.Fatalf("the \"not yet\" asked the data engine for %v", got)
	}
	r.activated()
	if !r.resent(distID) {
		t.Error("not sent again at once, though the two are in step")
	}
}

// A key's distribution that a peer answered "not yet" is answered by the
// peer's confirmation of what is sent again, under the same ID.
func TestAKeyDistributionMadeUnderAnOlderSerialIsResent(t *testing.T) {
	r := newReceiveRig(t, "key.sender.example.")
	tm := r.conf.InternalMp.MPTransport
	distID := r.notYetFromB(r.v)
	tm.TrackDnskeyPropagation(ZoneName(r.zone), distID, []uint16{7}, nil, []AgentId{roleB})
	tm.processDnskeyConfirmation(distID, roleB, "REJECTED", nil, nil, nil, true)
	r.agree()
	r.done()
	r.activated()
	if !r.resent(distID) {
		t.Fatal("not sent again")
	}
	tm.ProcessDnskeyConfirmation(distID, roleB, "SUCCESS", nil, nil)
	if _, open := tm.pendingDnskeyPropagations[distID]; open {
		t.Error("b's success of what was sent again did not settle the key's propagation")
	}
}

func TestNothingIsSentAgainOnceTheProviderNoLongerContributes(t *testing.T) {
	r := newReceiveRig(t, "norole.sender.example.")
	distID := r.notYetFromB(r.v)
	r.agree()
	r.done()
	// the active instructions give a no role (no transition the judge lets
	// through does so before S17b; set by hand)
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active.Reading = freezeAt(t, 42, "v", "b", "")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.activated()
	if r.resent(distID) {
		t.Error("sent again by a provider with no role")
	}
	if len(r.conf.InternalMp.MPTransport.notYets.forZone(ZoneName(r.zone))) != 0 {
		t.Error("the book still holds what no longer goes")
	}
}

// The combiner tells the serial it acts by on its confirmations, as
// "acting", never as "instr".
func TestTheCombinersConfirmationTellsWhatItActsBy(t *testing.T) {
	zone := "acting.receive.example."
	h := &ActingHandover{Zone: zone, Serial: 42, Digest: "abcd", Step: 0, Records: []string{"x"}}
	s := &actingStore{zones: map[string]*heldHandover{handoverKey(zone): {handover: h}}}
	prev := actingHeld.Load()
	actingHeld.Store(s)
	t.Cleanup(func() { actingHeld.Store(prev) })
	app := actingAppFor(zone)
	if confirmStamp(app) != nil {
		t.Errorf("the combiner's confirmation carries \"instr\": %s", app)
	}
	if a := confirmActing(app); a == nil || *a != (ActingStamp{Serial: 42, Digest: "abcd"}) {
		t.Errorf("acting: %+v in %s", a, app)
	}
	if !strings.Contains(string(app), `"acting":{"serial":42,"digest":"abcd","step":0}`) {
		t.Errorf("the application field: %s", app)
	}
	if actingAppFor("other.receive.example.") != nil {
		t.Error("an application field for a zone the combiner was handed nothing of")
	}
}
