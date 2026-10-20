/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const answerCombiner = "combiner.us.example."

// answerRig is an agent ("us") of a zone with the providers us, p2 and p3,
// signed by signers, that answers requests for the zone's state: its zone
// has loaded, its own state is read unless a test says otherwise, and what
// it enqueues lands in a reliable queue whose worker is not running.
type answerRig struct {
	conf  *Config
	mpzd  *MPZoneData
	zdr   *ZoneDataRepo
	lem   *LeaderElectionManager
	queue *transport.ReliableMessageQueue
	zone  ZoneName
}

func newAnswerRig(t *testing.T, zone string, signers []string) *answerRig {
	t.Helper()
	asMPAgent(t)
	mpzd := providersTestZone(t, zone, []string{"us", "p2", "p3"}, signers)
	mpzd.Ready = true
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: "us", WeAreSigner: slices.Contains(signers, "us"), ZoneSigned: len(signers) > 0}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: usAgent})
	queue := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.MPTransport = &MPTransportBridge{
		TransportManager: &transport.TransportManager{ReliableQueue: queue, PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar, combinerID: answerCombiner,
	}
	lem := NewLeaderElectionManager(usAgent, time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	conf.InternalMp.LeaderElectionManager = lem
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	r := &answerRig{conf: conf, mpzd: mpzd, zdr: zdr, lem: lem, queue: queue, zone: ZoneName(mpzd.ZoneName)}
	zdr.markOwnState(r.zone, true, "")
	return r
}

// holds puts records in this agent's own data, as its own read leaves them.
func (r *answerRig) holds(t *testing.T, rrs ...string) {
	t.Helper()
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		r.zdr.AddConfirmedRR(r.zone, usAgent, rr)
	}
}

func (r *answerRig) inventory(t *testing.T, items ...KeyInventoryItem) {
	t.Helper()
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: string(r.zone), Inventory: items, Received: time.Now()})
}

func (r *answerRig) answer(t *testing.T) *ZoneUpdate {
	t.Helper()
	return r.conf.buildCatchUpAnswer(r.zdr, r.zone, &CatchUp{Request: "r1", Reason: "start"})
}

// ops is an answer's operations by type: the records, and whether the
// type is there at all.
func ops(zu *ZoneUpdate) map[string]core.RROperation {
	out := map[string]core.RROperation{}
	for _, op := range zu.Operations {
		out[op.RRtype] = op
	}
	return out
}

func (r *answerRig) ns(name string) string { return string(r.zone) + " 3600 IN NS " + name }

func (r *answerRig) cds(t *testing.T) string {
	t.Helper()
	c := &dns.CDS{DS: *testDnskey(t, string(r.zone), 257).ToDS(dns.SHA256)}
	c.Hdr = dns.RR_Header{Name: string(r.zone), Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	return c.String()
}

// A complete answer has a replace for NS and CDS, and from a provider in
// signers= for DNSKEY, with the records and the key states of the signer's
// inventory.
func TestAnAnswerNamesNSAndCDSAndASignersDNSKEY(t *testing.T) {
	yes := true
	r := newAnswerRig(t, "names.answer.example.", []string{"us", "p2"})
	cds := r.cds(t)
	r.holds(t, r.ns("ns.us.example."), cds)
	ksk := invItem(t, string(r.zone), 257, KeyStateActive, &yes)
	theirs := invItem(t, string(r.zone), 257, DnskeyStateForeign, nil)
	r.inventory(t, ksk, theirs)

	zu := r.answer(t)
	if !zu.CatchUp.IsComplete() || zu.CatchUp.Request != "r1" {
		t.Fatalf("the answer is %+v, want complete for r1", *zu.CatchUp)
	}
	got := ops(zu)
	if op := got["NS"]; op.Operation != "replace" || len(op.Records) != 1 {
		t.Errorf("NS: %+v", op)
	}
	if op := got["CDS"]; op.Operation != "replace" || len(op.Records) != 1 {
		t.Errorf("CDS: %+v", op)
	}
	op, ok := got["DNSKEY"]
	if !ok || op.Operation != "replace" || len(op.Records) != 1 {
		t.Fatalf("DNSKEY: %+v, want this provider's served key alone", op)
	}
	if rr, err := dns.NewRR(op.Records[0]); err != nil || rr.(*dns.DNSKEY).KeyTag() != ksk.KeyTag {
		t.Errorf("DNSKEY: %v, want the key %d", op.Records[0], ksk.KeyTag)
	}
	if len(op.KeyStates) != 1 || op.KeyStates[0].KeyTag != ksk.KeyTag || op.KeyStates[0].State != KeyStateActive || op.KeyStates[0].DS == nil || !*op.KeyStates[0].DS {
		t.Errorf("the key states: %+v", op.KeyStates)
	}
}

// An agent that holds nothing still answers, complete: an empty replace
// for NS and CDS, and for DNSKEY at a signer.
func TestAnAgentThatHoldsNothingStillAnswers(t *testing.T) {
	r := newAnswerRig(t, "nothing.answer.example.", []string{"us"})
	r.inventory(t, invItem(t, string(r.zone), 257, DnskeyStateForeign, nil))
	zu := r.answer(t)
	if !zu.CatchUp.IsComplete() {
		t.Fatalf("not complete: %+v", *zu.CatchUp)
	}
	got := ops(zu)
	for _, typ := range []string{"NS", "CDS", "DNSKEY"} {
		if op, ok := got[typ]; !ok || op.Operation != "replace" || len(op.Records) != 0 {
			t.Errorf("%s: %+v (present %v), want an empty replace", typ, op, ok)
		}
	}
}

// A provider not in signers= names no DNSKEY: a provider moved from
// signers= to servers= does not withdraw its keys.
func TestAServerNamesNoDNSKEY(t *testing.T) {
	r := newAnswerRig(t, "server.answer.example.", []string{"p2"})
	r.holds(t, r.ns("ns.us.example."))
	zu := r.answer(t)
	if _, ok := ops(zu)["DNSKEY"]; ok || !zu.CatchUp.IsComplete() {
		t.Errorf("a server's answer: %+v, complete %v", zu.Operations, zu.CatchUp.IsComplete())
	}
}

// After a restart the agent's own data can lack its DNSKEYs while the
// inventory is there: the answer takes them from the inventory.
func TestAnAnswerAfterARestartCarriesTheSignersDNSKEYs(t *testing.T) {
	yes := true
	r := newAnswerRig(t, "restart.answer.example.", []string{"us"})
	r.inventory(t, invItem(t, string(r.zone), 257, KeyStateActive, &yes), invItem(t, string(r.zone), 256, KeyStateActive, nil))
	if op := ops(r.answer(t))["DNSKEY"]; len(op.Records) != 2 || len(op.KeyStates) != 2 {
		t.Errorf("DNSKEY: %+v", op)
	}
}

// No answer names the KEY (decision 27), whatever the agent's data holds.
func TestNoAnswerNamesTheKEY(t *testing.T) {
	r := newAnswerRig(t, "key.answer.example.", []string{"us"})
	r.inventory(t)
	r.holds(t, string(r.zone)+" 3600 IN KEY 256 3 15 dGVzdA==")
	if _, ok := ops(r.answer(t))["KEY"]; ok {
		t.Error("the answer names the KEY")
	}
}

// Only the agent that leads the zone names its CSYNC.
func TestOnlyTheLeadersAnswerCarriesACSYNC(t *testing.T) {
	r := newAnswerRig(t, "csync.answer.example.", []string{"us"})
	r.inventory(t)
	r.holds(t, string(r.zone)+" 3600 IN CSYNC 1 3 NS")
	if _, ok := ops(r.answer(t))["CSYNC"]; ok {
		t.Error("an agent that does not lead names the CSYNC")
	}
	r.lem.mu.Lock()
	r.lem.elections[r.zone] = &LeaderElection{Zone: r.zone, Leader: usAgent, LeaderExpiry: time.Now().Add(time.Hour)}
	r.lem.mu.Unlock()
	if op, ok := ops(r.answer(t))["CSYNC"]; !ok || len(op.Records) != 1 {
		t.Errorf("the leader's answer: CSYNC %+v (present %v)", op, ok)
	}
}

// tracked gives a record of this agent's own data a tracking entry with
// the given state and confirmation from source.
func (r *answerRig) tracked(t *testing.T, rrStr string, state RRState, source, status string) {
	t.Helper()
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		t.Fatal(err)
	}
	tr := r.zdr.getOrCreateTracking(r.zone, usAgent, rr.Header().Rrtype)
	tr.Tracked = append(tr.Tracked, TrackedRR{RR: rr, State: state, UpdatedAt: time.Now(),
		Confirmations: map[string]RRConfirmation{source: {Status: status, Timestamp: time.Now()}}})
}

// A record that the agent's own combiner refused is left out of the answer
// (decision 43). One that only a peer refused is named: leaving it out of a
// replace would remove it at the asker.
func TestAnAnswerLeavesOutARecordItsCombinerRefused(t *testing.T) {
	r := newAnswerRig(t, "refused.answer.example.", []string{"p2"})
	keep, refused := r.ns("ns1.us.example."), r.ns("ns2.us.example.")
	r.holds(t, keep, refused)
	r.tracked(t, refused, RRStateRejected, answerCombiner, "rejected")
	got := ops(r.answer(t))["NS"]
	if len(got.Records) != 1 || !strings.Contains(got.Records[0], "ns1.us.example.") {
		t.Errorf("NS: %v, want the record the combiner took alone", got.Records)
	}
}

func TestAnAnswerKeepsARecordOnlyAPeerRefused(t *testing.T) {
	r := newAnswerRig(t, "peerrefused.answer.example.", []string{"p2"})
	rec := r.ns("ns1.us.example.")
	r.holds(t, rec)
	r.tracked(t, rec, RRStateRejected, "agent.p2.example.", "rejected")
	if got := ops(r.answer(t))["NS"]; len(got.Records) != 1 {
		t.Errorf("NS: %v, want the record a peer refused", got.Records)
	}
}

// Not complete: a signer with no inventory, an agent that has not read its
// own state, a zone that has not loaded. The answer says why and carries no
// operation.
func TestASignerWithoutAnInventoryAnswersNotComplete(t *testing.T) {
	r := newAnswerRig(t, "noinv.answer.example.", []string{"us"})
	r.holds(t, r.ns("ns.us.example."))
	zu := r.answer(t)
	if zu.CatchUp.IsComplete() || zu.CatchUp.Complete == nil || zu.CatchUp.Why != whyNoInventory || len(zu.Operations) != 0 {
		t.Errorf("a signer with no inventory: %+v, %d operations", *zu.CatchUp, len(zu.Operations))
	}
}

func TestAnAgentThatHasNotReadItsOwnStateSendsNoOperation(t *testing.T) {
	r := newAnswerRig(t, "notread.answer.example.", []string{"p2"})
	r.zdr.mu.Lock()
	r.zdr.ownState = nil
	r.zdr.mu.Unlock()
	r.holds(t, r.ns("ns.us.example."))
	zu := r.answer(t)
	if zu.CatchUp.IsComplete() || zu.CatchUp.Why != whyOwnStateNotRead || len(zu.Operations) != 0 {
		t.Errorf("an agent that has not read its own state: %+v, %d operations", *zu.CatchUp, len(zu.Operations))
	}

	r.mpzd.Ready = false
	if zu := r.answer(t); zu.CatchUp.Why != whyZoneNotLoaded || len(zu.Operations) != 0 {
		t.Errorf("a zone that has not loaded: %+v", *zu.CatchUp)
	}
}

// The answer is enqueued for the asker alone, and not tracked: tracking it
// would put another distribution ID on the records, here on one whose own
// distribution is not confirmed yet.
func TestTheAnswerIsNotTracked(t *testing.T) {
	r := newAnswerRig(t, "untracked.answer.example.", []string{"p2"})
	rec := r.ns("ns.us.example.")
	r.holds(t, rec, r.ns("ns2.us.example."))
	pending, _ := dns.NewRR(r.ns("ns2.us.example."))
	for i, tr := range r.zdr.Tracking[r.zone][usAgent][dns.TypeNS].Tracked {
		if tr.RR.String() == pending.String() {
			r.zdr.Tracking[r.zone][usAgent][dns.TypeNS].Tracked[i].State = RRStatePending
			r.zdr.Tracking[r.zone][usAgent][dns.TypeNS].Tracked[i].DistributionID = "own"
		}
	}
	r.queue.Enqueue(&transport.OutgoingMessage{DistributionID: "earlier", RecipientID: "agent.p3.example.", Zone: string(r.zone)})
	before := slices.Clone(r.zdr.Tracking[r.zone][usAgent][dns.TypeNS].Tracked)
	if _, err := r.conf.catchUpAnswer(r.zdr, r.zone, "agent.p2.example.", &CatchUp{Request: "r1", Reason: "start"}); err != nil {
		t.Fatal(err)
	}
	var to []string
	for _, m := range r.queue.GetPendingMessages() {
		if m.DistributionID != "earlier" {
			to = append(to, m.RecipientID)
		}
	}
	if len(to) != 1 || to[0] != "agent.p2.example." {
		t.Errorf("the answer is queued for %v, want the asker alone", to)
	}
	after := r.zdr.Tracking[r.zone][usAgent][dns.TypeNS].Tracked
	if len(after) != len(before) {
		t.Fatalf("the answer changed the tracking: %d entries, were %d", len(after), len(before))
	}
	for i := range after {
		if after[i].DistributionID != before[i].DistributionID || after[i].State != before[i].State {
			t.Errorf("the answer changed the tracking: %+v, was %+v", after[i], before[i])
		}
	}
}

// The answer carries what the provider says about each key: its state, and
// its ds as the signer's row has it, unset where the row's is.
func TestAnAnswerCarriesTheKeyStates(t *testing.T) {
	yes := true
	r := newAnswerRig(t, "states.answer.example.", []string{"us"})
	ksk := invItem(t, string(r.zone), 257, KeyStateActive, &yes)
	next := invItem(t, string(r.zone), 257, KeyStatePublished, nil)
	r.inventory(t, ksk, next)
	op := ops(r.answer(t))["DNSKEY"]
	states := map[uint16]core.KeyState{}
	for _, s := range op.KeyStates {
		states[s.KeyTag] = s
	}
	if s := states[ksk.KeyTag]; s.State != KeyStateActive || s.DS == nil || !*s.DS {
		t.Errorf("the active KSK: %+v", s)
	}
	if s := states[next.KeyTag]; s.State != KeyStatePublished || s.DS != nil {
		t.Errorf("the published KSK: %+v, want its ds unset", s)
	}
}

// An asker whose answers do not reach it asks again and again. Each new
// answer takes the older one, still queued for that asker and zone, out of
// the queue, so one answer waits there, the latest. An answer for another
// asker, or for another zone, stays; and once the asker has confirmed an
// answer, the next one is queued as before.
func TestANewerAnswerReplacesTheOlderOneStillQueued(t *testing.T) {
	r := newAnswerRig(t, "replaced.answer.example.", []string{"p2"})
	r.holds(t, r.ns("ns.us.example."))
	const p2, p3 = AgentId("agent.p2.example."), AgentId("agent.p3.example.")
	ask := func(zone ZoneName, peer AgentId, req string) {
		t.Helper()
		if _, err := r.conf.catchUpAnswer(r.zdr, zone, peer, &CatchUp{Request: req, Reason: "start"}); err != nil {
			t.Fatal(err)
		}
	}
	queued := func(zone ZoneName, peer AgentId) []string {
		var ids []string
		for _, m := range r.queue.GetPendingMessages() {
			if m.Zone == string(zone) && m.RecipientID == string(peer) {
				ids = append(ids, m.DistributionID)
			}
		}
		return ids
	}

	other := ZoneName("other.answer.example.")
	ask(r.zone, p3, "q1")
	ask(other, p2, "o1")
	ask(r.zone, p2, "r1")
	first := queued(r.zone, p2)
	for i := 2; i <= 50; i++ {
		ask(r.zone, p2, fmt.Sprintf("r%d", i))
	}
	last := queued(r.zone, p2)
	if len(last) != 1 || slices.Equal(last, first) {
		t.Fatalf("after 50 requests the queue holds %v for the asker, want one answer, not the first (%v)", last, first)
	}
	if last[0] != r.zdr.catchUpAnswers[r.zone][p2] {
		t.Errorf("the answer queued is %s, want the latest (%s)", last[0], r.zdr.catchUpAnswers[r.zone][p2])
	}
	if n, m := len(queued(r.zone, p3)), len(queued(other, p2)); n != 1 || m != 1 {
		t.Errorf("another asker's answer (%d queued) or another zone's (%d) was taken out", n, m)
	}

	r.queue.MarkConfirmed(last[0], string(p2))
	ask(r.zone, p2, "r51")
	if got := queued(r.zone, p2); len(got) != 1 || got[0] == last[0] {
		t.Errorf("after the asker confirmed an answer, the next request left %v queued, want its own answer", got)
	}
}

// An answer that carries a DNSKEY operation is remembered with its keys,
// for the asker's confirmation of it (creditFromAnswerLocked); an answer
// without one is not.
func TestAnAnswerWithADnskeyOperationIsRemembered(t *testing.T) {
	yes := true
	const asker = AgentId("agent.p2.example.")
	r := newAnswerRig(t, "remembered.answer.example.", []string{"us"})
	k := invItem(t, string(r.zone), 257, KeyStateActive, &yes)
	r.inventory(t, k)
	if _, err := r.conf.catchUpAnswer(r.zdr, r.zone, asker, &CatchUp{Request: "r1", Reason: "start"}); err != nil {
		t.Fatal(err)
	}
	key, err := dns.NewRR(k.KeyRR)
	if err != nil {
		t.Fatal(err)
	}
	ans := r.conf.InternalMp.MPTransport.answersSent[r.zdr.catchUpAnswers[r.zone][asker]]
	if ans == nil || ans.asker != asker || ans.zone != r.zone || !ans.keys[key.(*dns.DNSKEY).KeyTag()] {
		t.Errorf("the answer is remembered as %+v, want its asker, zone and key", ans)
	}

	s := newAnswerRig(t, "server.remembered.answer.example.", []string{"p2"})
	if _, err := s.conf.catchUpAnswer(s.zdr, s.zone, asker, &CatchUp{Request: "r1", Reason: "start"}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.conf.InternalMp.MPTransport.answersSent); n != 0 {
		t.Errorf("%d answers remembered for a server's answer, which has no DNSKEY operation", n)
	}
}
