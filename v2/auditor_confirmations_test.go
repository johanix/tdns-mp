/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp #152: each agent copies its final confirmation of a distribution
 * to the zone's auditors, and the auditor says from them which member a
 * distribution waits for.
 *
 * The tests run a provider group on the transport harness: every peer is a
 * bridge answering NOTIFY(CHUNK) on a loopback socket of its own, so every
 * message of a distribution travels: the sync, the immediate PENDING, the
 * final confirmation and its copy. A receiving agent's final confirmation is
 * its own SynchedDataEngine's, made when the agent's combiner has answered;
 * the combiner's answer is the one thing put in by hand, where the agent
 * gets it.
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	fleetAuditor = "aud.agent.example."
	fleetP1      = "p1.agent.example."
	fleetP2      = "p2.agent.example."
	fleetP3      = "p3.agent.example."
)

// fleetPeer is one member of the test fleet: a harness peer that listens,
// and counts the NOTIFYs it gets by sender.
type fleetPeer struct {
	*peerEnv
	addr string

	mu   sync.Mutex
	from map[string]int
}

// receivedFrom is how many NOTIFY(CHUNK)s have reached the peer from sender.
func (p *fleetPeer) receivedFrom(sender string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.from[sender]
}

// auditFleet is a provider group with its auditor.
type auditFleet struct {
	t     *testing.T
	ctx   context.Context
	peers map[string]*fleetPeer

	sm     *AuditStateManager
	engine *AuditorEngine // the auditor's
}

// newAuditFleet starts the auditor, the originating agent p1 and the given
// receiving agents. Every peer knows every other's address, as discovery
// would have left it. A receiving agent runs its SynchedDataEngine and has
// a combiner to forward to; of the originator only the bridge is needed,
// and what is confirmed to it stays in its confirmation queue to be read.
func newAuditFleet(t *testing.T, receivers ...string) *auditFleet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &auditFleet{t: t, ctx: ctx, peers: map[string]*fleetPeer{}}

	aud := f.listen(fleetAuditor, roleAuditor)
	f.sm = NewAuditStateManager()
	f.sm.LocalIdentity = fleetAuditor
	aud.Registry.AuditState = f.sm
	f.engine = &AuditorEngine{stateManager: f.sm, msgQs: aud.MsgQs}

	f.listen(fleetP1, roleAgent)
	for _, id := range receivers {
		f.startAgent(id)
	}
	return f
}

// listen builds a peer and has it answer NOTIFY(CHUNK) over TCP through its
// receive pipeline, the way tdns routes them in production.
func (f *auditFleet) listen(identity, role string) *fleetPeer {
	f.t.Helper()
	p := &fleetPeer{
		peerEnv: newPeer(f.t, identity, "edns0", &integEnvConfig{ControlZoneIsIdentity: true, Role: role}),
		from:    map[string]int{},
	}
	p.MsgQs.Confirmation = make(chan *ConfirmationDetail, 32)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.t.Fatalf("listen: %v", err)
	}
	p.addr = ln.Addr().String()
	p.Bridge.StartIncomingMessageRouter(f.ctx)
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// a NOTIFY's name is <distribution>.<the sender's identity>
		qname := r.Question[0].Name
		if _, sender, ok := strings.Cut(qname, "."); ok {
			p.mu.Lock()
			p.from[sender]++
			p.mu.Unlock()
		}
		_ = p.Bridge.ChunkHandler.RouteViaRouter(f.ctx, qname, r, w)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})

	for _, other := range f.peers {
		introduce(f.t, p, other)
		introduce(f.t, other, p)
	}
	f.peers[identity] = p
	return p
}

// introduce gives from the address of to.
func introduce(t *testing.T, from, to *fleetPeer) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(to.addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	peer := from.Bridge.PeerRegistry.GetOrCreate(to.Identity)
	peer.SetDiscoveryAddress(&transport.Address{Host: host, Port: uint16(port), Transport: "tcp"})
	peer.PreferredTransport = "DNS"
}

// startAgent adds an agent to the fleet: a listening peer whose
// SynchedDataEngine runs, with a combiner to forward remote updates to.
func (f *auditFleet) startAgent(identity string) *fleetPeer {
	f.t.Helper()
	p := f.listen(identity, roleAgent)
	p.Bridge.combinerID = AgentId("combiner." + identity)
	p.MsgQs.SynchedDataUpdate = make(chan *SynchedDataUpdate, 4)
	p.MsgQs.SynchedDataCmd = make(chan *SynchedDataCmd, 4)
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.MPTransport = p.Bridge
	conf.InternalMp.MsgQs = p.MsgQs
	conf.InternalMp.AgentRegistry = p.Registry
	go conf.SynchedDataEngine(f.ctx, p.MsgQs)
	return p
}

// nsAdd is a distribution's content: one NS record added at the zone's apex.
func nsAdd(zone, target string) []core.RROperation {
	return []core.RROperation{{Operation: "add", RRtype: "NS", Records: []string{zone + " 3600 IN NS " + target}}}
}

// distribute sends a distribution from one agent to another member, as the
// originator's reliable queue does.
func (f *auditFleet) distribute(from, to, zone, distID string, ops []core.RROperation, sent time.Time) {
	f.t.Helper()
	sender := f.peers[from]
	peer, ok := sender.Bridge.PeerRegistry.Get(to)
	if !ok {
		f.t.Fatalf("%s does not know %s", from, to)
	}
	ctx, cancel := context.WithTimeout(f.ctx, integTestTimeout)
	defer cancel()
	if _, err := sender.Bridge.SendSyncWithFallback(ctx, peer, &PeerSyncRequest{
		SenderID: from, Zone: zone, MessageType: "sync", DistributionID: distID, Operations: ops, Timestamp: sent,
	}); err != nil {
		f.t.Fatalf("sync %s from %s to %s: %v", distID, from, to, err)
	}
}

// auditorReceives hands the auditor's engine the distribution that has
// reached its bridge: the engine logs it, follows it and confirms it.
func (f *auditFleet) auditorReceives() {
	f.t.Helper()
	msg, ok := recvMsgWithin(f.t, f.peers[fleetAuditor].MsgQs.Msg, integTestTimeout)
	if !ok {
		f.t.Fatal("no distribution reached the auditor")
	}
	f.engine.onInboundMsg(&hsync.InboundMsg{
		MessageType: hsync.AgentMsg(msg.MessageType), Originator: hsync.PeerID(msg.OriginatorID), Zone: hsync.ZoneName(msg.Zone), Payload: msg,
	})
}

// combinerAnswers takes the distribution that has reached an agent through
// the agent's own handling, up to its combiner, and has the combiner answer:
// the agent's SynchedDataEngine then makes the agent's final confirmation.
func (f *auditFleet) combinerAnswers(agent, status string, rejected ...RejectedItemInfo) {
	f.t.Helper()
	p := f.peers[agent]
	msg, ok := recvMsgWithin(f.t, p.MsgQs.Msg, integTestTimeout)
	if !ok {
		f.t.Fatalf("no distribution reached %s", agent)
	}
	p.Registry.MsgHandler(msg, p.MsgQs.SynchedDataUpdate, p.MsgQs.SynchedDataCmd)

	// The agent forwarded the update to its combiner under an ID of its
	// own; the combiner's answer names that one.
	var forwarded string
	for _, m := range p.Bridge.GetQueuePendingMessages() {
		if m.RecipientID == string(p.Bridge.combinerID) && m.Zone == string(msg.Zone) {
			forwarded = m.DistributionID
		}
	}
	if forwarded == "" {
		f.t.Fatalf("%s forwarded nothing to its combiner", agent)
	}
	p.Bridge.MarkDeliveryConfirmed(forwarded, string(p.Bridge.combinerID))
	answer := &ConfirmationDetail{
		DistributionID: forwarded, Zone: msg.Zone, Source: string(p.Bridge.combinerID),
		Status: status, RejectedItems: rejected, Timestamp: time.Now(),
	}
	if len(rejected) == 0 {
		for _, op := range msg.Operations {
			answer.AppliedRecords = append(answer.AppliedRecords, op.Records...)
		}
	} else {
		answer.Message = "rejected by the combiner"
	}
	p.MsgQs.Confirmation <- answer
}

// view is the auditor's "confirmations" answer for the zone, over its API.
func (f *auditFleet) view(zone string) []AuditDistributionSummary {
	f.t.Helper()
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.AuditStateManager = f.sm
	resp := auditAPI(f.t, conf, AuditPost{Command: "confirmations", Zone: zone})
	if resp.Error {
		f.t.Fatalf("confirmations: %s", resp.ErrorMsg)
	}
	return resp.Distributions
}

// distribution finds one distribution in the auditor's view.
func (f *auditFleet) distribution(zone, originator, distID string) *AuditDistributionSummary {
	f.t.Helper()
	for _, d := range f.view(zone) {
		if d.DistributionID == distID && d.Originator == originator {
			return &d
		}
	}
	return nil
}

// memberState is a member's state in a distribution as the auditor shows
// it; "" when the view has no such member, or no such distribution.
func (f *auditFleet) memberState(zone, originator, distID, member string) (state, status, reason string) {
	f.t.Helper()
	d := f.distribution(zone, originator, distID)
	if d == nil {
		return "", "", ""
	}
	for _, m := range d.Members {
		if m.Identity == member {
			return m.State, m.Status, m.Reason
		}
	}
	return "", "", ""
}

// awaitMember waits until the auditor shows the member in the wanted state.
func (f *auditFleet) awaitMember(zone, originator, distID, member, want string) {
	f.t.Helper()
	deadline := time.Now().Add(integTestTimeout)
	for {
		got, _, _ := f.memberState(zone, originator, distID, member)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("distribution %s from %s: the auditor shows %s as %q, want %q; view: %+v", distID, originator, member, got, want, f.view(zone))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// awaitConfirmation waits for a confirmation of the distribution from the
// given peer to reach p's confirmation queue, and returns its status.
// Confirmations of others that come before it are passed over.
func (f *auditFleet) awaitConfirmation(p *fleetPeer, from, distID string) string {
	f.t.Helper()
	deadline := time.Now().Add(integTestTimeout)
	for time.Now().Before(deadline) {
		c, ok := recvWithin(p.MsgQs.Confirmation, 50*time.Millisecond)
		if ok && c.Source == from && c.DistributionID == distID {
			return c.Status
		}
	}
	f.t.Fatalf("no confirmation of %s from %s reached %s", distID, from, p.Identity)
	return ""
}

func waitingObservations(sm *AuditStateManager, zone, about string) (waiting, cleared []string) {
	for _, o := range sm.SnapshotAllObservations(zone) {
		if o.Provider != about {
			continue
		}
		switch {
		case strings.Contains(o.Message, "has waited"):
			waiting = append(waiting, o.Message)
		case strings.Contains(o.Message, "confirmed after"), strings.Contains(o.Message, "answered"):
			cleared = append(cleared, o.Message)
		}
	}
	return waiting, cleared
}

// A distribution in a zone with an auditor, one of whose members is stopped:
// the auditor names the distribution and the member it waits for, says so
// in an observation once the threshold has passed, and shows the
// distribution completed when the member returns and confirms.
//
// On the way: a member's copy goes to the auditor on its final confirmation
// and not on the immediate PENDING, once, and the originator still gets
// both; and in a zone without an auditor nobody gets a copy.
func TestTheAuditorShowsWhichMemberADistributionWaitsFor(t *testing.T) {
	const zone = "blocked.audit.example."
	const threshold = 2 * time.Minute
	seedAuditedZone(t, zone, fleetAuditor, fleetP1, fleetP2, fleetP3)
	f := newAuditFleet(t, fleetP2, fleetP3)
	aud, origin := f.peers[fleetAuditor], f.peers[fleetP1]

	// Earlier, all three providers up: p2 and p3 confirm a distribution, so
	// the auditor knows both as members that send it their confirmations.
	for _, member := range []string{fleetP2, fleetP3} {
		f.distribute(fleetP1, member, zone, "d0", nsAdd(zone, "ns0.p1.example."), time.Now())
		f.combinerAnswers(member, "SUCCESS")
		f.awaitMember(zone, fleetP1, "d0", member, "confirmed")
	}
	if d := f.distribution(zone, fleetP1, "d0"); d.State != "unseen" {
		t.Errorf("a distribution the auditor has only seen confirmations of is %q, want unseen: %+v", d.State, d)
	}
	if got := f.awaitConfirmation(origin, fleetP2, "d0"); got != "PENDING" {
		t.Fatalf("the first word from p2 on d0 is %s, want PENDING", got)
	}
	if got := f.awaitConfirmation(origin, fleetP2, "d0"); got != "SUCCESS" {
		t.Fatalf("the second word from p2 on d0 is %s, want SUCCESS", got)
	}
	copies := aud.receivedFrom(fleetP2)
	if copies != 1 {
		t.Errorf("the auditor got %d messages from p2 for d0, want 1: the copy of its final confirmation", copies)
	}

	// p3 stops. p1 distributes d1 to p2, the auditor and p3; it does not
	// reach p3.
	ops := nsAdd(zone, "ns1.p1.example.")
	f.distribute(fleetP1, fleetP2, zone, "d1", ops, time.Now())
	f.distribute(fleetP1, fleetAuditor, zone, "d1", ops, time.Now())
	f.auditorReceives()
	received := time.Now()

	// p2 has the distribution and has said PENDING to the originator. That
	// is no final word, and none of it went to the auditor.
	if got := f.awaitConfirmation(origin, fleetP2, "d1"); got != "PENDING" {
		t.Fatalf("the first word from p2 on d1 is %s, want PENDING", got)
	}
	time.Sleep(50 * time.Millisecond)
	if n := aud.receivedFrom(fleetP2); n != copies {
		t.Errorf("p2's PENDING was copied to the auditor: %d messages from p2, want %d", n, copies)
	}
	d := f.distribution(zone, fleetP1, "d1")
	if d == nil {
		t.Fatalf("the auditor does not show d1; view: %+v", f.view(zone))
	}
	if d.State != "pending" || d.Summary != "add NS (1 record)" || len(d.Members) != 2 {
		t.Errorf("d1 after it reached the auditor = %+v; want it pending, carrying the NS, awaiting p2 and p3", d)
	}
	for _, member := range []string{fleetP2, fleetP3} {
		if state, _, _ := f.memberState(zone, fleetP1, "d1", member); state != "pending" {
			t.Errorf("%s in d1 before any final confirmation is %q, want pending", member, state)
		}
	}

	// p2's combiner answers: p2's final confirmation goes to the originator
	// and, as a copy, to the auditor.
	f.combinerAnswers(fleetP2, "SUCCESS")
	f.awaitMember(zone, fleetP1, "d1", fleetP2, "confirmed")
	if got := f.awaitConfirmation(origin, fleetP2, "d1"); got != "SUCCESS" {
		t.Errorf("p2's final word on d1 at the originator is %s, want SUCCESS", got)
	}
	if n := aud.receivedFrom(fleetP2); n != copies+1 {
		t.Errorf("the auditor got %d messages from p2 for d1, want 1: the copy of its final confirmation", n-copies)
	}
	// The copy also goes where every confirmation goes at the auditor, to
	// be a row in its event log: all that an auditor on older code does
	// with it.
	if got := f.awaitConfirmation(aud, fleetP2, "d1"); got != "SUCCESS" {
		t.Errorf("the copy as the auditor's event log gets it says %s, want SUCCESS", got)
	}
	if n := len(aud.Bridge.GetQueuePendingMessages()); n != 0 {
		t.Errorf("the auditor has %d messages queued; it distributes nothing", n)
	}
	if state, _, _ := f.memberState(zone, fleetP1, "d1", fleetP3); state != "pending" {
		t.Errorf("the stopped p3 in d1 is %q, want pending", state)
	}
	if d := f.distribution(zone, fleetP1, "d1"); d.State != "pending" {
		t.Errorf("d1 with p3 stopped is %q, want pending", d.State)
	}

	// The observation: not before the threshold, once after it, and it
	// names the distribution, its originator and the member.
	state := newDetectorRunState()
	runDetectorsOnce(f.sm, state, received.Add(threshold-time.Second), 90*time.Second, threshold)
	if waiting, _ := waitingObservations(f.sm, zone, fleetP3); len(waiting) != 0 {
		t.Errorf("an observation before the threshold: %v", waiting)
	}
	runDetectorsOnce(f.sm, state, received.Add(threshold+time.Second), 90*time.Second, threshold)
	runDetectorsOnce(f.sm, state, received.Add(threshold+time.Minute), 90*time.Second, threshold)
	waiting, _ := waitingObservations(f.sm, zone, fleetP3)
	if len(waiting) != 1 {
		t.Fatalf("%d observations that d1 waits for p3, want 1: %v", len(waiting), waiting)
	}
	for _, want := range []string{"d1", "add NS", "from " + fleetP1, "confirmation from " + fleetP3} {
		if !strings.Contains(waiting[0], want) {
			t.Errorf("the observation %q does not say %q", waiting[0], want)
		}
	}
	if waiting, _ := waitingObservations(f.sm, zone, fleetP2); len(waiting) != 0 {
		t.Errorf("an observation about p2, which confirmed: %v", waiting)
	}

	// p3 returns; the originator's queue sends d1 again, p3's combiner
	// applies it and p3 confirms.
	f.distribute(fleetP1, fleetP3, zone, "d1", ops, time.Now())
	f.combinerAnswers(fleetP3, "SUCCESS")
	f.awaitMember(zone, fleetP1, "d1", fleetP3, "confirmed")
	if d := f.distribution(zone, fleetP1, "d1"); d.State != "completed" {
		t.Errorf("d1 with every member's confirmation in is %q, want completed: %+v", d.State, d)
	}
	runDetectorsOnce(f.sm, state, time.Now(), 90*time.Second, threshold)
	if waiting, cleared := waitingObservations(f.sm, zone, fleetP3); len(waiting) != 1 || len(cleared) != 1 || !strings.Contains(cleared[0], "d1") {
		t.Errorf("after p3 confirmed: waiting %v, cleared %v; want the one earlier observation and one that says p3 confirmed d1", waiting, cleared)
	}

	// A zone of the same providers that has no auditor: p2's final
	// confirmation goes to the originator and to nobody else.
	const unaudited = "unaudited.audit.example."
	zd := seedZoneWithHSYNC3(t, unaudited, fleetP1, fleetP2, fleetP3, fleetAuditor)
	addHSYNCPARAMServers(t, zd, shortLabel(fleetP1), shortLabel(fleetP2), shortLabel(fleetP3)) // the fourth identity holds no role
	before := map[string]int{}
	for id, p := range f.peers {
		before[id] = p.receivedFrom(fleetP2)
	}
	f.distribute(fleetP1, fleetP2, unaudited, "d2", nsAdd(unaudited, "ns2.p1.example."), time.Now())
	f.combinerAnswers(fleetP2, "SUCCESS")
	f.awaitConfirmation(origin, fleetP2, "d2") // the PENDING
	if got := f.awaitConfirmation(origin, fleetP2, "d2"); got != "SUCCESS" {
		t.Errorf("p2's final word on d2 at the originator is %s, want SUCCESS", got)
	}
	time.Sleep(50 * time.Millisecond)
	for _, id := range []string{fleetAuditor, fleetP3} {
		if n := f.peers[id].receivedFrom(fleetP2) - before[id]; n != 0 {
			t.Errorf("in a zone without an auditor, %d messages from p2 reached %s", n, id)
		}
	}
}

// A member's rejection reaches the auditor with its reason, and the
// distribution reads rejected once every member has answered.
func TestTheAuditorShowsARejectionWithItsReason(t *testing.T) {
	const zone = "refused.audit.example."
	seedAuditedZone(t, zone, fleetAuditor, fleetP1, fleetP2)
	f := newAuditFleet(t, fleetP2)

	ops := nsAdd(zone, "ns.elsewhere.example.")
	f.distribute(fleetP1, fleetP2, zone, "d7", ops, time.Now())
	f.distribute(fleetP1, fleetAuditor, zone, "d7", ops, time.Now())
	f.auditorReceives()
	f.combinerAnswers(fleetP2, "FAILED", RejectedItemInfo{Record: ops[0].Records[0], Reason: "NS target is not a nameserver of this provider"})
	f.awaitMember(zone, fleetP1, "d7", fleetP2, "rejected")

	state, status, reason := f.memberState(zone, fleetP1, "d7", fleetP2)
	if state != "rejected" || status != "FAILED" || reason != "NS target is not a nameserver of this provider" {
		t.Errorf("p2 in d7 = %s %s %q; want rejected, FAILED, with the combiner's reason", state, status, reason)
	}
	if d := f.distribution(zone, fleetP1, "d7"); d.State != "rejected" {
		t.Errorf("d7, refused by its one other member, is %q, want rejected", d.State)
	}
}

// A copy that reaches a peer that is no auditor (here an agent the zone
// lists under auditors=) is a confirmation of a distribution that is not
// the peer's own. It changes nothing there: the peer's own queued message,
// its DNSKEY tracking and its record tracking stand, and the confirmation
// is handed on as any other is.
func TestACopyChangesNothingAtAPeerThatIsNoAuditor(t *testing.T) {
	const zone = "misplaced.audit.example."
	// p3, an agent, is listed as the zone's auditor.
	seedAuditedZone(t, zone, fleetP3, fleetP1, fleetP2)
	f := newAuditFleet(t, fleetP2)
	p3 := f.listen(fleetP3, roleAgent)

	// p3 has business of its own with p2: a queued message, a DNSKEY
	// distribution it tracks, and a record waiting for p2's confirmation.
	own := &ZoneUpdate{Zone: zone, AgentId: fleetP3, Operations: nsAdd(zone, "ns.p3.example.")}
	if err := p3.Bridge.ReliableQueue.Enqueue(&transport.OutgoingMessage{DistributionID: "own1", RecipientID: fleetP2, Zone: zone, Payload: own}); err != nil {
		t.Fatal(err)
	}
	p3.Bridge.TrackDnskeyPropagation(zone, "own1", []uint16{4711}, nil, []AgentId{fleetP2})
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	zdr.MarkRRsPending(zone, fleetP3, own, "own1", []string{fleetP2})

	f.distribute(fleetP1, fleetP2, zone, "d9", nsAdd(zone, "ns9.p1.example."), time.Now())
	f.combinerAnswers(fleetP2, "SUCCESS")

	// the copy arrives at p3 and goes where every confirmation goes
	c, ok := recvWithin(p3.MsgQs.Confirmation, integTestTimeout)
	if !ok {
		t.Fatal("the copy did not reach p3")
	}
	if c.Source != fleetP2 || c.DistributionID != "d9" || c.Status != "SUCCESS" {
		t.Errorf("p3 was handed %+v, want p2's SUCCESS for d9", c)
	}
	zdr.ProcessConfirmation(c, p3.MsgQs) // as p3's SynchedDataEngine does with it

	// and nothing of p3's own has moved
	pending := p3.Bridge.GetQueuePendingMessages()
	if len(pending) != 1 || pending[0].DistributionID != "own1" || pending[0].RecipientID != fleetP2 {
		t.Errorf("p3's queue after the copy: %+v, want its own message to p2 still queued", pending)
	}
	p3.Bridge.dnskeyPropMu.Lock()
	prop := p3.Bridge.pendingDnskeyPropagations["own1"]
	p3.Bridge.dnskeyPropMu.Unlock()
	if prop == nil || prop.ExpectedAgents[fleetP2] || len(prop.Results) != 0 {
		t.Errorf("p3's DNSKEY tracking after the copy: %+v, want it untouched", prop)
	}
	tracked := zdr.Tracking[zone][fleetP3][dns.TypeNS]
	if tracked == nil || len(tracked.Tracked) != 1 || tracked.Tracked[0].State != RRStatePending || len(tracked.Tracked[0].Confirmations) != 0 {
		t.Errorf("p3's record tracking after the copy: %+v, want its record still pending, no confirmation booked", tracked)
	}
	if p3.Registry.AuditState != nil {
		t.Error("an agent has auditor state")
	}
}

// The copy can reach the auditor before the distribution does. It is kept,
// and counts when the distribution arrives. A distribution sent before the
// auditor started is not followed: its confirmations may have gone to a
// process that is no more.
func TestACopyBeforeTheDistributionAndADistributionFromBeforeTheStart(t *testing.T) {
	const zone = "early.audit.example."
	seedAuditedZone(t, zone, fleetAuditor, fleetP1, fleetP2, fleetP3)
	f := newAuditFleet(t, fleetP2)

	ops := nsAdd(zone, "ns5.p1.example.")
	f.distribute(fleetP1, fleetP2, zone, "d5", ops, time.Now())
	f.combinerAnswers(fleetP2, "SUCCESS")
	f.awaitMember(zone, fleetP1, "d5", fleetP2, "confirmed")
	if d := f.distribution(zone, fleetP1, "d5"); d.State != "unseen" || len(d.Members) != 1 {
		t.Errorf("d5 before it reached the auditor = %+v, want unseen with p2's confirmation", d)
	}
	f.distribute(fleetP1, fleetAuditor, zone, "d5", ops, time.Now())
	f.auditorReceives()
	if state, _, _ := f.memberState(zone, fleetP1, "d5", fleetP2); state != "confirmed" {
		t.Errorf("p2 in d5 after the distribution arrived is %q, want its earlier confirmation kept", state)
	}
	// p3 has never sent the auditor a confirmation: what it has confirmed
	// is not known, and the auditor does not say the distribution waits.
	if state, _, _ := f.memberState(zone, fleetP1, "d5", fleetP3); state != "unknown" {
		t.Errorf("p3, which has never sent a copy, is %q in d5, want unknown", state)
	}
	if d := f.distribution(zone, fleetP1, "d5"); d.State != "unknown" {
		t.Errorf("d5 is %q, want unknown: the one confirmation missing is that of a member that sends none", d.State)
	}
	det := newDetectorRunState()
	runDetectorsOnce(f.sm, det, time.Now().Add(time.Hour/2), 90*time.Second, 2*time.Minute)
	if waiting, _ := waitingObservations(f.sm, zone, fleetP3); len(waiting) != 0 {
		t.Errorf("an observation about a member that sends no copies: %v", waiting)
	}

	// sent an hour before this auditor started
	f.distribute(fleetP1, fleetAuditor, zone, "d6", nsAdd(zone, "ns6.p1.example."), f.sm.Started.Add(-time.Hour))
	f.auditorReceives()
	if d := f.distribution(zone, fleetP1, "d6"); d != nil {
		t.Errorf("a distribution sent before the auditor started is followed: %+v", d)
	}
}

// A copy is believed for the sender the transport established, and for no
// other. One that reaches the auditor's route with no transport sender is
// dropped: the sender its payload names is the claim to be checked, not
// what to check it against. The same copy from the member it names is
// booked.
//
// The receive pipeline stamps a transport sender on every message it
// routes, so the copy without one is handed to the bridge's callback as the
// parser leaves it, before that stamp. And no sync API endpoint takes the
// confirm verb: a copy cannot come in over HTTPS, where the transport's
// sender would be the one the body names.
func TestACopyWithoutATransportSenderIsNotBelieved(t *testing.T) {
	const zone = "sender.audit.example."
	seedAuditedZone(t, zone, fleetAuditor, fleetP1, fleetP2, fleetP3)
	f := newAuditFleet(t)
	aud := f.peers[fleetAuditor]

	body, err := json.Marshal(&DnsConfirmCopyPayload{
		DnsConfirmPayload: transport.DnsConfirmPayload{
			Type: transport.VerbConfirm, SenderID: fleetP2, Zone: zone,
			DistributionID: "d4", Status: "SUCCESS", Timestamp: time.Now().Unix(),
		},
		Originator: fleetP1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// the copy as the pipeline's parser hands it on
	parsed := func(transportSender string) *transport.IncomingMessage {
		t.Helper()
		msg, err := parseAppPayload("d4", body, "127.0.0.1:0")
		if err != nil || msg.Token() != transport.VerbConfirm || msg.SenderID != fleetP2 || msg.TransportSender != "" {
			t.Fatalf("the parsed copy = %+v, %v; want a confirm naming p2, no transport sender yet", msg, err)
		}
		msg.TransportSender = transportSender
		return msg
	}
	unbooked := func(when string) {
		t.Helper()
		if got := f.view(zone); len(got) != 0 {
			t.Errorf("%s: the auditor booked the copy: %+v", when, got)
		}
		if got := f.sm.Reporters(); len(got) != 0 {
			t.Errorf("%s: the auditor took %v for members that send it their confirmations", when, got)
		}
	}

	aud.Bridge.routeIncomingMessage(parsed(""))
	unbooked("a copy with no transport sender")

	// sent by a member other than the one the payload names
	aud.Bridge.routeIncomingMessage(parsed(fleetP3))
	unbooked("a copy that names another sender than the one that sent it")

	// over HTTPS: every endpoint refuses the verb before the pipeline
	srv := apiEndpointsServer(t, aud.peerEnv)
	for _, path := range []string{"/api/v1/hello", "/api/v1/beat", "/api/v1/sync/ping", "/api/v1/msg"} {
		res, err := srv.Client().Post(srv.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var reply map[string]interface{}
		err = json.NewDecoder(res.Body).Decode(&reply)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if reply["Error"] != true {
			t.Errorf("%s took a confirmation copy: %v", path, reply)
		}
	}
	unbooked("a copy posted to the sync API endpoints")

	// the same copy from the sender the transport established
	aud.Bridge.routeIncomingMessage(parsed(fleetP2))
	if state, status, _ := f.memberState(zone, fleetP1, "d4", fleetP2); state != "confirmed" || status != "SUCCESS" {
		t.Errorf("the copy from p2 itself: p2 in d4 is %q %q, want confirmed, SUCCESS; view: %+v", state, status, f.view(zone))
	}
	if !f.sm.Reporters()[fleetP2] {
		t.Error("p2 sent a copy and is not known as a member that sends them")
	}
}

// The distributions a zone keeps are bounded in age and in number.
func TestTheAuditorsDistributionsAgeOut(t *testing.T) {
	sm := NewAuditStateManager()
	zs := sm.GetOrCreateZone("bounds.audit.example.")
	members := []string{fleetP2, fleetP3}

	zs.NoteDistribution("done", fleetP1, "add NS (1 record)", members)
	sm.NoteConfirmation(zs.Zone, "done", fleetP1, fleetP2, "SUCCESS", "", nil)
	sm.NoteConfirmation(zs.Zone, "done", fleetP1, fleetP3, "SUCCESS", "", nil)
	zs.NoteDistribution("waits", fleetP1, "add NS (1 record)", members)
	sm.NoteConfirmation(zs.Zone, "waits", fleetP1, fleetP2, "SUCCESS", "", nil)
	sm.NoteConfirmation(zs.Zone, "copy-only", fleetP1, fleetP2, "SUCCESS", "", nil)

	has := func(id string) bool {
		zs.mu.RLock()
		defer zs.mu.RUnlock()
		return zs.Distributions[distributionKey(fleetP1, id)] != nil
	}
	now := time.Now()
	zs.pruneDistributions(now.Add(auditDistributionKeep - time.Minute))
	if !has("done") || !has("waits") || !has("copy-only") {
		t.Fatal("a distribution was dropped before its time")
	}
	zs.pruneDistributions(now.Add(auditDistributionKeep + time.Minute))
	if has("done") || has("copy-only") || !has("waits") {
		t.Errorf("after the keep time: done %v, copy-only %v, waits %v; want only the one that still waits", has("done"), has("copy-only"), has("waits"))
	}
	zs.pruneDistributions(now.Add(auditDistributionGiveUp + time.Minute))
	if has("waits") {
		t.Error("a distribution that still waits was kept past the time its sender gives up")
	}

	// The cap: confirmations of distributions that never arrive do not push
	// out one that is followed.
	zs.NoteDistribution("followed", fleetP1, "", members)
	for i := 0; i < 2*auditDistributionsMax; i++ {
		sm.NoteConfirmation(zs.Zone, "junk"+strconv.Itoa(i), fleetP1, fleetP2, "SUCCESS", "", nil)
	}
	zs.mu.RLock()
	n := len(zs.Distributions)
	zs.mu.RUnlock()
	if n > auditDistributionsMax || !has("followed") {
		t.Errorf("%d distributions kept (the cap is %d), the followed one kept: %v", n, auditDistributionsMax, has("followed"))
	}
}
