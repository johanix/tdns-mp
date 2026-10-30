package tdnsmp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The leader's withdrawal (design 5.2, plan S16), on S8's receive rig: the
// agent of provider a, at serial 41, where a and b serve the zone and n has
// a record and no role.

// heldForN puts n's NS records in the data, as a replace of n's made under
// in, at at, left them.
func (r *receiveRig) heldForN(in *Instructions, at time.Time, names ...string) {
	r.t.Helper()
	op := core.RROperation{Operation: "replace", RRtype: "NS"}
	for _, n := range names {
		op.Records = append(op.Records, r.ns(n))
	}
	if _, _, err := r.zdr.ProcessUpdate(&SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleN, UpdateType: "remote",
		Update:            &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleN, Operations: []core.RROperation{op}},
		OriginatingDistID: nextDistributionID(), OriginatingInstr: msgStampAt(in), OriginatingTime: at, DeliveredBy: roleN}); err != nil {
		r.t.Fatal(err)
	}
	if got := r.nsOf(roleN); len(got) != len(names) {
		r.t.Fatalf("n's NS in the data: %v", got)
	}
}

// withdrawal is sender's withdrawal of provider's NS records, made under
// under at at, handled by the data engine's remote case; ops replace the
// empty replace when given.
func (r *receiveRig) withdrawal(sender, provider AgentId, distID string, under *Instructions, at time.Time, ops ...core.RROperation) {
	r.t.Helper()
	if len(ops) == 0 {
		ops = []core.RROperation{{Operation: "replace", RRtype: "NS"}}
	}
	w := &Withdraw{Provider: string(provider), RRtype: "NS"}
	resp := make(chan *AgentMsgResponse, 1)
	r.conf.applyRemoteUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: provider, UpdateType: "remote",
		Update:            &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: provider, Operations: ops, Withdraw: w},
		OriginatingDistID: distID, OriginatingInstr: msgStampAt(under), Mechanism: "DNS", OriginatingTime: at, DeliveredBy: sender,
		Withdraw: w, Response: resp}, r.conf.InternalMp.MsgQs)
	select {
	case <-resp:
	default:
		r.t.Fatal("the data engine gave the withdrawal no answer")
	}
}

// refused: the agent's one answer to distID is a REJECTED to sender whose
// text holds why.
func (r *receiveRig) refused(distID string, sender AgentId, why string) {
	r.t.Helper()
	a := r.answered(distID)
	if len(a) != 1 || a[0].Status != "REJECTED" || a[0].OriginatingSender != string(sender) || !strings.Contains(a[0].Message, why) {
		var got []RemoteConfirmationDetail
		for _, d := range a {
			got = append(got, *d)
		}
		r.t.Errorf("the answers to %s: %+v, want a REJECTED to %s that says %q", distID, got, sender, why)
	}
}

func TestAWithdrawalIsTakenFromTheLeaderOnly(t *testing.T) {
	r := newReceiveRig(t, "leader.withdraw.example.")
	r.leads(roleB)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	const c = AgentId("c.role.example.")
	r.withdrawal(c, roleN, "d1", r.n, time.Now())
	r.refused("d1", c, "does not lead the zone")
	if got := r.nsOf(roleN); len(got) != 1 {
		t.Errorf("n's NS after a withdrawal from another than the leader: %v", got)
	}
	r.withdrawal(roleB, roleN, "d2", r.n, time.Now())
	if got := r.nsOf(roleN); len(got) != 0 {
		t.Errorf("n's NS after the leader's withdrawal: %v", got)
	}
	if r.sent()[freezeCombiner] != 1 {
		t.Errorf("queued %v: want the withdrawal handed to the combiner", r.sent())
	}
}

func TestAWithdrawalOfAListedProviderIsRefused(t *testing.T) {
	r := newReceiveRig(t, "listed.withdraw.example.")
	r.leads(roleB)
	r.withdrawal(roleB, roleB, "d1", r.n, time.Now())
	r.refused("d1", roleB, "the active instructions list "+roleB+" in servers=")
	if why := withdrawalRefusal(freezeAt(t, 41, "s", "a", ""), roleN, "DNSKEY"); why != "" {
		t.Errorf("a DNSKEY withdrawal of a provider in no signers= is refused: %s", why)
	}
	if why := withdrawalRefusal(r.n, roleN, "TXT"); why == "" {
		t.Error("a withdrawal of TXT records is taken")
	}
}

func TestAWithdrawalWithRecordsIsRefused(t *testing.T) {
	r := newReceiveRig(t, "records.withdraw.example.")
	r.leads(roleB)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	for i, ops := range [][]core.RROperation{
		{{Operation: "replace", RRtype: "NS", Records: []string{r.ns("ns2.n.example.")}}},
		{{Operation: "delete", RRtype: "NS", Records: []string{r.ns("ns1.n.example.")}}},
		{{Operation: "replace", RRtype: "NS"}, {Operation: "replace", RRtype: "NS"}},
		{{Operation: "replace", RRtype: "CDS"}},
	} {
		d := nextDistributionID()
		r.withdrawal(roleB, roleN, d, r.n, time.Now(), ops...)
		r.refused(d, roleB, "a withdrawal is one empty replace of the type it names")
		if got := r.nsOf(roleN); len(got) != 1 {
			t.Errorf("case %d: n's NS after a refused withdrawal: %v", i, got)
		}
	}
}

func TestAWithdrawalStampedAheadIsKeptUntilTheActiveSerialCatchesUp(t *testing.T) {
	r := newReceiveRig(t, "ahead.withdraw.example.")
	r.leads(roleB)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.agree()
	r.withdrawal(roleB, roleN, "d1", r.v, time.Now())
	if a := r.answered("d1"); len(a) != 1 || a[0].Status != "PENDING" || a[0].OriginatingSender != roleB {
		t.Fatalf("the answer to a withdrawal made under 42: %+v", a)
	}
	if len(r.kept()) != 1 || len(r.nsOf(roleN)) != 1 {
		t.Fatalf("kept %d, n's NS %v: want the withdrawal kept and n's NS held", len(r.kept()), r.nsOf(roleN))
	}
	r.done()
	r.activated()
	if got := r.nsOf(roleN); len(got) != 0 {
		t.Errorf("n's NS after the activation of 42: %v", got)
	}
}

func TestAWithdrawalStampedBehindIsRefusedAsStale(t *testing.T) {
	r := newReceiveRig(t, "behind.withdraw.example.")
	r.leads(roleB)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.withdrawal(roleB, roleN, "d1", freezeAt(t, 40, "o", "a,b", ""), time.Now())
	r.refused("d1", roleB, staleInstructions+":")
	if got := r.nsOf(roleN); len(got) != 1 {
		t.Errorf("n's NS after a stale withdrawal: %v", got)
	}
}

// A leader sends a withdrawal when its plan calls for one and what is in
// place still does: an agent that now leads, and still holds n's records,
// sends it; once it is pending removal, not again; one that does not lead,
// never.
func TestANewLeaderSendsAWithdrawalAgainWhenItsPlanCallsForIt(t *testing.T) {
	r := newReceiveRig(t, "again.withdraw.example.")
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.leads(roleB)
	if sent, err := r.conf.withdraw(r.zdr, ZoneName(r.zone), roleN, "NS"); sent || err == nil {
		t.Errorf("an agent that does not lead sent a withdrawal (%v, %v)", sent, err)
	}
	r.leads(roleA)
	if sent, err := r.conf.withdraw(r.zdr, ZoneName(r.zone), roleN, "NS"); !sent || err != nil {
		t.Fatalf("the new leader sent no withdrawal (%v, %v)", sent, err)
	}
	if r.sent()[freezeCombiner] != 1 {
		t.Errorf("queued %v: want the withdrawal handed to the combiner", r.sent())
	}
	if sent, _ := r.conf.withdraw(r.zdr, ZoneName(r.zone), roleN, "NS"); sent {
		t.Error("a withdrawal pending removal was sent again")
	}
}

// A withdrawal a member refused as stale is sent again by rule 6 once the
// leader is in step with it, as a withdrawal, under its own distribution
// ID; once the leader no longer leads, it is not.
func TestAWithdrawalRefusedAsStaleIsSentAgainWhenInStep(t *testing.T) {
	for _, stillLeads := range []bool{true, false} {
		r := newReceiveRig(t, map[bool]string{true: "resent.withdraw.example.", false: "dropped.withdraw.example."}[stillLeads])
		r.heldForN(r.n, time.Now(), "ns1.n.example.")
		r.leads(roleA)
		distID, err := r.conf.sendWithdrawal(r.zdr, ZoneName(r.zone), roleN, "NS")
		if err != nil {
			t.Fatal(err)
		}
		tm := r.conf.InternalMp.MPTransport
		// b's REJECTED stale-instructions settles the send in the queue,
		// and books it as "not yet"
		settleQueuedMessage(r.queue, distID, roleB, transport.ConfirmRejected)
		tm.noteNotYet(ZoneName(r.zone), roleB, distID, msgStampAt(r.v))
		r.agree()
		r.done()
		if !stillLeads {
			r.leads(roleB)
		}
		r.activated()
		if r.resent(distID) != stillLeads {
			t.Errorf("still leading %v: sent again to b %v", stillLeads, r.resent(distID))
		}
		if n := len(tm.notYets.forZone(ZoneName(r.zone))); n != 0 {
			t.Errorf("still leading %v: the book still holds %d", stillLeads, n)
		}
	}
}

// A withdrawal the queue does not take leaves nothing pending removal, so
// the plan's next call sends it again.
func TestAWithdrawalThatCannotBeQueuedIsNotLeftPending(t *testing.T) {
	r := newReceiveRig(t, "unqueued.send.withdraw.example.")
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.leads(roleA)
	tm := r.conf.InternalMp.MPTransport
	full := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{MaxQueueSize: 1})
	if err := full.Enqueue(&transport.OutgoingMessage{DistributionID: "x", RecipientID: roleB, Zone: r.zone, Payload: &ZoneUpdate{}}); err != nil {
		t.Fatal(err)
	}
	tm.ReliableQueue = full
	if sent, err := r.conf.withdraw(r.zdr, ZoneName(r.zone), roleN, "NS"); sent || err == nil {
		t.Fatalf("a withdrawal the queue could not take reads as sent (%v, %v)", sent, err)
	}
	if st := r.zdr.Tracking[ZoneName(r.zone)][roleN][dns.TypeNS].Tracked[0].State; st == RRStatePendingRemoval {
		t.Error("n's NS is left pending removal")
	}
	tm.ReliableQueue = r.queue
	if sent, err := r.conf.withdraw(r.zdr, ZoneName(r.zone), roleN, "NS"); !sent || err != nil {
		t.Errorf("the plan's next call did not send it (%v, %v)", sent, err)
	}
}

// The leader's clock is not the provider's: n's last replace, made under
// 41, is stamped later than the leader's withdrawal under 42, and the
// withdrawal is not stale for it.
func TestAWithdrawalIsNotStaleByTheLeadersClock(t *testing.T) {
	r := newReceiveRig(t, "clock.withdraw.example.")
	r.leads(roleB)
	r.agree()
	r.done()
	r.heldForN(r.n, time.Now().Add(time.Hour), "ns1.n.example.")
	r.withdrawal(roleB, roleN, "d1", r.v, time.Now())
	if got := r.nsOf(roleN); len(got) != 0 {
		t.Errorf("n's NS after the leader's withdrawal under 42: %v", got)
	}
}

// replaceAt is n's replace of its NS, made under in at at, for the agent's
// order (noteReplaceOrigin): whether it is stale.
func (r *receiveRig) staleAt(in *Instructions, at time.Time, w *Withdraw) bool {
	stale, _ := r.zdr.noteReplaceOrigin(&SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleN, OriginatingDistID: nextDistributionID(),
		OriginatingInstr: msgStampAt(in), OriginatingTime: at, Withdraw: w}, dns.TypeNS)
	return stale
}

// combinerStaleAt is the same at the combiner (staleCombinerReplace).
func combinerStaleAt(zone string, in *Instructions, at time.Time) bool {
	stale, _ := staleCombinerReplace(&CombinerSyncRequest{SenderID: roleN, DistributionID: nextDistributionID(), Timestamp: at,
		Instr: msgStampAt(in)}, zone, dns.TypeNS)
	return stale
}

func TestAReplaceAtAHigherSerialWinsOverTheLeadersWithdrawalWhateverTheClocks(t *testing.T) {
	r := newReceiveRig(t, "higher.withdraw.example.")
	now := time.Now()
	w := &Withdraw{Provider: roleN, RRtype: "NS"}
	if r.staleAt(r.v, now.Add(-time.Hour), nil) {
		t.Fatal("n's replace under 42 is stale")
	}
	if !r.staleAt(r.n, now, w) {
		t.Error("the leader's withdrawal under 41, later by its clock, is not stale for n's replace under 42")
	}
	const z = "higher.combiner.withdraw.example."
	if combinerStaleAt(z, r.v, now.Add(-time.Hour)) || !combinerStaleAt(z, r.n, now) {
		t.Error("at the combiner a replace under 41 is not stale for one under 42 that it took before")
	}
}

func TestAReplaceAtALowerSerialIsStale(t *testing.T) {
	r := newReceiveRig(t, "lower.withdraw.example.")
	now := time.Now()
	if r.staleAt(r.v, now, nil) || !r.staleAt(r.n, now.Add(time.Hour), nil) {
		t.Error("a replace under 41 is not stale for one under 42 applied before it, whatever the time")
	}
	const z = "lower.combiner.withdraw.example."
	if combinerStaleAt(z, r.v, now) || !combinerStaleAt(z, r.n, now.Add(time.Hour)) {
		t.Error("at the combiner a replace under 41 is not stale for one under 42")
	}
}

func TestWithdrawalsAreOrderedByTheStampAtSendThenTheCreationTime(t *testing.T) {
	now := time.Now()
	at := func(serial uint32, has bool, t time.Time, d string) replaceOrigin {
		return replaceOrigin{Time: t, DistID: d, Under: serial, HasUnder: has}
	}
	for _, tc := range []struct {
		name      string
		o, cur    replaceOrigin
		olderThan bool
	}{
		{"a lower serial, later", at(41, true, now.Add(time.Hour), "d2"), at(42, true, now, "d1"), true},
		{"a higher serial, earlier", at(43, true, now.Add(-time.Hour), "d1"), at(42, true, now, "d2"), false},
		{"the same serial, earlier", at(42, true, now.Add(-time.Second), "d2"), at(42, true, now, "d1"), true},
		{"the same serial, later", at(42, true, now.Add(time.Second), "d1"), at(42, true, now, "d2"), false},
		{"the same serial and time, a lower ID", at(42, true, now, "d1"), at(42, true, now, "d2"), true},
		{"no serial told, earlier", at(0, false, now.Add(-time.Second), "d2"), at(42, true, now, "d1"), true},
		{"no serial told, later", at(0, false, now.Add(time.Second), "d1"), at(42, true, now, "d2"), false},
	} {
		if got := tc.o.olderThan(tc.cur); got != tc.olderThan {
			t.Errorf("%s: older %v, want %v", tc.name, got, tc.olderThan)
		}
	}
}

// The combiner applies a removal in any origin's name that its own agent
// delivers with the withdrawal's flag: a delete, or a replace whose records
// are a subset of what the origin holds. A replace that adds a record is no
// removal, even a smaller one.
func TestARemovalInAnyOriginsNameFromItsOwnAgentIsApplied(t *testing.T) {
	mpzd, _ := withdrawnAtCombiner(t, "removal.combiner.withdraw.example.", "ns1", "ns2")
	z := mpzd.ZoneName
	ns := func(n string) string { return z + "\t3600\tIN\tNS\t" + n + ".gone.example." }
	for name, ops := range map[string][]core.RROperation{
		"a delete":           {{Operation: "delete", RRtype: "NS", Records: []string{ns("ns1")}}},
		"a subset replace":   {{Operation: "replace", RRtype: "NS", Records: []string{ns("ns2")}}},
		"an empty replace":   {{Operation: "replace", RRtype: "NS"}},
		"the whole replaced": {{Operation: "replace", RRtype: "NS", Records: []string{ns("ns1"), ns("ns2")}}},
	} {
		if !combinerRemovesOnly(z, goneOrigin, ops) {
			t.Errorf("%s is no removal", name)
		}
	}
}

func TestASmallerReplaceThatAddsARecordIsRefused(t *testing.T) {
	mpzd, _ := withdrawnAtCombiner(t, "adds.combiner.withdraw.example.", "ns1", "ns2")
	z := mpzd.ZoneName
	ops := []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{z + " 3600 IN NS ns3.gone.example."}}}
	if combinerRemovesOnly(z, goneOrigin, ops) {
		t.Error("a smaller replace that adds a record is taken as a removal")
	}
	if combinerRemovesOnly(z, goneOrigin, []core.RROperation{{Operation: "add", RRtype: "NS", Records: []string{z + " 3600 IN NS ns1.gone.example."}}}) {
		t.Error("an add is taken as a removal")
	}
}

// The withdrawal passes the combiner's origin checks: the origin does not
// vote, and the removal is applied all the same.
func TestAWithdrawalPassesTheCombinersOriginChecks(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, "checks.combiner.withdraw.example.", "ns1")
	resp := combinerWithdraws(mpzd, hdb, false)
	if resp.Status == "error" || len(resp.RejectedItems) != 0 {
		t.Fatalf("the combiner refused the withdrawal: %+v", resp)
	}
	if held := combinerHolds(mpzd, goneOrigin); len(held) != 0 {
		t.Errorf("the origin's NS after the withdrawal: %v", held)
	}
}

func TestTheCombinerTakesTheFlagFromItsOwnAgentOnly(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, "flag.combiner.withdraw.example.", "ns1")
	msg := &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{OriginatorID: goneOrigin, Zone: ZoneName(mpzd.ZoneName),
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}, Withdraw: &Withdraw{Provider: goneOrigin, RRtype: "NS"}}}
	local := map[string]bool{csyncOurAgent: true}
	if !combinerTakesRemoval(msg, csyncOurAgent, local) {
		t.Error("the flag from the combiner's own agent is not honoured")
	}
	if combinerTakesRemoval(msg, "agent.other.example.", local) {
		t.Error("the flag from another agent is honoured")
	}
	resp := combinerWithdraws(mpzd, hdb, true)
	if resp.Status != "error" || !strings.Contains(resp.Message, "is not a voting member") {
		t.Errorf("a withdrawal not flagged by the combiner's own agent: %+v, want the origin refused", resp)
	}
}

// On a zone whose edits wait for manual approval, the leader's withdrawal
// from the combiner's own agent is applied at once, not kept for approval.
func TestAWithdrawalIsNotKeptForManualApproval(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, "manual.combiner.withdraw.example.", "ns1")
	mpzd.Options[OptMPManualApproval] = true
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = hdb.KeyDB
	conf.SetMpConfig(&MultiProviderConf{Role: "combiner", Identity: csyncCombinerID, Agents: []*PeerConf{{Identity: csyncOurAgent}}})
	msgQs := &MsgQs{Msg: make(chan *AgentMsgPostPlus, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); CombinerMsgHandler(ctx, conf, msgQs, nil, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: goneOrigin, DeliveredBy: csyncOurAgent,
		Zone: ZoneName(mpzd.ZoneName), DistributionID: nextDistributionID(), Withdraw: &Withdraw{Provider: goneOrigin, RRtype: "NS"},
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}}}
	// a voting origin's edit behind it is kept for approval: once it is,
	// the withdrawal before it has been handled
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: AgentId(csyncLeaderA), DeliveredBy: csyncOurAgent,
		Zone: ZoneName(mpzd.ZoneName), DistributionID: nextDistributionID(),
		Operations: []core.RROperation{{Operation: "add", RRtype: "NS", Records: []string{mpzd.ZoneName + " 3600 IN NS ns.alpha.example."}}}}}
	waitUntil(t, "the edit behind the withdrawal was not kept for approval", func() bool {
		edits, _ := ListPendingEdits(hdb, mpzd.ZoneName)
		return len(edits) > 0
	})
	cancel()
	<-done
	edits, _ := ListPendingEdits(hdb, mpzd.ZoneName)
	for _, e := range edits {
		if e.SenderID == goneOrigin {
			t.Errorf("the withdrawal is kept for approval: %+v", e)
		}
	}
	if held := combinerHolds(mpzd, goneOrigin); len(held) != 0 {
		t.Errorf("the origin's NS after the withdrawal: %v", held)
	}
}

const goneOrigin = "agent.gone.example."

// withdrawnAtCombiner is a combiner's zone where goneOrigin, which has no
// record, holds NS records of the given names.
func withdrawnAtCombiner(t *testing.T, zone string, names ...string) (*MPZoneData, *HsyncDB) {
	t.Helper()
	mpzd, hdb := csyncCombinerZone(t, zone, false, false)
	// the zone's providers, as TestTheCombinerRefusesAnOriginThatDoesNotVote
	// has them: goneOrigin is none of them
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	var h3 []dns.RR
	for _, l := range []string{"us", "alpha", "beta"} {
		h3 = append(h3, &dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
			Data: &core.HSYNC3{State: 1, Label: l, Identity: "agent." + l + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	var rrs []string
	for _, n := range names {
		rrs = append(rrs, zone+" 3600 IN NS "+n+".gone.example.")
	}
	if _, err := mpzd.AddCombinerDataNG(goneOrigin, map[string][]string{zone: rrs}); err != nil {
		t.Fatal(err)
	}
	if held := combinerHolds(mpzd, goneOrigin); len(held) != len(names) {
		t.Fatalf("the origin's NS at the combiner: %v", held)
	}
	return mpzd, hdb
}

// combinerHolds is origin's NS records at the combiner.
func combinerHolds(mpzd *MPZoneData, origin string) []string {
	var out []string
	for _, rr := range mpzd.MP.AgentContributions[origin][mpzd.ZoneName][dns.TypeNS].RRs {
		out = append(out, rr.String())
	}
	return out
}

// combinerWithdraws is the combiner's processing of the withdrawal of
// goneOrigin's NS, flagged as from its own agent unless notFlagged.
func combinerWithdraws(mpzd *MPZoneData, hdb *HsyncDB, notFlagged bool) *CombinerSyncResponse {
	return CombinerProcessUpdate(&CombinerSyncRequest{SenderID: goneOrigin, DeliveredBy: csyncOurAgent, Zone: mpzd.ZoneName,
		Operations:     []core.RROperation{{Operation: "replace", RRtype: "NS"}},
		DistributionID: nextDistributionID(), Timestamp: time.Now(), Removal: !notFlagged}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
}

func TestTheConfirmationOfAWithdrawalGoesToTheLeader(t *testing.T) {
	r := newReceiveRig(t, "confirm.withdraw.example.")
	r.leads(roleB)
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.withdrawal(roleB, roleN, "d1", r.n, time.Now())
	var prc *PendingRemoteConfirmation
	for _, p := range r.zdr.PendingRemoteConfirms {
		if p.OriginatingDistID == "d1" {
			prc = p
		}
	}
	if prc == nil || prc.OriginatingSender != roleB {
		t.Errorf("the withdrawal's final confirmation goes to %+v, want the leader %s", prc, roleB)
	}
	// nothing held here: it goes to the combiner all the same, which may
	// hold what this agent does not, and its word to the leader
	r2 := newReceiveRig(t, "noop.confirm.withdraw.example.")
	r2.leads(roleB)
	r2.withdrawal(roleB, roleN, "d2", r2.n, time.Now())
	if a := r2.answered("d2"); len(a) != 0 || r2.sent()[freezeCombiner] != 1 {
		t.Errorf("a withdrawal of what is not held here: answered %d at once, queued %v, want it handed to the combiner", len(a), r2.sent())
	}
	prc = nil
	for _, p := range r2.zdr.PendingRemoteConfirms {
		if p.OriginatingDistID == "d2" {
			prc = p
		}
	}
	if prc == nil || prc.OriginatingSender != roleB {
		t.Errorf("the final confirmation of a withdrawal of what is not held goes to %+v, want %s", prc, roleB)
	}
}

// The leaving provider's own agent applies the withdrawal of its own
// records, and passes it to its combiner in its own name.
func TestTheLeavingProviderAppliesTheWithdrawalOfItsOwnRecords(t *testing.T) {
	r := newReceiveRig(t, "own.withdraw.example.")
	knownAs(t, r.store, r.zone, freezeAt(t, 41, "w", "b", ""))
	r.leads(roleB)
	op := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{r.ns("ns1.a.example.")}}
	if _, _, err := r.zdr.ProcessUpdate(&SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleA, UpdateType: "remote",
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleA, Operations: []core.RROperation{op}}, OriginatingTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r.withdrawal(roleB, roleA, "d1", freezeAt(t, 41, "w", "b", ""), time.Now())
	if got := r.nsOf(roleA); len(got) != 0 {
		t.Errorf("a's own NS after the leader's withdrawal: %v", got)
	}
	if r.sent()[freezeCombiner] != 1 {
		t.Errorf("queued %v: want the withdrawal handed to a's combiner", r.sent())
	}
}

func TestAMemberThatKnowsNoLeaderKeepsAWithdrawal(t *testing.T) {
	r := newReceiveRig(t, "noleader.withdraw.example.")
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.withdrawal(roleB, roleN, "d1", r.n, time.Now())
	if a := r.answered("d1"); len(a) != 1 || a[0].Status != "PENDING" || a[0].OriginatingSender != roleB {
		t.Fatalf("the answer to a withdrawal while no leader is known: %+v", a)
	}
	if len(r.kept()) != 1 || len(r.nsOf(roleN)) != 1 {
		t.Fatalf("kept %d, n's NS %v: want the withdrawal kept and n's NS held", len(r.kept()), r.nsOf(roleN))
	}
	r.leads(roleB)
	r.activated()
	if got := r.nsOf(roleN); len(got) != 0 {
		t.Errorf("n's NS once b is known to lead: %v", got)
	}
}

// The leader's withdrawal is done once every recipient has confirmed it,
// but a member with no role that has not, after the time-out.
func TestWithdrawalDoneReadsEveryRecipient(t *testing.T) {
	r := newReceiveRig(t, "done.withdraw.example.")
	ar := r.conf.InternalMp.AgentRegistry
	for _, a := range []AgentId{roleB, roleN} {
		ar.S.Set(a, NewAgent(a))
	}
	r.heldForN(r.n, time.Now(), "ns1.n.example.")
	r.leads(roleA)
	tm := r.conf.InternalMp.MPTransport
	tm.noRoleTimeout = 50 * time.Millisecond
	distID, err := r.conf.sendWithdrawal(r.zdr, ZoneName(r.zone), roleN, "NS")
	if err != nil {
		t.Fatal(err)
	}
	zone := ZoneName(r.zone)
	expected := r.zdr.Tracking[zone][roleN][dns.TypeNS].Tracked[0].ExpectedRecipients
	if len(expected) != 3 {
		t.Fatalf("the recipients the withdrawal waits for: %v, want the combiner, b and n", expected)
	}
	confirm := func(source string) {
		r.zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: distID, Zone: zone, Source: source, Status: "SUCCESS"}, r.conf.InternalMp.MsgQs)
	}
	confirm(freezeCombiner)
	if r.conf.withdrawalDone(r.zdr, zone, roleN, "NS") {
		t.Fatal("done before b confirmed")
	}
	confirm(roleB)
	if r.conf.withdrawalDone(r.zdr, zone, roleN, "NS") {
		t.Fatal("done before the time-out for n, which has no role")
	}
	time.Sleep(60 * time.Millisecond)
	if !r.conf.withdrawalDone(r.zdr, zone, roleN, "NS") {
		t.Error("not done after the time-out for n")
	}
	confirm(roleN)
	if got := r.nsOf(roleN); len(got) != 0 {
		t.Errorf("n's NS here once every recipient confirmed: %v", got)
	}
}

// The withdraw field travels on the sync wrapper, and the receiver names
// the update's agent by it.
func TestTheWithdrawFieldTravelsOnTheSyncWrapper(t *testing.T) {
	w := &Withdraw{Provider: roleN, RRtype: "NS"}
	m, err := syncAppMessage(&PeerSyncRequest{SenderID: roleB, Zone: "wire.withdraw.example.", MessageType: "sync",
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}, DistributionID: "d1", Withdraw: w}, roleA)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(m.Payload, &raw); err != nil || string(raw["withdraw"]) != `{"provider":"`+roleN+`","rrtype":"NS"}` {
		t.Fatalf("the wire payload's withdraw: %s (%v)", raw["withdraw"], err)
	}
	p, err := ParseSyncPayload(m.Payload)
	if err != nil || p.Withdraw == nil || *p.Withdraw != *w || p.OriginatorID != roleB {
		t.Errorf("the receiver's payload: %+v (%v)", p, err)
	}
}
