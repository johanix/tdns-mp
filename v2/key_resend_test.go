/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"encoding/json"
	"io"
	"log"
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #256: the key lifecycle's resend (E12, T6', or after a restart) reaches
// the peers. The signer marks the key in its inventory push; the agent
// distributes that key again, tracked for it, even with its key set
// unchanged. Unmarked, an unchanged inventory distributes nothing, and the
// resend never left the agent.

// The driver sends a distribution in flight again through Wire.Resend, with
// the key and whether it is a removal: on E12, and after a restart. The
// first send is not a resend.
func TestTheLifecyclesResendIsMarkedAsAResend(t *testing.T) {
	pol := driverPolicy
	pol.ResendAfter = 5 * time.Minute
	r := newDriverRig(t, "resend.marked.example.", pol, "p2")
	r.tick("mint")
	inFlight := append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...)
	if len(inFlight) == 0 {
		t.Fatal("precondition: nothing in flight")
	}
	if got := r.wire.resent(); len(got) != 0 {
		t.Fatalf("the first send was marked as a resend: %v", got)
	}
	r.clock.Advance(pol.ResendAfter + time.Second)
	r.tick("resend")
	got := r.wire.resent()
	for _, k := range inFlight {
		if !slices.Contains(got, k) {
			t.Errorf("key %d in flight past ResendAfter was not resent as a resend (resent %v)", k, got)
		}
	}

	// a removal in flight is sent again as a removal
	zsk := r.keysIn(KeyStateMpdist, "ZSK")
	if len(zsk) != 1 {
		t.Fatalf("precondition: ZSK in mpdist: %v", zsk)
	}
	if _, _, err := r.l.Apply(zsk[0], CmdWithdraw); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.wire.resentRemovals(), zsk[0]) {
		t.Fatal("the first removal was marked as a resend")
	}
	r.clock.Advance(pol.ResendAfter + time.Second)
	r.tick("removal resend")
	if !slices.Contains(r.wire.resentRemovals(), zsk[0]) {
		t.Errorf("the removal in flight past ResendAfter was not resent as a removal (resent removals %v)", r.wire.resentRemovals())
	}
	inFlight = slices.DeleteFunc(inFlight, func(k uint16) bool { return k == zsk[0] })

	// a new process sends what is in flight again, as a resend too
	wire := newFakeWire("p2")
	l2 := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, pol, wire)
	if err := l2.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, k := range inFlight {
		if !slices.Contains(wire.resent(), k) {
			t.Errorf("after a restart key %d in flight was not resent as a resend (resent %v)", k, wire.resent())
		}
	}

	// a key in flight whose distribution was not recorded starts a new one
	// at a restart, a resend as well: the agent's set has the key already
	if _, err := r.kdb.DB.Exec(`DELETE FROM MPKeyDistribution WHERE zonename=?`, r.l.Zone); err != nil {
		t.Fatal(err)
	}
	wire3 := newFakeWire("p2")
	l3 := NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, pol, wire3)
	if err := l3.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, k := range inFlight {
		if !slices.Contains(wire3.resent(), k) {
			t.Errorf("after a restart with no record, key %d in flight was not sent as a resend (resent %v)", k, wire3.resent())
		}
	}
}

// The agent: an inventory unchanged since the last one distributes nothing;
// the same inventory with a key marked as sent again distributes the set
// again, tracked for that key, and marked as a resend. A key the provider no
// longer serves (mpremove) goes as a removal, from the inventory's record.
func TestAKeyTheSignerSendsAgainIsDistributedAgainUnchanged(t *testing.T) {
	yes := true
	r := newLeaderSyncRig(t, "resend.keys.example.")
	ksk := invItem(t, r.mpzd.ZoneName, 257, KeyStateActive, &yes)
	next := invItem(t, r.mpzd.ZoneName, 256, KeyStateMpdist, nil)
	gone := invItem(t, r.mpzd.ZoneName, 256, DnskeyStateMpremove, nil)
	theirs := invItem(t, r.mpzd.ZoneName, 257, DnskeyStateForeign, nil)
	send := func(resend ...uint16) {
		r.e.handleKeystateInventory(r.ctx, "agent.us.example.", &KeystateInventoryMsg{SenderID: "signer.us.example.",
			Zone: r.mpzd.ZoneName, Inventory: []KeyInventoryItem{ksk, next, gone, theirs}, Owned: true, Resend: resend}, r.sdq, nil)
	}
	drain := func() []*SynchedDataUpdate {
		var out []*SynchedDataUpdate
		for {
			select {
			case u := <-r.sdq:
				out = append(out, u)
			case <-time.After(200 * time.Millisecond):
				return out
			}
		}
	}
	send() // the first inventory: every served key is an add
	if got := drain(); len(got) != 1 {
		t.Fatalf("the first inventory gave %d updates, want 1", len(got))
	}
	send()
	if got := drain(); len(got) != 0 {
		t.Fatalf("an unchanged, unmarked inventory gave %d updates, want none", len(got))
	}

	send(next.KeyTag)
	got := drain()
	if len(got) != 1 || !got[0].Resend || !slices.Equal(got[0].DnskeyKeyTags, []uint16{next.KeyTag}) || len(got[0].DnskeyRemovedKeyTags) != 0 {
		t.Fatalf("the key sent again: %+v, want one resend tracked for %d", got, next.KeyTag)
	}

	send(gone.KeyTag)
	got = drain()
	if len(got) != 1 || !got[0].Resend || !slices.Equal(got[0].DnskeyKeyTags, []uint16{gone.KeyTag}) ||
		!slices.Equal(got[0].DnskeyRemovedKeyTags, []uint16{gone.KeyTag}) {
		t.Fatalf("the removal sent again: %+v, want one resend tracked for the removal of %d", got, gone.KeyTag)
	}
	// the REPLACE of the current set carries the removal: no delete record,
	// which the repo, no longer holding the key, would refuse
	for _, rr := range got[0].Update.RRs {
		if rr.Header().Class == dns.ClassNONE {
			t.Errorf("the removal sent again carries a delete record: %s", rr)
		}
	}

	send(theirs.KeyTag) // another provider's key is not this provider's to send
	if got := drain(); len(got) != 0 {
		t.Errorf("another provider's key was sent again: %d updates", len(got))
	}

	send(12345) // a key the inventory does not have
	if got := drain(); len(got) != 0 {
		t.Errorf("a key the inventory does not have gave %d updates, want none", len(got))
	}
}

// The data engine, through the hsync engine as an inventory reaches it: a
// DNSKEY set the repo already holds goes to the peers only when marked as a
// resend, and is tracked for the keys sent again; a removal sent again
// passes the engine's ownership check, since the REPLACE carries it with no
// delete record; and a resend supersedes the earlier tracking of the same
// keys, so a key resent again and again leaves one entry.
func TestTheEngineDistributesAResendTheRepoHolds(t *testing.T) {
	asMPAgent(t)
	const zone = "resend.engine.example."
	const combiner = "combiner.a.role.example."
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, nil)
	zd.Logger = log.New(io.Discard, "", 0)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA})
	queue := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	tm := &MPTransportBridge{
		TransportManager:          &transport.TransportManager{ReliableQueue: queue, PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:             ar,
		combinerID:                combiner,
		pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{},
	}
	conf.InternalMp.MPTransport = tm
	msgQs := &MsgQs{SynchedDataUpdate: make(chan *SynchedDataUpdate, 4), SynchedDataCmd: make(chan *SynchedDataCmd, 4)}
	conf.InternalMp.MsgQs = msgQs
	runEngine(t, conf, msgQs)

	k1, k2 := testDnskey(t, zone, 257), testDnskey(t, zone, 256)
	toAgents := func() int {
		n := 0
		for _, m := range queue.GetPendingMessages() {
			if m.RecipientID == roleB {
				n++
			}
		}
		return n
	}
	tracked := func(tag uint16, removal bool) int {
		tm.dnskeyPropMu.Lock()
		defer tm.dnskeyPropMu.Unlock()
		n := 0
		for _, p := range tm.pendingDnskeyPropagations {
			if slices.Equal(p.KeyTags, []uint16{tag}) && p.Removed[tag] == removal {
				n++
			}
		}
		return n
	}
	sync := func(ds *DnskeyStatus) {
		ds.ZoneName = zone
		ar.SyncRequestHandler(AgentId(roleA), SyncRequest{ZoneName: ZoneName(zone), Command: "SYNC-DNSKEY-RRSET", DnskeyStatus: ds}, msgQs.SynchedDataUpdate, msgQs)
	}
	sent := func(want int, what string) {
		t.Helper()
		waitUntil(t, what, func() bool { return toAgents() == want })
	}

	sync(&DnskeyStatus{LocalAdds: []dns.RR{k1, k2}, CurrentLocalKeys: []dns.RR{k1, k2}})
	sent(1, "the first set went to the other agent")
	sync(&DnskeyStatus{LocalRemoves: []dns.RR{k2}, CurrentLocalKeys: []dns.RR{k1}})
	sent(2, "the removal of k2 went to the other agent")
	if tracked(k1.KeyTag(), false) != 0 {
		t.Fatal("precondition: k1 alone is tracked already")
	}

	// unmarked, the set the repo holds goes nowhere
	sync(&DnskeyStatus{LocalAdds: []dns.RR{k1}, CurrentLocalKeys: []dns.RR{k1}})
	time.Sleep(200 * time.Millisecond)
	if got := toAgents(); got != 2 {
		t.Fatalf("an unmarked set the repo holds went out (%d messages, want 2)", got)
	}
	// marked, it goes, tracked for k1
	sync(&DnskeyStatus{LocalAdds: []dns.RR{k1}, CurrentLocalKeys: []dns.RR{k1}, Resend: true})
	sent(3, "the resend of k1 went to the other agent")
	waitUntil(t, "the resend of k1 is tracked", func() bool { return tracked(k1.KeyTag(), false) == 1 })
	// again: the earlier tracking of k1 alone is superseded
	sync(&DnskeyStatus{LocalAdds: []dns.RR{k1}, CurrentLocalKeys: []dns.RR{k1}, Resend: true})
	sent(4, "the second resend of k1 went to the other agent")
	time.Sleep(200 * time.Millisecond)
	if n := tracked(k1.KeyTag(), false); n != 1 {
		t.Errorf("after two resends of k1, %d trackings of it, want 1", n)
	}

	// the removal of k2 sent again: no delete record, so the ownership check
	// lets it through, and it is tracked as a removal
	sync(&DnskeyStatus{CurrentLocalKeys: []dns.RR{k1}, ResendRemovedTags: []uint16{k2.KeyTag()}, Resend: true})
	sent(5, "the removal of k2 sent again went to the other agent")
	waitUntil(t, "the removal of k2 sent again is tracked", func() bool { return tracked(k2.KeyTag(), true) >= 1 })
}

// The mark travels: a signer's inventory with keys marked as sent again
// reaches the agent's inventory queue with them. An older agent decodes
// the post it knows and ignores the field.
func TestTheResendMarkTravelsToTheAgent(t *testing.T) {
	const zone = "resend.wire.example."
	k := invItem(t, zone, 256, KeyStateMpdist, nil)
	msg, err := keystateAppMessage(&PeerKeystateRequest{SenderID: "signer.us.example.", Zone: zone, Signal: "inventory",
		KeyInventory: inventoryEntriesOf([]KeyInventoryItem{k}), Owned: true, Resend: []uint16{k.KeyTag}, Timestamp: time.Now()}, "agent.us.example.")
	if err != nil {
		t.Fatal(err)
	}
	agent := &MPTransportBridge{msgQs: &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 1)}}
	agent.routeKeystateMessage(&transport.IncomingMessage{TypeToken: "keystate", Zone: zone, Payload: msg.Payload})
	inv, ok := recvWithin(agent.msgQs.KeystateInventory, time.Second)
	if !ok {
		t.Fatal("the agent's routing dropped the inventory")
	}
	if !slices.Equal(inv.Resend, []uint16{k.KeyTag}) || len(inv.Inventory) != 1 {
		t.Errorf("what reached the agent: resend %v, %d keys; want resend [%d] and the key", inv.Resend, len(inv.Inventory), k.KeyTag)
	}
	var older core.AgentKeystatePost
	if err := json.Unmarshal(msg.Payload, &older); err != nil || older.Signal != "inventory" || len(older.KeyInventory) != 1 {
		t.Errorf("an older agent cannot read the marked inventory: %+v, %v", older, err)
	}
}

// The signer: its wire's Resend pushes the inventory with the key marked,
// and the inventory request carries the mark; a plain push carries none.
func TestTheSignerMarksTheKeyItSendsAgain(t *testing.T) {
	got := make(chan []uint16, 1)
	w := &signerWire{conf: &Config{}, push: func(_ *Config, zone string, resend []uint16) {
		if zone != "marked.signer.example." {
			t.Errorf("pushed for %q", zone)
		}
		got <- resend
	}}
	w.Resend("marked.signer.example", 4711, false)
	if r, ok := recvWithin(got, time.Second); !ok || !slices.Equal(r, []uint16{4711}) {
		t.Errorf("the resend pushed %v (%v), want [4711]", r, ok)
	}
	if req := inventoryRequest("signer.example.", "z.example.", nil, true, []uint16{4711}, false); !slices.Equal(req.Resend, []uint16{4711}) || req.Signal != "inventory" {
		t.Errorf("the inventory request: %+v", req)
	}
	if req := inventoryRequest("signer.example.", "z.example.", nil, true, nil, false); len(req.Resend) != 0 {
		t.Errorf("a plain inventory carries a mark: %v", req.Resend)
	}
}

// A marked push reaches the agent's handler even while an RFI for the
// zone's inventory waits: the waiter would record it and drop the mark. An
// unmarked inventory still goes to the waiter.
func TestAMarkedPushIsNotTakenByAnRFIWaiter(t *testing.T) {
	const zone = "resend.rfi.example."
	k := invItem(t, zone, 256, KeyStateMpdist, nil)
	agent := &MPTransportBridge{msgQs: &MsgQs{KeystateInventory: make(chan *KeystateInventoryMsg, 1)}}
	waiter := make(chan *KeystateInventoryMsg, 1)
	agent.setKeystateRfi(zone, waiter)
	route := func(resend []uint16) {
		msg, err := keystateAppMessage(inventoryRequest("signer.us.example.", zone, inventoryEntriesOf([]KeyInventoryItem{k}), true, resend, false), "agent.us.example.")
		if err != nil {
			t.Fatal(err)
		}
		agent.routeKeystateMessage(&transport.IncomingMessage{TypeToken: "keystate", Zone: zone, Payload: msg.Payload})
	}
	route([]uint16{k.KeyTag})
	if _, ok := recvWithin(agent.msgQs.KeystateInventory, time.Second); !ok {
		t.Error("the marked push did not reach the agent's handler")
	}
	if _, took := recvWithin(waiter, 100*time.Millisecond); took {
		t.Error("the RFI waiter took the marked push")
	}
	route(nil)
	if _, ok := recvWithin(waiter, time.Second); !ok {
		t.Error("an unmarked inventory did not reach the RFI waiter")
	}
}

// A resend takes over the earlier tracking of its keys: what an agent had
// applied is carried over, and an answer to the earlier distribution that
// comes late still counts, so an agent slower than the resend interval does
// not hold the key back for good. A late rejection does not count: the
// resend's own answer decides.
func TestALateAnswerToASupersededDistributionStillCounts(t *testing.T) {
	const zone ZoneName = "late.superseded.example."
	const fast, slow = "agent.fast.example.", "agent.slow.example."
	const k uint16 = 4242
	for _, c := range []struct {
		name, late string
		done       bool
	}{{"a late success", "SUCCESS", true}, {"a late rejection", "REJECTED", false}} {
		t.Run(c.name, func(t *testing.T) {
			tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			tm.TrackDnskeyPropagation(zone, "first", []uint16{k}, nil, []AgentId{fast, slow})
			tm.ProcessDnskeyConfirmation("first", fast, "SUCCESS", nil, nil)
			// the signer sends the key again
			tm.TrackDnskeyPropagation(zone, "resend", []uint16{k}, nil, []AgentId{fast, slow})
			tm.foldIntoResend(zone, "resend")
			tm.dnskeyPropMu.Lock()
			_, first := tm.pendingDnskeyPropagations["first"]
			r := tm.pendingDnskeyPropagations["resend"]
			carried := r != nil && r.Results[fast][k] == "applied" && r.ExpectedAgents[fast]
			tm.dnskeyPropMu.Unlock()
			if first || !carried {
				t.Fatalf("after the resend: first still tracked %v, the fast agent's answer carried %v", first, carried)
			}
			// the slow agent answers the first distribution, late
			tm.ProcessDnskeyConfirmation("first", slow, c.late, nil, nil)
			tm.dnskeyPropMu.Lock()
			_, open := tm.pendingDnskeyPropagations["resend"]
			tm.dnskeyPropMu.Unlock()
			if open == c.done {
				t.Errorf("after %s to the superseded distribution, the resend's tracking is still open: %v, want %v", c.late, open, !c.done)
			}
		})
	}
}

// A resend takes over only a tracking of the same distribution. An open add
// of a key is not the removal resent for it: what a peer applied of the add
// is not a removal, and a late success on the add must not complete the
// removal. A tracking of fewer keys than the resend is not taken over
// either: a late success on it would credit the keys it did not carry.
func TestAResendTakesOverOnlyTheSameDistribution(t *testing.T) {
	const zone ZoneName = "other.superseded.example."
	const fast, slow = "agent.fast.example.", "agent.slow.example."
	const k, j uint16 = 4242, 4343
	for _, c := range []struct {
		name            string
		tags, removed   []uint16
		rtags, rremoved []uint16
	}{
		{"an add, then the removal resent", []uint16{k}, nil, []uint16{k}, []uint16{k}},
		{"fewer keys than the resend", []uint16{k}, nil, []uint16{k, j}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
			tm.TrackDnskeyPropagation(zone, "first", c.tags, c.removed, []AgentId{fast, slow})
			tm.ProcessDnskeyConfirmation("first", fast, "SUCCESS", nil, nil)
			tm.TrackDnskeyPropagation(zone, "resend", c.rtags, c.rremoved, []AgentId{fast, slow})
			tm.foldIntoResend(zone, "resend")
			tm.dnskeyPropMu.Lock()
			_, first := tm.pendingDnskeyPropagations["first"]
			carried := len(tm.pendingDnskeyPropagations["resend"].Results) > 0
			alias := tm.supersededBy["first"].to
			tm.dnskeyPropMu.Unlock()
			if !first || carried || alias != "" {
				t.Fatalf("after the resend: first still tracked %v (want true), answers carried %v, alias %q (want none)", first, carried, alias)
			}
			// the slow agent answers the first distribution, late
			tm.ProcessDnskeyConfirmation("first", slow, "SUCCESS", nil, nil)
			tm.dnskeyPropMu.Lock()
			_, first = tm.pendingDnskeyPropagations["first"]
			_, open := tm.pendingDnskeyPropagations["resend"]
			tm.dnskeyPropMu.Unlock()
			if first || !open {
				t.Errorf("after the late success on the first distribution: first still tracked %v (want false), the resend still open %v (want true)", first, open)
			}
		})
	}
}

// An alias of a superseded distribution is dropped once no answer to it can
// come any more, a day after the resend took it over, so a key resent for as
// long as its tracking stays open leaves no more aliases than a day's
// resends. A younger alias stays, and still leads a late answer home.
func TestASupersededAliasIsDroppedOnceNoAnswerCanCome(t *testing.T) {
	const zone ZoneName = "alias.age.example."
	const fast, slow = "agent.fast.example.", "agent.slow.example."
	const k uint16 = 4242
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation(zone, "first", []uint16{k}, nil, []AgentId{fast, slow})
	tm.TrackDnskeyPropagation(zone, "second", []uint16{k}, nil, []AgentId{fast, slow})
	tm.foldIntoResend(zone, "second")
	tm.dnskeyPropMu.Lock()
	s := tm.supersededBy["first"]
	s.at = s.at.Add(-noteMaxAge - time.Minute) // first was taken over a day ago
	tm.supersededBy["first"] = s
	tm.dnskeyPropMu.Unlock()

	tm.TrackDnskeyPropagation(zone, "third", []uint16{k}, nil, []AgentId{fast, slow})
	tm.foldIntoResend(zone, "third")
	tm.dnskeyPropMu.Lock()
	_, old := tm.supersededBy["first"]
	young := tm.supersededBy["second"]
	tm.dnskeyPropMu.Unlock()
	if old {
		t.Errorf("an alias older than the reliable queue's lifetime was kept")
	}
	if young.to != "third" {
		t.Fatalf("the younger alias: %+v, want it to lead to the third", young)
	}
	// a late answer to the second still counts at the third
	tm.ProcessDnskeyConfirmation("second", fast, "SUCCESS", nil, nil)
	tm.dnskeyPropMu.Lock()
	applied := tm.pendingDnskeyPropagations["third"].Results[fast][k]
	tm.dnskeyPropMu.Unlock()
	if applied != "applied" {
		t.Errorf("a late answer to a superseded distribution, through a young alias: %q, want applied", applied)
	}
}

// A key's result keeps the stamp of the answer that gave it, so that S8 can
// judge it: an agent's keys answered apart keep each its own answer's, a
// later confirmation (a PENDING arriving last, a final word sent again)
// moves none, and a resend carries each with its result (cubic's review of
// 347fe5b, CodeRabbit's of 07fdae9).
func TestAResultKeepsTheStampOfItsAnswer(t *testing.T) {
	const zone ZoneName = "stamped.superseded.example."
	const fast, slow = "agent.fast.example.", "agent.slow.example."
	a, b := testDnskeyRR(t, string(zone), 257), testDnskeyRR(t, string(zone), 256)
	keys := []uint16{a.KeyTag(), b.KeyTag()}
	tm := &MPTransportBridge{pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{}}
	tm.TrackDnskeyPropagation(zone, "first", keys, nil, []AgentId{fast, slow})
	confirm := func(status transport.ConfirmStatus, applied []string, ms *MsgStamp) {
		// as the confirmation callback does
		tm.noteConfirmation(confirmIn("first", fast, status, string(zone), applied, nil, nil, nil, false, ""), ms)
		tm.processDnskeyConfirmation("first", fast, status.String(), applied, nil, nil, ms)
	}
	partial, final := &MsgStamp{Epoch: 2, Seq: 5}, &MsgStamp{Epoch: 2, Seq: 6}
	confirm(transport.ConfirmPartial, []string{a.String()}, partial)
	confirm(transport.ConfirmSuccess, nil, final)
	confirm(transport.ConfirmPending, nil, &MsgStamp{Epoch: 2, Seq: 7})
	confirm(transport.ConfirmSuccess, nil, &MsgStamp{Epoch: 3, Seq: 1})

	stamped := func(prop *PendingDnskeyPropagation, which string) {
		t.Helper()
		if prop == nil {
			t.Fatalf("%s: not tracked", which)
		}
		for kt, want := range map[uint16]*MsgStamp{a.KeyTag(): partial, b.KeyTag(): final} {
			if prop.Results[fast][kt] != "applied" || prop.Stamps[fast][kt] != want {
				t.Errorf("%s, key %d: %q with stamp %+v, want applied with %+v", which, kt, prop.Results[fast][kt], prop.Stamps[fast][kt], want)
			}
		}
		if prop.Stamps[slow] != nil {
			t.Errorf("%s: an agent with no answer has stamps: %+v", which, prop.Stamps[slow])
		}
	}
	tm.dnskeyPropMu.Lock()
	stamped(tm.pendingDnskeyPropagations["first"], "the first")
	tm.dnskeyPropMu.Unlock()

	tm.TrackDnskeyPropagation(zone, "resend", keys, nil, []AgentId{fast, slow})
	tm.foldIntoResend(zone, "resend")
	tm.dnskeyPropMu.Lock()
	defer tm.dnskeyPropMu.Unlock()
	stamped(tm.pendingDnskeyPropagations["resend"], "the resend")
}
