/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// answer is a provider's answer to a request for the zone's state, as the
// synched data engine hands it on: a replace of NS and CDS, and, when
// dnskey is set, of DNSKEY with the keys and their states. complete is
// the answer's marker.
func (r *computedDSRig) answer(t *testing.T, from AgentId, complete, dnskey bool, keys ...word) {
	t.Helper()
	ops := []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{}}, {Operation: "replace", RRtype: "CDS", Records: []string{}}}
	if dnskey {
		op := core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{}}
		for _, k := range keys {
			op.Records = append(op.Records, k.key.String())
			op.KeyStates = append(op.KeyStates, core.KeyState{KeyTag: k.key.KeyTag(), State: k.state, DS: k.ds})
		}
		ops = append(ops, op)
	}
	b, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	var wire []core.RROperation
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	r.conf.noteForeignAnswer(r.ctx, ZoneName(r.mpzd.ZoneName), from, wire, complete)
}

// A complete answer makes its provider speak: the DS set is known once
// every provider in signers= has answered, one of them holding no key. An
// answer from a provider not in signers= makes nobody speak.
func TestACompleteAnswerMakesItsProviderSpeak(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "speak.answer.example.", []string{"p2", "p3"})
	ksk := testDnskey(t, r.mpzd.ZoneName, 257)
	r.leader("agent.us.example.")

	r.answer(t, "agent.p2.example.", true, true, word{ksk, KeyStateActive, &yes})
	if known, _ := r.dsSet(t); known {
		t.Fatal("the DS set is known while p3 has not spoken")
	}
	r.answer(t, "agent.p3.example.", true, true) // complete, and no key
	known, tags := r.dsSet(t)
	if !known || len(tags) != 1 || !tags[ksk.KeyTag()] {
		t.Fatalf("after both answers: known=%v tags=%v, want p2's KSK alone", known, tags)
	}

	r2 := newComputedDSRig(t, "nonsigner.answer.example.", []string{"p2"})
	r2.answer(t, "agent.p3.example.", true, false)
	if known, _ := r2.dsSet(t); known {
		t.Error("an answer from a provider not in signers= made the DS set known")
	}
}

// An answer without the marker counts for nothing: an empty DNSKEY set
// from a provider not heard from before does not make it speak.
func TestAnAnswerWithoutTheMarkerIsAppliedAndDoesNotCount(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "nomarker.answer.example.", []string{"p2", "p3"})
	r.answer(t, "agent.p2.example.", true, true, word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, &yes})
	r.answer(t, "agent.p3.example.", false, true)
	if known, _ := r.dsSet(t); known {
		t.Error("an answer without the marker made its provider speak")
	}
}

// A complete answer without a DNSKEY operation says nothing about keys:
// its sender's copy of the zone does not list it in signers=, while the
// asker's does. The provider stays silent, the DS set unknown, and no sync
// is asked for: never a removal of its DS at the parent.
func TestACompleteAnswerWithoutADNSKEYOperationLeavesItsProviderSilent(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "nodnskey.answer.example.", []string{"p2", "p3"})
	r.leader("agent.us.example.")
	r.answer(t, "agent.p2.example.", true, true, word{testDnskey(t, r.mpzd.ZoneName, 257), KeyStateActive, &yes})
	r.answer(t, "agent.p3.example.", true, false)
	if known, _ := r.dsSet(t); known {
		t.Error("a complete answer with no DNSKEY operation made its provider speak")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("%d syncs asked for", n)
	}
}

// The reverse difference: the asker's copy no longer lists p3 in signers=,
// p3's still does, and p3's answer names its keys. The asker does not put
// p3's DS back into the set it computes.
func TestAnAnswerFromAProviderTheAskerDoesNotListAsASignerAddsNoDS(t *testing.T) {
	yes := true
	r := newComputedDSRig(t, "reverse.answer.example.", []string{"p2"})
	ours, theirs := testDnskey(t, r.mpzd.ZoneName, 257), testDnskey(t, r.mpzd.ZoneName, 257)
	r.answer(t, "agent.p2.example.", true, true, word{ours, KeyStateActive, &yes})
	r.answer(t, "agent.p3.example.", true, true, word{theirs, KeyStateActive, &yes})
	known, tags := r.dsSet(t)
	if !known || len(tags) != 1 || !tags[ours.KeyTag()] {
		t.Errorf("known=%v tags=%v, want p2's KSK alone", known, tags)
	}
}

// engineRig runs the agent's data engine on a bridge whose reliable queue
// has no worker, for remote updates handed to it as the router does.
type engineRig struct {
	conf  *Config
	tm    *MPTransportBridge
	msgQs *MsgQs
	zone  ZoneName
	confs chan *RemoteConfirmationDetail
}

// runEngine runs the agent's data engine until the test ends, and waits for
// it to stop before the test's cleanup goes on: an engine still running after
// its test reads package state, the engine's logger among them, that the next
// test's set-up writes.
func runEngine(t *testing.T, conf *Config, msgQs *MsgQs) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conf.SynchedDataEngine(ctx, msgQs)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func newEngineRig(t *testing.T, zone string) *engineRig {
	t.Helper()
	return newEngineRigWith(t, zone, nil)
}

// newEngineRigWith is newEngineRig with setup run on the agent's config
// before its data engine starts.
func newEngineRigWith(t *testing.T, zone string, setup func(conf *Config)) *engineRig {
	t.Helper()
	asMPAgent(t)
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, nil)
	zd.Logger = log.New(io.Discard, "", 0)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA, Combiner: &PeerConf{Identity: "combiner.a.role.example."}})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	tm := &MPTransportBridge{
		TransportManager: &transport.TransportManager{ReliableQueue: transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{}), PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar,
		combinerID:       "combiner.a.role.example.",
	}
	conf.InternalMp.MPTransport = tm
	confs := make(chan *RemoteConfirmationDetail, 16)
	msgQs := &MsgQs{SynchedDataUpdate: make(chan *SynchedDataUpdate, 4), SynchedDataCmd: make(chan *SynchedDataCmd, 4),
		OnRemoteConfirmationReady: func(d *RemoteConfirmationDetail) { confs <- d }}
	conf.InternalMp.MsgQs = msgQs
	if setup != nil {
		setup(conf)
	}
	runEngine(t, conf, msgQs)
	return &engineRig{conf: conf, tm: tm, msgQs: msgQs, zone: ZoneName(zone), confs: confs}
}

// repo is what the engine holds for the zone, per agent and type.
func (r *engineRig) repo(t *testing.T) map[AgentId]map[uint16][]TrackedRRInfo {
	t.Helper()
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: r.zone, Response: resp}
	got, ok := recvWithin(resp, 5*time.Second)
	if !ok || got.Error {
		t.Fatalf("the engine did not answer: %+v", got)
	}
	return got.ZDR[r.zone]
}

// remote hands the engine an update from from, sent at sentAt under distID.
func (r *engineRig) remote(t *testing.T, from AgentId, sentAt time.Time, distID string, cu *CatchUp, ops ...core.RROperation) {
	t.Helper()
	done := make(chan *AgentMsgResponse, 1)
	r.msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: r.zone, AgentId: from, UpdateType: "remote", DeliveredBy: from,
		OriginatingDistID: distID, OriginatingTime: sentAt, CatchUp: cu,
		Update: &ZoneUpdate{Zone: r.zone, AgentId: from, Operations: ops, CatchUp: cu}, Response: done}
	if _, ok := recvWithin(done, 5*time.Second); !ok {
		t.Fatal("the engine did not answer")
	}
}

func (r *engineRig) keyStates(from AgentId) []core.KeyState {
	r.tm.foreignKeyStatesMu.Lock()
	defer r.tm.foreignKeyStatesMu.Unlock()
	return r.tm.foreignKeyStates[r.zone][from]
}

func dnskeyOp(t *testing.T, zone string, state string, ds bool) core.RROperation {
	t.Helper()
	k := testDnskey(t, zone, 257)
	return core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{k.String()},
		KeyStates: []core.KeyState{{KeyTag: k.KeyTag(), State: state, DS: &ds}}}
}

func complete() *CatchUp {
	yes := true
	return &CatchUp{Request: "r1", Complete: &yes}
}

// What a stale replace says about keys is stale too. An older distribution
// that arrives after a newer answer does not overwrite the key states the
// answer gave.
func TestAStaleDNSKEYReplaceDoesNotOverwriteTheKeyStates(t *testing.T) {
	r := newEngineRig(t, "stale.keys.example.")
	now := time.Now()
	newer := dnskeyOp(t, string(r.zone), KeyStateActive, true)
	r.remote(t, roleB, now, "d2", complete(), newer)
	r.remote(t, roleB, now.Add(-time.Minute), "d1", nil, dnskeyOp(t, string(r.zone), KeyStatePublished, false))
	got := r.keyStates(roleB)
	if len(got) != 1 || got[0].KeyTag != newer.KeyStates[0].KeyTag {
		t.Errorf("the key states are %+v, want the answer's", got)
	}
}

// And a late answer does not overwrite the key states of a newer
// distribution.
func TestALateAnswerDoesNotOverwriteANewerDistributionsKeyStates(t *testing.T) {
	r := newEngineRig(t, "late.answer.example.")
	now := time.Now()
	newer := dnskeyOp(t, string(r.zone), KeyStateActive, true)
	r.remote(t, roleB, now, "d2", nil, newer)
	r.remote(t, roleB, now.Add(-time.Minute), "d1", complete(), dnskeyOp(t, string(r.zone), KeyStatePublished, false))
	got := r.keyStates(roleB)
	if len(got) != 1 || got[0].KeyTag != newer.KeyStates[0].KeyTag {
		t.Errorf("the key states are %+v, want the newer distribution's", got)
	}
}

// A stale replace in an update that changes something else goes no further
// than the repo: the update passed on to the combiner leaves it out, so the
// combiner does not put the older set back. What the engine notes of each
// set it passes on is the update it enqueued for the combiner.
func TestAStaleReplaceIsNotPassedOnToTheCombiner(t *testing.T) {
	r := newEngineRig(t, "stale.forward.example.")
	toCombiner := func() []string {
		var ids []string
		for _, m := range r.tm.ReliableQueue.GetPendingMessages() {
			if m.RecipientID == string(r.tm.combinerID) {
				ids = append(ids, m.DistributionID)
			}
		}
		return ids
	}
	now := time.Now()
	r.remote(t, roleB, now, "d2", nil, dnskeyOp(t, string(r.zone), KeyStateActive, true))
	first := toCombiner()
	ns := string(r.zone) + " 3600 IN NS ns.b.role.example."
	r.remote(t, roleB, now.Add(-time.Minute), "d1", complete(),
		core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}},
		dnskeyOp(t, string(r.zone), KeyStatePublished, false))
	both := toCombiner()
	if len(first) != 1 || len(both) != 2 {
		t.Fatalf("passed on to the combiner: %v, then %v; want one update each time", first, both)
	}
	notes := r.conf.InternalMp.ZoneDataRepo.notes[r.zone][roleB]
	if n := notes[dns.TypeDNSKEY]; n == nil || n.distID != first[0] {
		t.Errorf("the DNSKEY set was last passed on in %+v, want the newer distribution's update %s", n, first[0])
	}
	if n := notes[dns.TypeNS]; n == nil || n.distID == first[0] {
		t.Errorf("the NS set was passed on in %+v, want the second update", n)
	}
}

// Every replace of an update counts as a change: one whose set is already
// there does not hide one before it that changed something.
func TestEveryReplaceOfAnUpdateCountsAsAChange(t *testing.T) {
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	const zone = "every.replace.example."
	ns := zone + " 3600 IN NS ns.b.role.example."
	u := func(ops ...core.RROperation) *SynchedDataUpdate {
		return &SynchedDataUpdate{Zone: zone, AgentId: roleB, UpdateType: "remote", Update: &ZoneUpdate{Zone: zone, AgentId: roleB, Operations: ops}}
	}
	if changed, _, err := zdr.ProcessUpdate(u(core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}})); err != nil || !changed {
		t.Fatalf("the first NS: changed=%v err=%v", changed, err)
	}
	cds := &dns.CDS{DS: *testDnskey(t, zone, 257).ToDS(dns.SHA256)}
	cds.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	changed, _, err := zdr.ProcessUpdate(u(
		core.RROperation{Operation: "replace", RRtype: "CDS", Records: []string{cds.String()}},
		core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}))
	if err != nil || !changed {
		t.Errorf("an update whose CDS replace changed something and whose NS replace did not: changed=%v err=%v", changed, err)
	}
}

// Every update that changes nothing is confirmed, also when it lists no
// record (decision 42): an answer that changes nothing, and an empty
// replace of a set that is already absent, from an agent this one holds
// nothing of.
func TestAnAnswerThatChangesNothingIsConfirmed(t *testing.T) {
	r := newEngineRig(t, "nochange.answer.example.")
	r.remote(t, roleB, time.Now(), "d2", complete(),
		core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{}},
		core.RROperation{Operation: "replace", RRtype: "CDS", Records: []string{}})
	for {
		d, ok := recvWithin(r.confs, time.Second)
		if !ok {
			t.Fatal("the answer that changes nothing was not confirmed")
		}
		if d.OriginatingDistID == "d2" {
			if d.OriginatingSender != roleB || d.Status != "ok" {
				t.Errorf("the confirmation: %+v", *d)
			}
			return
		}
	}
}

func TestAnEmptyReplaceThatChangesNothingIsConfirmed(t *testing.T) {
	r := newEngineRig(t, "empty.replace.example.")
	r.remote(t, roleB, time.Now(), "d1", nil, core.RROperation{Operation: "replace", RRtype: "CDS", Records: []string{}})
	d, ok := recvWithin(r.confs, time.Second)
	if !ok || d.OriginatingDistID != "d1" || d.Status != "ok" {
		t.Errorf("an empty replace that changes nothing: confirmed=%v %+v", ok, d)
	}
}

// A CSYNC in an answer from an agent that is not the leader this agent
// knows is refused, and the answer counts all the same: its provider, not
// heard from before, has spoken, here with no key.
func TestAnAnswerWhoseCSYNCIsRefusedStillCounts(t *testing.T) {
	r := newEngineRig(t, "csync.refused.example.")
	csync := core.RROperation{Operation: "replace", RRtype: "CSYNC", Records: []string{string(r.zone) + " 3600 IN CSYNC 1 3 NS"}}
	r.remote(t, roleB, time.Now(), "d1", complete(), csync, core.RROperation{Operation: "replace", RRtype: "DNSKEY", Records: []string{}})
	r.tm.foreignKeyStatesMu.Lock()
	_, spoke := r.tm.foreignKeyStates[r.zone][roleB]
	r.tm.foreignKeyStatesMu.Unlock()
	if !spoke {
		t.Error("the answer whose CSYNC was refused did not make its provider speak")
	}
	for {
		d, ok := recvWithin(r.confs, time.Second)
		if !ok {
			t.Fatal("the refused CSYNC got no REJECTED confirmation")
		}
		if d.OriginatingDistID == "d1" && d.Status == "REJECTED" {
			break
		}
	}
}

// The CSYNC the start-up hydration took from the combiner stays in the
// agent's data after an answer whose CSYNC was refused, and the refused one
// does not go on to the combiner.
func TestARefusedCSYNCLeavesTheRestoredOneInPlace(t *testing.T) {
	const zone = "csync.restored.example."
	restored := zone + "\t3600\tIN\tCSYNC\t1 3 NS"
	r := newEngineRigWith(t, zone, func(conf *Config) {
		conf.InternalMp.MPZoneNames = []string{zone}
		conf.InternalMp.editsRequest = func(context.Context, *tdns.ZoneData, *MPTransportBridge, *MsgQs) (*EditsResponseMsg, time.Time, error) {
			return &EditsResponseMsg{SenderID: "combiner.a.role.example.", Zone: zone, Message: editsLoaded,
				AgentRecords: map[string]map[string][]string{roleB: {zone: {restored}}}}, time.Now(), nil
		}
	})
	newer := core.RROperation{Operation: "replace", RRtype: "CSYNC", Records: []string{zone + " 3600 IN CSYNC 2 3 NS"}}
	u := &ZoneUpdate{Zone: r.zone, AgentId: roleB, Operations: []core.RROperation{newer}, CatchUp: complete()}
	done := make(chan *AgentMsgResponse, 1)
	r.msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: r.zone, AgentId: roleB, UpdateType: "remote", DeliveredBy: roleB,
		OriginatingDistID: "d1", OriginatingTime: time.Now(), CatchUp: u.CatchUp, Update: u, Response: done}
	if _, ok := recvWithin(done, 5*time.Second); !ok {
		t.Fatal("the engine did not answer")
	}
	held := r.repo(t)[roleB][dns.TypeCSYNC]
	if len(held) != 1 || held[0].RR != restored {
		t.Errorf("the agent holds %+v as roleB's CSYNC, want the restored one", held)
	}
	for _, op := range u.Operations {
		if op.RRtype == "CSYNC" {
			t.Error("the refused CSYNC was left in the update the combiner is sent")
		}
	}
}

// resync's apply leaves this agent's own DNSKEY set alone: no answer of its
// combiner holds it. The keys are the ones the start-up hydration took from
// the signer's inventory, held as confirmed: an apply would drop them.
func TestResyncKeepsTheLocalDNSKEYs(t *testing.T) {
	const zone = "resync.dnskeys.example."
	r := newEngineRigWith(t, zone, func(conf *Config) {
		conf.InternalMp.MPZoneNames = []string{zone}
		conf.InternalMp.MPTransport.signerID = "signer.a.role.example."
		conf.InternalMp.editsRequest = func(context.Context, *tdns.ZoneData, *MPTransportBridge, *MsgQs) (*EditsResponseMsg, time.Time, error) {
			return &EditsResponseMsg{SenderID: "combiner.a.role.example.", Zone: zone, Message: editsLoaded}, time.Now(), nil
		}
		mpzd, _ := Zones.Get(zone)
		mpzd.EnsureMP()
		mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: "a", WeAreSigner: true, ZoneSigned: true}
		yes := true
		mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: zone, Inventory: []KeyInventoryItem{invItem(t, zone, 257, KeyStateActive, &yes)}, Received: time.Now()})
	})
	if n := len(r.repo(t)[roleA][dns.TypeDNSKEY]); n != 1 {
		t.Fatalf("%d local DNSKEYs after the start-up hydration, want the inventory's", n)
	}
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "resync", Zone: r.zone, Response: resp}
	if _, ok := recvWithin(resp, 10*time.Second); !ok {
		t.Fatal("the resync got no answer")
	}
	if n := len(r.repo(t)[roleA][dns.TypeDNSKEY]); n != 1 {
		t.Errorf("%d local DNSKEYs after the resync, want the one the agent had", n)
	}
}
