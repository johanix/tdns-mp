/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The zone's SIG(0) key under a transition (plan S14): who is asked, an
// answer counted only at the asker's active serial, the holds and their one
// exception, keyPending and the offers again, the KEY as the group's, and
// the status.

// keepServed has conf's store keep the zone at the instructions its served
// copy carries, enforced, and returns their serial.
func keepServed(t *testing.T, conf *Config, mpzd *MPZoneData) SerialDigest {
	t.Helper()
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("the apex: %v", err)
	}
	n, err := ReadInstructions(apex)
	if err != nil || n == nil {
		t.Fatalf("the served instructions: %v", err)
	}
	s := newStore(t)
	prev := instrStore.Load()
	instrStore.Store(s)
	t.Cleanup(func() { instrStore.Store(prev) })
	conf.InternalMp.Instructions = s
	s.Note(mpzd.ZoneName, n, nil)
	enforced(t, s, mpzd.ZoneName)
	return sd(n)
}

// trustKey records that the parent trusts the zone's key keyid, as tdns's
// poll does when the parent says so.
func trustKey(kdb *tdns.KeyDB, zone string, keyid uint16) {
	tdns.UpdateParentState(kdb, zone, keyid, edns0.KeyStateTrusted)
}

// trustActiveKeys is trustKey for every active key of the zone: a rig whose
// leader holds a key the parent trusts already, and syncs at once.
func trustActiveKeys(t *testing.T, kdb *tdns.KeyDB, zone string) {
	t.Helper()
	rows, err := activeSig0Rows(kdb, ZoneName(zone))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		trustKey(kdb, zone, r.keyid)
	}
}

func noKeyAt(at SerialDigest) *ConfigResponseMsg {
	return stampedAt(at, &ConfigResponseMsg{ConfigData: map[string]string{"status": "no sig0 key for zone"}})
}

// Two agents lead a zone at once only under different active serials: under
// one serial they are one group, with one leader. Each asks the other for
// the key, and the other's "no key here" carries the other's active serial:
// it counts for nothing, and neither makes a key. The same answer at the
// asker's own serial lets the leader make one (decision 101).
func TestTwoLeadersNeverBothMakeAKey(t *testing.T) {
	for _, zone := range []string{"alpha.two.leaders.example.", "bravo.two.leaders.example."} {
		r := newKeyRoundRig(t, zone, "UPDATE")
		own := keepServed(t, r.conf, r.mpzd)
		r.caughtUp()
		round := &keyRound{serial: own, known: true}
		other := SerialDigest{Serial: own.Serial + 1, Digest: "the other leader's"}
		r.decide(map[AgentId]keyReply{r.them: round.atSerial(classifyKeyAnswer(noKeyAt(other)))})
		if got := r.active(t); len(got) != 0 {
			t.Errorf("%s: a key was made on a \"no key here\" told under another serial: %v", zone, got)
		}
		r.decide(map[AgentId]keyReply{r.them: round.atSerial(classifyKeyAnswer(noKeyAt(own)))})
		if got := r.active(t); len(got) != 1 {
			t.Errorf("%s: at the asker's own serial no key was made: %v", zone, got)
		}
	}
}

// During a transition the key is asked of every voting member under both
// serials: a provider that votes only under the serial agreed on is asked
// too, and not before.
func TestDuringATransitionTheKeyIsAskedOfVotingMembersUnderBothSerials(t *testing.T) {
	r := newThawRig(t, "both.key.example.", roleA)
	const roleC = "c.role.example."
	for _, id := range []string{roleB, roleN, roleC} {
		r.conf.InternalMp.AgentRegistry.S.Set(AgentId(id), NewAgent(AgentId(id)))
	}
	z := ZoneName(r.zone)
	before := r.conf.zoneKeyPeerIDs(z)
	if slices.Contains(before, roleC) || !slices.Contains(before, roleB) {
		t.Fatalf("at rest the key is asked of %v: want b and not c", before)
	}
	v := jAt(t, 42, `servers="a,b,c" nsmgmt="agent" suffix="v"`, append(slices.Clone(freezeRecords), `3600 IN HSYNC3 ON c c.role.example. .`)...)
	r.holdUnjudged(v, time.Now())
	if got := r.conf.zoneKeyPeerIDs(z); !slices.Contains(got, roleC) || !slices.Contains(got, roleB) {
		t.Errorf("agreeing on a serial where c votes, the key is asked of %v: want b and c", got)
	}
}

// The key's offers and its publication are held during a transition: the
// poll does not run, and the KEY is not published.
func TestTheKeyOffersAreHeldDuringATransition(t *testing.T) {
	r := newNotifyRig(t, "offers.held.example.", "UPDATE")
	var polled atomic.Int32
	r.conf.InternalMp.keyPoll = func(context.Context, ZoneName, string, uint16, uint8) { polled.Add(1) }
	testSig0Key(t, r.mpzd.KeyDB, r.mpzd.ZoneName) // not trusted by the parent yet
	freezeServed(t, r.conf, r.mpzd)
	z := ZoneName(r.mpzd.ZoneName)
	if held := r.conf.ParentSyncAfterKeyPublication(r.ctx, z, r.mpzd.ZoneName, 4711, dns.ED25519); !held || polled.Load() != 0 {
		t.Errorf("the key's offer during the freeze: held %v, polled %d", held, polled.Load())
	}
	if err := r.conf.publishZoneKey(r.ctx, z, nil, false, 0); !errors.Is(err, errHeldDuringTransition) {
		t.Errorf("the KEY's publication during the freeze: %v", err)
	}
}

// A rollover under way whose DS sync waits for the parent to trust the
// zone's key lets the key's offers pass the freeze: otherwise the rollover
// and the thaw would wait for each other. Once the parent trusts the key
// nothing waits on it, and they are held again.
func TestTheKeyOffersPassWhileARolloverWaitsOnKeyPending(t *testing.T) {
	r := newNotifyRig(t, "offers.pass.example.", "UPDATE")
	var polled atomic.Int32
	r.conf.InternalMp.keyPoll = func(context.Context, ZoneName, string, uint16, uint8) { polled.Add(1) }
	k := testSig0Key(t, r.mpzd.KeyDB, r.mpzd.ZoneName)
	freezeServed(t, r.conf, r.mpzd)
	z := ZoneName(r.mpzd.ZoneName)
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Rollover: true, Received: time.Now()})
	if held := r.conf.ParentSyncAfterKeyPublication(r.ctx, z, r.mpzd.ZoneName, k.keyid, dns.ED25519); held || polled.Load() != 1 {
		t.Errorf("the key's offer while a rollover waits on it: held %v, polled %d", held, polled.Load())
	}
	trustKey(r.mpzd.KeyDB, r.mpzd.ZoneName, k.keyid)
	if held := r.conf.ParentSyncAfterKeyPublication(r.ctx, z, r.mpzd.ZoneName, k.keyid, dns.ED25519); !held || polled.Load() != 1 {
		t.Errorf("the key's offer once the parent trusts the key: held %v, polled %d", held, polled.Load())
	}
}

// Every sync the leader asks for, the election's included, waits until the
// parent trusts the zone's key, and goes out when it does.
func TestTheSyncIsHeldUntilTheKeyIsUsable(t *testing.T) {
	r := newKeyHoldRig(t, "usable.key.example.")
	tdns.UpdateParentState(r.mpzd.KeyDB, string(r.zone), r.key.keyid, edns0.KeyStateUnknown) // a parent that does not know the key yet
	got := r.explicit(t)
	if !strings.Contains(got.Msg, "(the parent has not taken the key)") {
		t.Errorf("the explicit sync's answer: %q", got.Msg)
	}
	r.conf.requestDelegationSync(r.ctx, string(r.zone), "the election") // as the election asks
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent before it trusted the key", n)
	}
	if !r.keyOwed() {
		t.Fatal("the held sync is not owed for the key")
	}
	trustKey(r.mpzd.KeyDB, string(r.zone), r.key.keyid)
	r.conf.releaseKeyHold(r.ctx, r.zone) // as the poll's end does
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// A parent that takes NOTIFY only needs no SIG(0) key: nothing is pending
// for one, and the leader's sync is not held for it.
func TestANotifyOnlyParentIsNotHeldForAKey(t *testing.T) {
	h := newHoldRig(t, "notify.only.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
	testSig0Key(t, h.mpzd.KeyDB, h.mpzd.ZoneName) // never offered to the parent
	z := ZoneName(h.mpzd.ZoneName)
	if h.conf.keyPending(h.ctx, z) {
		t.Error("a key is pending for a parent that takes NOTIFY only")
	}
	if held, why := h.conf.holdForZoneKey(h.ctx, tdns.DelegationSyncRequest{ZoneName: string(z), ZoneData: h.mpzd.ZoneData}); held {
		t.Errorf("the sync is held for the key at a parent that takes NOTIFY only: %s", why)
	}
}

// At the leader a key the parent has not taken is offered again by the key
// rounds: at most every keyOfferEvery, and not after the parent trusts it,
// when the round's entry ends.
func TestAKeyThatTheParentHasNotTakenIsOfferedAgain(t *testing.T) {
	r := newKeyRoundRig(t, "offered.again.example.", "UPDATE")
	r.conf.InternalMp.keyPoll = func(_ context.Context, _ ZoneName, _ string, keyid uint16, _ uint8) { r.polls <- keyid }
	k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	if !r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Fatal("the leader does not keep the entry for a key the parent has not taken")
	}
	if peers := r.conf.keyRoundPeers(r.zone); len(peers) != 0 {
		t.Errorf("a leader that holds the key asks %v for it", peers)
	}
	if r.decide(nil) {
		t.Error("the round ended while the parent does not trust the key")
	}
	if keyid := r.polled(t, "the first offer"); keyid != k.keyid {
		t.Errorf("key %d offered, want %d", keyid, k.keyid)
	}
	if !strings.Contains(r.alog.String(), "the parent has not taken the zone's SIG(0) key, offering it again") {
		t.Errorf("no line for the offer:\n%s", r.alog)
	}
	waitUntil(t, "the offer's poll did not end", func() bool { running, _, _ := r.conf.InternalMp.keyPolls.state(r.zone); return running == 0 })
	r.decide(nil)
	r.notPolled(t, "a round within keyOfferEvery of the offer")

	saved := keyOfferEvery
	keyOfferEvery = 0
	t.Cleanup(func() { keyOfferEvery = saved })
	r.decide(nil)
	r.polled(t, "a round after keyOfferEvery")
	waitUntil(t, "the offer's poll did not end", func() bool { running, _, _ := r.conf.InternalMp.keyPolls.state(r.zone); return running == 0 })

	trustKey(r.mpzd.KeyDB, string(r.zone), k.keyid)
	if !r.decide(nil) {
		t.Error("the round did not end once the parent trusts the key")
	}
	r.notPolled(t, "a key the parent trusts")
	if r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Error("the leader still wants a key the parent trusts")
	}
}

// receivesPublish is a SYNC from originator, over DNS, whose transport
// established transportSender, carrying ops and a publish instruction.
func (r *notifyRig) receivesPublish(t *testing.T, originator, transportSender string, publish *core.PublishInstruction, ops ...core.RROperation) string {
	t.Helper()
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{
		MessageType:    "sync",
		OriginatorID:   originator,
		YourIdentity:   r.us.Identity,
		Zone:           r.mpzd.ZoneName,
		Operations:     ops,
		Publish:        publish,
		Time:           time.Now().Format(time.RFC3339Nano),
		Timestamp:      time.Now().Unix(),
		DistributionID: distID,
	})
	if err != nil {
		t.Fatalf("the SYNC: %v", err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{
		TypeToken:       "sync",
		DistributionID:  distID,
		SenderID:        originator,
		TransportSender: transportSender,
		Mechanism:       transport.MechanismDNS,
		Zone:            r.mpzd.ZoneName,
		Payload:         body,
		ReceivedAt:      time.Now(),
		SourceAddr:      "127.0.0.1:0",
	})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the SYNC")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
	return distID
}

// toCombiner records the publish instruction of every update the agent
// hands its combiner with a KEY or an instruction.
func toCombiner(t *testing.T) chan *core.PublishInstruction {
	t.Helper()
	got := make(chan *core.PublishInstruction, 8)
	saved := enqueueForCombiner
	enqueueForCombiner = func(tm *MPTransportBridge, zone ZoneName, update *ZoneUpdate, distID string) (string, error) {
		if _, ok := opOf(update, "KEY"); ok || update.Publish != nil {
			got <- update.Publish
		}
		return saved(tm, zone, update, distID)
	}
	t.Cleanup(func() { enqueueForCombiner = saved })
	return got
}

// The zone's KEY is the group's: taken from the zone's leader only. Another
// agent's KEY is rejected, and its publish instruction dropped; the
// leader's goes into the repo and on to the combiner, with its instruction
// (#206).
func TestAKEYIsTakenFromTheLeaderOnly(t *testing.T) {
	r := receivingRig(t, "key.leader.only.example.")
	combiner := toCombiner(t)
	z := r.mpzd.ZoneName
	sender := r.peer.Identity
	k := testSig0Key(t, newMPTestKeyDB(t), z)
	op := core.RROperation{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}
	publish := &core.PublishInstruction{KEYRRs: []string{k.key.String()}, Locations: []string{"at-apex", "at-ns"}}

	r.leader(r.lem.localID) // the sender does not lead
	distID := r.receivesPublish(t, sender, sender, publish, op)
	c := r.answered(t, distID)
	want := "a KEY is taken only from the zone's delegation sync leader: the sender is " + sender + ", the leader is " + string(r.lem.localID)
	if c.Status != "REJECTED" || len(c.RejectedItems) != 1 || c.RejectedItems[0].Reason != want {
		t.Errorf("a KEY from an agent that does not lead: the sender got %+v", *c)
	}
	if got := r.repo(t)[AgentId(sender)][dns.TypeKEY]; len(got) != 0 {
		t.Errorf("the agent's repo holds the KEY of an agent that does not lead: %+v", got)
	}
	if got, ok := recvWithin(combiner, 200*time.Millisecond); ok {
		t.Errorf("a KEY of an agent that does not lead went to the combiner, with %+v", got)
	}

	r.leader(AgentId(sender))
	r.receivesPublish(t, sender, sender, publish, op)
	var held TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && held.RR == ""; time.Sleep(10 * time.Millisecond) {
		if got := r.repo(t)[AgentId(sender)][dns.TypeKEY]; len(got) == 1 {
			held = got[0]
		}
	}
	if held.RR == "" {
		t.Fatalf("the leader's KEY is not in the agent's repo\n%s", r.log)
	}
	if got, ok := recvWithin(combiner, 5*time.Second); !ok || got == nil || !slices.Equal(got.Locations, publish.Locations) {
		t.Errorf("the leader's KEY went to the combiner with the instruction %+v (handed over %v), want %+v", got, ok, publish)
	}
	// the same KEY again changes nothing in the repo, and the instruction
	// still reaches the combiner: a member that held the KEY before gets it
	r.receivesPublish(t, sender, sender, publish, op)
	if got, ok := recvWithin(combiner, 5*time.Second); !ok || got == nil {
		t.Errorf("the leader's instruction with a KEY the repo holds: %+v (handed over %v)", got, ok)
	}
}

// Only the leader's answer to a request for the zone's state names the
// zone's KEY, with its publish instruction; a member's names none.
func TestOnlyTheLeadersAnswerNamesTheKEY(t *testing.T) {
	r := newAnswerRig(t, "key.answer.example.", []string{"us"})
	r.inventory(t)
	k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	publishKEY(t, r.mpzd, k)
	zu := r.answer(t)
	if _, ok := opOf(zu, "KEY"); ok || zu.Publish != nil {
		t.Errorf("an agent that does not lead names the KEY: %+v", zu)
	}
	r.leads()
	zu = r.answer(t)
	if op, ok := opOf(zu, "KEY"); !ok || !slices.Equal(op.Records, []string{k.key.String()}) {
		t.Errorf("the leader's answer: KEY %+v (present %v)", op, ok)
	}
	if zu.Publish == nil || !slices.Equal(zu.Publish.KEYRRs, []string{k.key.String()}) || !slices.Contains(zu.Publish.Locations, "at-apex") {
		t.Errorf("the leader's answer carries the publish instruction %+v", zu.Publish)
	}
}

// The leader names the KEY from its keystore, the key whose KEY the zone
// publishes: its data, which the key's set-up never wrote, holds none. A key
// it holds that the zone does not publish is not named.
func TestTheLeadersAnswerTakesTheKEYFromItsKeystoreNotItsData(t *testing.T) {
	r := newAnswerRig(t, "keystore.answer.example.", []string{"us"})
	r.inventory(t)
	r.leads()
	k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	publishKEY(t, r.mpzd, testSig0Key(t, newMPTestKeyDB(t), string(r.zone)))
	if op, ok := opOf(r.answer(t), "KEY"); ok {
		t.Errorf("the leader names a KEY the zone does not publish: %+v", op)
	}
	publishKEY(t, r.mpzd, k)
	if agentRepo, ok := r.zdr.Repo.Get(r.zone); ok {
		if nod, ok := agentRepo.Data.Get(usAgent); ok {
			if keys, ok := nod.RRtypes.Get(dns.TypeKEY); ok && len(keys.RRs) > 0 {
				t.Fatalf("the leader's data holds a KEY: %v", keys.RRs)
			}
		}
	}
	if op, ok := opOf(r.answer(t), "KEY"); !ok || !slices.Equal(op.Records, []string{k.key.String()}) {
		t.Errorf("the leader's answer: KEY %+v (present %v), want the key from its keystore", op, ok)
	}
}

// leads has the rig's agent lead the zone.
func (r *answerRig) leads() {
	r.lem.mu.Lock()
	defer r.lem.mu.Unlock()
	r.lem.elections[r.zone] = &LeaderElection{Zone: r.zone, Leader: usAgent, LeaderExpiry: time.Now().Add(time.Hour)}
}

// publishKEY puts k's KEY, alone, at the apex of the agent's copy.
func publishKEY(t *testing.T, mpzd *MPZoneData, k sig0Row) {
	t.Helper()
	zd := mpzd.ZoneData
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		t.Fatal("the zone has no apex")
	}
	apex.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: []dns.RR{k.key}})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
}

// opOf is zu's operation of rrtype.
func opOf(zu *ZoneUpdate, rrtype string) (core.RROperation, bool) {
	for _, op := range zu.Operations {
		if op.RRtype == rrtype {
			return op, true
		}
	}
	return core.RROperation{}, false
}

// A leader whose round finds the zone's published KEY held by nobody asked
// shows the key as LOST, until a round finds it held.
func TestALostKeyShowsLOST(t *testing.T) {
	r := newKeyRoundRig(t, "lost.status.example.", "UPDATE")
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}})
	if got := r.conf.zoneKeyLine(r.ctx, r.zone); got != "LOST" {
		t.Errorf("the status of a lost key: %q, want LOST", got)
	}
	r.decide(map[AgentId]keyReply{r.them: {outcome: keyGot, data: keyData(k)}})
	r.polled(t, "the key handed over")
	if got := r.conf.zoneKeyLine(r.ctx, r.zone); got != "" {
		t.Errorf("the status once the key is held and trusted: %q", got)
	}
}

// The leader's KEY goes to the other agents with its publish instruction,
// as to its own combiner, so that every provider publishes it at-ns under
// its own nameservers (#206): the transport carries the instruction to an
// agent, and the agent's handler hands it on.
func TestTheKEYGoesToThePeersWithItsPublishInstruction(t *testing.T) {
	r := receivingRig(t, "publish.peers.example.")
	z := r.mpzd.ZoneName
	k := testSig0Key(t, newMPTestKeyDB(t), z)
	publish := &core.PublishInstruction{KEYRRs: []string{k.key.String()}, Locations: []string{"at-apex", "at-ns"}}
	update := &ZoneUpdate{Zone: ZoneName(z), AgentId: AgentId(r.us.Identity), Publish: publish,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}}}
	if err := r.us.Bridge.deliverGenericMessage(r.ctx, &transport.OutgoingMessage{DistributionID: nextDistributionID(),
		RecipientID: r.peer.Identity, Zone: z, Payload: update}); err != nil {
		t.Fatalf("the KEY to the peer: %v", err)
	}
	amp, ok := recvMsgWithin(t, r.peer.MsgQs.Msg, 10*time.Second)
	if !ok || amp.Publish == nil || !slices.Equal(amp.Publish.KEYRRs, publish.KEYRRs) || !slices.Equal(amp.Publish.Locations, publish.Locations) {
		t.Fatalf("the peer got %+v (received %v), want the KEY's publish instruction", amp, ok)
	}
}

// While this agent does not know the zone's active serial (design 3.4), its
// key rounds know none: no key and no "no key here" counts, though the
// store holds a newer copy of the zone.
func TestNoKeyAnswerCountsWhileTheActiveSerialIsNotKnown(t *testing.T) {
	r := newThawRig(t, "unknown.key.example.", roleA)
	z := ZoneName(r.zone)
	if got, known := r.conf.activeSerial(z); !known || got != sd(r.n) {
		t.Fatalf("with its record the agent's active serial is %+v (known %v), want %d", got, known, r.n.Serial)
	}
	r.noRecord(r.v)
	got, known := r.conf.activeSerial(z)
	if known {
		t.Fatalf("with no record the agent knows the active serial %+v", got)
	}
	round := &keyRound{serial: got, known: known}
	if a := round.atSerial(classifyKeyAnswer(noKeyAt(sd(r.v)))); a.outcome != keyOtherSerial {
		t.Errorf("a \"no key here\" while the active serial is not known counts as %+v", a)
	}
}

// A voting member under the other serial of a transition that was not asked
// (it is not known here yet) has not said it holds none: the leader's round
// does not find the published KEY lost.
func TestAKeyIsNotLostWhileAVoterUnderTheOtherSerialWasNotAsked(t *testing.T) {
	r := newKeyRoundRig(t, "other.voter.key.example.", "UPDATE")
	keepServed(t, r.conf, r.mpzd)
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	s := r.conf.InternalMp.Instructions
	n := s.activeReading(r.mpzd.ZoneName)
	v := *n
	v.Serial = n.Serial + 1
	v.Records = append(slices.Clone(n.Records), InstrRecord{Label: "charlie", Identity: "agent.charlie.example."})
	v.Servers = append(slices.Clone(n.Servers), "charlie")
	if err := s.update(r.mpzd.ZoneName, func(z *zoneSerials) error {
		z.Held = append(z.Held, heldSerial{SerialDigest: sd(&v), Reading: &v, Since: time.Now()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}})
	if got := r.conf.zoneKeyLine(r.ctx, r.zone); got == "LOST" {
		t.Error("the KEY is LOST though a voting member under the serial agreed on was not asked")
	}
	if _, lost := r.conf.InternalMp.keyPolls.lostKey(r.zone); lost {
		t.Error("the round marked the KEY lost")
	}
}

// A KEY's publish instruction goes with its KEY: a replace of the KEY that
// the repo finds older than the one it applied goes no further, and its
// instruction, which names the older KEY, does not reach the combiner.
func TestAStaleKEYsPublishInstructionDoesNotReachTheCombiner(t *testing.T) {
	const zone = "stale.publish.example."
	r := newEngineRigWith(t, zone, func(conf *Config) {
		lem := NewLeaderElectionManager(roleA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
		t.Cleanup(func() { stopElectionTimers(lem) })
		lem.elections[ZoneName(zone)] = &LeaderElection{Zone: ZoneName(zone), Leader: roleB, LeaderExpiry: time.Now().Add(time.Hour)}
		conf.InternalMp.LeaderElectionManager = lem
	})
	combiner := toCombiner(t)
	send := func(k sig0Row, sentAt time.Time, distID string) {
		t.Helper()
		done := make(chan *AgentMsgResponse, 1)
		r.msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: r.zone, AgentId: roleB, UpdateType: "remote", DeliveredBy: roleB,
			OriginatingDistID: distID, OriginatingTime: sentAt,
			Update: &ZoneUpdate{Zone: r.zone, AgentId: roleB, Publish: &core.PublishInstruction{KEYRRs: []string{k.key.String()}, Locations: []string{"at-apex"}},
				Operations: []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}}},
			Response: done}
		if _, ok := recvWithin(done, 5*time.Second); !ok {
			t.Fatal("the engine did not answer")
		}
	}
	older, newer := testSig0Key(t, newMPTestKeyDB(t), zone), testSig0Key(t, newMPTestKeyDB(t), zone)
	now := time.Now()
	send(newer, now, "d-newer")
	if got, ok := recvWithin(combiner, 5*time.Second); !ok || got == nil || !slices.Equal(got.KEYRRs, []string{newer.key.String()}) {
		t.Fatalf("the newer KEY went to the combiner with %+v (handed over %v)", got, ok)
	}
	send(older, now.Add(-time.Minute), "d-older")
	if got, ok := recvWithin(combiner, 300*time.Millisecond); ok {
		t.Errorf("a stale KEY replace handed the combiner the instruction %+v", got)
	}
}

// What the leader sends again to a peer now in step names the zone's KEY
// with its publish instruction, as the leader's every KEY goes (#206).
func TestTheKEYSentAgainCarriesItsPublishInstruction(t *testing.T) {
	r := newReceiveRig(t, "resend.key.example.")
	mpzd, _ := Zones.Get(r.zone)
	mpzd.KeyDB = newMPTestKeyDB(t)
	k := testSig0Key(t, mpzd.KeyDB, r.zone)
	publishKEY(t, mpzd, k)
	r.leads(roleA)
	distID := r.notYetFromB(r.v)
	r.agree()
	r.done()
	sent := make(chan *ZoneUpdate, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.conf.InternalMp.MPTransport.TransportManager.StartReliableQueue(ctx, func(_ context.Context, m *transport.OutgoingMessage) error {
		if u, ok := m.Payload.(*ZoneUpdate); ok && m.RecipientID == roleB && m.DistributionID == distID {
			sent <- u
		}
		return nil
	})
	r.activated()
	u, ok := recvWithin(sent, 5*time.Second)
	if !ok {
		t.Fatal("nothing was sent again to b")
	}
	if op, ok := opOf(u, "KEY"); !ok || !slices.Equal(op.Records, []string{k.key.String()}) {
		t.Fatalf("what was sent again names KEY %+v (present %v)", op, ok)
	}
	if u.Publish == nil || !slices.Equal(u.Publish.KEYRRs, []string{k.key.String()}) {
		t.Errorf("the KEY was sent again with the publish instruction %+v", u.Publish)
	}
}

// While the zone reconciles, its other serial is the one it reconciles
// from: a serial held above the active one, the next transition's, is not
// asked for the key.
func TestWhileReconcilingTheKeyIsNotAskedUnderANewerHeldSerial(t *testing.T) {
	r := newFreezeRig(t, "reconciling.key.example.")
	const roleC = "c.role.example."
	next := jAt(t, 43, `servers="a,b,c" nsmgmt="agent" suffix="next"`, append(slices.Clone(freezeRecords), `3600 IN HSYNC3 ON c c.role.example. .`)...)
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active = &heldSerial{SerialDigest: sd(r.v), Reading: r.v, Since: time.Now()}
		z.From = &heldSerial{SerialDigest: sd(r.n), Reading: r.n, Since: time.Now()}
		z.Held = []heldSerial{{SerialDigest: sd(next), Reading: next, Since: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := r.store.transitionVoters(r.zone); slices.Contains(got, roleC) || !slices.Contains(got, roleB) {
		t.Errorf("reconciling from 41 to 42 with 43 held, the key is asked of %v: want b and not c", got)
	}
}

// An offer again that the freeze holds is not made, and counts as none: it
// goes at the next round once a rollover under way waits on the key, not
// keyOfferEvery later.
func TestAnOfferTheFreezeHoldsIsNotCountedAsMade(t *testing.T) {
	r := newKeyRoundRig(t, "offer.held.example.", "UPDATE")
	r.conf.InternalMp.keyPoll = func(_ context.Context, _ ZoneName, _ string, keyid uint16, _ uint8) { r.polls <- keyid }
	k := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	freezeServed(t, r.conf, r.mpzd)
	r.decide(nil)
	r.notPolled(t, "an offer again during the freeze")
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: r.mpzd.ZoneName, Rollover: true, Received: time.Now()})
	r.decide(nil)
	if keyid := r.polled(t, "the offer once a rollover waits on the key"); keyid != k.keyid {
		t.Errorf("key %d offered, want %d", keyid, k.keyid)
	}
}

// A peer's REPLACE of the zone's KEY that is the same as the local agent's
// contribution leaves the peer none of its own: a second KEY it published
// before does not stay beside the local one. The fleet's take-away of a
// second KEY at a leader, at a combiner whose own agent had led the zone.
// The removal is told to the peer whether or not this combiner serves KEYs.
func TestAKEYReplaceTheLocalAgentHoldsLeavesThePeerNoOlderKEY(t *testing.T) {
	for name, apply := range map[string]bool{"a combiner that serves KEYs": true, "a combiner that serves no KEY": false} {
		zone := "keydedup.acting.example."
		_, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`)...)
		policy := mpzd.getEditPolicy()
		if !apply {
			policy = &editPolicy{NSmgmt: core.HsyncNSmgmtOWNER, ParentSync: core.HsyncParentSyncOwner}
		}
		if got := policy.canApply(dns.TypeKEY); got != apply {
			t.Fatalf("%s: the combiner applies KEYs: %v", name, got)
		}
		pub, second := testSig0Key(t, newMPTestKeyDB(t), zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key
		mpzd.Lock()
		mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
			actUs:    {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub}}}},
			actOther: {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub, second}}}},
		}
		mpzd.Unlock()
		req := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(), Timestamp: time.Now(),
			Operations: []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{pub.String()}}}}
		resp := mpzd.combinerProcessOperations(req, zone, nil, map[string]bool{actUs: true}, policy)
		if !slices.Contains(resp.RemovedRecords, second.String()) {
			t.Errorf("%s: the peer's second KEY is not named removed: %s %+v", name, resp.Message, resp.RemovedRecords)
		}
		mpzd.Lock()
		left := mpzd.MP.AgentContributions[actOther][zone][dns.TypeKEY].RRs
		mpzd.Unlock()
		if slices.ContainsFunc(left, func(rr dns.RR) bool { return rr.String() == second.String() }) {
			t.Errorf("%s: the peer's second KEY is still stored: %v", name, left)
		}
	}
}

// When the peer's own KEY cannot be removed for good (the store fails),
// its REPLACE is refused as a failed REPLACE is, so that the peer sends it
// again: it is not told its records were applied. Its records stay, as the
// store still holds them, so that the retry removes them for good.
func TestAKEYReplaceWhoseRemovalFailsIsRefused(t *testing.T) {
	const zone = "keydedupfail.acting.example."
	_, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`)...)
	pub, second := testSig0Key(t, newMPTestKeyDB(t), zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key
	var failed bool
	var stored []dns.RR // the peer's KEY as the store last took it
	mpzd.Lock()
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actUs:    {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub}}}},
		actOther: {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub, second}}}},
	}
	mpzd.MP.PersistContributions = func(_, sender string, c map[string]map[uint16]core.RRset) error {
		if !failed {
			failed = true
			return errors.New("the store is full")
		}
		if sender == actOther {
			stored = slices.Clone(c[zone][dns.TypeKEY].RRs)
		}
		return nil
	}
	mpzd.Unlock()
	replace := func() *CombinerSyncResponse {
		req := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(), Timestamp: time.Now(),
			Operations: []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{pub.String()}}}}
		return mpzd.combinerProcessOperations(req, zone, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy())
	}
	resp := replace()
	if len(resp.RejectedItems) != 1 || !strings.Contains(resp.RejectedItems[0].Reason, "replace failed") {
		t.Errorf("a REPLACE whose removal failed: %s %+v", resp.Status, resp.RejectedItems)
	}
	if slices.Contains(resp.AppliedRecords, pub.String()) {
		t.Errorf("a REPLACE whose removal failed is told applied: %+v", resp.AppliedRecords)
	}
	mpzd.Lock()
	kept := len(mpzd.MP.AgentContributions[actOther][zone][dns.TypeKEY].RRs)
	mpzd.Unlock()
	if kept != 2 {
		t.Fatalf("after the failed removal the peer holds %d KEYs, want its 2 back", kept)
	}
	if resp := replace(); len(resp.RejectedItems) != 0 || !slices.Contains(resp.RemovedRecords, second.String()) {
		t.Errorf("the retry: %s %+v, removed %v", resp.Status, resp.RejectedItems, resp.RemovedRecords)
	}
	if len(stored) != 0 {
		t.Errorf("after the retry the store holds the peer's KEYs %v", stored)
	}
}

// A newer REPLACE of the same peer's KEY that comes while a failed removal
// is undone is not undone with it: the removal and its undoing hold the
// zone's lock between them, so the newer one lands after, and stays.
func TestANewerKEYReplaceIsNotUndoneByAFailedRemoval(t *testing.T) {
	const zone = "keydedupnewer.acting.example."
	_, mpzd := actingCombiner(t, zone, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`)...)
	pub, second, third := testSig0Key(t, newMPTestKeyDB(t), zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key
	newer := make(chan struct{})
	var once sync.Once
	mpzd.Lock()
	mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{
		actUs:    {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub}}}},
		actOther: {zone: {dns.TypeKEY: core.RRset{Name: zone, RRtype: dns.TypeKEY, RRs: []dns.RR{pub, second}}}},
	}
	mpzd.MP.PersistContributions = func(string, string, map[string]map[uint16]core.RRset) error {
		failed := false
		once.Do(func() {
			failed = true
			// the newer REPLACE comes now, and waits for the zone
			go func() {
				defer close(newer)
				mpzd.ReplaceCombinerDataByRRtype(actOther, zone, dns.TypeKEY, []dns.RR{third})
			}()
			time.Sleep(50 * time.Millisecond)
		})
		if failed {
			return errors.New("the store is full")
		}
		return nil
	}
	mpzd.Unlock()
	req := &CombinerSyncRequest{SenderID: actOther, Zone: zone, DistributionID: nextDistributionID(), Timestamp: time.Now(),
		Operations: []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{pub.String()}}}}
	mpzd.combinerProcessOperations(req, zone, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy())
	if _, ok := recvWithin(newer, 5*time.Second); !ok {
		t.Fatal("the newer REPLACE did not end")
	}
	mpzd.Lock()
	got := slices.Clone(mpzd.MP.AgentContributions[actOther][zone][dns.TypeKEY].RRs)
	mpzd.Unlock()
	if len(got) != 1 || got[0].String() != third.String() {
		t.Errorf("the peer's KEY after the failed removal and the newer REPLACE: %v, want the newer one alone", got)
	}
}
