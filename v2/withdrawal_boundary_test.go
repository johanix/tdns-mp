/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The leader's withdrawal at the transport boundary (plan S16), on the
 * receiving rig: the peer leads the zone and sends the withdrawal over the
 * wire to the agent under test.
 */
package tdnsmp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A member's refusal of a withdrawal as older than the provider's own
// replace reaches the leader's confirmation callback with both stamps at
// one serial, and is booked to go again, after a wait.
func TestTransportBoundary_ARefusalAsOlderIsBookedToGoAgain(t *testing.T) {
	zone := "older.boundary.example."
	r, in := serialsRig(t, zone, true)
	distID := nextDistributionID()
	r.peer.Bridge.stamps.sent(distID, r.us.Identity, zone, msgStampAt(in[42]))
	r.peer.Bridge.ChunkHandler.OnConfirmationReceived(&transport.IncomingConfirmation{DistributionID: distID, PeerID: r.us.Identity,
		Status: transport.ConfirmRejected, Zone: zone, Message: staleWithdrawal + ": older than the provider's own records applied here",
		App: r.us.Bridge.stamps.confirmAppFor(zone)})
	open := r.peer.Bridge.notYets.forZone(ZoneName(zone))
	if len(open) != 1 || open[0].distID != distID {
		t.Fatalf("the leader's book of what goes again: %+v", open)
	}
	if !open[0].notBefore.After(open[0].at) {
		t.Errorf("it goes at %v, booked at %v: want a wait", open[0].notBefore, open[0].at)
	}
}

// The way a rig's auditor takes the leader's withdrawal: the transport names
// the provider as the message's originator, and the auditor's final word goes
// to the leader all the same.
func TestTransportBoundary_TheAuditorsFinalWordOnAWithdrawalGoesToTheLeader(t *testing.T) {
	zone := "auditor.boundary.example."
	r := newNotifyRig(t, zone, "NOTIFY", repeat(time.Minute, 4)...)
	peer := r.peer.Identity
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: zone,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY"}}, Time: time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(),
		DistributionID: distID, Withdraw: &Withdraw{Provider: "agent.gone.boundary.example.", RRtype: "DNSKEY"}})
	if err != nil {
		t.Fatal(err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "sync", DistributionID: distID, SenderID: peer,
		TransportSender: peer, Mechanism: transport.MechanismDNS, Zone: zone, Payload: body, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the withdrawal")
	}
	var got *RemoteConfirmationDetail
	(&AuditorEngine{msgQs: &MsgQs{OnRemoteConfirmationReady: func(d *RemoteConfirmationDetail) { got = d }}}).recordSyncMsg(amp)
	if got == nil || got.OriginatingSender != peer {
		t.Errorf("the auditor's final word: %+v, want it to go to the leader %s", got, peer)
	}
}

// The peer leads the zone, and gone, which has a record and no role, has
// NS records at the agent. The peer's withdrawal of them reaches the agent
// over the wire and is taken: they leave the agent's data, the agent hands
// the withdrawal to its combiner, and the combiner's confirmation goes back
// to the leader as its final word, naming what was removed.
func TestTransportBoundary_AWithdrawalReachesTheRecipientsCombiner(t *testing.T) {
	zone := "withdraw.boundary.example."
	const gone = "agent.gone.boundary.example."
	var in Instructions
	r := newNotifyRigWith(t, zone, "NOTIFY", true, func(r *notifyRig) {
		apex, err := r.mpzd.OwnerForAnalysis(zone)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		base, err := ReadInstructions(apex)
		if err != nil || base == nil {
			t.Fatalf("the zone's reading: %v %v", base, err)
		}
		in = *base
		in.Records = append(slices.Clone(base.Records), InstrRecord{Label: "gone", Identity: gone})
		store := newStore(t)
		store.Note(zone, &in, nil)
		enforced(t, store, zone)
		kept, err := loadKeptLists(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.conf.InternalMp.Instructions, r.conf.InternalMp.Kept = store, kept
		r.us.Bridge.stamps = newStampTable(r.us.Identity, store, 1, false, nil)
	}, repeat(time.Minute, 4)...)
	peer := r.peer.Identity
	r.us.Registry.S.Set(AgentId(peer), NewAgent(AgentId(peer)))
	r.leader(AgentId(peer))

	rr, err := dns.NewRR(zone + " 3600 IN NS ns1.gone.boundary.example.")
	if err != nil {
		t.Fatal(err)
	}
	rec := rr.String()
	held := make(chan *AgentMsgResponse, 1)
	r.us.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(zone), AgentId: gone, UpdateType: "remote",
		Update:            &ZoneUpdate{Zone: ZoneName(zone), AgentId: gone, Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{rec}}}},
		OriginatingDistID: nextDistributionID(), OriginatingTime: time.Now(), DeliveredBy: gone, Mechanism: "DNS", Response: held}
	r.combinerTakes(r.heldBy(t, gone, dns.TypeNS, rec).DistributionID, rec)

	before := r.combinerDists()
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: zone,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}, Time: time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(),
		DistributionID: distID, Instr: msgStampAt(&in), Withdraw: &Withdraw{Provider: gone, RRtype: "NS"}})
	if err != nil {
		t.Fatal(err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "sync", DistributionID: distID, SenderID: peer,
		TransportSender: peer, Mechanism: transport.MechanismDNS, Zone: zone, Payload: body, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the withdrawal")
	}
	if amp.OriginatorID != gone || amp.DeliveredBy != AgentId(peer) || amp.Withdraw == nil {
		t.Fatalf("the withdrawal as routed: originator %s, delivered by %s, withdraw %+v", amp.OriginatorID, amp.DeliveredBy, amp.Withdraw)
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)

	toCombiner := r.newCombinerDist(before, 10*time.Second)
	if toCombiner == "" {
		t.Fatalf("the withdrawal did not go to the agent's combiner\n%s", r.log)
	}
	for _, info := range r.repo(t)[gone][dns.TypeNS] {
		if info.RR == rec && info.State != RRStateRemoved.String() {
			t.Errorf("gone's NS at the agent after the withdrawal: %s", info.State)
		}
	}
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(toCombiner, rigCombiner, transport.ConfirmSuccess, zone, nil, []string{rec}, nil, nil, false, ""))
	if c := r.answered(t, distID); c.Status != "SUCCESS" || !slices.Contains(c.RemovedRecords, rec) {
		t.Errorf("the leader's final confirmation: %+v, want a success that names %s as removed", *c, rec)
	}

	// only a sync is a withdrawal: an RFI that carries the field keeps its
	// authenticated sender, and the field is dropped
	rfi, err := json.Marshal(DnsSyncPayload{MessageType: "rfi", RfiType: "SYNC", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: zone,
		Time: time.Now().Format(time.RFC3339Nano), Withdraw: &Withdraw{Provider: gone, RRtype: "NS"}})
	if err != nil {
		t.Fatal(err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "rfi", SenderID: peer, TransportSender: peer,
		Mechanism: transport.MechanismDNS, Zone: zone, Payload: rfi, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	if amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second); !ok || amp.OriginatorID != AgentId(peer) || amp.Withdraw != nil {
		t.Errorf("an RFI with the withdraw field, as routed: %+v", amp)
	}

	// an agent's update to its combiner, in the provider's name, keeps the
	// field: it is the combiner's flag
	upd, err := json.Marshal(DnsSyncPayload{MessageType: "update", OriginatorID: gone, YourIdentity: r.us.Identity, Zone: zone,
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}, Time: time.Now().Format(time.RFC3339Nano),
		DistributionID: nextDistributionID(), Withdraw: &Withdraw{Provider: gone, RRtype: "NS"}})
	if err != nil {
		t.Fatal(err)
	}
	// the sender the transport takes from such a payload is the provider
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "update", SenderID: gone, TransportSender: peer,
		Mechanism: transport.MechanismDNS, Zone: zone, Payload: upd, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	if amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second); !ok || amp.OriginatorID != gone || amp.Withdraw == nil {
		t.Errorf("an update with the withdraw field, as routed: %+v", amp)
	}
}

// Each of the removal's three withdrawals goes over the wire and reaches a
// member: it leaves the member's data, its combiner gets it, and the
// confirmation goes back to the leader.
func TestTransportBoundary_ARemovalsWithdrawalsReachEveryMember(t *testing.T) {
	const gone = "agent.gone.boundary.example."
	for _, c := range []struct{ rrtype, rdata string }{
		{"NS", "ns1.gone.boundary.example."},
		{"CDS", "4711 15 2 0000000000000000000000000000000000000000000000000000000000000000"},
		{"DNSKEY", "257 3 15 11qYAYKxCrfVS/7TyWQHOg7nGkjJ3KgP9h8fZqXsIY8="},
	} {
		t.Run(c.rrtype, func(t *testing.T) {
			zone := strings.ToLower(c.rrtype) + ".removal.boundary.example."
			var in Instructions
			r := newNotifyRigWith(t, zone, "NOTIFY", true, func(r *notifyRig) {
				apex, err := r.mpzd.OwnerForAnalysis(zone)
				if err != nil || apex == nil {
					t.Fatalf("apex: %v", err)
				}
				base, err := ReadInstructions(apex)
				if err != nil || base == nil {
					t.Fatalf("the zone's reading: %v %v", base, err)
				}
				in = *base
				in.Records = append(slices.Clone(base.Records), InstrRecord{Label: "gone", Identity: gone})
				store := newStore(t)
				store.Note(zone, &in, nil)
				enforced(t, store, zone)
				kept, err := loadKeptLists(nil)
				if err != nil {
					t.Fatal(err)
				}
				r.conf.InternalMp.Instructions, r.conf.InternalMp.Kept = store, kept
				r.us.Bridge.stamps = newStampTable(r.us.Identity, store, 1, false, nil)
			}, repeat(time.Minute, 4)...)
			peer := r.peer.Identity
			r.us.Registry.S.Set(AgentId(peer), NewAgent(AgentId(peer)))
			r.leader(AgentId(peer))
			t2 := dns.StringToType[c.rrtype]
			rr, err := dns.NewRR(zone + " 3600 IN " + c.rrtype + " " + c.rdata)
			if err != nil {
				t.Fatal(err)
			}
			rec := rr.String()
			held := make(chan *AgentMsgResponse, 1)
			r.us.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(zone), AgentId: gone, UpdateType: "remote",
				Update:            &ZoneUpdate{Zone: ZoneName(zone), AgentId: gone, Operations: []core.RROperation{{Operation: "replace", RRtype: c.rrtype, Records: []string{rec}}}},
				OriginatingDistID: nextDistributionID(), OriginatingTime: time.Now(), DeliveredBy: gone, Mechanism: "DNS", Response: held}
			r.combinerTakes(r.heldBy(t, gone, t2, rec).DistributionID, rec)

			before := r.combinerDists()
			distID := nextDistributionID()
			body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: zone,
				Operations: []core.RROperation{{Operation: "replace", RRtype: c.rrtype}}, Time: time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(),
				DistributionID: distID, Instr: msgStampAt(&in), Withdraw: &Withdraw{Provider: gone, RRtype: c.rrtype}})
			if err != nil {
				t.Fatal(err)
			}
			r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "sync", DistributionID: distID, SenderID: peer,
				TransportSender: peer, Mechanism: transport.MechanismDNS, Zone: zone, Payload: body, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
			amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
			if !ok {
				t.Fatal("the transport did not queue the withdrawal")
			}
			r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
			toCombiner := r.newCombinerDist(before, 10*time.Second)
			if toCombiner == "" {
				t.Fatalf("the withdrawal of %s did not go to the agent's combiner\n%s", c.rrtype, r.log)
			}
			r.us.Bridge.ChunkHandler.OnConfirmationReceived(confirmIn(toCombiner, rigCombiner, transport.ConfirmSuccess, zone, nil, []string{rec}, nil, nil, false, ""))
			if a := r.answered(t, distID); a.Status != "SUCCESS" || !slices.Contains(a.RemovedRecords, rec) {
				t.Errorf("the leader's final confirmation: %+v, want a success that names %s as removed", *a, rec)
			}
		})
	}
}

// The agent passes the leader's withdrawal on to its combiner as an update
// in the withdrawn provider's name (deliverGenericMessage). At the
// combiner's boundary the update keeps the flag and its originator, and the
// combiner, whose own agent delivered it, removes the provider's records
// although the provider does not vote in the zone.
func TestTransportBoundary_TheCombinerTakesAWithdrawalFromItsOwnAgent(t *testing.T) {
	mpzd, hdb := withdrawnAtCombiner(t, "wire.combiner.withdraw.example.", "ns1")
	zone := mpzd.ZoneName
	distID := nextDistributionID()
	m, err := syncAppMessage(&PeerSyncRequest{SenderID: goneOrigin, Zone: zone, MessageType: "update", Timestamp: time.Now(),
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS"}}, DistributionID: distID,
		Withdraw: &Withdraw{Provider: goneOrigin, RRtype: "NS"}}, csyncCombinerID)
	if err != nil {
		t.Fatal(err)
	}
	msgQs := &MsgQs{Msg: make(chan *AgentMsgPostPlus, 1)}
	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()}, msgQs: msgQs}
	// the agent has an address: no discovery of it starts
	if err := tm.PeerRegistry.GetOrCreate(csyncOurAgent).SetDNSCarrierAddress(&transport.Address{Host: "127.0.0.1", Port: 53, Transport: "udp"}); err != nil {
		t.Fatal(err)
	}
	tm.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "update", DistributionID: distID, SenderID: goneOrigin, TransportSender: csyncOurAgent,
		Mechanism: transport.MechanismDNS, Zone: zone, Payload: m.Payload, ReceivedAt: time.Now(), SourceAddr: "127.0.0.1:0"})
	amp, ok := recvMsgWithin(t, msgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the update")
	}
	if amp.MessageType != core.AgentMsgUpdate || amp.OriginatorID != goneOrigin || amp.DeliveredBy != csyncOurAgent || amp.Withdraw == nil {
		t.Fatalf("the update as routed: type %s, originator %s, delivered by %s, withdraw %+v", amp.MessageType, amp.OriginatorID, amp.DeliveredBy, amp.Withdraw)
	}
	combinerHandles(t, mpzd, hdb, amp)
	if held := combinerHolds(mpzd, goneOrigin); len(held) != 0 {
		t.Errorf("the provider's NS at the combiner after the withdrawal: %v", held)
	}
}
