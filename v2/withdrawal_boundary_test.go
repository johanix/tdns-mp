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
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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
