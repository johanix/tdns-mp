/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Messages between serials at the transport boundary (plan S8), on the
 * receiving rig: the peer sends a SYNC over the wire to the agent under
 * test, which keeps or refuses it by the stamp, and answers over the wire.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// serialsRig is the receiving rig whose agent keeps the zone's serials:
// active at 41, or at 42 when ahead; 42 held. It stamps its confirmations,
// keeps what rule 6 keeps, and hands its activation to its data engine.
func serialsRig(t *testing.T, zone string, ahead bool) (*notifyRig, map[uint32]*Instructions) {
	t.Helper()
	in := map[uint32]*Instructions{}
	var store *InstructionStore
	r := newNotifyRigWith(t, zone, "NOTIFY", true, func(r *notifyRig) {
		apex, err := r.mpzd.OwnerForAnalysis(zone)
		if err != nil || apex == nil {
			t.Fatalf("apex: %v", err)
		}
		base, err := ReadInstructions(apex)
		if err != nil || base == nil {
			t.Fatalf("the zone's reading: %v %v", base, err)
		}
		for _, s := range []uint32{41, 42} {
			c := *base
			c.Serial, c.Suffix = s, fmt.Sprintf("s%d", s)
			in[s] = &c
		}
		store = newStore(t)
		store.Note(zone, in[41], nil)
		enforced(t, store, zone)
		store.Note(zone, in[42], nil)
		if ahead {
			if err := store.Activate(zone, Thaw{From: sd(in[41]), To: sd(in[42])}); err != nil {
				t.Fatal(err)
			}
		}
		kept, err := loadKeptLists(nil)
		if err != nil {
			t.Fatal(err)
		}
		r.conf.InternalMp.Instructions, r.conf.InternalMp.Kept = store, kept
		r.us.Bridge.stamps = newStampTable(r.us.Identity, store, 1, false, nil)
		store.onActive = func(z string) { r.conf.askActivated(ZoneName(z)) }
	}, repeat(time.Minute, 4)...)
	r.us.Registry.S.Set(AgentId(r.peer.Identity), NewAgent(AgentId(r.peer.Identity)))
	return r, in
}

// receivesUnder is the peer's SYNC of ops, stamped as made under in, as it
// reaches the agent over the wire; it returns its distribution ID.
func (r *notifyRig) receivesUnder(t *testing.T, in *Instructions, ops ...core.RROperation) string {
	t.Helper()
	distID := nextDistributionID()
	peer := r.peer.Identity
	body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: peer, YourIdentity: r.us.Identity, Zone: r.mpzd.ZoneName,
		Operations: ops, Time: time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(), DistributionID: distID,
		Instr: msgStampAt(in)})
	if err != nil {
		t.Fatalf("the SYNC: %v", err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{TypeToken: "sync", DistributionID: distID, SenderID: peer,
		TransportSender: peer, Mechanism: transport.MechanismDNS, Zone: r.mpzd.ZoneName, Payload: body, ReceivedAt: time.Now(),
		SourceAddr: "127.0.0.1:0"})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the SYNC")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
	return distID
}

// pendingSays waits for the agent's PENDING of the distribution that says
// text, at the sender, over the wire.
func (r *notifyRig) pendingSays(t *testing.T, distID, text string) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
		c, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
		if !ok {
			break
		}
		if c.DistributionID == distID && c.Status == "PENDING" && c.Message == text {
			return
		}
	}
	t.Fatalf("the sender got no PENDING of %s that says %q\n%s", distID, text, r.log)
}

// The peer's SYNC made under 42 reaches the agent at 41: kept, and the peer
// told why in a PENDING. When the agent makes 42 active it takes it, hands
// it to its combiner, and the peer's final confirmation carries the agent's
// stamp at 42.
func TestTransportBoundary_AMessageAcrossTheThawIsKeptThenTaken(t *testing.T) {
	zone := "kept.boundary.example."
	r, in := serialsRig(t, zone, false)
	peer := AgentId(r.peer.Identity)
	rec := zone + " 3600 IN NS ns1.peer.boundary.example."
	distID := r.receivesUnder(t, in[42], core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{rec}})
	r.pendingSays(t, distID, "kept: this agent acts by serial 41, the message was made under 42")
	if got := r.repo(t)[peer][dns.TypeNS]; len(got) != 0 {
		t.Fatalf("a kept SYNC reached the repo: %+v", got)
	}

	if err := r.conf.InternalMp.Instructions.Activate(zone, Thaw{From: sd(in[41]), To: sd(in[42])}); err != nil {
		t.Fatal(err)
	}
	var held TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && held.RR == ""; time.Sleep(10 * time.Millisecond) {
		if got := r.repo(t)[peer][dns.TypeNS]; len(got) == 1 {
			held = got[0]
		}
	}
	if held.RR == "" {
		t.Fatalf("the kept SYNC was not taken at the activation\n%s", r.log)
	}
	r.confirms(rigCombiner, held.DistributionID, held.RR)
	c := r.answered(t, distID)
	if c.Status != "SUCCESS" || c.Instr == nil || c.Instr.Active != 42 || !c.Instr.Known {
		t.Errorf("the peer's final confirmation: %+v (stamp %+v), want a success at 42", *c, c.Instr)
	}
}

// The peer's SYNC made under 41 reaches the agent at 42: refused, with a
// final REJECTED that names stale-instructions and carries the agent's
// stamp at 42, so the sender reads it as "not yet" (decision 31). Nothing
// reaches the repo. (What the sender sends again is the unit tests'.)
func TestTransportBoundary_AStaleMessageIsRefusedOverTheWire(t *testing.T) {
	zone := "stale.boundary.example."
	r, in := serialsRig(t, zone, true)
	peer := AgentId(r.peer.Identity)
	rec := zone + " 3600 IN NS ns1.peer.boundary.example."
	distID := r.receivesUnder(t, in[41], core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{rec}})
	c := r.answered(t, distID)
	if c.Status != "REJECTED" || !strings.HasPrefix(c.Message, staleInstructions+":") {
		t.Errorf("the peer's final confirmation: %+v, want a stale refusal", *c)
	}
	if c.Instr == nil || c.Instr.Active != 42 {
		t.Errorf("the refusal's stamp: %+v, want the agent's at 42", c.Instr)
	}
	if !(&MPTransportBridge{stamps: stampsSentAt(r.peer.Identity, zone, distID, string(r.us.Identity), in[41])}).
		notYetFrom(distID, r.us.Identity, transport.ConfirmRejected, c.Instr) {
		t.Error("the sender would take the refusal as final")
	}
	if got := r.repo(t)[peer][dns.TypeNS]; len(got) != 0 {
		t.Errorf("a stale SYNC reached the repo: %+v", got)
	}
}

// stampsSentAt is a sender's stamp table that recorded a send of distID to
// recipient under in.
func stampsSentAt(self, zone, distID, recipient string, in *Instructions) *stampTable {
	t := newStampTable(self, nil, 1, false, nil)
	t.sent(distID, recipient, zone, msgStampAt(in))
	return t
}
