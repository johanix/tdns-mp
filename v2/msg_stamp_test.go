/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Stamps on messages and confirmations (plan S5b).
 */
package tdnsmp

import (
	"encoding/json"
	"net"
	"slices"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// Every sync-family message carries the stamp its send gave it: sync,
// update and rfi.
func TestEverySyncFamilyMessageCarriesTheSendersStamp(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	for _, verb := range []string{"sync", "update", "rfi"} {
		ms := st.messageStamp(stampZone)
		msg, err := syncAppMessage(&PeerSyncRequest{SenderID: stampAlpha, Zone: stampZone, MessageType: verb, Instr: ms}, stampBeta)
		if err != nil {
			t.Fatal(err)
		}
		var p DnsSyncPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.Instr == nil || *p.Instr != *ms || p.Instr.Active != 7 {
			t.Errorf("%s: the stamp on the wire: %+v, want %+v", verb, p.Instr, ms)
		}
	}
}

// EDITS, CONFIG and AUDIT carry the stamp too.
func TestConfigEditsAndAuditCarryTheStamp(t *testing.T) {
	ms := stampTableAt(t, stampAlpha, stampAt(t, 7, "a")).messageStamp(stampZone)
	edits, err := editsAppMessage(&PeerEditsRequest{SenderID: stampAlpha, Zone: stampZone, Instr: ms}, stampBeta)
	if err != nil {
		t.Fatal(err)
	}
	config, err := configAppMessage(&PeerConfigRequest{SenderID: stampAlpha, Zone: stampZone, Instr: ms}, stampBeta)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := auditAppMessage(&PeerAuditRequest{SenderID: stampAlpha, Zone: stampZone, Instr: ms}, stampBeta)
	if err != nil {
		t.Fatal(err)
	}
	var e DnsEditsPayload
	var c DnsConfigPayload
	var a DnsAuditPayload
	for _, d := range []struct {
		raw []byte
		v   any
		got func() *MsgStamp
	}{{edits.Payload, &e, func() *MsgStamp { return e.Instr }}, {config.Payload, &c, func() *MsgStamp { return c.Instr }},
		{audit.Payload, &a, func() *MsgStamp { return a.Instr }}} {
		if err := json.Unmarshal(d.raw, d.v); err != nil {
			t.Fatal(err)
		}
		if got := d.got(); got == nil || *got != *ms {
			t.Errorf("%T: the stamp on the wire: %+v", d.v, got)
		}
	}
}

// A message stamp is this agent's at the moment of the send: a resend
// after the active serial moved carries the newer serial and a higher
// sequence, and the distribution records the stamp of the latest send.
func TestAResendCarriesTheStampOfItsSend(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	first := st.messageStamp(stampZone)
	st.sent("d1", stampBeta, stampZone, first)
	st.store.Note(stampZone, stampAt(t, 8, "a"), nil)
	resend := st.messageStamp(stampZone)
	st.sent("d1", stampBeta, stampZone, resend)
	if resend.Active != 8 || resend.Seq <= first.Seq || resend.Epoch != first.Epoch {
		t.Errorf("the resend's stamp: %+v after %+v", resend, first)
	}
	rows := st.distributionStamps(stampZone)
	if len(rows) != 1 || rows[0].Sent == nil || rows[0].Sent.Serial != 8 {
		t.Errorf("the distribution's rows: %+v", rows)
	}
}

// Each distribution keeps, per recipient, its latest send's stamp and the
// recipient's latest confirmation's.
func TestADistributionRecordsTheStampOfEachSend(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	st.sent("d1", stampBeta, stampZone, st.messageStamp(stampZone))
	st.sent("d1", stampDelta, stampZone, st.messageStamp(stampZone))
	st.confirmed("d1", stampBeta, stampZone, &MsgStamp{Epoch: 3, Seq: 9, InstrStamp: tells(seven, seven)}, "PENDING")
	rows := st.distributionStamps("")
	if len(rows) != 2 {
		t.Fatalf("rows: %+v", rows)
	}
	beta := rows[slices.IndexFunc(rows, func(r DistributionStamps) bool { return r.Recipient == stampBeta })]
	if beta.Confirmed == nil || beta.Confirmed.Serial != 7 || beta.Status != "PENDING" || beta.Sent == nil {
		t.Errorf("beta's row: %+v", beta)
	}
	delta := rows[slices.IndexFunc(rows, func(r DistributionStamps) bool { return r.Recipient == stampDelta })]
	if delta.Confirmed != nil || delta.Status != "" {
		t.Errorf("delta's row, not confirmed: %+v", delta)
	}
	if got := st.distributionStamps("other.example."); len(got) != 0 {
		t.Errorf("another zone's rows: %+v", got)
	}
}

// A message's stamp and a beat's are ordered by one sequence: a beat older
// than a message keeps the message's stamp of its zone and takes the
// others; a newer beat that no longer tells a zone drops it.
func TestAStampFromAMessageIsOrderedWithTheBeats(t *testing.T) {
	seven, eight, nine := stampAt(t, 7, "a"), stampAt(t, 8, "a"), stampAt(t, 9, "a")
	bob := stampTableAt(t, stampBeta, seven)
	beat := func(seq uint64, zones map[string]InstrStamp) {
		bob.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
			stampAlpha: {Identity: stampAlpha, Epoch: 1, Seq: seq, Instr: zones}}}, stampAlpha, "DNS")
	}
	beat(10, map[string]InstrStamp{stampZone: tells(seven, seven), "other.example.": tells(seven, seven)})
	bob.noteMessage(stampAlpha, stampZone, &MsgStamp{Epoch: 1, Seq: 12, InstrStamp: tells(eight, eight)})
	beat(11, map[string]InstrStamp{stampZone: tells(seven, seven), "other.example.": tells(eight, eight)})
	m := bob.heard(stampAlpha)
	if m.Instr[stampZone].Active != 8 || m.Instr["other.example."].Active != 8 {
		t.Fatalf("after the message and an older beat: %+v", m.Instr)
	}
	bob.noteMessage(stampAlpha, stampZone, &MsgStamp{Epoch: 1, Seq: 11, InstrStamp: tells(seven, seven)})
	if got := bob.heard(stampAlpha).Instr[stampZone].Active; got != 8 {
		t.Errorf("an older message replaced a newer stamp: active %d", got)
	}
	beat(13, map[string]InstrStamp{stampZone: tells(nine, nine)})
	m = bob.heard(stampAlpha)
	if m.Instr[stampZone].Active != 9 || len(m.Instr) != 1 {
		t.Errorf("after a newer beat with one zone: %+v", m.Instr)
	}
	// a later start's first message replaces everything kept
	bob.noteMessage(stampAlpha, stampZone, &MsgStamp{Epoch: 2, Seq: 1, InstrStamp: tells(seven, seven)})
	if m := bob.heard(stampAlpha); m.Epoch != 2 || m.Instr[stampZone].Active != 7 {
		t.Errorf("a new epoch's message: %+v", m)
	}
}

// A confirmation's application field carries the confirmer's stamp, and
// reads back; a confirmer with nothing to tell sends none.
func TestEveryConfirmationCarriesTheConfirmersStamp(t *testing.T) {
	st := stampTableAt(t, stampBeta, stampAt(t, 7, "a"))
	app := st.confirmAppFor(stampZone)
	ms := confirmStamp(app)
	if ms == nil || ms.Active != 7 || ms.Epoch != 1 {
		t.Fatalf("the stamp in %s: %+v", app, ms)
	}
	if got := st.confirmAppFor("other.example."); got != nil {
		t.Errorf("a zone with no serials kept: %s", got)
	}
	var none *stampTable
	if got := none.confirmAppFor(stampZone); got != nil {
		t.Errorf("a role that tells nothing: %s", got)
	}
	if confirmStamp(json.RawMessage(`{"instr":`)) != nil || confirmStamp(nil) != nil {
		t.Error("a field that does not parse, or none, gave a stamp")
	}
}

// Over DNS: alice's SYNC to bob carries her stamp, which bob notes first
// hand; bob's PENDING carries his, which reaches alice's trackers (the
// confirmation detail, the distribution's row) and is noted as his. Before
// alice listens, the transport's inline acknowledgement is all she gets,
// and it tells her nothing of bob.
func TestTransportBoundary_ConfirmationCarriesTheReceiversStamp(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
	zone := "msg.stamps.example."
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	apex, err := zd.GetOwner(zone)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInstructions(apex)
	if err != nil || in == nil {
		t.Fatalf("the zone's reading: %v %v", in, err)
	}
	for _, p := range []*peerEnv{env.Alice, env.Bob} {
		s := newStore(t)
		s.Note(zone, in, nil)
		p.Bridge.stamps = newStampTable(p.Identity, s, 1, false, nil)
	}
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	bobLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDNS(t, env.ctx, bobLn, env.Bob)
	toBob := peerFromAddress(bob, bobLn.Addr().String())
	toBob.SetMechanismState("DNS", transport.PeerStateOperational, "test")
	if err := env.Alice.Bridge.PeerRegistry.Add(toBob); err != nil {
		t.Fatal(err)
	}
	send := func(distID string) {
		t.Helper()
		req := &PeerSyncRequest{SenderID: alice, Zone: zone, MessageType: "sync", DistributionID: distID,
			Records: map[string][]string{zone: {zone + " 3600 IN TXT \"s5b\""}}}
		if _, err := env.Alice.Bridge.SendSyncWithFallback(env.ctx, toBob, req); err != nil {
			t.Fatalf("the sync: %v", err)
		}
		if req.Instr == nil {
			t.Fatal("the send set no stamp")
		}
		waitUntil(t, "bob did not note alice's stamp from her sync", func() bool {
			m := env.Bob.Bridge.stamps.heard(alice)
			return m != nil && m.ZoneSeq[canonicalName(zone)] == req.Instr.Seq
		})
	}

	// alice does not listen yet: bob's PENDING cannot reach her
	send(nextDistributionID())
	if m := env.Alice.Bridge.stamps.heard(bob); m != nil {
		t.Fatalf("alice noted bob from the inline acknowledgement: %+v", m)
	}

	aliceLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.Alice.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, aliceLn, env.Alice)
	env.Alice.Registry.S.Set(AgentId(bob), NewAgent(AgentId(bob)))
	// bob made alice a peer at her first sync; now he has her address
	toAlice := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	if err := toAlice.SetDNSCarrierAddress(peerFromAddress(alice, aliceLn.Addr().String()).DNSCarrierAddress()); err != nil {
		t.Fatal(err)
	}
	distID := nextDistributionID()
	send(distID)
	c, ok := recvWithin(env.Alice.MsgQs.Confirmation, integTestTimeout)
	for ok && c.DistributionID != distID {
		c, ok = recvWithin(env.Alice.MsgQs.Confirmation, integTestTimeout)
	}
	if !ok || c.Status != "PENDING" || c.Instr == nil || c.Instr.Active != in.Serial || c.Instr.ActiveDigest != in.Digest() {
		t.Fatalf("bob's PENDING at alice: %+v", c)
	}
	if m := env.Alice.Bridge.stamps.heard(bob); m == nil || m.ZoneSeq[canonicalName(zone)] != c.Instr.Seq {
		t.Errorf("alice did not note bob's stamp from his confirmation: %+v", m)
	}
	rows := env.Alice.Bridge.stamps.distributionStamps(zone)
	i := slices.IndexFunc(rows, func(r DistributionStamps) bool { return r.DistributionID == distID })
	if i < 0 || rows[i].Sent == nil || rows[i].Confirmed == nil || rows[i].Status != "PENDING" {
		t.Errorf("the distribution's row: %+v", rows)
	}
}
