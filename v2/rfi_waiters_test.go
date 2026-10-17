/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Two zones ask the same peer for their SIG(0) key at the same time and the
// answers come back in the other order: each request gets its own zone's
// answer.
func TestRfiWaiters_ConcurrentZones(t *testing.T) {
	var w rfiWaiters[*ConfigResponseMsg]
	peer := "agent.p.example."
	ansA, cancelA := w.register(rfiWaitKey(peer, "a.example.", "sig0key", "na"))
	defer cancelA()
	ansB, cancelB := w.register(rfiWaitKey(peer, "b.example.", "sig0key", "nb"))
	defer cancelB()

	if !w.deliver(rfiWaitKey(peer, "b.example.", "sig0key", "nb"), &ConfigResponseMsg{Zone: "b.example."}) {
		t.Fatal("answer for b.example. found no waiter")
	}
	if !w.deliver(rfiWaitKey(peer, "a.example.", "sig0key", "na"), &ConfigResponseMsg{Zone: "a.example."}) {
		t.Fatal("answer for a.example. found no waiter")
	}

	if m, ok := recvWithin(ansA, time.Second); !ok || m.Zone != "a.example." {
		t.Errorf("request for a.example. got %+v (ok=%v)", m, ok)
	}
	if m, ok := recvWithin(ansB, time.Second); !ok || m.Zone != "b.example." {
		t.Errorf("request for b.example. got %+v (ok=%v)", m, ok)
	}
}

// An answer must match sender, zone, subtype and nonce; names compare as DNS
// names. A request that is done leaves nothing behind.
func TestRfiWaiters_Key(t *testing.T) {
	var w rfiWaiters[*ConfigResponseMsg]
	ans, cancel := w.register(rfiWaitKey("agent.p.example.", "a.example.", "sig0key", "n1"))

	for _, k := range []string{
		rfiWaitKey("agent.q.example.", "a.example.", "sig0key", "n1"),
		rfiWaitKey("agent.p.example.", "b.example.", "sig0key", "n1"),
		rfiWaitKey("agent.p.example.", "a.example.", "upstream", "n1"),
		rfiWaitKey("agent.p.example.", "a.example.", "sig0key", "n2"),
		rfiWaitKey("agent.p.example.", "a.example.", "sig0key", ""),
	} {
		if w.deliver(k, &ConfigResponseMsg{}) {
			t.Errorf("answer %q was taken by the request for agent.p.example. a.example. sig0key n1", k)
		}
	}
	if !w.deliver(rfiWaitKey("Agent.P.Example", "A.example", "sig0key", "n1"), &ConfigResponseMsg{}) {
		t.Fatal("answer differing only in case and trailing dot found no waiter")
	}
	if _, ok := recvWithin(ans, time.Second); !ok {
		t.Error("request got no answer")
	}
	cancel()
	if len(w.waiting) != 0 {
		t.Errorf("waiters left behind: %v", w.waiting)
	}
}

func configAnswer(t *testing.T, transportSender, named, zone, subtype, nonce string) *transport.IncomingMessage {
	t.Helper()
	payload, err := json.Marshal(&DnsConfigPayload{MessageType: "config", MyIdentity: named, Zone: zone,
		Subtype: subtype, ConfigData: map[string]string{"from": transportSender}, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	return &transport.IncomingMessage{TypeToken: "config", SenderID: named, TransportSender: transportSender, Zone: zone, Payload: payload}
}

func auditAnswer(t *testing.T, transportSender, named, zone, nonce string) *transport.IncomingMessage {
	t.Helper()
	payload, err := json.Marshal(&DnsAuditPayload{MessageType: "audit", MyIdentity: named, Zone: zone,
		AuditData: transportSender, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	return &transport.IncomingMessage{TypeToken: "audit", SenderID: named, TransportSender: transportSender, Zone: zone, Payload: payload}
}

// Only the agent that was asked can answer: the answer is matched on the
// sender the transport established, and one whose payload names another
// agent is dropped.
func TestRouteConfig_OnlyTheAskedAgentAnswers(t *testing.T) {
	const a, b, zone = "agent.a.example.", "agent.b.example.", "z.example."
	tm := &MPTransportBridge{msgQs: &MsgQs{}}
	ans, cancel := tm.msgQs.configWaiters.register(rfiWaitKey(a, zone, "sig0key", "n1"))
	defer cancel()

	tm.routeConfigMessage(configAnswer(t, b, a, zone, "sig0key", "n1"))  // b claims to be a
	tm.routeConfigMessage(configAnswer(t, "", a, zone, "sig0key", "n1")) // no transport sender
	tm.routeConfigMessage(configAnswer(t, b, b, zone, "sig0key", "n1"))  // b, honestly
	if m, ok := recvWithin(ans, 100*time.Millisecond); ok {
		t.Fatalf("request to %s took an answer from %s", a, m.ConfigData["from"])
	}

	tm.routeConfigMessage(configAnswer(t, a, a, zone, "sig0key", "n1"))
	if m, ok := recvWithin(ans, time.Second); !ok || m.SenderID != a || m.ConfigData["from"] != a {
		t.Fatalf("request to %s: got %+v (ok=%v), want %s's answer", a, m, ok, a)
	}
}

// A request that timed out is asked again; the first request's answer,
// arriving late, does not answer the second.
func TestRouteConfig_LateAnswerDoesNotAnswerTheRetry(t *testing.T) {
	const a, zone = "agent.a.example.", "z.example."
	tm := &MPTransportBridge{msgQs: &MsgQs{}}
	_, cancelFirst := tm.msgQs.configWaiters.register(rfiWaitKey(a, zone, "sig0key", "first"))
	cancelFirst() // timed out
	retry, cancelRetry := tm.msgQs.configWaiters.register(rfiWaitKey(a, zone, "sig0key", "retry"))
	defer cancelRetry()

	tm.routeConfigMessage(configAnswer(t, a, a, zone, "sig0key", "first"))
	if _, ok := recvWithin(retry, 100*time.Millisecond); ok {
		t.Fatal("the retry took the answer to the request that timed out")
	}
	tm.routeConfigMessage(configAnswer(t, a, a, zone, "sig0key", "retry"))
	if _, ok := recvWithin(retry, time.Second); !ok {
		t.Fatal("the retry got no answer")
	}
}

// The same two rules for AUDIT.
func TestRouteAudit_SenderAndNonce(t *testing.T) {
	const a, b, zone = "agent.a.example.", "agent.b.example.", "z.example."
	tm := &MPTransportBridge{msgQs: &MsgQs{}}
	ans, cancel := tm.msgQs.auditWaiters.register(rfiWaitKey(a, zone, "", "n1"))
	defer cancel()

	tm.routeAuditMessage(auditAnswer(t, b, a, zone, "n1"))
	tm.routeAuditMessage(auditAnswer(t, a, a, zone, "n0"))
	if m, ok := recvWithin(ans, 100*time.Millisecond); ok {
		t.Fatalf("request took a wrong answer: %+v", m)
	}
	tm.routeAuditMessage(auditAnswer(t, a, a, zone, "n1"))
	if m, ok := recvWithin(ans, time.Second); !ok || m.AuditData != a {
		t.Fatalf("got %+v (ok=%v), want %s's answer", m, ok, a)
	}
}

// routeVia hands a wire payload from sender to receiver through the
// receiver's production router, as the transport would.
func routeVia(t *testing.T, receiver *peerEnv, senderPeer *transport.Peer, sender string, body []byte) {
	t.Helper()
	ctx, msgType := buildDispatchContext(t, receiver.Bridge, sender, nextDistributionID(), body)
	ctx.Peer = senderPeer
	if err := receiver.Bridge.Router.Route(ctx, msgType); err != nil {
		t.Fatalf("Router.Route(%s) at %s: %v", msgType, receiver.Identity, err)
	}
}

// The nonce makes the round trip: Alice's RFI carries it to Bob, Bob's
// CONFIG answer carries it back, and Alice's request is answered. This runs
// the production builders and handlers on both sides.
func TestRfiConfig_NonceRoundTrip(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Alice.Registry.S.Set(AgentId(bob), NewAgent(AgentId(bob)))
	alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	bobPeer := env.Alice.Bridge.PeerRegistry.GetOrCreate(bob)
	seedZoneWithHSYNC3(t, dispatchZone, alice, bob)
	env.Alice.Bridge.StartIncomingMessageRouter(env.ctx)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)

	// Alice asks, as RequestAndWaitForConfig does.
	nonce := newRfiNonce()
	answer, cancel := env.Alice.MsgQs.configWaiters.register(rfiWaitKey(bob, dispatchZone, "sig0key", nonce))
	defer cancel()
	rfi, err := syncAppMessage(rfiSyncRequest(alice, &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: AgentId(alice),
		YourIdentity: AgentId(bob), Zone: dispatchZone, RfiType: "CONFIG", RfiSubtype: "sig0key", Nonce: nonce}), bob)
	if err != nil {
		t.Fatal(err)
	}
	routeVia(t, env.Bob, alicePeer, alice, rfi.Payload)

	got, ok := recvWithin(env.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("RFI did not reach Bob's MsgQs.Msg")
	}
	if got.Nonce != nonce {
		t.Fatalf("Bob sees RFI nonce %q, want %q", got.Nonce, nonce)
	}

	// Bob answers with the nonce he was given, as sendConfigToAgent does.
	reply, err := configAppMessage(&PeerConfigRequest{SenderID: bob, Zone: string(got.Zone), Subtype: got.RfiSubtype,
		ConfigData: map[string]string{"k": "v"}, Nonce: got.Nonce, Timestamp: time.Now()}, alice)
	if err != nil {
		t.Fatal(err)
	}
	routeVia(t, env.Alice, bobPeer, bob, reply.Payload)

	m, ok := recvWithin(answer, integTestTimeout)
	if !ok {
		t.Fatal("Alice's request got no answer")
	}
	if m.SenderID != bob || m.Zone != dispatchZone || m.Subtype != "sig0key" || m.ConfigData["k"] != "v" {
		t.Errorf("answer: %+v", *m)
	}
}

// The combiner's EDITS answer for a zone arrives after that zone's request
// timed out, before or while the next zone's request waits. The late answer
// is dropped, and the next zone's request gets its own zone's answer.
func TestRouteEdits_LateAnswerThenNextZone(t *testing.T) {
	const combiner = "combiner.p.example."
	edits := func(t *testing.T, zone string) *transport.IncomingMessage {
		t.Helper()
		payload, err := json.Marshal(&DnsEditsPayload{MessageType: "edits", MyIdentity: combiner,
			YourIdentity: "agent.p.example.", Zone: zone, Timestamp: time.Now().Unix(),
			AgentRecords: map[string]map[string][]string{"agent.p.example.": {zone: {zone + " 3600 IN TXT \"edits\""}}}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return &transport.IncomingMessage{TypeToken: "edits", Payload: payload}
	}

	for _, lateWhileWaiting := range []bool{false, true} {
		name := "before the next request"
		if lateWhileWaiting {
			name = "while the next request waits"
		}
		t.Run(name, func(t *testing.T) {
			tm := &MPTransportBridge{msgQs: NewMsgQs()}
			waiters := &tm.msgQs.editsWaiters

			// The request for a.example. times out unanswered.
			_, cancelA := waiters.register(rfiWaitKey(combiner, "a.example.", "", ""))
			cancelA()

			if !lateWhileWaiting {
				tm.routeEditsMessage(edits(t, "a.example."))
			}
			ansB, cancelB := waiters.register(rfiWaitKey(combiner, "b.example.", "", ""))
			if lateWhileWaiting {
				tm.routeEditsMessage(edits(t, "a.example."))
			}
			if m, ok := recvWithin(ansB, 100*time.Millisecond); ok {
				t.Fatalf("request for b.example. took the late answer for %s", m.Zone)
			}

			tm.routeEditsMessage(edits(t, "b.example."))
			m, ok := recvWithin(ansB, time.Second)
			if !ok || m.Zone != "b.example." || m.SenderID != combiner || len(m.AgentRecords["agent.p.example."]["b.example."]) != 1 {
				t.Fatalf("request for b.example. got %+v (ok=%v)", m, ok)
			}
			cancelB()
			if len(waiters.waiting) != 0 {
				t.Errorf("waiters left behind: %v", waiters.waiting)
			}
		})
	}
}

// A peer's key whose KEY RR belongs to another name is refused before it
// reaches the keystore.
func TestImportSig0KeyFromPeer_WrongOwner(t *testing.T) {
	key := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "b.example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pem, err := tdns.PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM: %v", err)
	}
	configData := map[string]string{"algorithm": "ED25519", "privatekey": pem, "keyrr": key.String()}

	// hdb is nil: the check must refuse before the keystore is touched.
	err = importSig0KeyFromPeer(nil, "a.example.", configData)
	if err == nil || !strings.Contains(err.Error(), "not a KEY for") {
		t.Fatalf("import of b.example.'s key as a.example.: err = %v, want a refusal", err)
	}
}
