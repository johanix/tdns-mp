/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// #254: a KEYSTATE is taken by an agent only from its own signer, and by a
// signer only from its own agents. Admission lets in every member of a zone,
// and a held peer; a KEYSTATE moves the agent's key inventory, its own read
// and its DS intent, and the signer's key lifecycle.

func keystateInventoryFrom(t *testing.T, sender, to string) []byte {
	t.Helper()
	body, err := json.Marshal(&DnsKeystatePayload{MessageType: "keystate", MyIdentity: sender, YourIdentity: to, Zone: dispatchZone,
		Signal: "inventory", Timestamp: time.Now().Unix(),
		KeyInventory: []KeyInventoryEntry{{KeyTag: 12345, Algorithm: 15, Flags: 257, State: "active",
			KeyRR: dispatchZone + " 3600 IN DNSKEY 257 3 15 dGVzdA=="}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Another agent's inventory, admitted as a member of the zone, is refused
// before the handler: nothing reaches the agent's inventory queue, from
// which alone the inventory, the own read and the DS intent are set
// (noteKeyInventory). The same inventory from the agent's own signer is
// taken.
func TestAKeystateFromAPeerAgentIsRefused(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	seedZoneWithHSYNC3(t, dispatchZone, alice, bob)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	env.Bob.Bridge.signerID = "signer.bob.example."

	distID := nextDistributionID()
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, alice, distID, keystateInventoryFrom(t, alice, bob))
	ctx.Peer = alicePeer
	if err := env.Bob.Bridge.Router.Route(ctx, msgType); err != nil {
		t.Fatalf("a refusal is no handler error: %v", err)
	}
	if rc, _ := ctx.Data["response_rcode"].(int); rc != dns.RcodeRefused {
		t.Errorf("a peer agent's KEYSTATE: response_rcode = %v, want REFUSED", ctx.Data["response_rcode"])
	}
	if mt, _ := ctx.Data["message_type"].(string); mt == "keystate" {
		t.Error("the KEYSTATE handler ran for a peer agent's message")
	}
	if m, ok := recvWithin(env.Bob.MsgQs.KeystateInventory, 300*time.Millisecond); ok {
		t.Fatalf("a peer agent's inventory reached the agent: %+v", *m)
	}

	// from the agent's own signer it is taken
	env.Bob.Bridge.signerID = alice
	ctx, msgType = buildDispatchContext(t, env.Bob.Bridge, alice, nextDistributionID(), keystateInventoryFrom(t, alice, bob))
	ctx.Peer = alicePeer
	if err := env.Bob.Bridge.Router.Route(ctx, msgType); err != nil {
		t.Fatal(err)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.KeystateInventory, integTestTimeout); !ok {
		t.Error("the agent's own signer's inventory did not reach the agent")
	}
}

// The rule, for each role: an agent's own signer and a signer's own agents
// pass, compared as canonical names; anyone else, and no sender, is refused
// with REFUSED and nothing after it run. An auditor keeps what admission lets
// in, and other verbs pass.
func TestTheKeystateSenderRuleForEachRole(t *testing.T) {
	tm := &MPTransportBridge{signerID: "Signer.Example", authorizedPeers: func() []string { return []string{"agent.own.example."} }}
	for _, c := range []struct {
		role, sender string
		taken        bool
	}{
		{roleAgent, "signer.example.", true},
		{roleAgent, "agent.peer.example.", false},
		{roleAgent, "", false},
		{roleSigner, "AGENT.own.example", true},
		{roleSigner, "agent.peer.example.", false},
		{roleSigner, "", false},
		{roleAuditor, "agent.peer.example.", true},
	} {
		ran := false
		next := func(*transport.MessageContext) error { ran = true; return nil }
		ctx := transport.NewMessageContext(new(dns.Msg), "127.0.0.1:0")
		ctx.PeerID = c.sender
		ctx.SetIncoming(&transport.IncomingMessage{TypeToken: "keystate", Zone: dispatchZone})
		tm.role = c.role
		if err := tm.refuseForeignKeystate(ctx, next); err != nil {
			t.Fatalf("%s from %q: a refusal is no handler error: %v", c.role, c.sender, err)
		}
		rc, _ := ctx.Data["response_rcode"].(int)
		if ran != c.taken || (!c.taken && rc != dns.RcodeRefused) {
			t.Errorf("%s from %q: handler ran %v, rcode %v; want taken %v", c.role, c.sender, ran, ctx.Data["response_rcode"], c.taken)
		}
	}
	// another verb passes, whoever sends it
	tm.role = roleAgent
	ran := false
	ctx := transport.NewMessageContext(new(dns.Msg), "127.0.0.1:0")
	ctx.PeerID = "agent.peer.example."
	ctx.SetIncoming(&transport.IncomingMessage{TypeToken: "sync", Zone: dispatchZone})
	if err := tm.refuseForeignKeystate(ctx, func(*transport.MessageContext) error { ran = true; return nil }); err != nil || !ran {
		t.Errorf("a SYNC was stopped by the KEYSTATE rule (ran %v, %v)", ran, err)
	}
	// a role whose agent has no signer configured takes none
	if why := (&MPTransportBridge{}).keystateSenderRefusal(roleAgent, "signer.example."); why == "" {
		t.Error("an agent with no signer took a KEYSTATE")
	}
}
