/*
 * Transport-dispatch gate (C0.5; 2026-09-09 amendment §E to the v4 plan).
 *
 * The C0 goldens lock BYTES. This file locks DISPATCH: for every wire verb
 * the agent router accepts, a payload built with today's structs
 *
 *   (a) resolves to that verb in the production parser (parseAppPayload),
 *   (b) is accepted by the registered handler through the real middleware
 *       chain (Router.Route, not the handler function directly), and
 *   (c) is delivered by the RouteToCallback -> routeIncomingMessage seam to
 *       the MP queue the role message handlers read.
 *
 * A relocated handler (C3), a split chunk path (C5) or a collapsed verb
 * table (C6) that still compiles but no longer dispatches fails here, not on
 * the fleet. Contexts are built the way ChunkNotifyHandler.RouteViaRouter
 * builds them after decryption (buildDispatchContext), so handlers see the
 * Data keys production gives them.
 */

package tdnsmp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

const dispatchZone = "dispatch.example."

// buildDispatchContext mirrors RouteViaRouter's post-decryption context.
func buildDispatchContext(t *testing.T, tm *MPTransportBridge, senderHint, distID string, payload []byte) (*transport.MessageContext, transport.MessageType) {
	t.Helper()
	im, err := parseAppPayload(distID, payload, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("parseAppPayload: %v", err)
	}
	im.TransportSender = senderHint
	msgType := transport.MessageType(im.Type)

	ctx := transport.NewMessageContext(new(dns.Msg), "127.0.0.1:0")
	ctx.DistributionID = distID
	ctx.PeerID = senderHint
	ctx.ChunkPayload = payload
	ctx.RemoteAddr = "127.0.0.1:0"
	ctx.ChunkCrypted = false
	ctx.SignatureValid = true
	ctx.SignatureReason = "decrypted_by_router"
	ctx.Data["local_id"] = tm.LocalID
	if tm.DNSTransport != nil {
		ctx.Data["transport"] = tm.DNSTransport
	}
	ctx.Data["response_peer_id"] = senderHint
	if tm.ChunkHandler != nil {
		if cb := tm.ChunkHandler.OnConfirmationReceived; cb != nil {
			// Same repackaging as buildConfirmMessageContext: HandleConfirmation
			// type-asserts the unnamed func type.
			ctx.Data["on_confirmation_received"] = func(distributionID string, senderID string, status transport.ConfirmStatus,
				zone string, applied []string, removed []string, rejected []transport.RejectedItemDTO, ignored []string, truncated bool, nonce string) {
				cb(distributionID, senderID, status, zone, applied, removed, rejected, ignored, truncated, nonce)
			}
		}
		if tm.ChunkHandler.GossipForPeer != nil {
			ctx.Data["gossip_for_peer"] = tm.ChunkHandler.GossipForPeer
		}
	}
	ctx.Data["incoming_message"] = im
	if im.Zone != "" {
		ctx.Data["zone"] = im.Zone
	}
	return ctx, msgType
}

func recvWithin[T any](ch <-chan T, d time.Duration) (T, bool) {
	var zero T
	select {
	case v := <-ch:
		return v, true
	case <-time.After(d):
		return zero, false
	}
}

func dispatchResponse(t *testing.T, ctx *transport.MessageContext) string {
	t.Helper()
	resp, ok := ctx.Data["response"].([]byte)
	if !ok {
		return ""
	}
	return string(resp)
}

type dispatchCase struct {
	name string
	verb string
	// build returns the payload struct marshalled onto the wire.
	build func(alice, bob, distID string) interface{}
	// wantAck is a substring the handler must put in ctx.Data["response"]
	// ("" = the handler prepares no response).
	wantAck string
	// unhandled marks a verb the agent router has no handler for: it must be
	// REFUSED on the wire and must NOT reach any MP queue.
	unhandled bool
	// observe asserts the MP-side delivery.
	observe func(t *testing.T, env *integEnv, alice, distID string)
}

func dispatchCases() []dispatchCase {
	rr := dispatchZone + " 3600 IN TXT \"dispatch\""
	return []dispatchCase{
		{name: "hello", verb: "hello",
			build: func(a, b, d string) interface{} {
				return &transport.DnsHelloPayload{MessageType: "hello", MyIdentity: a, YourIdentity: b,
					Zone: dispatchZone, SharedZones: []string{dispatchZone}, Timestamp: time.Now().Unix(), Nonce: "hello-" + d}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				r, ok := recvWithin(env.Bob.MsgQs.Hello, integTestTimeout)
				if !ok {
					t.Fatal("hello did not reach MsgQs.Hello")
				}
				if r.MessageType != AgentMsgHello || string(r.Identity) != alice || string(r.Zone) != dispatchZone || r.DistributionID != distID {
					t.Errorf("hello report: %+v", *r)
				}
			}},
		{name: "beat", verb: "beat", wantAck: "beat acknowledged",
			build: func(a, b, d string) interface{} {
				return &transport.DnsBeatPayload{MessageType: "beat", MyIdentity: a, YourIdentity: b,
					Zones: []string{dispatchZone}, MyBeatInterval: 45, Sequence: 7, State: "OPERATIONAL", Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				r, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout)
				if !ok {
					t.Fatal("beat did not reach MsgQs.Beat")
				}
				if r.MessageType != AgentMsgBeat || string(r.Identity) != alice || string(r.Zone) != dispatchZone ||
					r.BeatInterval != 45 || r.Transport != "DNS" || r.DistributionID != distID {
					t.Errorf("beat report: %+v", *r)
				}
			}},
		{name: "ping", verb: "ping", wantAck: "ping_confirm",
			build: func(a, b, d string) interface{} {
				return &transport.DnsPingPayload{MessageType: "ping", MyIdentity: a, YourIdentity: b,
					Nonce: "ping-" + d, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				r, ok := recvWithin(env.Bob.MsgQs.Ping, integTestTimeout)
				if !ok {
					t.Fatal("ping did not reach MsgQs.Ping")
				}
				if r.MessageType != AgentMsgPing || string(r.Identity) != alice || r.DistributionID != distID {
					t.Errorf("ping report: %+v", *r)
				}
			}},
		{name: "sync", verb: "sync", wantAck: `"type":"confirm"`,
			build: func(a, b, d string) interface{} {
				return &DnsSyncPayload{MessageType: "sync", OriginatorID: a, YourIdentity: b, Zone: dispatchZone,
					Records: map[string][]string{dispatchZone: {rr}}, Timestamp: time.Now().Unix(), DistributionID: d, Nonce: "sync-" + d}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.Msg, integTestTimeout)
				if !ok {
					t.Fatal("sync did not reach MsgQs.Msg")
				}
				if m.MessageType != AgentMsgNotify || string(m.OriginatorID) != alice || string(m.DeliveredBy) != alice ||
					string(m.Zone) != dispatchZone || m.DistributionID != distID || len(m.Records[dispatchZone]) != 1 {
					t.Errorf("sync msg: %+v", m.AgentMsgPost)
				}
			}},
		{name: "rfi", verb: "rfi", wantAck: `"type":"confirm"`,
			build: func(a, b, d string) interface{} {
				return &DnsSyncPayload{MessageType: "rfi", OriginatorID: a, YourIdentity: b, Zone: dispatchZone,
					RfiType: "downstream", RfiSubtype: "ns", Timestamp: time.Now().Unix(), DistributionID: d, Nonce: "rfi-" + d}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.Msg, integTestTimeout)
				if !ok {
					t.Fatal("rfi did not reach MsgQs.Msg")
				}
				if m.MessageType != AgentMsgRfi || string(m.OriginatorID) != alice || m.RfiType != "downstream" ||
					m.RfiSubtype != "ns" || m.DistributionID != distID {
					t.Errorf("rfi msg: %+v", m.AgentMsgPost)
				}
			}},
		{name: "update-refused-on-agent", verb: "update", unhandled: true,
			// "update" is the agent->combiner verb; the agent router has no
			// handler for it. It must be refused AND not leak to MsgQs.Msg.
			build: func(a, b, d string) interface{} {
				return &DnsSyncPayload{MessageType: "update", OriginatorID: a, YourIdentity: b, Zone: dispatchZone,
					Records: map[string][]string{dispatchZone: {rr}}, Timestamp: time.Now().Unix(), DistributionID: d}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				if m, leaked := recvWithin(env.Bob.MsgQs.Msg, 150*time.Millisecond); leaked {
					t.Errorf("refused update leaked to MsgQs.Msg: %+v", m.AgentMsgPost)
				}
			}},
		{name: "keystate-inventory", verb: "keystate", wantAck: "keystate inventory received",
			build: func(a, b, d string) interface{} {
				return &DnsKeystatePayload{MessageType: "keystate", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					Signal: "inventory", Timestamp: time.Now().Unix(),
					KeyInventory: []KeyInventoryEntry{{KeyTag: 12345, Algorithm: 15, Flags: 257, State: "active",
						KeyRR: dispatchZone + " 3600 IN DNSKEY 257 3 15 dGVzdA=="}}}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.KeystateInventory, integTestTimeout)
				if !ok {
					t.Fatal("keystate inventory did not reach MsgQs.KeystateInventory")
				}
				if m.SenderID != alice || m.Zone != dispatchZone || len(m.Inventory) != 1 || m.Inventory[0].KeyTag != 12345 {
					t.Errorf("keystate inventory: %+v", *m)
				}
			}},
		{name: "keystate-signal", verb: "keystate", wantAck: "keystate propagated received",
			build: func(a, b, d string) interface{} {
				return &DnsKeystatePayload{MessageType: "keystate", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					Signal: "propagated", KeyTag: 12345, Algorithm: 15, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.KeystateSignal, integTestTimeout)
				if !ok {
					t.Fatal("keystate signal did not reach MsgQs.KeystateSignal")
				}
				if m.SenderID != alice || m.Zone != dispatchZone || m.Signal != "propagated" || m.KeyTag != 12345 {
					t.Errorf("keystate signal: %+v", *m)
				}
			}},
		{name: "edits", verb: "edits", wantAck: "edits received",
			build: func(a, b, d string) interface{} {
				return &DnsEditsPayload{MessageType: "edits", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					AgentRecords: map[string]map[string][]string{b: {dispatchZone: {rr}}}, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.EditsResponse, integTestTimeout)
				if !ok {
					t.Fatal("edits did not reach MsgQs.EditsResponse")
				}
				if m.SenderID != alice || m.Zone != dispatchZone || len(m.AgentRecords) != 1 {
					t.Errorf("edits: %+v", *m)
				}
			}},
		{name: "config", verb: "config", wantAck: "config received",
			build: func(a, b, d string) interface{} {
				return &DnsConfigPayload{MessageType: "config", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					Subtype: "policy", ConfigData: map[string]string{"k": "v"}, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.ConfigResponse, integTestTimeout)
				if !ok {
					t.Fatal("config did not reach MsgQs.ConfigResponse")
				}
				if m.SenderID != alice || m.Zone != dispatchZone || m.Subtype != "policy" || m.ConfigData["k"] != "v" {
					t.Errorf("config: %+v", *m)
				}
			}},
		{name: "audit", verb: "audit", wantAck: "audit received",
			build: func(a, b, d string) interface{} {
				return &DnsAuditPayload{MessageType: "audit", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					AuditData: map[string]interface{}{"check": "ok"}, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.AuditResponse, integTestTimeout)
				if !ok {
					t.Fatal("audit did not reach MsgQs.AuditResponse")
				}
				if m.SenderID != alice || m.Zone != dispatchZone {
					t.Errorf("audit: %+v", *m)
				}
			}},
		{name: "status-update", verb: "status-update", wantAck: "status-update received",
			build: func(a, b, d string) interface{} {
				return &DnsStatusUpdatePayload{MessageType: "status-update", MyIdentity: a, YourIdentity: b, Zone: dispatchZone,
					SubType: "delegation-change", NSRecords: []string{dispatchZone + " 3600 IN NS ns1.example."}, Result: "ok", Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				m, ok := recvWithin(env.Bob.MsgQs.StatusUpdate, integTestTimeout)
				if !ok {
					t.Fatal("status-update did not reach MsgQs.StatusUpdate")
				}
				if m.SenderID != alice || m.Zone != dispatchZone || m.SubType != "delegation-change" || len(m.NSRecords) != 1 {
					t.Errorf("status-update: %+v", *m)
				}
			}},
		{name: "relocate", verb: "relocate",
			build: func(a, b, d string) interface{} {
				return &DnsRelocatePayload{Type: "relocate", SenderID: a,
					NewAddress: DnsAddress{Host: "192.0.2.3", Port: 5353, Transport: "udp"},
					Reason:     "dispatch-test", ValidUntil: time.Now().Add(time.Hour).Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				// routeRelocateMessage is synchronous inside the callback.
				peer, ok := env.Bob.Bridge.PeerRegistry.Get(alice)
				if !ok {
					t.Fatal("relocate: sender not in PeerRegistry")
				}
				addr := peer.CurrentAddress()
				if addr == nil || addr.Host != "192.0.2.3" || addr.Port != 5353 {
					t.Errorf("relocate: operational address not applied: %+v", addr)
				}
			}},
		{name: "confirm", verb: "confirm",
			build: func(a, b, d string) interface{} {
				return &transport.DnsConfirmPayload{Type: "confirm", SenderID: a, Zone: dispatchZone, DistributionID: d,
					Status: "ok", AppliedRecords: []string{rr}, Timestamp: time.Now().Unix()}
			},
			observe: func(t *testing.T, env *integEnv, alice, distID string) {
				c, ok := recvWithin(env.Bob.MsgQs.Confirmation, integTestTimeout)
				if !ok {
					t.Fatal("confirm did not reach MsgQs.Confirmation")
				}
				if c.DistributionID != distID || c.Source != alice || c.Status != "SUCCESS" || string(c.Zone) != dispatchZone {
					t.Errorf("confirm: %+v", *c)
				}
			}},
	}
}

// TestTransportDispatch_PerVerb is the C0.5 gate. Re-run after every
// C3/C5/C6 sub-step; a verb that stops dispatching fails its subtest.
func TestTransportDispatch_PerVerb(t *testing.T) {
	for _, tc := range dispatchCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
			alice, bob := env.Alice.Identity, env.Bob.Identity

			// Alice is known to Bob on both stores: the MP registry (so an
			// inbound hello does not kick discovery) and the transport
			// registry with a shared zone (HandleSync's zero-zone gate).
			env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
			alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
			// C7: shared zones are derived from HSYNC3 participation.
			seedZoneWithHSYNC3(t, dispatchZone, alice, bob)

			// The production seam: RouteToCallback -> routeIncomingMessage.
			env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)

			distID := nextDistributionID()
			body, err := json.Marshal(tc.build(alice, bob, distID))
			if err != nil {
				t.Fatalf("marshal %s payload: %v", tc.verb, err)
			}

			// (a) verb table: the production parser must extract this verb.
			if got := wireVerb(body); got != tc.verb {
				t.Fatalf("wireVerb: got %q, want %q", got, tc.verb)
			}

			// (b) handler through the middleware chain
			ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, alice, distID, body)
			ctx.Peer = alicePeer
			if string(msgType) != tc.verb {
				t.Fatalf("pre-parsed type: got %q, want %q", msgType, tc.verb)
			}
			if err := env.Bob.Bridge.Router.Route(ctx, msgType); err != nil {
				t.Fatalf("Router.Route(%s): %v", tc.verb, err)
			}
			resp := dispatchResponse(t, ctx)
			if tc.unhandled {
				if rc, _ := ctx.Data["response_rcode"].(int); rc != dns.RcodeRefused {
					t.Errorf("unhandled %s: response_rcode = %v, want REFUSED", tc.verb, ctx.Data["response_rcode"])
				}
				if !strings.Contains(resp, `"status":"unsupported"`) {
					t.Errorf("unhandled %s: response %q lacks unsupported status", tc.verb, resp)
				}
			} else {
				if tc.verb != "confirm" {
					if mt, _ := ctx.Data["message_type"].(string); mt != tc.verb {
						t.Errorf("ctx.Data[message_type] = %q, want %q", mt, tc.verb)
					}
					im, _ := ctx.Data["incoming_message"].(*transport.IncomingMessage)
					if im == nil || im.Type != tc.verb || im.TypeToken != tc.verb || im.Token() != tc.verb {
						t.Errorf("ctx.Data[incoming_message] = %+v, want Type/TypeToken %q (C1 seam)", im, tc.verb)
					}
				}
				if tc.wantAck != "" && !strings.Contains(resp, tc.wantAck) {
					t.Errorf("response %q lacks %q", resp, tc.wantAck)
				}
				if tc.wantAck == "" && resp != "" && tc.verb != "confirm" {
					t.Errorf("%s: unexpected response %q", tc.verb, resp)
				}
			}

			// (c) MP-side delivery
			tc.observe(t, env, alice, distID)
		})
	}
}
