package tdnsmp

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// TestAppVerbTable locks the per-role verb sets that the three deleted
// transport initializers (InitializeRouter, InitializeCombinerRouter,
// InitializeSignerRouter) registered before C3.
func TestAppVerbTable(t *testing.T) {
	want := map[string][]string{
		roleAgent:    {"audit", "config", "edits", "keystate", "relocate", "rfi", "status-update", "sync"},
		roleAuditor:  {"audit", "config", "edits", "keystate", "relocate", "rfi", "status-update", "sync"},
		roleCombiner: {"rfi", "status-update", "update"},
		roleSigner:   {"keystate", "rfi", "status-update"},
	}
	for role, verbs := range want {
		var got []string
		for i := range appVerbRegistry {
			v := &appVerbRegistry[i]
			if v.handle != nil && roleAccepts(v, role) {
				got = append(got, v.token)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(verbs, ",") {
			t.Errorf("%s verbs: got %v, want %v", role, got, verbs)
		}
	}
	// Every application verb has an MP consumer; transport-own verbs may
	// have none (confirm) but never a handler here.
	for i := range appVerbRegistry {
		v := &appVerbRegistry[i]
		if v.handle != nil && v.route == nil {
			t.Errorf("%s: handler without route", v.token)
		}
		if v.handle == nil && len(v.roles) != 0 {
			t.Errorf("%s: transport-own verb with roles", v.token)
		}
	}
}

// TestTransportDispatch_RoleTables drives a signer- and a combiner-shaped
// router (transport.InitializeRouter without confirmations + the role's
// verbs) through Router.Route and checks accept/refuse per role, plus the
// combiner's pending-ack contract on update.
func TestTransportDispatch_RoleTables(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice := env.Alice.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	alicePeer := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	seedZoneWithHSYNC3(t, dispatchZone, alice, env.Bob.Identity)

	newRoleRouter := func(role string) *transport.DNSMessageRouter {
		r := transport.NewDNSMessageRouter()
		if err := transport.InitializeRouter(r, &transport.RouterConfig{TransportManager: env.Bob.Bridge, PeerRegistry: env.Bob.Bridge.PeerRegistry}); err != nil {
			t.Fatal(err)
		}
		if err := env.Bob.Bridge.RegisterAppVerbs(r, role); err != nil {
			t.Fatal(err)
		}
		r.Use(transport.RouteToCallback(env.Bob.Bridge.routeIncomingMessage))
		return r
	}
	route := func(r *transport.DNSMessageRouter, payload interface{}) (*transport.MessageContext, error) {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, alice, nextDistributionID(), body)
		ctx.Peer = alicePeer
		return ctx, r.Route(ctx, msgType)
	}
	syncPayload := func(verb string) *DnsSyncPayload {
		return &DnsSyncPayload{MessageType: verb, OriginatorID: alice, YourIdentity: env.Bob.Identity, Zone: dispatchZone,
			Records: map[string][]string{dispatchZone: {dispatchZone + " 3600 IN TXT \"role\""}}, Timestamp: time.Now().Unix()}
	}
	refused := func(t *testing.T, ctx *transport.MessageContext, verb string) {
		t.Helper()
		if rc, _ := ctx.Data["response_rcode"].(int); rc != dns.RcodeRefused {
			t.Errorf("%s: expected REFUSED, got %v", verb, ctx.Data["response_rcode"])
		}
	}

	t.Run("combiner", func(t *testing.T) {
		r := newRoleRouter(roleCombiner)
		ctx, err := route(r, syncPayload("update"))
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if mt, _ := ctx.Data["message_type"].(string); mt != "update" {
			t.Errorf("update: message_type = %q", mt)
		}
		if !strings.Contains(dispatchResponse(t, ctx), `"status":"pending"`) {
			t.Errorf("update: combiner must answer a pending ack, got %s", dispatchResponse(t, ctx))
		}
		m, ok := recvWithin(env.Bob.MsgQs.Msg, integTestTimeout)
		if !ok || m.MessageType != AgentMsg("update") {
			t.Errorf("update did not reach MsgQs.Msg as AgentMsgUpdate: %v %v", ok, m)
		}
		ctx, _ = route(r, syncPayload("sync"))
		refused(t, ctx, "sync on combiner")
		if _, leaked := recvWithin(env.Bob.MsgQs.Msg, 100*time.Millisecond); leaked {
			t.Error("refused sync leaked to MsgQs.Msg")
		}
	})
	t.Run("signer", func(t *testing.T) {
		r := newRoleRouter(roleSigner)
		ctx, err := route(r, &DnsKeystatePayload{MessageType: "keystate", MyIdentity: alice, YourIdentity: env.Bob.Identity,
			Zone: dispatchZone, Signal: "propagated", KeyTag: 7, Timestamp: time.Now().Unix()})
		if err != nil {
			t.Fatalf("keystate: %v", err)
		}
		if mt, _ := ctx.Data["message_type"].(string); mt != "keystate" {
			t.Errorf("keystate: message_type = %q", mt)
		}
		if m, ok := recvWithin(env.Bob.MsgQs.KeystateSignal, integTestTimeout); !ok || m.KeyTag != 7 {
			t.Errorf("keystate signal not delivered: %v %v", ok, m)
		}
		ctx, _ = route(r, &DnsEditsPayload{MessageType: "edits", MyIdentity: alice, YourIdentity: env.Bob.Identity, Zone: dispatchZone, Timestamp: time.Now().Unix()})
		refused(t, ctx, "edits on signer")
		ctx, _ = route(r, syncPayload("sync"))
		refused(t, ctx, "sync on signer")
	})
}
