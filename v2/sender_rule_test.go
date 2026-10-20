/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// routeAs routes a payload into bob's router as one that came from sender
// (the context's peer), through the middleware chain, as the production
// path does. It returns the context, for the answer.
func routeAs(t *testing.T, env *integEnv, sender string, payload []byte) *transport.MessageContext {
	t.Helper()
	distID := nextDistributionID()
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, sender, distID, payload)
	ctx.Peer = env.Bob.Bridge.PeerRegistry.GetOrCreate(sender)
	_ = env.Bob.Bridge.Router.Route(ctx, msgType)
	return ctx
}

// senderRuleEnv is alice and bob, each the other's peer in a zone both
// serve, bob's router running with the production middleware.
func senderRuleEnv(t *testing.T) (*integEnv, string, string) {
	t.Helper()
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	seedZoneWithHSYNC3(t, dispatchZone, alice, bob)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	return env, alice, bob
}

func refused(ctx *transport.MessageContext) bool {
	rc, _ := ctx.Data["response_rcode"].(int)
	return rc == dns.RcodeRefused
}

// Every verb whose payload names another sender than the one the
// transport established, or names none, is refused, and reaches nothing.
// A payload that names its own sender in another case, or without the
// trailing dot, passes.
func TestAPayloadThatNamesAnotherSenderIsRefused(t *testing.T) {
	const carol = "carol.agent.example."
	rr := dispatchZone + " 3600 IN TXT \"named\""
	payloads := map[string]func(named, you string) interface{}{
		"hello": func(named, you string) interface{} {
			return &transport.DnsHelloPayload{MessageType: "hello", MyIdentity: named, YourIdentity: you, Zone: dispatchZone,
				SharedZones: []string{dispatchZone}, Timestamp: time.Now().Unix()}
		},
		"beat": func(named, you string) interface{} {
			return &transport.DnsBeatPayload{MessageType: "beat", MyIdentity: named, YourIdentity: you, Zones: []string{dispatchZone}, Timestamp: time.Now().Unix()}
		},
		"sync": func(named, you string) interface{} {
			return &DnsSyncPayload{MessageType: "sync", OriginatorID: named, YourIdentity: you, Zone: dispatchZone,
				Records: map[string][]string{dispatchZone: {rr}}, Timestamp: time.Now().Unix()}
		},
		"rfi": func(named, you string) interface{} {
			return &DnsSyncPayload{MessageType: "rfi", OriginatorID: named, YourIdentity: you, Zone: dispatchZone, RfiType: "SYNC", Timestamp: time.Now().Unix()}
		},
		"relocate": func(named, you string) interface{} {
			return &DnsRelocatePayload{Type: "relocate", SenderID: named, NewAddress: DnsAddress{Host: "192.0.2.9", Port: 5353, Transport: "udp"},
				ValidUntil: time.Now().Add(time.Hour).Unix()}
		},
	}
	for verb, build := range payloads {
		t.Run(verb, func(t *testing.T) {
			env, alice, bob := senderRuleEnv(t)
			for _, tc := range []struct {
				named string
				pass  bool
			}{
				{carol, false},
				{"", false},
				{strings.ToUpper(alice), true},
				{strings.TrimSuffix(alice, "."), true},
			} {
				body, err := json.Marshal(build(tc.named, bob))
				if err != nil {
					t.Fatal(err)
				}
				ctx := routeAs(t, env, alice, body)
				if refused(ctx) == tc.pass {
					t.Errorf("%s naming %q from %s: refused=%v, want %v", verb, tc.named, alice, refused(ctx), !tc.pass)
				}
				drainBob(env)
			}
		})
	}
}

// drainBob empties bob's queues between messages.
func drainBob(env *integEnv) {
	q := env.Bob.MsgQs
	for {
		select {
		case <-q.Msg:
		case <-q.Hello:
		case <-q.Beat:
		case <-q.Ping:
		case <-q.Confirmation:
		case <-time.After(20 * time.Millisecond):
			return
		}
	}
}

// A refused message is not delivered: the middleware is before
// RouteToCallback, so neither the handler's acknowledgement nor the
// application's queue sees it.
func TestARefusedMessageIsNotDelivered(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	body, _ := json.Marshal(&DnsSyncPayload{MessageType: "sync", OriginatorID: "carol.agent.example.", YourIdentity: bob, Zone: dispatchZone,
		Records: map[string][]string{dispatchZone: {dispatchZone + " 3600 IN TXT \"x\""}}, Timestamp: time.Now().Unix()})
	ctx := routeAs(t, env, alice, body)
	if !refused(ctx) {
		t.Fatal("not refused")
	}
	if resp := dispatchResponse(t, ctx); resp != "" {
		t.Errorf("the refused message was answered %q", resp)
	}
	if m, ok := recvWithin(env.Bob.MsgQs.Msg, 100*time.Millisecond); ok {
		t.Errorf("the refused message reached MsgQs.Msg: %+v", m.AgentMsgPost)
	}
}

// The route functions take the sender the middleware checked, whichever
// field of the payload names it: a relocate that names its sender in
// MyIdentity moves that sender's address (it moved a peer named ""), and a
// SYNC that names it in MyIdentity gets its PENDING.
func TestARouteFunctionTakesTheCheckedSender(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	seedZoneWithHSYNC3(t, dispatchZone, alice, bob)
	// alice listens, so that bob's PENDING reaches her
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.Alice.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, env.Alice)
	env.Alice.Registry.S.Set(AgentId(bob), NewAgent(AgentId(bob)))
	env.Alice.Bridge.PeerRegistry.GetOrCreate(bob)
	if err := env.Bob.Bridge.PeerRegistry.Add(peerFromAddress(alice, ln.Addr().String())); err != nil {
		t.Fatal(err)
	}
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)

	distID := nextDistributionID()
	sync := `{"MessageType":"sync","MyIdentity":"` + alice + `","YourIdentity":"` + bob + `","Zone":"` + dispatchZone +
		`","DistributionID":"` + distID + `","Records":{"` + dispatchZone + `":["` + dispatchZone + ` 3600 IN TXT \"pending\""]}}`
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, alice, distID, []byte(sync))
	if err := env.Bob.Bridge.Router.Route(ctx, msgType); err != nil {
		t.Fatalf("the sync: %v", err)
	}
	c, ok := recvWithin(env.Alice.MsgQs.Confirmation, integTestTimeout)
	if !ok || c.Status != "PENDING" || c.DistributionID != distID {
		t.Fatalf("alice got %+v as bob's PENDING", c)
	}

	relocate := `{"type":"relocate","MyIdentity":"` + alice + `","new_address":{"host":"192.0.2.7","port":5353,"transport":"udp"},"valid_until":` +
		jsonInt(time.Now().Add(time.Hour).Unix()) + `}`
	routeAs(t, env, alice, []byte(relocate))
	if p, ok := env.Bob.Bridge.PeerRegistry.Get(alice); !ok || p.CurrentAddress() == nil || p.CurrentAddress().Host != "192.0.2.7" {
		t.Errorf("the relocate did not move the sender's address: %+v", p)
	}
	if _, ok := env.Bob.Bridge.PeerRegistry.Get(""); ok {
		t.Error("the relocate made a peer named \"\"")
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Over HTTPS the sender the transport established is the client
// certificate's name: a /msg under a member's certificate that names
// another member is refused, with or without the trailing dot; one that
// names the certificate's own member without it passes.
func TestAnAPIMsgThatNamesAnotherMemberIsRefused(t *testing.T) {
	const zone = "apimsg.sender.example."
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob, carol := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity), "carol.agent.example."
	zd := seedZoneWithHSYNC3(t, zone, alice, bob, carol)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob), shortLabel(carol))
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	send := apiSender(srv, alice, clientCert(t, alice))
	for _, tc := range []struct {
		named string
		pass  bool
	}{
		{carol, false},
		{strings.TrimSuffix(carol, "."), false},
		{strings.TrimSuffix(alice, "."), true},
	} {
		msg, err := syncAppMessage(&PeerSyncRequest{SenderID: tc.named, Zone: zone, MessageType: "sync", Timestamp: time.Now(),
			DistributionID: nextDistributionID(), Operations: []core.RROperation{{Operation: "replace", RRtype: "TXT",
				Records: []string{zone + " 3600 IN TXT \"api\""}}}}, bob)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		_, _ = send.SendApp(ctx, peer, msg)
		cancel()
		_, delivered := recvMsgWithin(t, env.Bob.MsgQs.Msg, 300*time.Millisecond)
		if delivered != tc.pass {
			t.Errorf("a /msg under %s's certificate naming %q: delivered=%v, want %v", alice, tc.named, delivered, tc.pass)
		}
	}
}

// /hello has no certificate sender (the peer's TLSA need not be known when
// its hello arrives): the middleware compares the body with itself, and a
// hello under another certificate is not refused for it.
func TestAnAPIHelloIsNotHeldToItsCertificate(t *testing.T) {
	const zone = "apihello.sender.example."
	env, srv, _ := apiGossipEnv(t, zone)
	alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()
	if _, err := apiSender(srv, alice, clientCert(t, "carol.agent.example.")).Hello(ctx, peer,
		&transport.HelloRequest{SenderID: alice, SharedZones: []string{zone}, Timestamp: time.Now()}); err != nil {
		t.Logf("hello: %v", err)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Hello, integTestTimeout); !ok {
		t.Error("alice's hello under another certificate did not reach MsgQs.Hello")
	}
}

// h3up is one HSYNC3 record of a test zone: its identity, the identity it
// names as its upstream (none: "."), and whether it is ON.
type h3up struct {
	id, upstream string
	on           bool
}

// standingsZone is a zone with the HSYNC3 records given, labelled by their
// first label, and servers= and auditors= as given.
func standingsZone(t *testing.T, zone string, recs []h3up, servers, auditors []string) {
	t.Helper()
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.id)
	}
	zd := seedZoneWithHSYNC3(t, zone, ids...)
	apex, err := zd.GetOwner(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	var rrs []dns.RR
	for _, r := range recs {
		up := "."
		if r.upstream != "" {
			up = shortLabel(r.upstream)
		}
		h3 := &core.HSYNC3{Label: shortLabel(r.id), Identity: r.id, Upstream: up}
		if r.on {
			h3.State = 1
		}
		rrs = append(rrs, &dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600}, Data: h3})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: rrs})
	zd.Data.Set(zone, *apex)
	setRoles(t, zd, servers, auditors)
}

// rfiFrom is alice's RFI to bob, routed through bob's router.
func rfiFrom(t *testing.T, env *integEnv, zone, rfiType, subtype string) *transport.MessageContext {
	t.Helper()
	body, err := json.Marshal(&DnsSyncPayload{MessageType: "rfi", OriginatorID: env.Alice.Identity, YourIdentity: env.Bob.Identity,
		Zone: zone, RfiType: rfiType, RfiSubtype: subtype, Timestamp: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := routeAs(t, env, env.Alice.Identity, body)
	drainBob(env)
	return ctx
}

// A SYNC whose sender is not a voting member of the zone is refused, with
// its reason on the wire: an auditor, and a record with no role. A voting
// member's passes.
func TestASyncFromAMemberThatDoesNotVoteIsRefused(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	sync := func(zone string) *transport.MessageContext {
		body, _ := json.Marshal(&DnsSyncPayload{MessageType: "sync", OriginatorID: alice, YourIdentity: bob, Zone: zone,
			Records: map[string][]string{zone: {zone + " 3600 IN TXT \"v\""}}, Timestamp: time.Now().Unix()})
		ctx := routeAs(t, env, alice, body)
		return ctx
	}
	for _, tc := range []struct {
		name             string
		servers, auditor []string
		pass             bool
	}{
		{"an auditor", []string{bob}, []string{alice}, false},
		{"a record with no role", []string{bob}, nil, false},
		{"a voting member", []string{alice, bob}, nil, true},
	} {
		zone := strings.ReplaceAll(tc.name, " ", "-") + ".syncvote.example."
		standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}}, tc.servers, tc.auditor)
		ctx := sync(zone)
		_, delivered := recvMsgWithin(t, env.Bob.MsgQs.Msg, 200*time.Millisecond)
		if delivered != tc.pass || refused(ctx) == tc.pass {
			t.Errorf("%s: delivered=%v refused=%v", tc.name, delivered, refused(ctx))
		}
		if !tc.pass && !strings.Contains(dispatchResponse(t, ctx), "sync refused: "+alice+" is not a voting member of zone "+zone) {
			t.Errorf("%s: the refusal says %q", tc.name, dispatchResponse(t, ctx))
		}
	}
}

// A peer authorized by configuration is held to the RFI rules like any
// other (2.2): RFI SYNC and AUDIT need it to be a member of the zone; CONFIG
// upstream and downstream a member, related by an ON record's upstream, and
// not an auditor only. Other types pass: the election's, and CONFIG sig0key.
func TestAnAuthorizedPeerIsHeldToTheRFIRules(t *testing.T) {
	env, alice, bob := senderRuleEnv(t) // every peer authorized by configuration
	const outside = "outside.rfirules.example."
	standingsZone(t, outside, []h3up{{bob, "", true}}, []string{bob}, nil)
	for _, rfi := range []string{"SYNC", "AUDIT"} {
		ctx := rfiFrom(t, env, outside, rfi, "")
		if !refused(ctx) || !strings.Contains(dispatchResponse(t, ctx), "rfi "+rfi+" refused: "+alice+" is not a member of zone "+outside) {
			t.Errorf("RFI %s from a peer the zone does not list: %q", rfi, dispatchResponse(t, ctx))
		}
	}
	for _, rfi := range [][2]string{{"ELECT-CALL", ""}, {"CONFIG", "sig0key"}} {
		if ctx := rfiFrom(t, env, outside, rfi[0], rfi[1]); refused(ctx) {
			t.Errorf("RFI %s %s was refused: %q", rfi[0], rfi[1], dispatchResponse(t, ctx))
		}
	}

	const related = "related.rfirules.example."
	standingsZone(t, related, []h3up{{alice, bob, true}, {bob, alice, true}}, []string{alice, bob}, nil)
	for _, sub := range []string{"upstream", "downstream"} {
		if ctx := rfiFrom(t, env, related, "CONFIG", sub); refused(ctx) {
			t.Errorf("CONFIG %s from a related member: %q", sub, dispatchResponse(t, ctx))
		}
	}
	// one way: alice's ON record names bob as its upstream, bob's names
	// none. alice may ask bob for upstream's config, and not downstream's
	const oneway = "oneway.rfirules.example."
	standingsZone(t, oneway, []h3up{{alice, bob, true}, {bob, "", true}}, []string{alice, bob}, nil)
	if ctx := rfiFrom(t, env, oneway, "CONFIG", "upstream"); refused(ctx) {
		t.Errorf("CONFIG upstream from a member that names this agent as its upstream: %q", dispatchResponse(t, ctx))
	}
	if ctx := rfiFrom(t, env, oneway, "CONFIG", "downstream"); !refused(ctx) {
		t.Error("CONFIG downstream from a member that is not this agent's upstream was not refused")
	}
	const unrelated = "unrelated.rfirules.example."
	standingsZone(t, unrelated, []h3up{{alice, "", true}, {bob, "", true}}, []string{alice, bob}, nil)
	for _, sub := range []string{"upstream", "downstream"} {
		if ctx := rfiFrom(t, env, unrelated, "CONFIG", sub); !refused(ctx) || !strings.Contains(dispatchResponse(t, ctx), "is not related to this agent") {
			t.Errorf("CONFIG %s from an unrelated member: %q", sub, dispatchResponse(t, ctx))
		}
	}
	const auditor = "auditor.rfirules.example."
	standingsZone(t, auditor, []h3up{{alice, bob, true}, {bob, alice, true}}, []string{bob}, []string{alice})
	if ctx := rfiFrom(t, env, auditor, "CONFIG", "upstream"); !refused(ctx) || !strings.Contains(dispatchResponse(t, ctx), "is an auditor only") {
		t.Errorf("CONFIG upstream from an auditor: %q", dispatchResponse(t, ctx))
	}
	const off = "off.rfirules.example."
	standingsZone(t, off, []h3up{{alice, bob, false}, {bob, alice, true}}, []string{alice, bob}, nil)
	if ctx := rfiFrom(t, env, off, "CONFIG", "upstream"); !refused(ctx) {
		t.Errorf("CONFIG upstream from a member whose ON record is gone: %q", dispatchResponse(t, ctx))
	}
}

// A LEGACY peer (an established peer with no zone shared) gets no answer to
// an RFI: it is refused, also for a zone in which this agent has no
// standing.
func TestALegacyPeerGetsNoAnswerToAnRFI(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	const ours, theirs = "ours.legacy-rfi.example.", "theirs.legacy-rfi.example."
	standingsZone(t, ours, []h3up{{bob, "", true}}, []string{bob}, nil)
	standingsZone(t, theirs, []h3up{{alice, "", true}}, []string{alice}, nil)
	if !env.Bob.Registry.isKnownLegacy(alice) {
		t.Fatal("precondition: alice is not LEGACY at bob")
	}
	for zone, want := range map[string]string{
		ours:   "rfi SYNC refused: " + alice + " is not a member of zone " + ours,
		theirs: "rfi SYNC refused: this agent is not a member of zone " + theirs,
	} {
		ctx := rfiFrom(t, env, zone, "SYNC", "")
		if !refused(ctx) || !strings.Contains(dispatchResponse(t, ctx), want) {
			t.Errorf("zone %s: %q, want %q", zone, dispatchResponse(t, ctx), want)
		}
	}
}

// The hand-over of the zone's SIG(0) key still passes: a CONFIG sig0key
// from a voting member to a holder listed with no role is not held to the
// holder's standing.
func TestTheKeyHandOverStillPasses(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	const zone = "keyhandover.rules.example."
	standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}}, []string{alice}, nil)
	body, _ := json.Marshal(&DnsSyncPayload{MessageType: "rfi", OriginatorID: alice, YourIdentity: bob, Zone: zone,
		RfiType: "CONFIG", RfiSubtype: "sig0key", Timestamp: time.Now().Unix()})
	ctx := routeAs(t, env, alice, body)
	if refused(ctx) {
		t.Fatalf("the request for the key was refused: %q", dispatchResponse(t, ctx))
	}
	if m, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout); !ok || m.RfiSubtype != "sig0key" {
		t.Errorf("the request for the key did not reach the holder: %+v", m)
	}
}

// An OFF record is nobody's upstream or downstream: an OFF record that
// names this agent as its upstream is no downstream of it; this agent's own
// OFF record names no upstream; and an ON record of this agent's names no
// upstream whose record is OFF.
func TestAnOFFRecordIsNobodysDownstream(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	at := func(zone string, recs []h3up) *ZoneAgentData {
		t.Helper()
		standingsZone(t, zone, recs, []string{alice, bob}, nil)
		zad, err := env.Bob.Registry.GetZoneAgentData(ZoneName(zone))
		if err != nil {
			t.Fatal(err)
		}
		return zad
	}
	if zad := at("offdown.records.example.", []h3up{{alice, bob, false}, {bob, "", true}}); len(zad.MyDownstreams) != 0 {
		t.Errorf("an OFF record naming this agent as upstream is a downstream: %v", zad.MyDownstreams)
	}
	if zad := at("offown.records.example.", []h3up{{alice, "", true}, {bob, alice, false}}); zad.MyUpstream != "" {
		t.Errorf("this agent's own OFF record names the upstream %q", zad.MyUpstream)
	}
	if zad := at("offup.records.example.", []h3up{{alice, "", false}, {bob, alice, true}}); zad.MyUpstream != "" {
		t.Errorf("an upstream whose record is OFF is named: %q", zad.MyUpstream)
	}
	if zad := at("on.records.example.", []h3up{{alice, bob, true}, {bob, alice, true}}); len(zad.MyDownstreams) != 1 || zad.MyUpstream != AgentId(alice) {
		t.Errorf("ON records: downstreams %v, upstream %q", zad.MyDownstreams, zad.MyUpstream)
	}
}

// The combiner refuses the operations of an origin that is not a voting
// member of the zone, each with its reason; a zone with no HSYNC3 records is
// left as it is.
func TestTheCombinerRefusesAnOriginThatDoesNotVote(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "origin.votes.example.", false, false)
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	var rrs []dns.RR
	for _, l := range []string{"us", "alpha", "beta"} {
		rrs = append(rrs, &dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
			Data: &core.HSYNC3{State: 1, Label: l, Identity: "agent." + l + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: rrs})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	rec := mpzd.ZoneName + " 3600 IN TXT \"origin\""
	update := func(origin string) *CombinerSyncResponse {
		return CombinerProcessUpdate(&CombinerSyncRequest{SenderID: origin, DeliveredBy: csyncOurAgent, Zone: mpzd.ZoneName,
			Operations:     []core.RROperation{{Operation: "add", RRtype: "TXT", Records: []string{rec}}},
			DistributionID: nextDistributionID(), Timestamp: time.Now()}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
	}
	resp := update("agent.gamma.example.")
	if resp.Status != "error" || len(resp.RejectedItems) != 1 || !strings.Contains(resp.RejectedItems[0].Reason, "agent.gamma.example. is not a voting member of zone") {
		t.Errorf("an origin that does not vote: %+v", resp)
	}
	for _, r := range update(csyncLeaderA).RejectedItems {
		if strings.Contains(r.Reason, "voting member") {
			t.Errorf("a voting origin was refused for its standing: %+v", r)
		}
	}
}

func TestTheCombinerLeavesAZoneWithoutHSYNC3AsItIs(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "nohsync3.origin.example.", false, false) // HSYNCPARAM, no HSYNC3
	resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: "agent.gamma.example.", DeliveredBy: csyncOurAgent, Zone: mpzd.ZoneName,
		Operations:     []core.RROperation{{Operation: "add", RRtype: "TXT", Records: []string{mpzd.ZoneName + " 3600 IN TXT \"x\""}}},
		DistributionID: nextDistributionID(), Timestamp: time.Now()}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
	for _, r := range resp.RejectedItems {
		if strings.Contains(r.Reason, "voting member") {
			t.Errorf("a zone with no HSYNC3 records refused an origin for its standing: %+v", resp)
		}
	}
}

// The operator's requests go to voting members only: the SIG(0) key, as the
// leader's own request asks, and AUDIT, which an auditor never answered.
func TestTheOperatorsKeyRequestGoesToVotingMembersOnly(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob, carol := env.Alice.Identity, env.Bob.Identity, "carol.agent.example."
	const zone = "operator.keyask.example."
	standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}, {carol, "", true}}, []string{alice, bob}, []string{carol})
	ask := func(rfiType, subtype string) map[AgentId]*RfiData {
		resp := make(chan *AgentMgmtResponse, 1)
		env.Bob.Registry.CommandHandler(&AgentMgmtPostPlus{AgentMgmtPost: AgentMgmtPost{Command: "send-rfi", Zone: zone,
			RfiType: rfiType, RfiSubtype: subtype}, Response: resp}, nil, env.Bob.MsgQs)
		got, ok := recvWithin(resp, 30*time.Second)
		if !ok {
			t.Fatal("no answer")
		}
		return got.RfiResponse
	}
	for _, rfi := range [][2]string{{"CONFIG", "sig0key"}, {"AUDIT", ""}} {
		got := ask(rfi[0], rfi[1])
		if len(got) != 1 || got[AgentId(alice)] == nil {
			t.Errorf("%s %s asked %v, want the voting member alone", rfi[0], rfi[1], got)
		}
	}
}

// Election messages go to the zone's voting members and its auditors, by
// an explicit test: not to a member with no role.
func TestElectionMessagesGoToVotingMembersAndAuditors(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice, bob, carol, dave := env.Alice.Identity, env.Bob.Identity, "carol.agent.example.", "dave.agent.example."
	const zone = "elect.recipients.example."
	standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}, {carol, "", true}, {dave, "", true}}, []string{alice, bob}, []string{carol})
	var agents []*Agent
	for _, id := range []string{alice, bob, carol, dave} {
		agents = append(agents, NewAgent(AgentId(id)))
	}
	var got []string
	for _, a := range electRecipients(zone, agents, AgentId(bob)) {
		got = append(got, string(a.ID))
	}
	if strings.Join(got, " ") != alice+" "+carol {
		t.Errorf("election messages go to %v, want the other voting member and the auditor", got)
	}
}

// gossipGroup is a zone of alice, bob and carol, with the roles given, and
// bob's provider group for it.
func gossipGroup(t *testing.T, env *integEnv, zone string, servers, auditors []string) string {
	t.Helper()
	alice, bob, carol := env.Alice.Identity, env.Bob.Identity, "carol.agent.example."
	standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}, {carol, "", true}}, servers, auditors)
	var group string
	for _, p := range []*peerEnv{env.Alice, env.Bob} {
		pgm := p.Registry.ProviderGroupManager
		pgm.RecomputeGroups()
		pg := pgm.GetGroupForZone(ZoneName(zone))
		if pg == nil {
			t.Fatalf("%s has no group for the zone", p.Identity)
		}
		group = pg.GroupHash
	}
	return group
}

func rowOf(gst *GossipStateTable, group, id string) *MemberState {
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	return gst.States[group][id]
}

func electionOf(gst *GossipStateTable, group string) *GroupElectionState {
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	return gst.Elections[group]
}

// beatWithGossip is alice's beat to bob, carrying gossip, through bob's
// router.
func beatWithGossip(t *testing.T, env *integEnv, zone string, gossip []GossipMessage) {
	t.Helper()
	g, err := json.Marshal(gossip)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(&transport.DnsBeatPayload{MessageType: "beat", MyIdentity: env.Alice.Identity, YourIdentity: env.Bob.Identity,
		Zones: []string{zone}, Gossip: g, Timestamp: time.Now().Unix()})
	if ctx := routeAs(t, env, env.Alice.Identity, body); refused(ctx) {
		t.Fatalf("the beat was refused: %q", dispatchResponse(t, ctx))
	}
}

// Gossip for a group this agent does not have, or from a sender that is not
// a member of the group, is not taken.
func TestGossipForAnUnknownGroupIsNotTaken(t *testing.T) {
	gst := NewGossipStateTable("bob.agent.example.")
	msg := &GossipMessage{GroupHash: "0123456789abcdef", Members: map[string]*MemberState{
		"alice.agent.example.": {Identity: "alice.agent.example.", Timestamp: time.Now()}},
		Election: GroupElectionState{Leader: "alice.agent.example.", Term: 3}}
	gst.MergeGossip(msg, "alice.agent.example.", nil, false)
	if rowOf(gst, "0123456789abcdef", "alice.agent.example.") != nil || electionOf(gst, "0123456789abcdef") != nil {
		t.Error("gossip for a group not known here was taken")
	}
	other := &ProviderGroup{GroupHash: "0123456789abcdef", Members: []string{"bob.agent.example.", "carol.agent.example."},
		VotingMembers: []string{"bob.agent.example.", "carol.agent.example."}}
	gst.MergeGossip(msg, "alice.agent.example.", other, false)
	if rowOf(gst, "0123456789abcdef", "alice.agent.example.") != nil || electionOf(gst, "0123456789abcdef") != nil {
		t.Error("gossip from a sender that is not a member of the group was taken")
	}
}

// From a member that does not vote (an auditor), a beat's gossip gives its
// own row and nothing else: not another member's row.
func TestGossipFromAMemberThatDoesNotVoteIsItsOwnRowOnly(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	const zone = "gossip.auditor.example."
	group := gossipGroup(t, env, zone, []string{bob, "carol.agent.example."}, []string{alice})
	beatWithGossip(t, env, zone, []GossipMessage{{GroupHash: group, Members: map[string]*MemberState{
		alice:                  {Identity: alice, Timestamp: time.Now()},
		"carol.agent.example.": {Identity: "carol.agent.example.", Timestamp: time.Now()},
	}}})
	gst := env.Bob.Registry.GossipStateTable
	if rowOf(gst, group, alice) == nil {
		t.Error("the auditor's own row was not taken")
	}
	beatWithGossip(t, env, zone, []GossipMessage{{GroupHash: group, Members: map[string]*MemberState{alice: {Identity: alice, Timestamp: time.Now()}},
		GroupName: GroupNameProposal{Name: "auditors-choice", ProposedAt: time.Now().Add(-time.Hour)}}})
	gst.mu.RLock()
	name := gst.Names[group]
	gst.mu.RUnlock()
	if name != nil && name.Name == "auditors-choice" {
		t.Error("an auditor's proposal of the group's name was taken")
	}
	if rowOf(gst, group, "carol.agent.example.") != nil {
		t.Error("another member's row was taken from an auditor")
	}
}

// An election record from a member that does not vote is not taken, and no
// term from one.
func TestAnElectionRecordFromAMemberThatDoesNotVoteIsNotTaken(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	const zone = "gossip.election.example."
	group := gossipGroup(t, env, zone, []string{bob, "carol.agent.example."}, []string{alice})
	beatWithGossip(t, env, zone, []GossipMessage{{GroupHash: group, Members: map[string]*MemberState{alice: {Identity: alice, Timestamp: time.Now()}},
		Election: GroupElectionState{Leader: "carol.agent.example.", Term: 9}}})
	if e := electionOf(env.Bob.Registry.GossipStateTable, group); e != nil {
		t.Errorf("an election record from an auditor was taken: %+v", e)
	}
	// from a voting member it is
	group2 := gossipGroup(t, env, "gossip.voter.example.", []string{alice, bob, "carol.agent.example."}, nil)
	beatWithGossip(t, env, "gossip.voter.example.", []GossipMessage{{GroupHash: group2, Members: map[string]*MemberState{alice: {Identity: alice, Timestamp: time.Now()}},
		Election: GroupElectionState{Leader: alice, Term: 4}}})
	if e := electionOf(env.Bob.Registry.GossipStateTable, group2); e == nil || e.Term != 4 {
		t.Errorf("a voting member's election record was not taken: %+v", e)
	}
}

// The answer to a beat brings rows and no election record, over either
// mechanism: the peer that answers is not authenticated (decision 35).
func TestAnAnswersGossipBringsNoElectionRecord(t *testing.T) {
	for _, mech := range []string{"DNS", "API"} {
		t.Run(mech, func(t *testing.T) {
			env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
			alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
			zone := strings.ToLower(mech) + ".answer.gossip.example."
			zd := seedZoneWithHSYNC3(t, zone, alice, bob)
			addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
			var group string
			for _, p := range []*peerEnv{env.Alice, env.Bob} {
				pgm := p.Registry.ProviderGroupManager
				pgm.RecomputeGroups()
				group = pgm.GetGroupForZone(ZoneName(zone)).GroupHash
				p.Registry.GossipStateTable.RefreshLocalStates(p.Registry, pgm)
			}
			// bob holds an election record, which his answer carries
			env.Bob.Registry.GossipStateTable.mergeGossip(&GossipMessage{GroupHash: group, Election: GroupElectionState{Leader: bob, Term: 7}})
			env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
			env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
			env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
			agent := NewAgent(AgentId(bob))
			switch mech {
			case "DNS":
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				serveDNS(t, env.ctx, ln, env.Bob)
				peer := peerFromAddress(bob, ln.Addr().String())
				peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "said hello")
				if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
					t.Fatal(err)
				}
				agent.DnsMethod = true
			case "API":
				srv := apiEndpointsServer(t, env.Bob)
				tr := apiSender(srv, alice)
				env.Alice.Bridge.APITransport = tr
				env.Alice.Bridge.TransportManager.APITransport = tr
				peer := transport.NewPeer(bob)
				peer.APIEndpoint = srv.URL + "/api/v1"
				peer.SetMechanismState("API", transport.PeerStateIntroducing, "said hello")
				if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
					t.Fatal(err)
				}
				agent.ApiMethod = true
			}
			resp, err := env.Alice.Bridge.SendBeatWithFallback(env.ctx, agent, 1)
			if err != nil || resp == nil || len(resp.Gossip) == 0 || !strings.Contains(string(resp.Gossip), `"term":7`) {
				t.Fatalf("the answer: %+v %v", resp, err)
			}
			ours := env.Alice.Registry.GossipStateTable
			if rowOf(ours, group, bob) == nil {
				t.Error("the answer's rows were not taken")
			}
			if e := electionOf(ours, group); e != nil {
				t.Errorf("the answer's election record was taken: %+v", e)
			}
		})
	}
}

// receivesThroughRouter is the notify rig's receives through the agent's
// router: the sender rule and the SYNC's handler first, as a SYNC from the
// wire goes, then the message handler. It reports whether the router took
// the SYNC.
func (r *notifyRig) receivesThroughRouter(t *testing.T, originator, transportSender string, ops ...core.RROperation) (string, bool) {
	t.Helper()
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{MessageType: "sync", OriginatorID: originator, YourIdentity: r.us.Identity,
		Zone: r.mpzd.ZoneName, Operations: ops, Time: time.Now().Format(time.RFC3339Nano), Timestamp: time.Now().Unix(), DistributionID: distID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, msgType := buildDispatchContext(t, r.us.Bridge, transportSender, distID, body)
	_ = r.us.Bridge.Router.Route(ctx, msgType)
	if refused(ctx) {
		return distID, false
	}
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the router did not queue the SYNC")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
	return distID, true
}

// The leader's CSYNC passes both rules, in their order: the router's (the
// sender of a SYNC is a voting member) and the data engine's (a CSYNC is
// taken only from the leader).
func TestALeadersCSYNCPassesBothRules(t *testing.T) {
	r := receivingRig(t, "bothrules.csync.example.")
	r.us.Bridge.StartIncomingMessageRouter(r.ctx)
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	op, rec := csyncOp(r.mpzd.ZoneName, 1000)
	if _, taken := r.receivesThroughRouter(t, string(leader), string(leader), op); !taken {
		t.Fatal("the router refused the leader's SYNC")
	}
	var held []TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && len(held) == 0; time.Sleep(10 * time.Millisecond) {
		held = r.repo(t)[leader][dns.TypeCSYNC]
	}
	if len(held) != 1 || held[0].RR != rec {
		t.Errorf("the agent holds %+v as the leader's CSYNC", held)
	}
}

// A CSYNC from a voting member that does not lead passes the router's rule
// and is rejected by the data engine's, as before.
func TestACSYNCFromAVotingMemberThatDoesNotLeadIsStillRejected(t *testing.T) {
	r := receivingRig(t, "notleader.csync.example.")
	r.us.Bridge.StartIncomingMessageRouter(r.ctx)
	r.leader(r.lem.localID)
	sender := r.peer.Identity
	op, rec := csyncOp(r.mpzd.ZoneName, 1000)
	distID, taken := r.receivesThroughRouter(t, sender, sender, op)
	if !taken {
		t.Fatal("the router refused a voting member's SYNC")
	}
	c := r.answered(t, distID)
	if c.Status != "REJECTED" || len(c.RejectedItems) != 1 || c.RejectedItems[0].Record != rec {
		t.Errorf("the sender got %+v, want the CSYNC rejected", *c)
	}
}

// The agent's own combiner and signer are not peers: the combiner's
// agent-resync, an RFI SYNC for a zone the combiner is no member of, is not
// held to the RFI rules.
func TestTheAgentsOwnCombinerIsNotHeldToTheRFIRules(t *testing.T) {
	// the combiner is authorized by configuration, as initMPAgent adds it
	env := newIntegEnv(t, &integEnvConfig{CombinerID: "combiner.bob.example.",
		AuthorizedPeers: []string{"alice.agent.example.", "bob.agent.example.", "combiner.bob.example."}})
	bob := env.Bob.Identity
	const zone = "own.combiner.rfi.example."
	standingsZone(t, zone, []h3up{{bob, "", true}}, []string{bob}, nil)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	body, _ := json.Marshal(&DnsSyncPayload{MessageType: "rfi", OriginatorID: "combiner.bob.example.", YourIdentity: bob,
		Zone: zone, RfiType: "SYNC", Timestamp: time.Now().Unix()})
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, "combiner.bob.example.", nextDistributionID(), body)
	_ = env.Bob.Bridge.Router.Route(ctx, msgType)
	if refused(ctx) {
		t.Fatalf("the agent's own combiner's RFI SYNC was refused: %q", dispatchResponse(t, ctx))
	}
	if _, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout); !ok {
		t.Error("the combiner's RFI SYNC did not reach the agent")
	}
}

// A provider zone is not judged by its origin's standing at the combiner:
// what agents contribute of its record types, the _signal KEYs among them,
// is not a member's zone data.
func TestTheCombinerTakesAProviderZoneFromAnyOrigin(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "provider.origin.example.", false, false)
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNC3,
		Class: dns.ClassINET, Ttl: 3600}, Data: &core.HSYNC3{State: 1, Label: "us", Identity: csyncOurAgent, Upstream: "."}}}})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	resp := CombinerProcessUpdate(&CombinerSyncRequest{SenderID: "agent.gamma.example.", DeliveredBy: csyncOurAgent, Zone: mpzd.ZoneName, ZoneClass: "provider",
		Operations:     []core.RROperation{{Operation: "add", RRtype: "TXT", Records: []string{mpzd.ZoneName + " 3600 IN TXT \"p\""}}},
		DistributionID: nextDistributionID(), Timestamp: time.Now()}, nil, map[string]bool{csyncOurAgent: true}, hdb, nil)
	for _, r := range resp.RejectedItems {
		if strings.Contains(r.Reason, "voting member") {
			t.Errorf("a provider zone's contribution was refused for its origin's standing: %+v", r)
		}
	}
}

// On a zone whose edits wait for manual approval, an edit from an origin
// that does not vote is refused at once, and not kept for the operator.
func TestAManualApprovalZoneKeepsNoEditOfAnOriginThatDoesNotVote(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "manual.origin.example.", false, false)
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	var rrs []dns.RR
	for _, l := range []string{"us", "alpha", "beta"} {
		rrs = append(rrs, &dns.PrivateRR{Hdr: dns.RR_Header{Name: mpzd.ZoneName, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600},
			Data: &core.HSYNC3{State: 1, Label: l, Identity: "agent." + l + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: rrs})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.ZoneData.InstallInitialSnapshot()
	mpzd.Options[OptMPManualApproval] = true
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = hdb.KeyDB
	conf.SetMpConfig(&MultiProviderConf{Role: "combiner", Identity: csyncCombinerID})
	msgQs := &MsgQs{Msg: make(chan *AgentMsgPostPlus, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); CombinerMsgHandler(ctx, conf, msgQs, nil, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	rec := mpzd.ZoneName + " 3600 IN NS ns.gamma.example."
	for _, origin := range []string{"agent.gamma.example.", csyncLeaderA} {
		msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: AgentId(origin), DeliveredBy: csyncOurAgent,
			Zone: ZoneName(mpzd.ZoneName), DistributionID: nextDistributionID(),
			Operations: []core.RROperation{{Operation: "add", RRtype: "NS", Records: []string{rec}}}}}
	}
	waitUntil(t, "the voting origin's edit was not kept for approval", func() bool {
		edits, _ := ListPendingEdits(hdb, mpzd.ZoneName)
		return len(edits) > 0
	})
	edits, _ := ListPendingEdits(hdb, mpzd.ZoneName)
	for _, e := range edits {
		if e.SenderID == "agent.gamma.example." {
			t.Errorf("an edit of an origin that does not vote is kept for approval: %+v", e)
		}
	}
}

// The middleware compares with the transport's sender when the context
// names no peer: a payload that names another sender is refused all the
// same.
func TestTheSenderRuleFallsBackOnTheTransportSender(t *testing.T) {
	env, alice, bob := senderRuleEnv(t)
	// a beat, which no later check judges by its sender
	body, _ := json.Marshal(&transport.DnsBeatPayload{MessageType: "beat", MyIdentity: "carol.agent.example.", YourIdentity: bob,
		Zones: []string{dispatchZone}, Timestamp: time.Now().Unix()})
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, alice, nextDistributionID(), body)
	ctx.PeerID = "" // the transport sender alone
	_ = env.Bob.Bridge.Router.Route(ctx, msgType)
	if !refused(ctx) {
		t.Error("a payload naming another sender than the transport's was not refused")
	}
	if b, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Errorf("the beat reached MsgQs.Beat as %s's", b.Identity)
	}
}

// The agent's own signer is not a peer either: its RFI is not held to the
// rules.
func TestTheAgentsOwnSignerIsNotHeldToTheRFIRules(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizedPeers: []string{"alice.agent.example.", "bob.agent.example.", "signer.bob.example."}})
	bob := env.Bob.Identity
	env.Bob.Bridge.signerID = "signer.bob.example."
	const zone = "own.signer.rfi.example."
	standingsZone(t, zone, []h3up{{bob, "", true}}, []string{bob}, nil)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	body, _ := json.Marshal(&DnsSyncPayload{MessageType: "rfi", OriginatorID: "signer.bob.example.", YourIdentity: bob,
		Zone: zone, RfiType: "SYNC", Timestamp: time.Now().Unix()})
	ctx, msgType := buildDispatchContext(t, env.Bob.Bridge, "signer.bob.example.", nextDistributionID(), body)
	_ = env.Bob.Bridge.Router.Route(ctx, msgType)
	if refused(ctx) {
		t.Fatalf("the agent's own signer's RFI was refused: %q", dispatchResponse(t, ctx))
	}
}

// The operator is told that a request the peer refused on the wire was not
// taken, with the error, not that its answer timed out.
func TestTheOperatorIsToldARefusedRequestWasNotTaken(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := env.Alice.Identity, env.Bob.Identity
	const zone = "nottaken.config.example."
	standingsZone(t, zone, []h3up{{alice, "", true}, {bob, "", true}}, []string{alice, bob}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, env.Bob)
	peer := peerFromAddress(bob, ln.Addr().String())
	peer.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test: as after a completed handshake")
	if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
		t.Fatal(err)
	}
	agent := NewAgent(AgentId(bob))
	agent.DnsMethod = true
	// alice is not bob's downstream: bob refuses the request on the wire
	resp, sendErr := requestConfig(env.Alice.Registry, agent, zone, "upstream", env.Alice.MsgQs)
	if resp != nil || sendErr == nil {
		t.Fatalf("the refused request: %+v %v", resp, sendErr)
	}
	if got := notTaken(sendErr); !strings.HasPrefix(got, "not taken: ") {
		t.Errorf("the operator is told %q", got)
	}
}
