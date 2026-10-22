/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// The named-sender SYNC carries the other identity in the payload. The
// transport sender is not in the request at all.
func TestInjectNamedSenderRequestNamesAnotherSender(t *testing.T) {
	const (
		named = "agent.c.example."
		zone  = "z.example."
		rr    = "z.example. 60 IN NS ns9.injected.example."
		dist  = "debug-inject-named-sender-1"
	)
	req := injectNamedSenderRequest(zone, named, []string{rr}, dist)
	if req.SenderID != named {
		t.Errorf("SenderID %q, want the named sender %q", req.SenderID, named)
	}
	if req.MessageType != "sync" || req.DistributionID != dist || req.Zone != zone {
		t.Errorf("request %+v", req)
	}
	if got := req.Records["z.example."]; len(got) != 1 || got[0] != rr {
		t.Errorf("records %v, want %q under z.example.", req.Records, rr)
	}

	msg, err := syncAppMessage(req, "agent.b.example.")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		OriginatorID   string `json:"OriginatorID"`
		DistributionID string `json:"distribution_id"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.OriginatorID != named || payload.DistributionID != dist {
		t.Errorf("wire originator %q distribution %q, want %q and %q", payload.OriginatorID, payload.DistributionID, named, dist)
	}
}

// The combiner update's origin is the identity that does not vote, and each
// RR type is one add.
func TestInjectCombinerUpdateCarriesTheOrigin(t *testing.T) {
	const (
		origin = "agent.d.example."
		zone   = "z.example."
	)
	ns1, err := dns.NewRR(zone + " 60 IN NS ns9.injected.example.")
	if err != nil {
		t.Fatal(err)
	}
	ns2, err := dns.NewRR(zone + " 60 IN NS ns8.injected.example.")
	if err != nil {
		t.Fatal(err)
	}
	a, err := dns.NewRR(zone + " 60 IN A 192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	zu, err := injectCombinerUpdate(zone, origin, []string{ns1.String(), a.String(), ns2.String()})
	if err != nil {
		t.Fatal(err)
	}
	if zu.AgentId != AgentId(origin) || zu.Zone != ZoneName(zone) {
		t.Errorf("update origin %q zone %q, want %q %q", zu.AgentId, zu.Zone, origin, zone)
	}
	if len(zu.Operations) != 2 {
		t.Fatalf("operations %+v, want one add per RR type", zu.Operations)
	}
	ns := zu.Operations[0]
	if ns.Operation != "add" || ns.RRtype != "NS" || len(ns.Records) != 2 || ns.Records[0] != ns1.String() || ns.Records[1] != ns2.String() {
		t.Errorf("NS operation %+v", ns)
	}
	if zu.Operations[1].Operation != "add" || zu.Operations[1].RRtype != "A" || len(zu.Operations[1].Records) != 1 || zu.Operations[1].Records[0] != a.String() {
		t.Errorf("A operation %+v", zu.Operations[1])
	}
}

// The KEYSTATE is from this agent and carries no keys.
func TestInjectKeystateRequestIsThisAgentWithAnEmptyInventory(t *testing.T) {
	const (
		self = "agent.a.example."
		zone = "z.example."
	)
	req := injectKeystateRequest(self, zone)
	if req.SenderID != self || req.Zone != zone || req.Signal != "inventory" || req.Owned {
		t.Errorf("request %+v", req)
	}
	if len(req.KeyInventory) != 0 {
		t.Errorf("inventory %+v, want none", req.KeyInventory)
	}

	msg, err := keystateAppMessage(req, "agent.b.example.")
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		MyIdentity   string            `json:"MyIdentity"`
		Signal       string            `json:"Signal"`
		KeyInventory []json.RawMessage `json:"KeyInventory"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.MyIdentity != self || payload.Signal != "inventory" || len(payload.KeyInventory) != 0 {
		t.Errorf("wire sender %q signal %q keys %d", payload.MyIdentity, payload.Signal, len(payload.KeyInventory))
	}
}

// A nil peer is an error. The check is before the payload is built, so it
// does not panic on peer.ID.
func TestSendSyncOnceRejectsANilPeer(t *testing.T) {
	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{}}
	resp, via, err := tm.sendSyncOnce(context.Background(), nil, &PeerSyncRequest{SenderID: "agent.c.example."})
	if err == nil || resp != nil || via != "" {
		t.Fatalf("nil peer: resp %v transport %q err %v", resp, via, err)
	}
}

// The injector stays off unless the agent's options list names it. A closed
// agent refuses before it looks for a transport.
func TestInjectIsRefusedUnlessTheAgentAllowsIt(t *testing.T) {
	conf := &Config{}
	amp := AgentMgmtPost{
		AgentId: "agent.b.example.",
		Zone:    "z.example.",
		RRs:     []string{"z.example. 60 IN NS ns9.injected.example."},
		Data:    map[string]interface{}{"as": "agent.c.example."},
	}
	resp := &AgentMgmtResponse{}
	conf.debugInjectNamedSender(amp, resp)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "allow-inject") {
		t.Fatalf("a closed injector answered %+v", resp)
	}

	mp := &MultiProviderConf{AgentOptionsStrs: []string{"allow-inject"}}
	parseMultiProviderOptions(mp)
	if !mp.AgentOptions[AgentOptAllowInject] {
		t.Fatal("allow-inject did not parse")
	}
	conf.InternalMp.mpConfig.Store(mp)
	resp = &AgentMgmtResponse{}
	conf.debugInjectNamedSender(amp, resp)
	if strings.Contains(resp.ErrorMsg, "allow-inject") {
		t.Fatalf("an allowed injector was refused: %s", resp.ErrorMsg)
	}
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "TransportManager") {
		t.Fatalf("an allowed injector with no transport answered %+v", resp)
	}
}

// An inject hello stays off unless the agent's options list names it, as the
// other injectors do. An allowed one reads its bounds before it looks for a
// transport, so a value out of bounds is refused with nothing sent.
func TestInjectHelloIsRefusedUnlessTheAgentAllowsIt(t *testing.T) {
	conf := &Config{}
	amp := AgentMgmtPost{AgentId: "agent.b.example.", Data: map[string]interface{}{"count": "3"}}
	resp := &AgentMgmtResponse{}
	conf.debugInjectHello(amp, resp)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "allow-inject") {
		t.Fatalf("a closed injector answered %+v", resp)
	}

	mp := &MultiProviderConf{AgentOptionsStrs: []string{"allow-inject"}}
	parseMultiProviderOptions(mp)
	conf.InternalMp.mpConfig.Store(mp)
	resp = &AgentMgmtResponse{}
	conf.debugInjectHello(AgentMgmtPost{AgentId: "agent.b.example.", Data: map[string]interface{}{"count": "201"}}, resp)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "count") || resp.Data != nil {
		t.Fatalf("a count out of bounds answered %+v", resp)
	}
	resp = &AgentMgmtResponse{}
	conf.debugInjectHello(amp, resp)
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "TransportManager") || resp.Data != nil {
		t.Fatalf("an allowed injector with no transport answered %+v", resp)
	}
}

// The count, the interval and the mechanism default as the CLI does, and a
// value outside the bounds, or one that does not parse, is refused.
func TestInjectHelloParamsKeepToTheBounds(t *testing.T) {
	count, interval, mech, err := injectHelloParams(nil)
	if err != nil || count != 40 || interval != 500*time.Millisecond || mech != "DNS" {
		t.Errorf("defaults: %d %s %s %v, want 40 500ms DNS", count, interval, mech, err)
	}
	count, interval, mech, err = injectHelloParams(map[string]interface{}{"count": "200", "interval": "100ms", "mechanism": "API"})
	if err != nil || count != 200 || interval != 100*time.Millisecond || mech != "API" {
		t.Errorf("the edges: %d %s %s %v, want 200 100ms API", count, interval, mech, err)
	}
	for _, bad := range []map[string]interface{}{
		{"count": "0"}, {"count": "201"}, {"count": "many"},
		{"interval": "50ms"}, {"interval": "11s"}, {"interval": "soon"},
		{"mechanism": "smtp"},
	} {
		if _, _, _, err := injectHelloParams(bad); err == nil {
			t.Errorf("%v was taken", bad)
		}
	}
}

// The hello an injector sends is this agent's, with the zones it shares with
// the target: only its rate lies.
func TestInjectHelloRequestIsThisAgents(t *testing.T) {
	req := injectHelloRequest("agent.a.example.", []ZoneName{"z1.example.", "z2.example."})
	if req.SenderID != "agent.a.example." {
		t.Errorf("SenderID %q, want this agent", req.SenderID)
	}
	if strings.Join(req.SharedZones, " ") != "z1.example. z2.example." {
		t.Errorf("shared zones %v", req.SharedZones)
	}
	if strings.Join(req.Capabilities, " ") != "sync beat relocate" || req.Timestamp.IsZero() {
		t.Errorf("request %+v, want the capabilities and a time as SendHelloWithFallback sends", req)
	}
}
