/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"encoding/json"
	"strings"
	"testing"

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
