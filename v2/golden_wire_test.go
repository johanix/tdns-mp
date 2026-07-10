/*
 * Golden-wire regression tests — the C0 gate (road-to-C Phase 4 / v3 C0.2).
 *
 * Stage C relocates the Dns*Payload types and collapses the MessageType
 * plumbing; its highest-consequence failure mode is SILENT wire drift (a
 * renamed JSON tag or verb that still compiles, still delivers, but no
 * longer dispatches on the other side). These tests lock today's wire:
 *
 *   - byte-exact JSON (tags + values) for the 13 Dns*Payload types,
 *   - the query-mode manifest (core.ManifestData + the metadata key
 *     convention from distrib.CreateManifestMetadata),
 *   - the wire verb set DetermineMessageType dispatches on.
 *
 * Any intentional wire change (e.g. C5's additive `envelope` field, F1's
 * Gossip→AppData rename) is made by regenerating the goldens with
 *
 *   go test -run TestGoldenWire -update ./...
 *
 * and REVIEWING the diff — never by hand-editing testdata. Goldens are
 * indented for reviewability; the wire itself is compact JSON with
 * identical tags/values.
 */
package tdnsmp

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/johanix/tdns-transport/v2/distrib"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

var updateGolden = flag.Bool("update", false, "rewrite golden wire testdata files")

// goldenWirePayloads returns fully-populated instances of every wire payload
// type (all fields set, including omitempty ones, so every tag is locked).
// Values are deterministic and distinctive so a swapped tag is caught.
func goldenWirePayloads() []struct {
	Name string
	V    interface{}
} {
	return []struct {
		Name string
		V    interface{}
	}{
		{"DnsHelloPayload", &transport.DnsHelloPayload{
			Type: "hello", SenderID: "legacy-sender.example.",
			Capabilities: []string{"cap-a", "cap-b"},
			SharedZones:  []string{"zone1.example.", "zone2.example."},
			Timestamp:    1700000001, Nonce: "hello-nonce",
			MessageType: "hello", MyIdentity: "me.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			Time: "2026-01-02T03:04:05Z",
		}},
		{"DnsBeatPayload", &transport.DnsBeatPayload{
			Type: "beat", SenderID: "legacy-sender.example.",
			Timestamp: 1700000002, Sequence: 42, State: "OPERATIONAL",
			MessageType: "beat", MyIdentity: "me.example.",
			YourIdentity: "you.example.", MyBeatInterval: 30,
			Zones:  []string{"zone1.example."},
			Time:   "2026-01-02T03:04:05Z",
			Gossip: json.RawMessage(`[{"group_hash":"gh1"}]`),
		}},
		{"DnsSyncPayload", &transport.DnsSyncPayload{
			MessageType: "sync", OriginatorID: "me.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			Nonce: "sync-nonce",
			Records: map[string][]string{
				"a.zone1.example.": {"a.zone1.example. 3600 IN A 192.0.2.1"},
			},
			Operations: []core.RROperation{{
				Operation: "add", RRtype: "A",
				Records: []string{"b.zone1.example. 3600 IN A 192.0.2.2"},
			}},
			Time: "2026-01-02T03:04:05Z", RfiType: "downstream",
			RfiSubtype: "ns", Timestamp: 1700000003,
			DistributionID: "dist-001", ZoneClass: "IN",
			Publish: &core.PublishInstruction{
				KEYRRs:    []string{"zone1.example. 3600 IN KEY 512 3 15 dGVzdA=="},
				CDSRRs:    []string{"zone1.example. 3600 IN CDS 12345 15 2 abcd"},
				Locations: []string{"at-apex", "at-ns"},
			},
		}},
		{"DnsRelocatePayload", &transport.DnsRelocatePayload{
			Type: "relocate", SenderID: "me.example.",
			NewAddress: transport.DnsAddress{
				Host: "192.0.2.3", Port: 5353, Transport: "udp", Path: "/x",
			},
			Reason: "ddos-mitigation", ValidUntil: 1700009999,
		}},
		{"DnsConfirmPayload", &transport.DnsConfirmPayload{
			Type: "confirm", SenderID: "me.example.", Zone: "zone1.example.",
			DistributionID: "dist-001", Nonce: "sync-nonce", Status: "ok",
			Message: "applied", AppliedCount: 2, RemovedCount: 1,
			RejectedCount:  1,
			AppliedRecords: []string{"a.zone1.example. 3600 IN A 192.0.2.1"},
			RemovedRecords: []string{"old.zone1.example. 3600 IN A 192.0.2.9"},
			RejectedItems: []transport.RejectedItemDTO{
				{Record: "bad.zone1.example. 3600 IN A 192.0.2.66", Reason: "not yours"},
			},
			IgnoredCount:   1,
			IgnoredRecords: []string{"dup.zone1.example. 3600 IN A 192.0.2.1"},
			Truncated:      true, Timestamp: 1700000004,
		}},
		{"DnsPingPayload", &transport.DnsPingPayload{
			Type: "ping", SenderID: "legacy-sender.example.",
			Nonce: "ping-nonce", Timestamp: 1700000005,
			MessageType: "ping", MyIdentity: "me.example.",
			YourIdentity: "you.example.", Time: "2026-01-02T03:04:05Z",
		}},
		{"DnsKeystatePayload", &transport.DnsKeystatePayload{
			MessageType: "keystate", MyIdentity: "me.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			KeyTag: 12345, Algorithm: 15, Signal: "inventory",
			Message: "full set",
			KeyInventory: []transport.KeyInventoryEntry{{
				KeyTag: 12345, Algorithm: 15, Flags: 257,
				State: "active",
				KeyRR: "zone1.example. 3600 IN DNSKEY 257 3 15 dGVzdA==",
			}},
			Timestamp: 1700000006, Type: "keystate",
			SenderID: "legacy-sender.example.",
		}},
		{"DnsKeystateConfirmPayload", &transport.DnsKeystateConfirmPayload{
			Type: "keystate_confirm", SenderID: "me.example.",
			Zone: "zone1.example.", KeyTag: 12345, Signal: "inventory",
			Status: "ok", Message: "ack", Timestamp: 1700000007,
		}},
		{"DnsEditsPayload", &transport.DnsEditsPayload{
			MessageType: "edits", MyIdentity: "combiner.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			AgentRecords: map[string]map[string][]string{
				"me.example.": {
					"a.zone1.example.": {"a.zone1.example. 3600 IN A 192.0.2.1"},
				},
			},
			Message: "current contributions", Timestamp: 1700000008,
			Type: "edits", SenderID: "legacy-sender.example.",
		}},
		{"DnsConfigPayload", &transport.DnsConfigPayload{
			MessageType: "config", MyIdentity: "me.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			Subtype:    "policy",
			ConfigData: map[string]string{"key1": "val1", "key2": "val2"},
			Message:    "config response", Timestamp: 1700000009,
			Type: "config", SenderID: "legacy-sender.example.",
		}},
		{"DnsAuditPayload", &transport.DnsAuditPayload{
			MessageType: "audit", MyIdentity: "me.example.",
			YourIdentity: "auditor.example.", Zone: "zone1.example.",
			AuditData: map[string]interface{}{"check": "ok", "count": 3},
			Message:   "audit response", Timestamp: 1700000010,
			Type: "audit", SenderID: "legacy-sender.example.",
		}},
		{"DnsStatusUpdatePayload", &transport.DnsStatusUpdatePayload{
			MessageType: "status-update", MyIdentity: "combiner.example.",
			YourIdentity: "you.example.", Zone: "zone1.example.",
			SubType:   "delegation-change",
			NSRecords: []string{"zone1.example. 3600 IN NS ns1.example."},
			DSRecords: []string{"zone1.example. 3600 IN DS 12345 15 2 abcd"},
			Result:    "ok", Msg: "parent synced", Timestamp: 1700000011,
			Type: "status-update", SenderID: "legacy-sender.example.",
		}},
		{"DnsPingConfirmPayload", &transport.DnsPingConfirmPayload{
			Type: "ping_confirm", SenderID: "you.example.",
			Nonce: "ping-nonce", DistributionID: "dist-002",
			Status: "ok", Message: "pong", Timestamp: 1700000012,
		}},
		{"ManifestData", &core.ManifestData{
			ChunkCount: 3, ChunkSize: 512,
			Metadata: map[string]interface{}{
				"content":         "key_operations",
				"distribution_id": "dist-003",
				"receiver_id":     "you.example.",
				"timestamp":       int64(1700000013),
			},
			Payload: []byte("inline-payload"),
		}},
	}
}

func TestGoldenWirePayloads(t *testing.T) {
	dir := filepath.Join("testdata", "golden-wire")
	if *updateGolden {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range goldenWirePayloads() {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := json.MarshalIndent(tc.V, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got = append(got, '\n')
			path := filepath.Join(dir, tc.Name+".json")
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run `go test -run TestGoldenWire -update`): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("WIRE DRIFT in %s — JSON no longer matches the golden.\n"+
					"If this change is INTENTIONAL (a planned wire change), regenerate with\n"+
					"`go test -run TestGoldenWire -update ./...` and review the diff.\n--- got ---\n%s\n--- want ---\n%s",
					tc.Name, got, want)
			}
		})
	}
}

// TestGoldenWireVerbs locks the wire verb set: the "MessageType" values
// DetermineMessageType dispatches on. A verb that disappears here delivers
// but no longer dispatches on an un-upgraded receiver — exactly the silent
// failure C6's wire-safety gate exists to prevent.
func TestGoldenWireVerbs(t *testing.T) {
	verbs := []string{
		"hello", "beat", "sync", "update", "ping", "confirm", "relocate",
		"rfi", "keystate", "edits", "config", "audit", "status-update",
	}
	for _, verb := range verbs {
		payload := []byte(`{"MessageType":"` + verb + `"}`)
		if got := transport.DetermineMessageType(payload); string(got) != verb {
			t.Errorf("verb %q no longer dispatches (got %q) — wire break for un-upgraded peers", verb, got)
		}
	}
	// And an unknown verb must stay unknown (the strictness the mixed-fleet
	// runbook relies on).
	if got := transport.DetermineMessageType([]byte(`{"MessageType":"no-such-verb"}`)); got != transport.MessageTypeUnknown {
		t.Errorf("unknown verb dispatched as %q", got)
	}
}

// TestGoldenWireManifestMetadata locks the metadata key CONVENTION that
// query-mode receivers read (content / distribution_id / receiver_id /
// timestamp). Values vary at runtime; the key set must not.
func TestGoldenWireManifestMetadata(t *testing.T) {
	md := distrib.CreateManifestMetadata("key_operations", "dist-004", "you.example.",
		map[string]interface{}{"extra": "x"})
	for _, key := range []string{"content", "distribution_id", "receiver_id", "timestamp", "extra"} {
		if _, ok := md[key]; !ok {
			t.Errorf("manifest metadata lost key %q", key)
		}
	}
	if md["content"] != "key_operations" {
		t.Errorf("manifest content = %v, want key_operations", md["content"])
	}
}
