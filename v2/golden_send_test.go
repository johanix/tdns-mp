/*
 * Send-side golden-wire tests (C2). The receive side is locked by
 * golden_wire_test.go; this locks the bytes the application-side payload
 * builders in mp_send.go put into an AppMessage, so that C4 (types out)
 * and any later change cannot silently alter what a peer receives.
 *
 * Regenerate deliberately with `go test -run TestGoldenWireSend -update ./...`
 * and review the diff.
 */

package tdnsmp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

func goldenSendMessages(t *testing.T) []struct {
	Name string
	Msg  *transport.AppMessage
} {
	t.Helper()
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const me, you, zone = "me.example.", "you.example.", "zone1.example."
	must := func(m *transport.AppMessage, err error) *transport.AppMessage {
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	syncReq := func(verb string) *transport.SyncRequest {
		return &transport.SyncRequest{
			SenderID: me, Zone: zone, MessageType: verb,
			Records: map[string][]string{"a.zone1.example.": {"a.zone1.example. 3600 IN A 192.0.2.1"}},
			Operations: []core.RROperation{{Operation: "add", RRtype: "A",
				Records: []string{"b.zone1.example. 3600 IN A 192.0.2.2"}}},
			Timestamp: ts, DistributionID: "dist-001", Nonce: "sync-nonce",
			RfiType: "downstream", RfiSubtype: "ns", ZoneClass: "IN",
			Publish: &core.PublishInstruction{
				KEYRRs:    []string{"zone1.example. 3600 IN KEY 512 3 15 dGVzdA=="},
				CDSRRs:    []string{"zone1.example. 3600 IN CDS 12345 15 2 abcd"},
				Locations: []string{"at-apex", "at-ns"},
			},
		}
	}
	return []struct {
		Name string
		Msg  *transport.AppMessage
	}{
		{"send-sync", must(syncAppMessage(syncReq("sync"), you))},
		{"send-sync-default", must(syncAppMessage(syncReq(""), you))},
		{"send-update", must(syncAppMessage(syncReq("update"), you))},
		{"send-rfi", must(syncAppMessage(syncReq("rfi"), you))},
		{"send-keystate-inventory", must(keystateAppMessage(&transport.KeystateRequest{
			SenderID: me, Zone: zone, Signal: "inventory", Message: "full set", Timestamp: ts,
			KeyInventory: []transport.KeyInventoryEntry{{KeyTag: 12345, Algorithm: 15, Flags: 257, State: "active",
				KeyRR: "zone1.example. 3600 IN DNSKEY 257 3 15 dGVzdA=="}},
		}, you))},
		{"send-keystate-signal", must(keystateAppMessage(&transport.KeystateRequest{
			SenderID: me, Zone: zone, KeyTag: 12345, Algorithm: 15, Signal: "propagated", Message: "ok", Timestamp: ts,
		}, you))},
		{"send-edits", must(editsAppMessage(&transport.EditsRequest{
			SenderID: "combiner.example.", Zone: zone, Message: "current contributions", Timestamp: ts,
			AgentRecords: map[string]map[string][]string{me: {"a.zone1.example.": {"a.zone1.example. 3600 IN A 192.0.2.1"}}},
		}, you))},
		{"send-config", must(configAppMessage(&transport.ConfigRequest{
			SenderID: me, Zone: zone, Subtype: "policy", ConfigData: map[string]string{"key1": "val1", "key2": "val2"},
			Message: "config response", Timestamp: ts,
		}, you))},
		{"send-audit", must(auditAppMessage(&transport.AuditRequest{
			SenderID: me, Zone: zone, AuditData: map[string]interface{}{"check": "ok", "count": 3},
			Message: "audit response", Timestamp: ts,
		}, "auditor.example."))},
		{"send-status-update", must(statusUpdateAppMessage(&core.StatusUpdatePost{
			Zone: zone, SubType: "delegation-change",
			NSRecords: []string{"zone1.example. 3600 IN NS ns1.example."},
			DSRecords: []string{"zone1.example. 3600 IN DS 12345 15 2 abcd"},
			Result:    "ok", Msg: "parent synced", Time: ts,
		}, "combiner.example.", you))},
	}
}

func TestGoldenWireSendPayloads(t *testing.T) {
	dir := filepath.Join("testdata", "golden-wire")
	wantMeta := map[string]struct {
		token, scope, dist string
		fireAndForget      bool
	}{
		"send-sync":               {"sync", "zone1.example.", "dist-001", false},
		"send-sync-default":       {"sync", "zone1.example.", "dist-001", false},
		"send-update":             {"update", "zone1.example.", "dist-001", false},
		"send-rfi":                {"rfi", "zone1.example.", "dist-001", false},
		"send-keystate-inventory": {"keystate", "zone1.example.", "", false},
		"send-keystate-signal":    {"keystate", "zone1.example.", "", false},
		"send-edits":              {"edits", "zone1.example.", "", false},
		"send-config":             {"config", "zone1.example.", "", false},
		"send-audit":              {"audit", "zone1.example.", "", false},
		"send-status-update":      {"status-update", "zone1.example.", "", true},
	}
	for _, tc := range goldenSendMessages(t) {
		t.Run(tc.Name, func(t *testing.T) {
			m := wantMeta[tc.Name]
			if tc.Msg.TypeToken != m.token || tc.Msg.Scope != m.scope || tc.Msg.DistributionID != m.dist || tc.Msg.FireAndForget != m.fireAndForget {
				t.Errorf("carrier metadata: got {%s %s %q %v}, want {%s %s %q %v}", tc.Msg.TypeToken, tc.Msg.Scope,
					tc.Msg.DistributionID, tc.Msg.FireAndForget, m.token, m.scope, m.dist, m.fireAndForget)
			}
			// The verb inside the payload must be the carrier's TypeToken
			// (the receiver dispatches on the payload, not the carrier).
			if got := transport.DetermineMessageType(tc.Msg.Payload); string(got) != tc.Msg.TypeToken {
				t.Errorf("payload MessageType %q != TypeToken %q", got, tc.Msg.TypeToken)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, tc.Msg.Payload, "", "  "); err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
			got := append(pretty.Bytes(), '\n')
			path := filepath.Join(dir, tc.Name+".json")
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run `go test -run TestGoldenWireSend -update`): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("SEND WIRE DRIFT in %s.\n--- got ---\n%s\n--- want ---\n%s", tc.Name, got, want)
			}
		})
	}
}
