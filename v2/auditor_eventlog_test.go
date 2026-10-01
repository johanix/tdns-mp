/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// The event log's details column holds what each message carried, in the
// message's own printable form (tdns-mp #102). These tests go through the
// auditor's real paths: the engine logs the event, and the API, the web
// fragment and the CLI read it back.

func newEventLogTestDB(t *testing.T) *tdns.KeyDB {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	if err := InitAuditEventLogTable(kdb); err != nil {
		t.Fatalf("InitAuditEventLogTable: %v", err)
	}
	return kdb
}

func onlyEvent(t *testing.T, kdb *tdns.KeyDB) AuditEvent {
	t.Helper()
	events, err := QueryAuditEvents(kdb, "", time.Time{}, 0)
	if err != nil {
		t.Fatalf("QueryAuditEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("%d events logged, want 1", len(events))
	}
	return events[0]
}

func testDNSKEYSync(t *testing.T) (*AgentMsgPostPlus, uint16) {
	t.Helper()
	ksk, kskTag := testDNSKEY(t, 257, testKSKPub)
	return &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType:    AgentMsgNotify,
		OriginatorID:   "agent.p1.example.",
		Zone:           "example.com.",
		DistributionID: "d-1",
		Operations: []core.RROperation{{
			Operation: "add", RRtype: "DNSKEY", Records: []string{ksk},
			KeyStates: []core.KeyState{{KeyTag: kskTag, State: "published", DS: boolp(true)}},
		}},
	}}, kskTag
}

func TestTheEventLogRecordsWhatASyncCarried(t *testing.T) {
	kdb := newEventLogTestDB(t)
	e := &AuditorEngine{auditLog: kdb}
	msg, kskTag := testDNSKEYSync(t)
	e.recordSyncMsg(msg)

	ev := onlyEvent(t, kdb)
	if ev.Details != msg.Describe() {
		t.Errorf("details = %q, want the message's own description %q", ev.Details, msg.Describe())
	}
	wantLines(t, ev.Details, fmt.Sprintf("key %d (KSK): DS yes, published", kskTag), "distribution: d-1")

	got, err := GetAuditEvent(kdb, ev.ID)
	if err != nil || got == nil {
		t.Fatalf("GetAuditEvent(%d) = %v, %v", ev.ID, got, err)
	}
	if got.Details != ev.Details || got.Summary != ev.Summary || !got.Time.Equal(ev.Time) {
		t.Errorf("GetAuditEvent(%d) = %+v, want %+v", ev.ID, *got, ev)
	}
	if got, err := GetAuditEvent(kdb, ev.ID+1000); got != nil || err != nil {
		t.Errorf("GetAuditEvent of an id that does not exist = %v, %v; want nil, nil", got, err)
	}
}

func dnskeySetSync(t *testing.T, sender string, zskState string) *AgentMsgPostPlus {
	t.Helper()
	ksk, kskTag := testDNSKEY(t, 257, testKSKPub)
	zsk, zskTag := testDNSKEY(t, 256, testZSKPub)
	return &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType:  AgentMsgNotify,
		OriginatorID: AgentId(sender),
		Zone:         "example.com.",
		Operations: []core.RROperation{{
			Operation: "replace", RRtype: "DNSKEY", Records: []string{ksk, zsk},
			KeyStates: []core.KeyState{
				{KeyTag: kskTag, State: "active", DS: boolp(true)},
				{KeyTag: zskTag, State: zskState, DS: boolp(false)},
			},
		}},
	}}
}

// A provider resends its whole DNSKEY set; the row says what the message
// carries, and the details show which key changed state since the same
// sender's previous distribution for the zone.
func TestTheEventLogShowsWhatChangedSinceTheSendersLastSync(t *testing.T) {
	kdb := newEventLogTestDB(t)
	e := &AuditorEngine{auditLog: kdb}
	e.recordSyncMsg(dnskeySetSync(t, "agent.p1.example.", "published"))
	e.recordSyncMsg(dnskeySetSync(t, "agent.p1.example.", "standby"))
	e.recordSyncMsg(dnskeySetSync(t, "agent.p2.example.", "standby"))

	events, err := QueryAuditEvents(kdb, "", time.Time{}, 0)
	if err != nil || len(events) != 3 {
		t.Fatalf("QueryAuditEvents = %d events, %v", len(events), err)
	}
	slices.SortFunc(events, func(a, b AuditEvent) int { return int(a.ID - b.ID) })
	_, kskTag := testDNSKEY(t, 257, testKSKPub)
	_, zskTag := testDNSKEY(t, 256, testZSKPub)
	for i, ev := range events {
		if ev.Summary != "replace DNSKEY (2 records)" {
			t.Errorf("event %d summary = %q, want the operation", i, ev.Summary)
		}
	}
	if strings.Contains(events[0].Details, "(was") || strings.Contains(events[0].Details, "(new)") {
		t.Errorf("the first sync from a sender shows changes:\n%s", events[0].Details)
	}
	wantLines(t, events[1].Details,
		fmt.Sprintf("key %d (ZSK): DS no, standby (was: published)", zskTag),
		fmt.Sprintf("key %d (KSK): DS yes, active\n", kskTag),
	)
	if strings.Contains(events[2].Details, "(was") {
		t.Errorf("another sender's sync is compared with the first sender's:\n%s", events[2].Details)
	}
}

func TestTheEventLogRecordsWhatAnRfiCarried(t *testing.T) {
	kdb := newEventLogTestDB(t)
	e := &AuditorEngine{auditLog: kdb}
	e.recordSyncMsg(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType: AgentMsgRfi, OriginatorID: "agent.p1.example.", Zone: "example.com.", RfiType: "ELECT-CALL",
	}})
	wantLines(t, onlyEvent(t, kdb).Details, "RFI from agent.p1.example.", "rfi: ELECT-CALL")
}

// A confirmation and a hello reach the log through the engine's other
// consumers: runAux and the hello adapter.
func TestTheEventLogRecordsConfirmationsAndHellos(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kdb := newEventLogTestDB(t)
	e := &AuditorEngine{auditLog: kdb}
	msgQs := &MsgQs{Confirmation: make(chan *ConfirmationDetail, 1)}
	go e.runAux(ctx, msgQs)
	confirm := &ConfirmationDetail{
		DistributionID: "d-1", Zone: "example.com.", Source: "agent.p2.example.", Status: "ok",
		AppliedRecords: []string{"example.com. 3600 IN NS ns1.p1.example."},
	}
	msgQs.Confirmation <- confirm
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := QueryAuditEvents(kdb, "", time.Time{}, 0)
		if err != nil {
			t.Fatalf("QueryAuditEvents: %v", err)
		}
		if len(events) == 1 {
			if events[0].Details != confirm.Describe() {
				t.Errorf("confirm details = %q, want %q", events[0].Details, confirm.Describe())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the confirmation was not logged")
		}
		time.Sleep(10 * time.Millisecond)
	}

	kdb = newEventLogTestDB(t)
	in := make(chan *AgentMsgReport, 1)
	out := adaptHelloReports(ctx, in, nil, kdb, nil)
	hello := &AgentMsgReport{MessageType: AgentMsgHello, Identity: "agent.p1.example.", Zone: "example.com.", Transport: "dns"}
	in <- hello
	select {
	case <-out:
	case <-time.After(5 * time.Second):
		t.Fatal("the hello was not passed on")
	}
	if got := onlyEvent(t, kdb).Details; got != hello.Describe() {
		t.Errorf("hello details = %q, want %q", got, hello.Describe())
	}
}

func auditAPI(t *testing.T, conf *Config, req AuditPost) AuditResponse {
	t.Helper()
	body, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	conf.APIauditor()(rec, httptest.NewRequest("POST", "/api/v1/auditor", bytes.NewReader(body)))
	var resp AuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response %q: %v", rec.Body.String(), err)
	}
	return resp
}

func TestEventlogShowReturnsOneEventWithItsDetails(t *testing.T) {
	kdb := newEventLogTestDB(t)
	msg, _ := testDNSKEYSync(t)
	(&AuditorEngine{auditLog: kdb}).recordSyncMsg(msg)
	ev := onlyEvent(t, kdb)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb

	resp := auditAPI(t, conf, AuditPost{Command: "eventlog-show", ID: ev.ID})
	if resp.Error || len(resp.Events) != 1 || resp.Events[0].Details != msg.Describe() {
		t.Errorf("eventlog-show %d = %+v; want the event with its details", ev.ID, resp)
	}
	if resp := auditAPI(t, conf, AuditPost{Command: "eventlog-show"}); !resp.Error {
		t.Errorf("eventlog-show without an id = %+v; want an error", resp)
	}
	if resp := auditAPI(t, conf, AuditPost{Command: "eventlog-show", ID: ev.ID + 1000}); !resp.Error || !strings.Contains(resp.ErrorMsg, "no event") {
		t.Errorf("eventlog-show of an unknown id = %+v; want \"no event\"", resp)
	}
}

func webGet(t *testing.T, mux *http.ServeMux, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

// Each row with details expands in place: a click loads the event-details
// fragment into a row of its own below it, and the event's tbody is kept
// across the list's periodic refresh, so an open row stays open.
func TestTheEventLogPageExpandsARowToItsDetails(t *testing.T) {
	kdb := newEventLogTestDB(t)
	now := time.Now()
	if err := InsertAuditEvent(kdb, &AuditEvent{Time: now, Zone: "example.com.", Originator: "agent.p1.example.",
		EventType: "sync", Summary: "sync with details", Details: "SYNC from agent.p1.example.\n  add TXT <b>"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertAuditEvent(kdb, &AuditEvent{Time: now.Add(-time.Minute), Zone: "example.com.", Originator: "agent.p1.example.",
		EventType: "hello", Summary: "an older event"}); err != nil {
		t.Fatal(err)
	}
	events, err := QueryAuditEvents(kdb, "", time.Time{}, 0)
	if err != nil || len(events) != 2 {
		t.Fatalf("QueryAuditEvents = %d events, %v", len(events), err)
	}
	withID, withoutID := events[0].ID, events[1].ID

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	ws, err := newAuditorWebServer(conf, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ws.registerRoutes(mux, func(h http.HandlerFunc) http.HandlerFunc { return h })

	rows := webGet(t, mux, "/web/fragment/eventlog-rows")
	wantLines(t, rows,
		fmt.Sprintf(`<tbody class="audit-event" id="audit-event-%d" hx-preserve>`, withID),
		fmt.Sprintf(`hx-get="/web/fragment/event-details?id=%d"`, withID),
		fmt.Sprintf(`hx-target="#audit-event-%d-details"`, withID),
		`hx-trigger="click once"`,
		`<td><code>SYNC</code></td>`,
		fmt.Sprintf(`<td colspan="7" id="audit-event-%d-details">`, withID),
		fmt.Sprintf(`<tbody class="audit-event" id="audit-event-%d" hx-preserve>`, withoutID),
	)
	if strings.Contains(rows, fmt.Sprintf("event-details?id=%d", withoutID)) {
		t.Errorf("a row with no details is clickable:\n%s", rows)
	}

	details := webGet(t, mux, fmt.Sprintf("/web/fragment/event-details?id=%d", withID))
	wantLines(t, details, `<pre class="audit-event-details">SYNC from agent.p1.example.`, "add TXT &lt;b&gt;")
	wantLines(t, webGet(t, mux, fmt.Sprintf("/web/fragment/event-details?id=%d", withoutID)), "No details were recorded")
	wantLines(t, webGet(t, mux, "/web/fragment/event-details?id=999999"), "Event not found")
	wantLines(t, webGet(t, mux, "/web/fragment/event-details?id=nonsense"), "Event not found")
}
