/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"strings"
	"testing"
	"time"
)

func TestInjectReport(t *testing.T) {
	taken := injectReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"target":          "agent.b.example.",
		"zone":            "z.example.",
		"distribution_id": "debug-inject-named-sender-1",
		"status":          "SUCCESS",
		"message":         "applied",
	}}, "named-sender", "", "")
	const wantTaken = "inject named-sender: agent.b.example. zone z.example. distribution debug-inject-named-sender-1: SUCCESS applied"
	if taken != wantTaken {
		t.Errorf("taken line %q, want %q", taken, wantTaken)
	}

	refused := injectReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"target":          "agent.b.example.",
		"zone":            "z.example.",
		"distribution_id": "debug-inject-named-sender-1",
		"status":          "REFUSED",
	}}, "named-sender", "agent.b.example.", "z.example.")
	const wantRefused = "inject named-sender: agent.b.example. zone z.example. distribution debug-inject-named-sender-1: REFUSED"
	if refused != wantRefused {
		t.Errorf("refused line %q, want %q", refused, wantRefused)
	}

	failed := injectReport(&AgentMgmtResponse{Error: true, ErrorMsg: "the send failed", Data: map[string]interface{}{
		"target":          "agent.b.example.",
		"zone":            "z.example.",
		"distribution_id": "debug-inject-named-sender-1",
		"status":          "SUCCESS",
		"message":         "applied",
		"error":           "DNS sync to agent.b.example.: NOTIFY exchange failed: i/o timeout",
	}}, "named-sender", "agent.b.example.", "z.example.")
	const wantFailed = "inject named-sender: agent.b.example. zone z.example. distribution debug-inject-named-sender-1: error: DNS sync to agent.b.example.: NOTIFY exchange failed: i/o timeout"
	if failed != wantFailed {
		t.Errorf("failed line %q, want %q", failed, wantFailed)
	}

	enqueued := injectReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"combiner":        "combiner.a.example.",
		"zone":            "z.example.",
		"distribution_id": "debug-inject-combiner-origin-1",
		"origin":          "agent.d.example.",
	}}, "combiner-origin", "", "z.example.")
	const wantEnqueued = "inject combiner-origin: combiner.a.example. zone z.example. distribution debug-inject-combiner-origin-1:"
	if enqueued != wantEnqueued {
		t.Errorf("enqueued line %q, want %q", enqueued, wantEnqueued)
	}

	takenKeystate := injectReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"target":   "agent.b.example.",
		"zone":     "z.example.",
		"accepted": true,
		"status":   "ACCEPTED",
	}}, "peer-keystate", "agent.b.example.", "z.example.")
	const wantTakenKeystate = "inject peer-keystate: agent.b.example. zone z.example.: ACCEPTED"
	if takenKeystate != wantTakenKeystate {
		t.Errorf("taken keystate line %q, want %q", takenKeystate, wantTakenKeystate)
	}

	declined := injectReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"target":  "agent.b.example.",
		"zone":    "z.example.",
		"status":  "NOT ACCEPTED",
		"message": "empty inventory",
	}}, "peer-keystate", "", "")
	const wantDeclined = "inject peer-keystate: agent.b.example. zone z.example.: NOT ACCEPTED empty inventory"
	if declined != wantDeclined {
		t.Errorf("declined keystate line %q, want %q", declined, wantDeclined)
	}
}

func TestDebugInjectCommandsAreWired(t *testing.T) {
	var injectName string
	for _, c := range debugAgentLeaves("agent") {
		if c.Name() == "inject" {
			injectName = c.Name()
			got := map[string]bool{}
			for _, sub := range c.Commands() {
				got[sub.Name()] = true
			}
			for _, name := range []string{"named-sender", "combiner-origin", "peer-keystate", "hello", "replace"} {
				if !got[name] {
					t.Errorf("inject is missing %s", name)
				}
			}
			if strings.TrimSpace(c.Short) == "" {
				t.Errorf("inject has no short help")
			}
		}
	}
	if injectName == "" {
		t.Fatal("debug leaves have no inject command")
	}
}

// An inject hello posts its flags as strings for the agent to check, the
// target as a name with its dot, and prints one line of counts.
func TestInjectHelloPostAndReport(t *testing.T) {
	post := injectHelloPost("agent.b.example", 40, 500*time.Millisecond, "API")
	data := post.Data
	if post.Command != "inject-hello" || post.AgentId != "agent.b.example." ||
		data["count"] != "40" || data["interval"] != "500ms" || data["mechanism"] != "api" {
		t.Errorf("post %+v", post)
	}

	line := injectHelloReport(&AgentMgmtResponse{Data: map[string]interface{}{
		"target": "agent.b.example.", "mechanism": "DNS",
		"count": "40", "sent": "40", "accepted": "38", "refused": "1", "failed": "1",
		"first_error": "NOTIFY returned rcode REFUSED",
	}}, "")
	const want = "inject hello: agent.b.example. mechanism DNS: sent 40 of 40, accepted 38, refused 1, failed 1: first error: NOTIFY returned rcode REFUSED"
	if line != want {
		t.Errorf("line %q, want %q", line, want)
	}
}

// A refusal is an outcome: the line, and no failure. A send that failed
// prints its line and then fails the command; an error with no receipt
// (usage, an injector that is off) fails it with no line (#277).
func TestInjectOutcome(t *testing.T) {
	report := func(amr *AgentMgmtResponse) string {
		return injectReport(amr, "replace", "agent.b.example.", "z.example.")
	}
	receipt := map[string]interface{}{"distribution_id": "debug-inject-replace-1", "transport": "DNS"}

	line, failure := injectOutcome(&AgentMgmtResponse{Status: "ok", Data: map[string]interface{}{
		"distribution_id": "debug-inject-replace-1", "status": "REFUSED"}}, report)
	if line != "inject replace: agent.b.example. zone z.example. distribution debug-inject-replace-1: REFUSED" || failure != "" {
		t.Errorf("refused: line %q failure %q, want the line and no failure", line, failure)
	}

	failedReceipt := map[string]interface{}{"distribution_id": "debug-inject-replace-1", "transport": "DNS",
		"error": "DNS sync to agent.b.example.: NOTIFY exchange failed: i/o timeout"}
	line, failure = injectOutcome(&AgentMgmtResponse{Error: true, ErrorMsg: "the send failed: i/o timeout", Data: failedReceipt}, report)
	if !strings.Contains(line, "distribution debug-inject-replace-1: error: ") || failure != "the send failed: i/o timeout" {
		t.Errorf("failed send: line %q failure %q, want the line with its distribution and the failure", line, failure)
	}

	line, failure = injectOutcome(&AgentMgmtResponse{Error: true, ErrorMsg: "zone is required"}, report)
	if line != "" || failure != "zone is required" {
		t.Errorf("usage error: line %q failure %q, want no line and the error", line, failure)
	}

	line, failure = injectOutcome(&AgentMgmtResponse{Error: true, Data: receipt}, report)
	if line == "" || failure == "" {
		t.Errorf("an error with no message: line %q failure %q, want the line and a failure", line, failure)
	}

	line, failure = injectOutcome(&AgentMgmtResponse{Error: true, ErrorMsg: "no hello reached agent.b.example.: 2 of 2 sent, 2 failed",
		Data: map[string]interface{}{"target": "agent.b.example.", "mechanism": "DNS", "count": "2", "sent": "2",
			"accepted": "0", "refused": "0", "failed": "2", "first_error": "no address available"}},
		func(amr *AgentMgmtResponse) string { return injectHelloReport(amr, "agent.b.example.") })
	if !strings.HasPrefix(line, "inject hello: agent.b.example. mechanism DNS: sent 2 of 2, accepted 0, refused 0, failed 2") ||
		!strings.HasPrefix(failure, "no hello reached") {
		t.Errorf("no hello reached: line %q failure %q", line, failure)
	}
}

// An inject replace posts the target and the zone with their dots, and the
// origin as given; one that is not RFC 3339 goes nowhere.
func TestInjectReplacePost(t *testing.T) {
	rrs := []string{"z.example.\t60\tIN\tNS\tns1.example."}
	post, err := injectReplacePost("agent.b.example", "z.example", "2026-10-26T17:00:00.5Z", rrs)
	if err != nil {
		t.Fatal(err)
	}
	if post.Command != "inject-replace" || post.AgentId != "agent.b.example." || post.Zone != "z.example." ||
		post.Data["origin_time"] != "2026-10-26T17:00:00.5Z" || len(post.RRs) != 1 {
		t.Errorf("post %+v", post)
	}
	if _, err := injectReplacePost("agent.b.example.", "z.example.", "2026-10-26 17:00", rrs); err == nil {
		t.Error("an origin that is not RFC 3339 was posted")
	}
	if _, err := injectReplacePost("agent.b.example.", "z.example.", "0001-01-01T00:00:00Z", rrs); err == nil {
		t.Error("the zero origin was posted")
	}
}
