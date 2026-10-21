/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"strings"
	"testing"
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
		"status":          "SUCCESS",
		"message":         "applied",
		"error":           "peer answered REFUSED",
	}}, "named-sender", "agent.b.example.", "z.example.")
	const wantRefused = "inject named-sender: agent.b.example. zone z.example. distribution debug-inject-named-sender-1: error: peer answered REFUSED"
	if refused != wantRefused {
		t.Errorf("refused line %q, want %q", refused, wantRefused)
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
			for _, name := range []string{"named-sender", "combiner-origin", "peer-keystate"} {
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
