/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode"
)

// Text another agent sent reaches the terminal through the event log's
// summary and details. A control character in it must arrive as an escape,
// not as a command to the terminal; the details keep their lines.
func TestEventPrintersDoNotPassTerminalControls(t *testing.T) {
	hostile := "rr\x1b]0;retitled\x07 \x1b[2J\rover\x7f\u009b1m\u202eevil\xff"
	e := AuditEvent{
		ID:          7,
		Time:        time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		Zone:        "example.com.",
		Originator:  "agent.p1.example.\x1b[31m",
		DeliveredBy: "agent.p2.example.",
		EventType:   "sync",
		Summary:     "sync from agent.p1.example.: " + hostile,
		Details:     "SYNC from agent.p1.example.\n  delete A (1 record)\n    " + hostile + " (not parsed)",
	}

	var list, show bytes.Buffer
	printEvents(&list, []AuditEvent{e}, true)
	printEvent(&show, e)

	for name, out := range map[string]string{"list --details": list.String(), "show": show.String()} {
		for _, r := range out {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Errorf("%s printed control character %U:\n%q", name, r, out)
			}
		}
		for _, want := range []string{`rr\x1b]0;retitled\x07 \x1b[2J\x0dover\x7f\u009b1m\u202eevil` + "\uFFFD", `agent.p1.example.\x1b[31m`} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, out)
			}
		}
		if !strings.Contains(out, "delete A (1 record)\n") {
			t.Errorf("%s lost the details' lines:\n%s", name, out)
		}
	}
	if n := strings.Count(list.String(), "\n        "); n != 3 {
		t.Errorf("list --details printed %d detail lines, want 3:\n%s", n, list.String())
	}
}
