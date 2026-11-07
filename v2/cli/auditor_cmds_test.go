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
	if !strings.Contains(list.String(), "  SYNC  ") || !strings.Contains(show.String(), "type:         SYNC") {
		t.Errorf("the event type is not shown in capitals:\n%s\n%s", list.String(), show.String())
	}
	if n := strings.Count(list.String(), "\n        "); n != 3 {
		t.Errorf("list --details printed %d detail lines, want 3:\n%s", n, list.String())
	}
}

// `auditor confirmations` names each distribution, its originator, and per
// member whether its confirmation was seen. A rejection's reason is a
// peer's text and reaches the terminal escaped. With --pending only the
// distributions that wait for a member are listed.
func TestConfirmationsPrinterShowsEachMembersState(t *testing.T) {
	seen := time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC)
	dists := []AuditDistributionSummary{
		{Zone: "example.com.", DistributionID: "69812b15", Originator: "agent.alpha.example.", Summary: "add NS (1 record)",
			State: "pending", AgeSeconds: 192, Members: []AuditDistributionMember{
				{Identity: "agent.bravo.example.", State: "confirmed", Status: "SUCCESS", Seen: seen},
				{Identity: "agent.charlie.example.", State: "pending", PendingSeconds: 190},
			}},
		{Zone: "example.com.", DistributionID: "69812b20", Originator: "agent.bravo.example.", Summary: "replace DNSKEY (2 records)",
			State: "rejected", AgeSeconds: 30, Members: []AuditDistributionMember{
				{Identity: "agent.alpha.example.", State: "rejected", Status: "FAILED", Reason: "not a signer\x1b[2J", Seen: seen},
				{Identity: "agent.delta.example.", State: "unknown", PendingSeconds: 30},
			}},
	}

	var all, pending bytes.Buffer
	if n := printDistributions(&all, dists, false); n != 2 {
		t.Errorf("printed %d distributions, want 2", n)
	}
	out := all.String()
	for _, want := range []string{
		"Zone: example.com.\n",
		"69812b15", "agent.alpha.example.", "3m12s", "pending", "add NS (1 record)",
		"agent.bravo.example.            confirmed  SUCCESS at 09:30:00",
		"agent.charlie.example.          pending    no confirmation seen for 3m10s",
		"agent.alpha.example.            rejected   FAILED: not a signer\\x1b[2J",
		"agent.delta.example.            unknown    no confirmation seen, and none from this member since the auditor started",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "Zone: ") != 1 {
		t.Errorf("the zone is named more than once for its distributions:\n%s", out)
	}
	for _, r := range out {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Errorf("the listing printed control character %U:\n%q", r, out)
		}
	}

	if n := printDistributions(&pending, dists, true); n != 1 || strings.Contains(pending.String(), "69812b20") || !strings.Contains(pending.String(), "69812b15") {
		t.Errorf("--pending printed %d distributions, want the one that waits:\n%s", n, pending.String())
	}
}
