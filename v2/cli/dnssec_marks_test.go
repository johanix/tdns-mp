/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"
)

// #260: a peer whose DNS data is not secure has a mark after its state, and
// a table or matrix with a mark, or from a node with DNSSEC validation off,
// is followed by the legend and, when validation is off, a warning.

func peerRow(id, state, chain, reason string) map[string]interface{} {
	p := map[string]interface{}{"peer_id": id, "peer_type": "agent", "transport": "API", "address": "-", "crypto_type": "TLS", "state": state}
	if chain != "" {
		p["dnssec"] = chain
	}
	if reason != "" {
		p["discovery_reason"] = reason
	}
	return p
}

func TestPeerListMarksAPeerWhoseChainIsNotSecure(t *testing.T) {
	const reason = "URI at _https._tcp.b.example.: answer insecure, DNSSEC validation required"
	out := printed(t, func() {
		displayPeers([]interface{}{
			peerRow("b.example.", "NEEDED", "insecure", reason),
			peerRow("c.example.", "OPERATIONAL", "bogus", "SVCB at api.c.example.: answer bogus, accepted as DNSSEC validation is off"),
			peerRow("d.example.", "OPERATIONAL", "secure", ""),
		}, false, false)
	})
	for _, want := range []string{"NEEDED(-)", "OPERATIONAL(!)", "Discovery:", "API to b.example.: " + reason, chainLegend[0], chainLegend[1]} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// State is each row's last field, as scripts read it ($NF), the mark
	// included, and the reasons are not in the table. Only a row has an
	// identity as its first field: scripts find a peer's row that way.
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasSuffix(f[0], ".example.") && len(f) != 6 {
			t.Errorf("line %q starts with an identity and is not a row", line)
		}
		if len(f) == 6 && strings.HasSuffix(f[0], ".example.") {
			if st := f[5]; st != "NEEDED(-)" && st != "OPERATIONAL(!)" && st != "OPERATIONAL" {
				t.Errorf("row %q: last field %q is not the state", line, st)
			}
		} else if len(f) > 6 && strings.HasSuffix(f[0], ".example.") && f[1] == "agent" {
			t.Errorf("row %q has more than the six columns", line)
		}
	}
	if strings.Contains(out, "OPERATIONAL(-)") || strings.Contains(out, "WARNING") {
		t.Errorf("a secure peer was marked, or a warning given with validation on:\n%s", out)
	}
}

func TestPeerListWithNothingToMarkHasNoNotes(t *testing.T) {
	out := printed(t, func() {
		displayPeers([]interface{}{peerRow("d.example.", "OPERATIONAL", "secure", "")}, false, false)
	})
	if strings.Contains(out, "(-)") || strings.Contains(out, "Discovery") || strings.Contains(out, "DNSSEC") {
		t.Errorf("notes for a secure peer:\n%s", out)
	}
}

func TestPeerListWarnsWhenValidationIsOff(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		out := printed(t, func() {
			displayPeers([]interface{}{peerRow("d.example.", "OPERATIONAL", "secure", "")}, verbose, true)
		})
		if !strings.Contains(out, "WARNING: DNSSEC validation is OFF on this node") || !strings.Contains(out, chainLegend[0]) {
			t.Errorf("verbose=%v: no warning or legend with validation off:\n%s", verbose, out)
		}
	}
}

func TestPeerListVerboseShowsTheVerdict(t *testing.T) {
	out := printed(t, func() {
		displayPeers([]interface{}{peerRow("b.example.", "NEEDED", "insecure", "URI at x.: answer insecure, DNSSEC validation required")}, true, false)
	})
	for _, want := range []string{"State:          NEEDED(-)", "DNSSEC:         insecure", "Discovery:      URI at x.: answer insecure"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output lacks %q:\n%s", want, out)
		}
	}
}

func TestGossipMatrixMarksCellsAndNamesWhereValidationIsOff(t *testing.T) {
	members := []string{"a.example.", "b.example.", "c.example."}
	matrix := []interface{}{
		map[string]interface{}{
			"reporter":    "a.example.",
			"age":         "1s",
			"peer_states": map[string]interface{}{"b.example.": "OPERATIONAL", "c.example.": "NEEDED"},
			"peer_chains": map[string]interface{}{"b.example.": "insecure", "c.example.": "bogus"},
			// a takes b's unvalidated data: its validation is off
			"dnssec_validation_off": true,
		},
		map[string]interface{}{
			"reporter":    "b.example.",
			"age":         "2s",
			"peer_states": map[string]interface{}{"a.example.": "OPERATIONAL", "c.example.": "OPERATIONAL"},
		},
	}
	out := printed(t, func() { printGossipMatrix(members, matrix) })
	for _, want := range []string{"OPERATIONAL(-)", "NEEDED(!)", "WARNING: DNSSEC validation is OFF on a", chainLegend[0], chainLegend[1]} {
		if !strings.Contains(out, want) {
			t.Errorf("matrix lacks %q:\n%s", want, out)
		}
	}
	// b's row has no marks: its cells are bare, and the columns stay apart.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "b") && strings.Contains(line, "(") && !strings.Contains(line, "beats") {
			t.Errorf("b's row carries a mark: %q", line)
		}
		if strings.Contains(line, "OPERATIONAL(-)NEEDED") {
			t.Errorf("cells run together: %q", line)
		}
	}
}

func TestGossipMatrixWithoutMarksHasNoNotes(t *testing.T) {
	members := []string{"a.example.", "b.example."}
	matrix := []interface{}{
		map[string]interface{}{"reporter": "a.example.", "age": "1s", "peer_states": map[string]interface{}{"b.example.": "OPERATIONAL"}},
	}
	out := printed(t, func() { printGossipMatrix(members, matrix) })
	if strings.Contains(out, "DNSSEC") || strings.Contains(out, "(-)") {
		t.Errorf("notes on a matrix with nothing to mark:\n%s", out)
	}
}
