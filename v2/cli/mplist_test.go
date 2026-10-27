/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"strings"
	"testing"

	tdnsmp "github.com/johanix/tdns-mp/v2"
)

// mplist shows each zone's serial and digest; a zone with an owner error
// shows ERR, and the error below the table; a zone with no instructions
// shows neither.
func TestMplistPrintsTheSerialAndTheOwnerError(t *testing.T) {
	out := printed(t, func() {
		ListMPZones(tdnsmp.MPListResponse{MPZones: map[string]tdnsmp.MPZoneInfo{
			"a.example.": {Serial: 7, Digest: "d7294061a3f8f5af", NSmgmt: "agent", ParentSync: "owner"},
			"b.example.": {OwnerError: "two HSYNCPARAM records", NSmgmt: "owner", ParentSync: "owner"},
			"c.example.": {NSmgmt: "owner", ParentSync: "owner"},
		}})
	})
	lines := strings.Split(out, "\n")
	row := func(zone string) []string {
		for _, l := range lines {
			if f := strings.Fields(l); len(f) > 0 && f[0] == zone {
				return f
			}
		}
		t.Fatalf("no row for %s in\n%s", zone, out)
		return nil
	}
	if f := strings.Fields(lines[0]); len(f) < 3 || f[1] != "Serial" || f[2] != "Digest" {
		t.Errorf("header %q", lines[0])
	}
	if f := row("a.example."); f[1] != "7" || f[2] != "d7294061a3f8f5af" {
		t.Errorf("a.example.: %v", f)
	}
	if f := row("b.example."); f[1] != "ERR" || f[2] != "-" {
		t.Errorf("b.example.: %v", f)
	}
	if f := row("c.example."); f[1] != "-" || f[2] != "-" {
		t.Errorf("c.example.: %v", f)
	}
	if !strings.Contains(out, "b.example.: two HSYNCPARAM records") {
		t.Errorf("the owner error is not listed:\n%s", out)
	}
}
