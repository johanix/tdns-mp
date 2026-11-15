/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"strings"
	"testing"

	tdnsmp "github.com/johanix/tdns-mp/v2"
)

// mplist shows each zone's serial and digest: where the daemon keeps
// serials, the active one, and "7->8" with a newer one held. A zone with an
// owner error shows ERR, and the error below the table; a zone with no
// instructions shows neither.
func TestMplistPrintsTheSerialAndTheOwnerError(t *testing.T) {
	out := printed(t, func() {
		ListMPZones(tdnsmp.MPListResponse{MPZones: map[string]tdnsmp.MPZoneInfo{
			"a.example.": {Serial: 7, Digest: "d7294061a3f8f5af", NSmgmt: "agent", ParentSync: "owner"},
			"b.example.": {OwnerError: "two HSYNCPARAM records", NSmgmt: "owner", ParentSync: "owner"},
			"c.example.": {NSmgmt: "owner", ParentSync: "owner"},
			// an agent's row: the active serial, and the newest held
			"d.example.": {Serial: 8, Digest: "9c01aa47b2e3f650", NSmgmt: "owner", ParentSync: "owner",
				Active: &tdnsmp.SerialDigest{Serial: 7, Digest: "5f3a19c2e07b4d11"},
				Newest: &tdnsmp.SerialDigest{Serial: 8, Digest: "9c01aa47b2e3f650"}},
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
	if f := row("d.example."); f[1] != "7->8" || f[2] != "5f3a19c2e07b4d11" {
		t.Errorf("d.example.: %v", f)
	}
	if !strings.Contains(out, "b.example.: two HSYNCPARAM records") {
		t.Errorf("the owner error is not listed:\n%s", out)
	}
}

// mplist shows the members with no role by label, and the agent's own
// standing in the This column (plan S15); a daemon that does not fill it
// shows "-".
func TestMplistShowsEachMembersStanding(t *testing.T) {
	out := printed(t, func() {
		ListMPZones(tdnsmp.MPListResponse{MPZones: map[string]tdnsmp.MPZoneInfo{
			"a.example.": {Serial: 7, Digest: "d7", Servers: []string{"alpha"}, NoRole: []string{"delta"}, This: "member, no role", NSmgmt: "owner", ParentSync: "owner"},
			"b.example.": {Serial: 7, Digest: "d7", Servers: []string{"alpha"}, NSmgmt: "owner", ParentSync: "owner"},
		}})
	})
	header := strings.Fields(strings.Split(out, "\n")[0])
	if len(header) < 8 || header[6] != "NoRole" || header[7] != "This" {
		t.Fatalf("header %v", header)
	}
	for _, want := range []string{"a.example.  7       d7      alpha    (none)   (none)    delta   member, no role", "b.example.  7       d7      alpha    (none)   (none)    (none)  -"} {
		if !strings.Contains(out, want) {
			t.Errorf("no row %q in\n%s", want, out)
		}
	}
}
