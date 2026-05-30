/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

type diffHooks struct {
	hsync3Changed  int
	localRemoved   int
	membersAdded   int
	lastAdded      []PeerID
	lastLocalAdded bool
}

func newDiffEngine(local string, gate bool, zones mapZoneLookup) (*Engine, *diffHooks) {
	h := &diffHooks{}
	deps := Deps{
		LocalID:             PeerID(local),
		Transport:           &mockTransport{},
		Zones:               zones,
		GateOnLocalPresence: gate,
		Host: HostCallbacks{
			OnHsync3Changed: func(zone ZoneName) { h.hsync3Changed++ },
			OnLocalRemoved:  func(zone ZoneName) { h.localRemoved++ },
			OnHsyncMembersAdded: func(zone ZoneName, added []PeerID, localAdded bool) {
				h.membersAdded++
				h.lastAdded = added
				h.lastLocalAdded = localAdded
			},
		},
	}
	return NewEngine(deps, DefaultConfig()), h
}

// Delta (a): the pre-diff guard mirrors the legacy weAreInHSYNC abort — when the
// local identity is absent from the zone's current HSYNC3 RRset, remote adds are
// ignored and the group recompute is suppressed.
func TestApplyHsyncDiff_guardSkipsWhenLocalAbsent(t *testing.T) {
	remote := mustHSYNC3RR(t, "rem", "rem.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{remote}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Adds: []dns.RR{remote}})

	if _, ok := e.registry.S.Get("rem.example."); ok {
		t.Fatal("guard should skip the remote add when local is absent from HSYNC3")
	}
	if h.hsync3Changed != 0 {
		t.Fatalf("group recompute must be suppressed when local absent, fired %d", h.hsync3Changed)
	}
	if h.membersAdded != 0 {
		t.Fatalf("OnHsyncMembersAdded must not fire when the guard trips, fired %d", h.membersAdded)
	}
}

// Delta (a): an explicit local-remove RR still fires OnLocalRemoved even though the
// guard is active (local already absent from the current RRset).
func TestApplyHsyncDiff_guardFiresLocalRemoved(t *testing.T) {
	localRR := mustHSYNC3RR(t, "loc", "local.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Removes: []dns.RR{localRR}})

	if h.localRemoved != 1 {
		t.Fatalf("OnLocalRemoved should fire once for a local-remove RR, fired %d", h.localRemoved)
	}
}

// Delta (b): adds fail closed when the zone view is unavailable (members==nil) —
// reconcile remains authoritative. Guard off here to isolate the fail-closed path.
func TestApplyHsyncDiff_failsClosedWhenZoneViewMissing(t *testing.T) {
	remote := mustHSYNC3RR(t, "rem", "rem.example.")
	e, _ := newDiffEngine("local.example.", false, mapZoneLookup{})

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Adds: []dns.RR{remote}})

	if _, ok := e.registry.S.Get("rem.example."); ok {
		t.Fatal("add must fail closed when the zone view is unavailable")
	}
}

// Delta (b): a role-less (OFF) HSYNC3 add is excluded; a member add is registered
// and surfaced (without the role-less one) to OnHsyncMembersAdded.
func TestApplyHsyncDiff_roleLessAddExcluded(t *testing.T) {
	local := mustHSYNC3RR(t, "loc", "local.example.")
	member := mustHSYNC3RR(t, "mem", "mem.example.")
	off := mustHSYNC3RR(t, "off", "off.example.")
	off.Data.(*core.HSYNC3).State = 0 // OFF — not a participant

	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{local, member, off}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Adds: []dns.RR{member, off}})

	if _, ok := e.registry.S.Get("mem.example."); !ok {
		t.Fatal("member add should be registered")
	}
	if _, ok := e.registry.S.Get("off.example."); ok {
		t.Fatal("role-less (OFF) add must be excluded")
	}
	if h.membersAdded != 1 || len(h.lastAdded) != 1 || h.lastAdded[0] != "mem.example." {
		t.Fatalf("OnHsyncMembersAdded should carry only the member add, fired=%d added=%v", h.membersAdded, h.lastAdded)
	}
}

// The local identity's own add is signalled via localAdded (drives the upstream
// CONFIG RFI re-home) and never registered as a remote peer.
func TestApplyHsyncDiff_localAddSignalled(t *testing.T) {
	local := mustHSYNC3RR(t, "loc", "local.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{local}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Adds: []dns.RR{local}})

	if h.membersAdded != 1 || !h.lastLocalAdded {
		t.Fatalf("local add should fire OnHsyncMembersAdded with localAdded=true, fired=%d localAdded=%v", h.membersAdded, h.lastLocalAdded)
	}
	if _, ok := e.registry.S.Get("local.example."); ok {
		t.Fatal("local identity must not be registered as a remote peer")
	}
}
