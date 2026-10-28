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
	hsync3Changed int
	localRemoved  int
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
		},
	}
	return NewEngine(deps, DefaultConfig()), h
}

// Delta (a): the pre-diff guard mirrors the legacy weAreInHSYNC abort — when the
// local identity is absent from the zone's current HSYNC3 RRset, remote adds are
// ignored. The provider groups are recomputed all the same: they are made from
// the zones' records, whoever is in them.
func TestApplyHsyncDiff_guardSkipsWhenLocalAbsent(t *testing.T) {
	remote := mustHSYNC3RR(t, "rem", "rem.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{remote}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Entered: idsOf(remote)})

	if _, ok := e.registry.S.Get("rem.example."); ok {
		t.Fatal("guard should skip the remote add when local is absent from HSYNC3")
	}
	if h.hsync3Changed != 1 {
		t.Fatalf("the groups are recomputed once when local is absent, fired %d", h.hsync3Changed)
	}
}

// Delta (a): an explicit local-remove RR still fires OnLocalRemoved even though the
// guard is active (local already absent from the current RRset).
func TestApplyHsyncDiff_guardFiresLocalRemoved(t *testing.T) {
	localRR := mustHSYNC3RR(t, "loc", "local.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Left: idsOf(localRR)})

	if h.localRemoved != 1 {
		t.Fatalf("OnLocalRemoved should fire once for a local-remove RR, fired %d", h.localRemoved)
	}
}

// The owner removes the local identity's HSYNC3 record, and with it the
// local identity's place in the zone's provider group. The guard trips, the
// local identity being gone from the RRset, and the provider groups are
// recomputed all the same, once: the zone is in another group now, or in
// none. The guard used to return before the recompute, and the agent kept
// the zone in the group it had been in.
func TestApplyHsyncDiff_guardRecomputesGroupsWhenLocalIsRemoved(t *testing.T) {
	localRR := mustHSYNC3RR(t, "loc", "local.example.")
	remote := mustHSYNC3RR(t, "rem", "rem.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{remote}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Left: idsOf(localRR)})

	if h.localRemoved != 1 {
		t.Fatalf("OnLocalRemoved should fire once for a local-remove RR, fired %d", h.localRemoved)
	}
	if h.hsync3Changed != 1 {
		t.Fatalf("the groups are recomputed once when the local identity is removed, fired %d", h.hsync3Changed)
	}
	if _, ok := e.registry.S.Get("rem.example."); ok {
		t.Fatal("the remote peer was registered while the guard tripped")
	}
}

// Delta (b): adds fail closed when the zone view is unavailable (members==nil) —
// reconcile remains authoritative. Guard off here to isolate the fail-closed path.
func TestApplyHsyncDiff_failsClosedWhenZoneViewMissing(t *testing.T) {
	remote := mustHSYNC3RR(t, "rem", "rem.example.")
	e, _ := newDiffEngine("local.example.", false, mapZoneLookup{})

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Entered: idsOf(remote)})

	if _, ok := e.registry.S.Get("rem.example."); ok {
		t.Fatal("add must fail closed when the zone view is unavailable")
	}
}

// Delta (b): a role-less (OFF) HSYNC3 add is excluded; a member add is
// registered, and the groups are recomputed once.
func TestApplyHsyncDiff_roleLessAddExcluded(t *testing.T) {
	local := mustHSYNC3RR(t, "loc", "local.example.")
	member := mustHSYNC3RR(t, "mem", "mem.example.")
	off := mustHSYNC3RR(t, "off", "off.example.")
	off.Data.(*core.HSYNC3).State = 0 // OFF — not a participant

	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{local, member, off}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Entered: idsOf(member, off)})

	if _, ok := e.registry.S.Get("mem.example."); !ok {
		t.Fatal("member add should be registered")
	}
	if _, ok := e.registry.S.Get("off.example."); ok {
		t.Fatal("role-less (OFF) add must be excluded")
	}
	if h.hsync3Changed != 1 {
		t.Fatalf("the groups are recomputed once after the adds, fired %d", h.hsync3Changed)
	}
}

// The local identity's own add is never registered as a remote peer, and
// the groups are recomputed. The agent checks the zone's election after the
// diff (zoneChanged, step 8).
func TestApplyHsyncDiff_localAddRecomputesAndRegistersNothing(t *testing.T) {
	local := mustHSYNC3RR(t, "loc", "local.example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{local}}}
	e, h := newDiffEngine("local.example.", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Entered: idsOf(local)})

	if h.hsync3Changed != 1 {
		t.Fatalf("the groups are recomputed once after the local add, fired %d", h.hsync3Changed)
	}
	if _, ok := e.registry.S.Get("local.example."); ok {
		t.Fatal("local identity must not be registered as a remote peer")
	}
}

// A local identity configured without the trailing dot, or in another case,
// is the zone's record of it: its add is never registered as a peer, its
// removal runs the teardown, and MarkNeeded stores no peer for it.
func TestApplyHsyncDiff_localIdentityComparedCanonically(t *testing.T) {
	local := mustHSYNC3RR(t, "loc", "Local.Example.")
	zones := mapZoneLookup{"z.test.": {zone: "z.test.", rrs: []dns.RR{local}}}
	e, h := newDiffEngine("local.example", true, zones)

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Entered: idsOf(local)})
	for _, id := range []PeerID{"Local.Example.", "local.example.", "local.example"} {
		if _, ok := e.registry.S.Get(id); ok {
			t.Errorf("the local identity was registered as peer %q", id)
		}
	}
	e.MarkNeeded("LOCAL.example.", "z.test.", nil)
	if n := len(e.registry.S.Keys()); n != 0 {
		t.Errorf("MarkNeeded stored %d peer(s) for the local identity", n)
	}

	_ = e.ApplyHsyncDiff("z.test.", HsyncDiff{Left: idsOf(local)})
	if h.localRemoved != 1 {
		t.Errorf("the local identity's removal ran the teardown %d times, want once", h.localRemoved)
	}
}
