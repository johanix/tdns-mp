/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// Step 8, design 4.5: one check of a zone's election, at its first load and
// at every change of its HSYNC3 or HSYNCPARAM, after the groups are
// recomputed (zoneChanged).

// zoneChangeRig is this agent (A) with its refresh callbacks, its hsync
// engine and an election manager whose leader's callback is recorded.
type zoneChangeRig struct {
	conf    *Config
	lem     *LeaderElectionManager
	pgm     *ProviderGroupManager
	elected chan ZoneName
}

func newZoneChangeRig(t *testing.T, zones ...*tdns.ZoneData) *zoneChangeRig {
	t.Helper()
	conf := roleConf(t, AppTypeMPAgent, "agent", arrivalA, zones...)
	ar := conf.InternalMp.AgentRegistry
	NewHsyncDataEngine(conf)
	r := &zoneChangeRig{conf: conf, pgm: ar.ProviderGroupManager, elected: make(chan ZoneName, 16)}
	r.lem = NewLeaderElectionManager(arrivalA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(r.lem) })
	conf.InternalMp.LeaderElectionManager = r.lem
	ar.LeaderElectionManager = r.lem
	r.lem.SetConfiguredPeersFunc(func(zone ZoneName) int { return configuredVotingPeers(zone, arrivalA) })
	r.lem.SetProviderGroupManager(r.pgm)
	r.lem.SetOnLeaderElected(func(zone ZoneName) error { r.elected <- zone; return nil })
	r.pgm.RecomputeGroups()
	return r
}

func (r *zoneChangeRig) electedWithin(t *testing.T, zone ZoneName, what string) {
	t.Helper()
	select {
	case z := <-r.elected:
		if z != zone {
			t.Fatalf("%s: elected for %s, want %s", what, z, zone)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: this agent was not elected for %s", what, zone)
	}
}

func (r *zoneChangeRig) holdsZoneElection(zone ZoneName) bool {
	r.lem.mu.RLock()
	defer r.lem.mu.RUnlock()
	_, ok := r.lem.elections[zone]
	return ok
}

// A zone of two providers whose owner takes the role of one: the zone is in
// no group now (#149), and the remaining provider leads it at once, with no
// restart. zoneChanged runs after the recompute: run before it, it would
// still find the zone's old group, and start nothing.
func TestAZoneReducedToOneVotingMemberGetsALeaderWithNoRestart(t *testing.T) {
	zd := providerZone(t, "reduced.onevoter.example.", arrivalA, arrivalB)
	r := newZoneChangeRig(t, zd)
	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA, arrivalB}, serving: []string{arrivalA, arrivalB}, parentsync: true})
	zone := ZoneName(zd.ZoneName)
	if r.pgm.GetGroupForZone(zone) == nil {
		t.Fatal("precondition: the zone of two providers is in no group")
	}
	if r.lem.IsLeader(zone) {
		t.Fatal("precondition: this agent leads a zone of two providers with no election")
	}

	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA, arrivalB}, serving: []string{arrivalA}, parentsync: true})
	if pg := r.pgm.GetGroupForZone(zone); pg != nil {
		t.Fatalf("the zone reduced to one voting member is in group %+v", pg)
	}
	r.electedWithin(t, zone, "the zone reduced to one voting member")
	if !r.lem.IsLeader(zone) {
		t.Error("the zone's one voting member does not lead it")
	}
}

// A zone this agent led alone, by its own election, joins a group: the
// zone's own election is dropped, and the group's decides.
func TestAPerZoneResultIsDroppedWhenAGroupCoversTheZone(t *testing.T) {
	zd := providerZone(t, "covered.perzone.example.", arrivalA)
	r := newZoneChangeRig(t, zd)
	zone := ZoneName(zd.ZoneName)
	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA}, serving: []string{arrivalA}, parentsync: true})
	r.electedWithin(t, zone, "the zone of one provider")
	if !r.holdsZoneElection(zone) {
		t.Fatal("precondition: the zone of one provider has no election of its own")
	}

	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA, arrivalB}, serving: []string{arrivalA, arrivalB}, parentsync: true})
	if r.pgm.GetGroupForZone(zone) == nil {
		t.Fatal("the zone of two providers is in no group")
	}
	if r.holdsZoneElection(zone) {
		t.Error("the zone's own election is still held while a group covers the zone")
	}
	if r.lem.IsLeader(zone) {
		t.Error("this agent leads the zone by its own election while a group covers it")
	}
}

// A zone with parentsync and no HSYNC3 RRset is no multi-provider zone, and
// elects at its first load as before.
func TestAZoneWithParentsyncAndNoHSYNC3StillElectsAtItsFirstLoad(t *testing.T) {
	zd := seedZoneWithHSYNC3(t, "plain.firstload.example.")
	zd.Logger = log.New(io.Discard, "", 0)
	zd.Options[tdns.OptParentSync] = true
	r := newZoneChangeRig(t)
	r.lem.electAtFirstLoad(zd)
	r.electedWithin(t, ZoneName(zd.ZoneName), "the plain zone's first load")
}

// The election manager, its callbacks and the zones' first-load callbacks
// are in place before RefreshEngine starts (setUpLeaderElection), so a first
// load gets all three: the parentsync detection, the first-load election,
// and zoneChanged.
func TestAFirstLoadAfterTheSetUpGetsEveryElectionCheck(t *testing.T) {
	multi := seedZoneWithHSYNC3(t, "multi.firstload.example.")
	multi.Logger = log.New(io.Discard, "", 0)
	plain := seedZoneWithHSYNC3(t, "plain.setup.firstload.example.")
	plain.Logger = log.New(io.Discard, "", 0)
	plain.Options[tdns.OptParentSync] = true
	// a zone whose option is still off when its first-load callbacks run:
	// the parentsync detection turns it on
	detect := seedZoneWithHSYNC3(t, "detect.firstload.example.")
	detect.Logger = log.New(io.Discard, "", 0)
	conf := roleConf(t, AppTypeMPAgent, "agent", arrivalA, multi, detect)
	NewHsyncDataEngine(conf)
	conf.Config.Internal.AllZones = []string{multi.ZoneName, plain.ZoneName, detect.ZoneName}
	conf.Config.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 8)
	before := map[string]int{multi.ZoneName: len(multi.OnFirstLoad), plain.ZoneName: len(plain.OnFirstLoad)}

	lem := conf.setUpLeaderElection(context.Background(), conf.MpConfig())
	t.Cleanup(func() { stopElectionTimers(lem) })
	if conf.InternalMp.LeaderElectionManager != lem || lem.onLeaderElected == nil || lem.onZoneJoined == nil {
		t.Fatal("the set-up did not wire the election manager and its callbacks")
	}
	// the multi-provider zone: the parentsync detection and the first-load
	// election; the plain zone with parentsync: the first-load election
	if got := len(multi.OnFirstLoad) - before[multi.ZoneName]; got != 2 {
		t.Errorf("the multi-provider zone got %d first-load callbacks, want 2", got)
	}
	if got := len(plain.OnFirstLoad) - before[plain.ZoneName]; got != 1 {
		t.Errorf("the plain zone with parentsync got %d first-load callbacks, want 1", got)
	}

	// The first load of the multi-provider zone, as tdns runs it: its
	// post-refresh callbacks, then its first-load callbacks.
	refreshWith(t, multi, zoneEdit{listed: []string{arrivalA}, serving: []string{arrivalA}, parentsync: true})
	for _, cb := range multi.OnFirstLoad {
		cb(multi)
	}
	for _, cb := range plain.OnFirstLoad {
		cb(plain)
	}
	zoneEdit{listed: []string{arrivalA, arrivalB}, serving: []string{arrivalA, arrivalB}, parentsync: true}.apply(t, detect)
	for _, cb := range detect.OnFirstLoad {
		cb(detect)
	}
	waitUntil(t, "the multi-provider zone's one voter leads it (zoneChanged)", func() bool { return lem.IsLeader(ZoneName(multi.ZoneName)) })
	waitUntil(t, "the plain zone with parentsync is led (the first-load election)", func() bool { return lem.IsLeader(ZoneName(plain.ZoneName)) })
	// (its SetupZoneSync then wants parentsync.schemes, which this config
	// has not got: the option is what the detection sets)
	if !detect.Options[tdns.OptParentSync] {
		t.Error("the parentsync detection did not enable the zone's delegation sync")
	}
}

// StartMPAgent runs setUpLeaderElection before it starts RefreshEngine.
func TestTheElectionIsSetUpBeforeTheRefreshEngineStarts(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "start_agent.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	setUp, refresh := token.NoPos, token.NoPos
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "StartMPAgent" {
			return true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setUpLeaderElection" && setUp == token.NoPos {
				setUp = call.Pos()
			}
			for _, a := range call.Args {
				if lit, ok := a.(*ast.BasicLit); ok && strings.Trim(lit.Value, `"`) == "RefreshEngine" && refresh == token.NoPos {
					refresh = call.Pos()
				}
			}
			return true
		})
		return false
	})
	if setUp == token.NoPos || refresh == token.NoPos {
		t.Fatalf("StartMPAgent: setUpLeaderElection at %v, RefreshEngine started at %v", setUp, refresh)
	}
	if setUp > refresh {
		t.Errorf("StartMPAgent starts RefreshEngine (%v) before it sets the election up (%v)", fset.Position(refresh), fset.Position(setUp))
	}
}

// The owner removes every provider's record of a zone this agent led alone,
// and puts them back: the lead is dropped while nobody is listed, and the
// return elects anew, so the new lead's set-up runs. A lead kept from
// before would have skipped it until its next renewal.
func TestAZoneWhoseRecordsAllGoAndComeBackGetsANewLead(t *testing.T) {
	zd := providerZone(t, "gone.back.records.example.", arrivalA)
	r := newZoneChangeRig(t, zd)
	zone := ZoneName(zd.ZoneName)
	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA}, serving: []string{arrivalA}, parentsync: true})
	r.electedWithin(t, zone, "the zone of one provider")

	refreshWith(t, zd, zoneEdit{parentsync: true}) // no HSYNC3 record left
	if r.holdsZoneElection(zone) {
		t.Fatal("the lead outlived the removal of every provider's record")
	}
	refreshWith(t, zd, zoneEdit{listed: []string{arrivalA}, serving: []string{arrivalA}, parentsync: true})
	r.electedWithin(t, zone, "the records back")
}
