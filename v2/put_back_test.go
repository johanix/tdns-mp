/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"

	"github.com/johanix/tdns-mp/v2/hsync"
)

// A provider put back after its removal is over (design 5.1 as amended
// 2026-11-03): its active serial has no record of it, so it shares nothing with
// anyone, and only a serial it holds can bring it back.

// withN is the owner's edit that puts n's record back, with no role.
func withN(t *testing.T, serial uint32) *Instructions {
	t.Helper()
	return jAt(t, serial, fmt.Sprintf(`servers="a,b" signers="a" nsmgmt="agent" suffix="%d"`, serial), freezeRecords...)
}

// nServes is the owner's edit that gives n a role.
func nServes(t *testing.T, serial uint32) *Instructions {
	t.Helper()
	return jAt(t, serial, fmt.Sprintf(`servers="a,b,n" signers="a" nsmgmt="agent" suffix="%d"`, serial), freezeRecords...)
}

// putBack is the leader's words to n, on the real stamps, from the thaw that
// took n's record to the thaw that gave it back, and n, as they found it: told
// safe to remove with nothing since.
type putBack struct {
	n                                          *leaverRig
	n43, n44                                   *Instructions
	toldThaw43, toldDone43, toldThaw, toldDone *GossipMessage
}

func newPutBack(t *testing.T, zone string) *putBack {
	t.Helper()
	a := newLeaverRig(t, zone, "agent")
	n41, n42, n43, n44 := a.n, a.v, withoutN(t, 43), withN(t, 44)
	a.holdUnjudged(n43, time.Now())
	a.run()
	a.n, a.v = n42, n43
	a.thawNow()
	p := &putBack{n43: n43, n44: n44, toldThaw43: a.stamps.entryFor(roleN)}
	if p.toldThaw43 == nil {
		t.Fatal("the thaw leaves a nothing to tell n")
	}
	a.stamps.acknowledged(roleN, p.toldThaw43)
	if err := a.store.Done(zone); err != nil {
		t.Fatal(err)
	}
	if p.toldDone43 = a.stamps.entryFor(roleN); p.toldDone43 == nil {
		t.Fatal("a has no word of done for n")
	}
	a.stamps.acknowledged(roleN, p.toldDone43)
	a.holdUnjudged(n44, time.Now())
	a.n, a.v = n43, n44
	a.thawNow()
	if a.active() != 44 {
		t.Fatalf("a is at %d", a.active())
	}
	if p.toldThaw = a.stamps.entryFor(roleN); p.toldThaw == nil {
		t.Fatal("a does not tell n of the thaw that gives it back")
	}
	if st := p.toldThaw.Members[roleA].Instr[zone]; st.Active != 44 || st.Thaw == nil || st.Thaw.From != sd(n43) || st.Thaw.To != sd(n44) {
		t.Fatalf("what a tells n: %+v", st)
	}
	a.stamps.acknowledged(roleN, p.toldThaw)
	if err := a.store.Done(zone); err != nil {
		t.Fatal(err)
	}
	if p.toldDone = a.stamps.entryFor(roleN); p.toldDone == nil {
		t.Fatal("a has no word of done for n at 44")
	}

	n := newLeaverRigAt(t, zone, n41, n42, a.parent)
	p.n = n
	n.stamps.localID = roleN
	mp := n.conf.MpConfig()
	id, names := mp.Identity, mp.Local.Nameservers
	mp.Identity, mp.Local.Nameservers = roleN, []string{"ns1.n.example."}
	t.Cleanup(func() { mp.Identity, mp.Local.Nameservers = id, names })
	n.holdUnjudged(n43, time.Now())
	n.stamps.note(p.toldThaw43, roleA, transport.MechanismDNS)
	n.conf.thawTurn(zone)
	if n.active() != 43 {
		t.Fatalf("n stays at %d", n.active())
	}
	return p
}

// atNoRecord has n hear "done": steady under a serial with no record of it.
func (p *putBack) atNoRecord(t *testing.T) *leaverRig {
	t.Helper()
	n := p.n
	n.stamps.note(p.toldDone43, roleA, transport.MechanismDNS)
	n.conf.thawTurn(n.zone)
	if st := status(t, n.store, n.zone); st.Phase != PhaseSteady || !n.conf.safeToRemove(n.zone) {
		t.Fatalf("n after a's word of done: phase %s, safe to remove %v", st.Phase, n.conf.safeToRemove(n.zone))
	}
	return n
}

// engineFor is the agent's engine, from the agent's own deps, on the rig's
// registry: what it names as a peer is what discovery and comms run with.
func engineFor(n *leaverRig) *hsync.Engine {
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: n.conf.MpConfig()}
	n.conf.InternalMp.AgentRegistry = ar
	n.conf.InternalMp.MPTransport.agentRegistry = ar
	deps, cfg := buildHsyncEngineDeps(n.conf)
	engine := hsync.NewEngine(deps, cfg)
	ar.HsyncEngine, ar.Registry = engine, engine.Registry()
	return engine
}

// On the real stamps, leader to leaver: the record back, then the role, the two
// edits of design 5.1. Before the start-over nothing can reach n, and its own
// judge refuses the role against the serial with no record of it.
func TestAProviderPutBackFollowsTheLeaderAndTakesItsRole(t *testing.T) {
	logs := captureLog(t)
	const zone = "back.remove.example."
	p := newPutBack(t, zone)
	n := p.atNoRecord(t)
	engine := engineFor(n)
	n.zoneServesNS(60)
	tm := n.conf.InternalMp.MPTransport
	if tm.TransportManager == nil {
		tm.TransportManager = &transport.TransportManager{}
	}
	tm.LocalID = roleN
	tm.getZone = func(name string) (*tdns.ZoneData, bool) {
		mpzd, ok := Zones.Get(name)
		if !ok {
			return nil, false
		}
		return mpzd.ZoneData, true
	}
	if engine.ZoneNamesPeer(hsync.PeerID(roleA)) {
		t.Fatal("precondition: under a serial with no record of n, its engine names a peer")
	}
	if ok, _ := tm.isInHSYNC(roleA, zone); ok {
		t.Fatal("precondition: under a serial with no record of n, a's hello is taken")
	}

	n.store.Note(zone, p.n44, nil)
	n.conf.thawTurn(zone)
	if !n.store.activeUnknown(zone) {
		t.Fatalf("n still knows an active serial: %+v", status(t, n.store, zone).Active)
	}
	if !strings.Contains(logs.String(), "the zone names this provider again") || !strings.Contains(logs.String(), "active_was=43") || !strings.Contains(logs.String(), "named_by=44") {
		t.Errorf("the log does not say so: %s", logs)
	}
	if n.conf.safeToRemove(zone) {
		t.Error("n is back, and told safe to remove")
	}
	if !engine.ZoneNamesPeer(hsync.PeerID(roleA)) || !engine.ZoneNamesPeer(hsync.PeerID(roleB)) {
		t.Error("its engine names no peer: discovery has nothing to run with")
	}
	if !slices.ContainsFunc(engine.Registry().GetPeersForZone(hsync.ZoneName(zone)), func(peer *hsync.Peer) bool { return peer.ID == hsync.PeerID(roleA) }) {
		t.Error("its peers were not asked for at once, as records entering")
	}
	if ok, why := tm.isInHSYNC(roleA, zone); !ok {
		t.Errorf("a's hello is refused: %s", why)
	}

	// a's word for the serial n dropped, from before: not asked for, and held
	// or not, not taken. Taken, n would start over at every turn until a thaws.
	n.conf.thawTurn(zone)
	for key := range n.conf.InternalMp.thaws.fetched {
		t.Errorf("n asked for a serial below the one that named it: %s", key)
	}
	n.leadGroup(p.n43, roleA)
	if err := n.store.Hold(zone, p.n43); err != nil {
		t.Fatal(err)
	}
	n.conf.thawTurn(zone)
	n.conf.thawTurn(zone)
	if !n.store.activeUnknown(zone) {
		t.Fatalf("n took the serial it dropped: %+v", status(t, n.store, zone))
	}
	if got := strings.Count(logs.String(), "the zone names this provider again"); got != 1 {
		t.Errorf("n started over %d times", got)
	}
	if line := n.conf.thawLine(zone); !strings.Contains(line, "named again by serial 44") {
		t.Errorf("n's status: %q", line)
	}

	// the leader's word: first hand, by the election n holds now
	n.leadGroup(p.n44, roleA)
	n.stamps.note(p.toldThaw, roleA, transport.MechanismDNS)
	n.conf.thawTurn(zone)
	if n.store.activeUnknown(zone) || n.active() != 44 {
		t.Fatalf("n after the leader's word: %+v", status(t, n.store, zone))
	}
	if got := n.store.namedAt(zone); got != 0 {
		t.Errorf("the serial that named n is kept past its active serial's: %d", got)
	}
	n.stamps.note(p.toldDone, roleA, transport.MechanismDNS)
	n.conf.thawTurn(zone)
	n.conf.thawTurn(zone)
	if st := status(t, n.store, zone); st.Phase != PhaseSteady {
		t.Errorf("n after a's word of done: phase %s", st.Phase)
	}

	n.store.Note(zone, nServes(t, 45), nil)
	if st := status(t, n.store, zone); slices.ContainsFunc(st.Refused, func(r Refusal) bool { return r.Code == RefusedRoleWithoutRecord }) {
		t.Errorf("the role is refused for a record n now holds: %+v", st.Refused)
	}
}

// The record and the role in one edit: refused, so it brings nothing back, and
// n stays as it was. The next edit, of the record alone, does.
func TestARefusedSerialDoesNotBringAProviderBack(t *testing.T) {
	const zone = "refused.back.remove.example."
	p := newPutBack(t, zone)
	n := p.atNoRecord(t)
	engine := engineFor(n)
	n.store.Note(zone, nServes(t, 44), nil)
	st := status(t, n.store, zone)
	if !slices.ContainsFunc(st.Refused, func(r Refusal) bool { return r.Code == RefusedRoleWithoutRecord }) {
		t.Fatalf("precondition: the role in one edit is not refused: %+v", st)
	}
	n.conf.thawTurn(zone)
	if n.store.activeUnknown(zone) || n.active() != 43 {
		t.Fatalf("a refused serial moved n: %+v", status(t, n.store, zone))
	}
	if engine.ZoneNamesPeer(hsync.PeerID(roleA)) {
		t.Error("a refused serial has n's engine name a peer")
	}
	if !n.conf.safeToRemove(zone) {
		t.Error("a refused serial ends n's safe to remove")
	}
	n.store.Note(zone, withN(t, 45), nil)
	n.conf.thawTurn(zone)
	if !n.store.activeUnknown(zone) {
		t.Errorf("the record alone, above the refused serial, does not bring n back: %+v", status(t, n.store, zone))
	}
}

// Reconciling to the serial that took its record, n is still leaving: a serial
// that names it waits until the transition is done.
func TestAProviderReconcilingIsNotBroughtBack(t *testing.T) {
	const zone = "reconciling.back.remove.example."
	p := newPutBack(t, zone)
	n := p.n
	n.store.Note(zone, p.n44, nil)
	n.conf.thawTurn(zone)
	if n.store.activeUnknown(zone) || n.active() != 43 {
		t.Fatalf("n, reconciling, started over: %+v", status(t, n.store, zone))
	}
	n.stamps.note(p.toldDone43, roleA, transport.MechanismDNS)
	n.conf.thawTurn(zone)
	n.conf.thawTurn(zone)
	if !n.store.activeUnknown(zone) {
		t.Errorf("n, done, did not start over: %+v", status(t, n.store, zone))
	}
}

// With its record under the active serial, a provider with no role is a member:
// it follows its peers, and nothing is to start over.
func TestALeaverWithItsRecordIsNotBroughtBack(t *testing.T) {
	const zone = "kept.back.remove.example."
	r := newLeaverRig(t, zone, "agent")
	r.next()
	mp := r.conf.MpConfig()
	id := mp.Identity
	mp.Identity = roleN
	t.Cleanup(func() { mp.Identity = id })
	r.stamps.localID = roleN
	r.holdUnjudged(withN(t, 43), time.Now())
	before := r.active()
	r.conf.startOverIfNamedAgain(zone)
	if r.store.activeUnknown(zone) || r.active() != before {
		t.Errorf("a provider still leaving started over: %+v", status(t, r.store, zone))
	}
}

func TestNamedAgainReadsEveryGuard(t *testing.T) {
	without, without2, with := withoutN(t, 43), withoutN(t, 44), withN(t, 45)
	at := func(in *Instructions) *heldSerial { return &heldSerial{SerialDigest: sd(in), Reading: in} }
	refused := heldSerial{SerialDigest: sd(with), Reading: with, Refused: []Refusal{{Code: RefusedRoleWithoutRecord}}}
	withS := *at(with)
	for _, c := range []struct {
		name string
		z    zoneSerials
		want bool
	}{
		{"a serial names it", zoneSerials{Active: at(without), Held: []heldSerial{withS}}, true},
		{"a later serial names it", zoneSerials{Active: at(without), Held: []heldSerial{*at(without2), withS}}, true},
		{"no active serial known", zoneSerials{Held: []heldSerial{withS}}, false},
		{"its record under the active serial", zoneSerials{Active: at(with), Held: []heldSerial{withS}}, false},
		{"no serial names it", zoneSerials{Active: at(without), Held: []heldSerial{*at(without2)}}, false},
		{"none held", zoneSerials{Active: at(without)}, false},
		{"only a refused serial names it", zoneSerials{Active: at(without), Held: []heldSerial{refused}}, false},
		{"an owner error", zoneSerials{Active: at(without), Held: []heldSerial{withS}, OwnerError: "x"}, false},
		{"thawed from, until done", zoneSerials{Active: at(without), Held: []heldSerial{withS}, From: at(without)}, false},
		{"its removal under way, one edit taking its roles and record", zoneSerials{Active: at(without), Held: []heldSerial{withS}, Removals: []Removal{{Identity: roleN}}}, false},
		{"a step's sets held", zoneSerials{Active: at(without), Held: []heldSerial{withS}, Sets: []byte("{}")}, false},
		{"waiting for the leader's step", zoneSerials{Active: at(without), Held: []heldSerial{withS}, Pending: true}, false},
	} {
		if got := c.z.namedAgain(roleN) != nil; got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	// an OFF record registers no member, and names no one back
	off := jAt(t, 46, `servers="a,b" signers="a" nsmgmt="agent"`, freezeRecords[0], freezeRecords[1], `3600 IN HSYNC3 OFF n n.role.example. .`)
	if (&zoneSerials{Active: at(without), Held: []heldSerial{*at(off)}}).namedAgain(roleN) != nil {
		t.Error("an OFF record brought it back")
	}
}

// The turn has the zone's name folded (askThaw), and the store the name as it
// was spelled: the same store entry starts over, and none is made beside it.
func TestAZoneSpelledAnotherWayStartsOverToo(t *testing.T) {
	const zone = "Spelled.Back.Remove.Example."
	turn := canonicalName(zone)
	if turn == zone {
		t.Fatalf("precondition: %s folds to itself", zone)
	}
	s := newStore(t)
	noteKnown(t, s, zone, withoutN(t, 43))
	s.Note(zone, withN(t, 44), nil)
	started, err := s.startOver(turn, roleN)
	if err != nil || started == nil {
		t.Fatalf("by the turn's name: %+v, %v", started, err)
	}
	if started.name != zone || started.was.Serial != 43 || started.named.Serial != 44 {
		t.Errorf("started over: %+v", started)
	}
	if !s.activeUnknown(zone) {
		t.Errorf("the zone still knows an active serial: %+v", status(t, s, zone))
	}
	if got := s.namedAt(turn); got != 44 {
		t.Errorf("the serial that named it, by the turn's name: %d", got)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if z := s.zones[turn]; z != nil {
		t.Errorf("an entry beside the zone's: %+v", z)
	}
}
