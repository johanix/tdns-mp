/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Tellings by interest (plan S22).
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"

	transport "github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// zonesTold are the zones a stamp entry of sender's tells, folded and
// sorted; nil with no entry.
func zonesTold(e *GossipMessage, sender string) []string {
	if e == nil || e.Members[sender] == nil {
		return nil
	}
	var out []string
	for zone := range e.Members[sender].Instr {
		out = append(out, canonicalName(zone))
	}
	slices.Sort(out)
	return out
}

// heardAtRest has st hear peer's stamp of stampZone at in, and takes the
// zones its first stamp has to be told once off as told.
func heardAtRest(t *testing.T, st *stampTable, peer string, epoch, seq uint64, in *Instructions) {
	t.Helper()
	st.note(told(peer, epoch, seq, tells(in, in)), peer, "DNS")
	st.toldOnce(peer, st.entryFor(peer))
}

// A beat tells a zone only while something is going on in it (design rule
// 4, plan S22). At rest it tells none, and its row goes all the same, with
// the sender's epoch. A rollover under way, or a newer serial, has the zone
// told; so has each other mark of a zone not at rest.
func TestAStampIsToldOnlyWhileSomethingIsGoingOn(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	e := st.entryFor(stampBeta)
	if e == nil || e.Members[stampAlpha] == nil {
		t.Fatal("no row at rest")
	}
	if row := e.Members[stampAlpha]; len(row.Instr) != 0 || row.Epoch != 1 {
		t.Errorf("the row at rest: %+v, want no zone, epoch 1", row)
	}

	st.rollover = func(string) bool { return true }
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("with a rollover under way: %v", got)
	}
	st.rollover = nil
	noteKnown(t, st.store, stampZone, stampAt(t, 8, "a"))
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("with a newer serial: %v", got)
	}

	rest := tells(seven, seven)
	if !atRest(rest) {
		t.Fatalf("a steady stamp is not at rest: %+v", rest)
	}
	for name, mark := range map[string]func(*InstrStamp){
		"not known":     func(s *InstrStamp) { s.Known = false },
		"owner error":   func(s *InstrStamp) { s.Error = "two digests" },
		"refused":       func(s *InstrStamp) { s.Refused = "no-steps" },
		"agreeing":      func(s *InstrStamp) { s.Agreeing = 8 },
		"reconciling":   func(s *InstrStamp) { s.Reconciling = true },
		"a step":        func(s *InstrStamp) { s.Step = &InstrStep{} },
		"a removal":     func(s *InstrStamp) { s.Removals = []InstrRemoval{{}} },
		"a rollover":    func(s *InstrStamp) { s.Rollover = true },
		"newer":         func(s *InstrStamp) { s.Newest = 8 },
		"other digests": func(s *InstrStamp) { s.NewestDigest = "other" },
	} {
		s := rest
		mark(&s)
		if atRest(s) {
			t.Errorf("%s: at rest", name)
		}
	}
}

// A beat tells a zone to the peer that this agent has work for it with: an
// owed or a kept list, a catch-up with that peer not done, a message to it
// not yet confirmed; and to that peer only.
func TestAStampIsToldWhileWorkIsOwedKeptOrUnderWay(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	st.work = func(peer string) map[string]bool {
		return map[string]bool{stampZone: core.EqualNames(peer, stampBeta)}
	}
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("to the peer with work: %v", got)
	}
	if got := zonesTold(st.entryFor(stampDelta), stampAlpha); len(got) != 0 {
		t.Errorf("to another member: %v", got)
	}

	// the work, from each of its sources
	const owed, kept, caught, open, sent, other = "owed.example.", "kept.example.", "catchup.example.", "open.example.", "sent.example.", "other.example."
	conf := &Config{}
	conf.InternalMp.Kept = &keptLists{lists: map[string]map[string][]keptEntry{
		owed: {listOwed: {{}}}, kept: {listKept: {{}}}, other: {listOwed: nil},
	}}
	cu := newCatchUpTracker(stampAlpha, nil, time.Hour)
	cu.peers[open] = map[AgentId]*catchUpPeer{stampBeta: {State: catchUpIdle}}
	cu.peers[caught] = map[AgentId]*catchUpPeer{stampBeta: {State: catchUpIdle, Complete: true}, stampDelta: {State: catchUpIdle}}
	conf.InternalMp.CatchUp = cu
	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{
		ReliableQueue: transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})}}
	for _, m := range []*transport.OutgoingMessage{
		{DistributionID: "d1", RecipientID: stampBeta, Zone: sent},
		{DistributionID: "d2", RecipientID: stampDelta, Zone: other},
	} {
		if err := tm.ReliableQueue.Enqueue(m); err != nil {
			t.Fatal(err)
		}
	}
	got := slices.Sorted(maps.Keys(conf.workWith(tm, stampBeta)))
	if want := []string{kept, open, owed, sent}; !slices.Equal(got, want) {
		t.Errorf("the work with beta: %v, want %v", got, want)
	}
}

// A beat tells a zone at rest here to a peer whose latest first-hand stamp
// of it is not at rest, or tells other serials; and stops once the peer's
// newer beat no longer tells it. (The same serial under another digest is
// an owner error, which has the zone told to every member.)
func TestAStampIsToldToAPeerWhoseStampDiffers(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	heardAtRest(t, st, stampBeta, 1, 1, seven)
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Fatalf("to a peer at rest at the same serial: %v", got)
	}
	for i, their := range []InstrStamp{
		tells(stampAt(t, 6, "a"), stampAt(t, 6, "a")),
		tells(seven, stampAt(t, 8, "a")),
	} {
		st.note(told(stampBeta, 1, uint64(2+2*i), their), stampBeta, "DNS")
		if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, []string{stampZone}) {
			t.Errorf("to a peer that tells %+v: %v", their, got)
		}
		if got := zonesTold(st.entryFor(stampDelta), stampAlpha); len(got) != 0 {
			t.Errorf("to another member: %v", got)
		}
		// the peer's next beat tells no zone: it is at rest there too
		st.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
			stampBeta: {Identity: stampBeta, Epoch: 1, Seq: uint64(3 + 2*i)}}}, stampBeta, "DNS")
		if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
			t.Errorf("after the peer's beat with no zone: %v", got)
		}
	}
}

// A peer's first stamp since this agent's start, or one of its new epoch,
// has every zone the two share told to it once: tellOnceBatch at a time,
// each until a beat that told it is acknowledged. A newer stamp of the
// same epoch does not, nor does a zone no longer shared stay owed.
func TestAPeersRestartListsEveryZoneOnce(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	var all []string
	for i := range tellOnceBatch + 5 {
		zone := fmt.Sprintf("z%02d.example.", i)
		noteKnown(t, st.store, zone, seven)
		all = append(all, zone)
	}
	all = append(all, stampZone)
	slices.Sort(all)

	st.note(told(stampBeta, 1, 1, tells(seven, seven)), stampBeta, "DNS")
	first := st.entryFor(stampBeta)
	if got := zonesTold(first, stampAlpha); !slices.Equal(got, all[:tellOnceBatch]) {
		t.Fatalf("the first beat after the peer's start: %v, want %v", got, all[:tellOnceBatch])
	}
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, all[:tellOnceBatch]) {
		t.Errorf("again, the first unacknowledged: %v", got)
	}
	st.toldOnce(stampBeta, first)
	next := st.entryFor(stampBeta)
	if got := zonesTold(next, stampAlpha); !slices.Equal(got, all[tellOnceBatch:]) {
		t.Errorf("the next beat: %v, want %v", got, all[tellOnceBatch:])
	}
	st.toldOnce(stampBeta, next)
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Errorf("after every zone was told once: %v", got)
	}
	st.note(told(stampBeta, 1, 2, tells(seven, seven)), stampBeta, "DNS")
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Errorf("after a newer stamp of the same epoch: %v", got)
	}

	// a new epoch, by a message: every zone once more, but one no longer
	// shared, which is owed no more
	st.noteMessage(stampBeta, stampZone, &MsgStamp{Epoch: 2, Seq: 1, InstrStamp: tells(seven, seven)})
	again := st.entryFor(stampBeta)
	if got := zonesTold(again, stampAlpha); !slices.Equal(got, all[:tellOnceBatch]) {
		t.Errorf("after the peer's new epoch: %v, want %v", got, all[:tellOnceBatch])
	}
	st.toldOnce(stampBeta, again)
	gone := all[tellOnceBatch]
	st.store.mu.Lock()
	delete(st.store.zones, gone)
	st.store.mu.Unlock()
	last := st.entryFor(stampBeta)
	if got := zonesTold(last, stampAlpha); !slices.Equal(got, all[tellOnceBatch+1:]) {
		t.Errorf("with %s no longer shared: %v, want %v", gone, got, all[tellOnceBatch+1:])
	}
	st.toldOnce(stampBeta, last)
	st.mu.Lock()
	left, owed := st.once[canonicalName(stampBeta)]
	st.mu.Unlock()
	if owed {
		t.Errorf("still owed once: %v", slices.Sorted(maps.Keys(left)))
	}
}

// A row of gossip lists no zone, whatever goes on in them: a zone's group
// is the group manager's, and what a zone needs told rides in the stamp
// entry.
func TestARowListsNoZoneWhenNothingIsGoingOn(t *testing.T) {
	pgm := NewProviderGroupManager(stampAlpha)
	pgm.Groups["g1"] = &ProviderGroup{GroupHash: "g1", Members: []string{stampAlpha, stampBeta}, Zones: []ZoneName{stampZone, "other.example."}}
	ar := &AgentRegistry{
		S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: stampAlpha},
		TransportManager:     &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()},
		ProviderGroupManager: pgm, GossipStateTable: NewGossipStateTable(stampAlpha),
	}
	ar.GossipStateTable.RefreshLocalStates(ar, pgm)
	msgs := ar.GossipStateTable.BuildGossipForPeer(stampBeta, pgm)
	if len(msgs) != 1 || msgs[0].Members[stampAlpha] == nil {
		t.Fatalf("the gossip for beta: %+v", msgs)
	}
	if z := msgs[0].Members[stampAlpha].Zones; len(z) != 0 {
		t.Errorf("the own row lists %v", z)
	}
}

// At rest, a beat to a peer that shares 95 zones carries no stamp, and its
// gossip stays far under what a beat carries inline (64 KB); a beat that
// tells every zone once, at the peer's start, stays under it too.
func TestABeatOf95ZonesAtRestIsSmall(t *testing.T) {
	const zones = 95
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	pg := &ProviderGroup{GroupHash: "g1", Members: []string{stampAlpha, stampBeta, stampDelta}}
	for i := range zones - 1 {
		zone := fmt.Sprintf("zone%03d.customer.example.", i)
		noteKnown(t, st.store, zone, seven)
		pg.Zones = append(pg.Zones, ZoneName(zone))
	}
	pg.Zones = append(pg.Zones, stampZone)
	pgm := NewProviderGroupManager(stampAlpha)
	pgm.Groups[pg.GroupHash] = pg
	ar := &AgentRegistry{
		S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: stampAlpha},
		TransportManager:     &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()},
		ProviderGroupManager: pgm, GossipStateTable: NewGossipStateTable(stampAlpha),
	}
	ar.GossipStateTable.RefreshLocalStates(ar, pgm)
	beat := func() []byte {
		t.Helper()
		msgs := ar.GossipStateTable.BuildGossipForPeer(stampBeta, pgm)
		if e := st.entryFor(stampBeta); e != nil {
			msgs = append(msgs, *e)
		}
		data, err := json.Marshal(msgs)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	st.note(told(stampBeta, 1, 1, tells(seven, seven)), stampBeta, "DNS")
	once := beat()
	for e := st.entryFor(stampBeta); len(zonesTold(e, stampAlpha)) > 0; e = st.entryFor(stampBeta) {
		st.toldOnce(stampBeta, e)
	}
	rest := beat()
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Fatalf("at rest the beat tells %d zones", len(got))
	}
	t.Logf("the gossip of a beat of %d zones: %d bytes at rest, %d at the peer's start", zones, len(rest), len(once))
	if len(rest) > 4<<10 {
		t.Errorf("at rest: %d bytes", len(rest))
	}
	if len(once) > 16<<10 {
		t.Errorf("at the peer's start: %d bytes", len(once))
	}
}

// The agent's stamp table reads the agent's work with each peer when a
// beat is made; the auditor's has none.
func TestTheAgentsStampsReadItsWork(t *testing.T) {
	for _, c := range []struct {
		role  string
		init  func(*Config, *MultiProviderConf) error
		wired bool
	}{
		{"agent", (*Config).initMPAgent, true},
		{"auditor", (*Config).initMPAuditor, false},
	} {
		conf := &Config{Config: &tdns.Config{}}
		conf.Config.Internal.StopCh = make(chan struct{})
		mp := &MultiProviderConf{Role: c.role, Identity: c.role + ".work.example."}
		conf.SetMpConfig(mp)
		err := c.init(conf, mp)
		close(conf.Config.Internal.StopCh)
		if err != nil {
			t.Fatalf("%s: init: %v", c.role, err)
		}
		st := conf.InternalMp.MPTransport.stamps
		if st == nil || (st.work != nil) != c.wired {
			t.Fatalf("%s: the stamp table's work wired: %v, want %v", c.role, st != nil && st.work != nil, c.wired)
		}
		if !c.wired {
			continue
		}
		conf.InternalMp.Kept = &keptLists{lists: map[string]map[string][]keptEntry{stampZone: {listOwed: {{}}}}}
		if got := st.work(stampBeta); !got[stampZone] {
			t.Errorf("the agent's work, read at the beat: %v", got)
		}
	}
}
