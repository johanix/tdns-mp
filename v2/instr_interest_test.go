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
	"reflect"
	"slices"
	"strings"
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
	st.acknowledged(peer, st.entryFor(peer))
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
// of it is not at rest, or tells other serials. A peer's stamp at rest is
// kept until the peer tells another (F3 of the external review): one that
// lags, at rest at an older serial, goes on being told the newer, and
// fetches it. One not at rest is dropped once the peer's newer beat no
// longer tells it. (The same serial under another digest is an owner error,
// which has the zone told to every member.)
func TestAStampIsToldToAPeerWhoseStampDiffers(t *testing.T) {
	seven, six := stampAt(t, 7, "a"), stampAt(t, 6, "a")
	st := stampTableAt(t, stampAlpha, seven)
	heardAtRest(t, st, stampBeta, 1, 1, seven)
	toldTo := func(peer string) []string {
		e := st.entryFor(peer)
		st.acknowledged(peer, e)
		return zonesTold(e, stampAlpha)
	}
	empty := func(seq uint64) *GossipMessage {
		return &GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
			stampBeta: {Identity: stampBeta, Epoch: 1, Seq: seq}}}
	}
	if got := toldTo(stampBeta); len(got) != 0 {
		t.Fatalf("to a peer at rest at the same serial: %v", got)
	}

	// a peer that lags, at rest at 6
	st.note(told(stampBeta, 1, 2, tells(six, six)), stampBeta, "DNS")
	if got := toldTo(stampBeta); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("to a peer at rest at 6: %v", got)
	}
	if got := toldTo(stampDelta); len(got) != 0 {
		t.Errorf("to another member: %v", got)
	}
	st.note(empty(3), stampBeta, "DNS")
	if got := toldTo(stampBeta); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("to a peer at rest at 6, after its beat with no zone: %v", got)
	}
	st.note(told(stampBeta, 1, 4, tells(seven, seven)), stampBeta, "DNS")
	if got := toldTo(stampBeta); len(got) != 0 {
		t.Errorf("after the peer tells 7: %v", got)
	}

	// a peer not at rest, whose next beat tells no zone
	st.note(told(stampBeta, 1, 5, tells(seven, stampAt(t, 8, "a"))), stampBeta, "DNS")
	if got := toldTo(stampBeta); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("to a peer not at rest: %v", got)
	}
	st.note(empty(6), stampBeta, "DNS")
	if got := toldTo(stampBeta); len(got) != 0 {
		t.Errorf("after the peer's beat with no zone: %v", got)
	}
}

// drainOnce has st make beats to peer, each acknowledged (acknowledged), until
// one tells no zone; it gives the zones each told, folded.
func drainOnce(t *testing.T, st *stampTable, peer, sender string) [][]string {
	t.Helper()
	var beats [][]string
	for range 100 {
		e := st.entryFor(peer)
		told := zonesTold(e, sender)
		if len(told) == 0 {
			return beats
		}
		beats = append(beats, told)
		st.acknowledged(peer, e)
	}
	t.Fatal("the beats never ran out of zones to tell once")
	return nil
}

// A peer's first stamp since this agent's start, or one of its new epoch,
// has every zone the two share told to it once: as many a beat as the
// entry's budget holds, each until a beat that told it is acknowledged,
// none of them a partial beat (nothing goes on in them). A newer stamp of
// the same epoch does not, nor does a zone no longer shared stay owed.
func TestAPeersRestartListsEveryZoneOnce(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	all := []string{stampZone}
	for i := range 299 {
		zone := fmt.Sprintf("z%03d.example.", i)
		noteKnown(t, st.store, zone, seven)
		all = append(all, zone)
	}
	slices.Sort(all)

	st.note(told(stampBeta, 1, 1, tells(seven, seven)), stampBeta, "DNS")
	// one beat that is not acknowledged: its zones are told again later
	if e := st.entryFor(stampBeta); len(zonesTold(e, stampAlpha)) == 0 || e.Members[stampAlpha].Partial {
		t.Fatalf("the first beat after the peer's start: %+v", e)
	}
	beats := drainOnce(t, st, stampBeta, stampAlpha)
	var got []string
	for _, b := range beats {
		got = append(got, b...)
	}
	slices.Sort(got)
	if !slices.Equal(got, all) || len(beats) < 2 {
		t.Errorf("told once in %d beats: %d zones, want each of %d once over more than one beat", len(beats), len(got), len(all))
	}
	st.note(told(stampBeta, 1, 2, tells(seven, seven)), stampBeta, "DNS")
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Errorf("after a newer stamp of the same epoch: %v", got)
	}
	// what beta was told is noted, and dropped for a zone no longer shared
	pruned := all[len(all)-1]
	st.store.mu.Lock()
	delete(st.store.zones, pruned)
	st.store.mu.Unlock()
	all = all[:len(all)-1]
	if acked := st.ackedFor(stampBeta, all); len(acked) != len(all) {
		t.Errorf("%d stamps noted as told to beta, want %d (not %s's)", len(acked), len(all), pruned)
	}

	// a new epoch, by a message: what beta was told is forgotten, and every
	// zone is told once more, but one no longer shared, which is owed no more
	st.noteMessage(stampBeta, stampZone, &MsgStamp{Epoch: 2, Seq: 1, InstrStamp: tells(seven, seven)})
	if acked := st.ackedFor(stampBeta, all); len(acked) != 0 {
		t.Errorf("after beta's new epoch, %d stamps still noted as told to it", len(acked))
	}
	first := st.entryFor(stampBeta)
	st.acknowledged(stampBeta, first)
	gone := ""
	for _, zone := range all {
		if !slices.Contains(zonesTold(first, stampAlpha), zone) {
			gone = zone
			break
		}
	}
	st.store.mu.Lock()
	delete(st.store.zones, gone)
	st.store.mu.Unlock()
	got = zonesTold(first, stampAlpha)
	for _, b := range drainOnce(t, st, stampBeta, stampAlpha) {
		got = append(got, b...)
	}
	slices.Sort(got)
	if want := slices.DeleteFunc(slices.Clone(all), func(z string) bool { return z == gone }); !slices.Equal(got, want) {
		t.Errorf("after the peer's new epoch, with %s no longer shared: %d zones, want %d", gone, len(got), len(want))
	}
	st.mu.Lock()
	left, owed := st.once[canonicalName(stampBeta)]
	st.mu.Unlock()
	if owed {
		t.Errorf("still owed once: %v", slices.Sorted(maps.Keys(left)))
	}
}

// massEdit is local's stamp table with n zones that a rollover waiting on
// many signers is going on in: stamps of about a kilobyte each, as a
// reconciliation's are, more than one beat holds. Twenty more zones are at
// rest.
func massEdit(t *testing.T, local string, n int) (*stampTable, []string) {
	t.Helper()
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, local, seven)
	zones := []string{stampZone}
	for i := range n - 1 {
		zone := fmt.Sprintf("edited%04d.customer.example.", i)
		noteKnown(t, st.store, zone, seven)
		zones = append(zones, zone)
	}
	for i := range 20 {
		noteKnown(t, st.store, fmt.Sprintf("rest%02d.customer.example.", i), seven)
	}
	slices.Sort(zones)
	var signers []string
	for i := range 30 {
		signers = append(signers, fmt.Sprintf("agent.signer%02d.provider.example.", i))
	}
	edited := func(zone string) bool { return !strings.HasPrefix(zone, "rest") }
	st.rollover = edited
	st.waitsOn = func(string) []string { return signers }
	return st, zones
}

// A mass edit's beats always fit (plan S22, amended 2026-10-30): each
// tells no more than the entry's budget holds, says it is partial while
// zones are left out, and in ceil(n/K) beats, K the fewest any beat tells,
// every zone is told, each beat acknowledged: a zone just told does not
// hold back those not told yet (F1 of the external review). A zone told
// only for the peer's new epoch waits until the edited zones fit.
func TestAMassEditsBeatsAlwaysFit(t *testing.T) {
	for _, n := range []int{40, 1000} {
		st, zones := massEdit(t, stampAlpha, n)
		tellEveryZoneOnce(st, stampBeta)
		var beats [][]string
		fewest := n
		seen := map[string]int{}
		for b := 0; len(seen) < n && b < 2*n; b++ {
			e := st.entryFor(stampBeta)
			row := e.Members[stampAlpha]
			data, err := json.Marshal(row.Instr)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > stampEntryBudget {
				t.Fatalf("%d zones, beat %d: %d bytes of stamps, over the budget of %d", n, b, len(data), stampEntryBudget)
			}
			if !row.Partial {
				t.Fatalf("%d zones, beat %d: told %d and not partial", n, b, len(row.Instr))
			}
			told := zonesTold(e, stampAlpha)
			if i := slices.IndexFunc(told, func(z string) bool { return strings.HasPrefix(z, "rest") }); i >= 0 {
				t.Fatalf("%d zones, beat %d: %s, at rest, told while edited zones are left out", n, b, told[i])
			}
			beats = append(beats, told)
			fewest = min(fewest, len(told))
			for _, z := range told {
				if _, ok := seen[z]; !ok {
					seen[z] = b
				}
			}
			st.acknowledged(stampBeta, e)
		}
		if len(seen) != len(zones) {
			t.Fatalf("%d zones: %d told in %d beats", n, len(seen), len(beats))
		}
		if within := (n + fewest - 1) / fewest; len(beats) > within {
			t.Errorf("%d zones: every zone told in %d beats, want at most ceil(%d/%d) = %d", n, len(beats), n, fewest, within)
		}
		t.Logf("%d zones: %d to %d a beat, all told in %d beats", n, fewest, len(beats[0]), len(beats))
	}
}

// A partial beat keeps what the receiver holds of the zones it does not
// tell, exactly as they were told and heard; a full beat drops them, as
// before.
func TestAPartialBeatKeepsTheZonesItDoesNotTell(t *testing.T) {
	seven := stampAt(t, 7, "a")
	bob := stampTableAt(t, stampBeta, seven)
	const other = "other.example."
	noteKnown(t, bob.store, other, seven)
	going := tells(seven, stampAt(t, 8, "a"))
	going.Reconciling = true
	going.Step = &InstrStep{Number: 1, Of: 2, What: "a step", Sets: json.RawMessage(`{"servers":["alpha"]}`), Digest: "d1"}
	beat := func(seq uint64, partial bool, zones ...string) *GossipMessage {
		row := &MemberState{Identity: stampAlpha, Timestamp: time.Now(), Epoch: 1, Seq: seq, Crypto: true,
			Instr: map[string]InstrStamp{}, Partial: partial}
		for _, z := range zones {
			row.Instr[z] = going
		}
		return &GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{stampAlpha: row}}
	}
	bob.note(beat(1, false, stampZone, other), stampAlpha, "DNS")
	first := bob.heard(stampAlpha).ZoneHeard[other]
	time.Sleep(10 * time.Millisecond)

	bob.note(beat(2, true, stampZone), stampAlpha, "DNS")
	m := bob.heard(stampAlpha)
	if _, kept := m.Instr[other]; !kept || !m.ZoneHeard[other].Equal(first) {
		t.Errorf("after a partial beat: %s kept %v, heard %s, want kept as heard at %s", other, kept, m.ZoneHeard[other], first)
	}
	// kept exactly: a zone left out never reads as done (S12 reads a stamp
	// without reconciling so)
	if !reflect.DeepEqual(m.Instr[other], going) {
		t.Errorf("after a partial beat %s is %+v, want it as told: %+v", other, m.Instr[other], going)
	}
	if !m.ZoneHeard[stampZone].After(first) {
		t.Errorf("the zone the partial beat told was not heard anew: %s", m.ZoneHeard[stampZone])
	}

	bob.note(beat(3, false, stampZone), stampAlpha, "DNS")
	if _, kept := bob.heard(stampAlpha).Instr[other]; kept {
		t.Errorf("a full beat that does not tell %s kept it", other)
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
// tells zones once, at the peer's start, holds no more than the entry's
// budget.
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
		st.acknowledged(stampBeta, e)
	}
	rest := beat()
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Fatalf("at rest the beat tells %d zones", len(got))
	}
	t.Logf("the gossip of a beat of %d zones: %d bytes at rest, %d at the peer's start", zones, len(rest), len(once))
	if len(rest) > 4<<10 {
		t.Errorf("at rest: %d bytes", len(rest))
	}
	if len(once) > stampEntryBudget+4<<10 {
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

// A zone whose stamp changed since an acknowledged beat to the peer told it
// goes first, ahead of its turn: a step, a step held, a "done" each wait a
// whole rotation otherwise.
func TestAChangedStampGoesFirst(t *testing.T) {
	st, zones := massEdit(t, stampAlpha, 40)
	for seen := map[string]bool{}; len(seen) < len(zones); {
		e := st.entryFor(stampBeta)
		for _, z := range zonesTold(e, stampAlpha) {
			seen[z] = true
		}
		st.acknowledged(stampBeta, e)
	}
	turn := st.entryFor(stampBeta)
	st.acknowledged(stampBeta, turn)
	target := zonesTold(turn, stampAlpha)[0] // just told: a rotation away
	signers := st.waitsOn(target)
	st.waitsOn = func(zone string) []string {
		if zone == target {
			return signers[:5]
		}
		return signers
	}
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Contains(got, target) {
		t.Errorf("the changed zone %s is not in the next beat: %v", target, got)
	}
}

// Changed zones leave room for the zones that are due, told longer ago than
// refresh, up to half the budget and no more than those need; while none is
// due they take the whole budget (F1, F2 of the external review).
func TestChangedZonesLeaveRoomForTheDueOnes(t *testing.T) {
	split := func(nChanged int, due bool) (changedBytes, unchanged int, partial bool) {
		t.Helper()
		st, zones := massEdit(t, stampAlpha, 40)
		for seen := map[string]bool{}; len(seen) < len(zones); {
			e := st.entryFor(stampBeta)
			for _, z := range zonesTold(e, stampAlpha) {
				seen[z] = true
			}
			st.acknowledged(stampBeta, e)
		}
		changed := map[string]bool{}
		for _, z := range zones[:nChanged] {
			changed[z] = true
		}
		signers := st.waitsOn(zones[0])
		st.waitsOn = func(zone string) []string {
			if changed[zone] {
				return signers[:10]
			}
			return signers
		}
		if due {
			st.refresh = time.Nanosecond
			time.Sleep(time.Millisecond)
		}
		e := st.entryFor(stampBeta)
		for zone, ist := range e.Members[stampAlpha].Instr {
			if changed[zone] {
				changedBytes += newToTell(zone, ist).size
			} else {
				unchanged++
			}
		}
		return changedBytes, unchanged, e.Members[stampAlpha].Partial
	}
	if b, _, partial := split(30, false); b <= stampEntryBudget*3/4 || !partial {
		t.Errorf("with 30 changed and none due: %d bytes of changed zones, partial %v", b, partial)
	}
	if b, n, partial := split(30, true); b > stampEntryBudget/2 || n == 0 || !partial {
		t.Errorf("with 30 changed and 10 due: %d bytes of changed zones (half the budget is %d), %d due told, partial %v",
			b, stampEntryBudget/2, n, partial)
	}
	if b, n, _ := split(39, true); b <= stampEntryBudget*3/4 || n != 1 {
		t.Errorf("with 39 changed and 1 due: %d bytes of changed zones, %d due told", b, n)
	}
}

// A zone that comes to rest after a beat told it is told once more, at
// rest, so that the peer stops holding it as going on; then not again. A
// beat that is not acknowledged does not count.
func TestAZoneThatComesToRestIsToldOnce(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	going := true
	st.rollover = func(string) bool { return going }
	e := st.entryFor(stampBeta)
	if got := zonesTold(e, stampAlpha); !slices.Equal(got, []string{stampZone}) {
		t.Fatalf("while going on: %v", got)
	}
	st.acknowledged(stampBeta, e)
	going = false
	for i, ack := range []bool{false, true} {
		e := st.entryFor(stampBeta)
		if got := zonesTold(e, stampAlpha); !slices.Equal(got, []string{stampZone}) || e.Members[stampAlpha].Instr[stampZone].Rollover {
			t.Fatalf("beat %d at rest: %v, want the zone told at rest", i, got)
		}
		if ack {
			st.acknowledged(stampBeta, e)
		}
	}
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); len(got) != 0 {
		t.Errorf("after the acknowledged beat at rest: %v", got)
	}
}

// A peer that lags, at rest at an older serial, keeps the newer serial a
// sender told it once at rest after the sender's full beats no longer tell
// it, and tells it back (F3 of the external review); a zone no longer shared
// goes, at rest or not.
func TestALaggingPeerKeepsTheNewerSerialItWasTold(t *testing.T) {
	seven, eight := stampAt(t, 7, "a"), stampAt(t, 8, "a")
	bob := stampTableAt(t, stampBeta, seven)
	bob.note(told(stampAlpha, 1, 1, tells(eight, eight)), stampAlpha, "DNS")
	bob.acknowledged(stampAlpha, bob.entryFor(stampAlpha))
	bob.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		stampAlpha: {Identity: stampAlpha, Epoch: 1, Seq: 2}}}, stampAlpha, "DNS")
	if st, kept := bob.heard(stampAlpha).Instr[stampZone]; !kept || st.Active != 8 {
		t.Fatalf("after alice's full beat with no zone: kept %v, %+v", kept, st)
	}
	if got := zonesTold(bob.entryFor(stampAlpha), stampBeta); !slices.Equal(got, []string{stampZone}) {
		t.Errorf("bob, at 7, tells alice: %v", got)
	}
	bob.store.mu.Lock()
	delete(bob.store.zones, stampZone)
	bob.store.mu.Unlock()
	bob.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		stampAlpha: {Identity: stampAlpha, Epoch: 1, Seq: 3}}}, stampAlpha, "DNS")
	if _, kept := bob.heard(stampAlpha).Instr[stampZone]; kept {
		t.Error("a zone no longer shared is kept")
	}
}

// Zones told once, over several beats, after the receiver's start are kept
// by it as each later beat leaves them out (F4 of the external review).
func TestAOnceListingOverSeveralBeatsKeepsTheEarlierZones(t *testing.T) {
	seven := stampAt(t, 7, "a")
	alice, bob := stampTableAt(t, stampAlpha, seven), stampTableAt(t, stampBeta, seven)
	all := []string{stampZone}
	for i := range 299 {
		zone := fmt.Sprintf("z%03d.example.", i)
		noteKnown(t, alice.store, zone, seven)
		noteKnown(t, bob.store, zone, seven)
		all = append(all, zone)
	}
	slices.Sort(all)
	tellEveryZoneOnce(alice, stampBeta)
	beats := 0
	for e := alice.entryFor(stampBeta); len(zonesTold(e, stampAlpha)) > 0; e = alice.entryFor(stampBeta) {
		bob.note(e, stampAlpha, "DNS")
		alice.acknowledged(stampBeta, e)
		beats++
	}
	if got := slices.Sorted(maps.Keys(bob.heard(stampAlpha).Instr)); beats < 2 || !slices.Equal(got, all) {
		t.Errorf("after %d beats bob holds %d of alice's %d zones", beats, len(got), len(all))
	}
}

// The turn of the zones told goes on only when the beat that told them is
// acknowledged: a beat lost is made again (F5 of the external review).
func TestTheTurnMovesWhenABeatIsAcknowledged(t *testing.T) {
	st, _ := massEdit(t, stampAlpha, 40)
	first := zonesTold(st.entryFor(stampBeta), stampAlpha)
	again := st.entryFor(stampBeta)
	if got := zonesTold(again, stampAlpha); !slices.Equal(got, first) {
		t.Fatalf("after a beat that was not acknowledged: %v, want %v again", got, first)
	}
	st.acknowledged(stampBeta, again)
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); slices.ContainsFunc(got, func(z string) bool { return slices.Contains(first, z) }) {
		t.Errorf("after the acknowledged beat: %v, want none of %v", got, first)
	}
}

// A beat takes its sequence before it reads the stamps it tells: a message
// whose stamp is read while the beat is made carries a later sequence, so
// the receiver keeps the message's newer stamp (N1 of the external review).
func TestABeatTakesItsSequenceBeforeItsStamps(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	tellEveryZoneOnce(st, stampBeta)
	var msg *MsgStamp
	inside := false
	st.rollover = func(zone string) bool {
		if !inside && msg == nil {
			inside = true
			msg = st.messageStamp(zone)
			inside = false
		}
		return false
	}
	e := st.entryFor(stampBeta)
	if msg == nil || msg.Seq <= e.Members[stampAlpha].Seq {
		t.Errorf("the beat's sequence %d, a message's made while it was made %+v", e.Members[stampAlpha].Seq, msg)
	}
}

// An acknowledgement of a beat made before the peer's new epoch counts for
// nothing: the zones it told are still owed once to the peer as it is now,
// and an acknowledgement of a beat older than the latest made counts for
// nothing either (S2 of the external review).
func TestAnAcknowledgementFromBeforeThePeersNewEpochCountsForNothing(t *testing.T) {
	seven := stampAt(t, 7, "a")
	st := stampTableAt(t, stampAlpha, seven)
	for i := range 299 {
		noteKnown(t, st.store, fmt.Sprintf("z%03d.example.", i), seven)
	}
	owed := func() map[string]bool {
		st.mu.Lock()
		defer st.mu.Unlock()
		return maps.Clone(st.once[canonicalName(stampBeta)])
	}
	st.note(told(stampBeta, 1, 1, tells(seven, seven)), stampBeta, "DNS")
	late := st.entryFor(stampBeta)
	st.note(told(stampBeta, 2, 1, tells(seven, seven)), stampBeta, "DNS")
	st.entryFor(stampBeta) // the new epoch's first beat, its zones counted
	st.acknowledged(stampBeta, late)
	left := owed()
	for _, z := range zonesTold(late, stampAlpha) {
		if !left[z] {
			t.Fatalf("%s, told in a beat made before beta's new epoch, is no longer owed to it", z)
		}
	}
}

// A change told in a beat that was not acknowledged is told again when it
// is undone: the peer may hold it (S2 of the external review).
func TestAChangeInABeatNotAcknowledgedIsToldAgain(t *testing.T) {
	st := stampTableAt(t, stampAlpha, stampAt(t, 7, "a"))
	heardAtRest(t, st, stampBeta, 1, 1, stampAt(t, 7, "a"))
	rolling := true
	st.rollover = func(string) bool { return rolling }
	if got := zonesTold(st.entryFor(stampBeta), stampAlpha); !slices.Equal(got, []string{stampZone}) {
		t.Fatalf("the rollover: %v", got)
	}
	rolling = false // the beat that told it was not acknowledged
	e := st.entryFor(stampBeta)
	if got := zonesTold(e, stampAlpha); !slices.Equal(got, []string{stampZone}) || e.Members[stampAlpha].Instr[stampZone].Rollover {
		t.Errorf("after the rollover ended, its beat not acknowledged: %v", got)
	}
}
