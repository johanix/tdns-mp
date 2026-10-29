package tdnsmp

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// The restart rule (plan S9), on the thaw rig: agent a, in a zone that a and
// b serve and n has a record in, active at 41 (n) until the test takes its
// record away.

// noRecord has the agent start over with no record of the zone, as one
// whose record was lost: the copies given are held, and no active serial is
// known.
func (r *thawRig) noRecord(copies ...*Instructions) {
	r.t.Helper()
	if err := r.store.Forget(r.zone); err != nil {
		r.t.Fatal(err)
	}
	for _, in := range copies {
		r.store.Note(r.zone, in, nil)
	}
	if !r.store.activeUnknown(r.zone) {
		r.t.Fatal("an active serial is known with no record")
	}
}

// restart is the agent's start: its store and its lists read from disk, a
// new epoch, and nothing heard or thawed yet.
func (r *thawRig) restart() {
	r.t.Helper()
	r.load()
	r.stamps = newStampTable(roleA, r.store, 2, true, nil)
	r.stamps.rollover = r.conf.InternalMp.MPTransport.rolloverAt
	r.conf.InternalMp.MPTransport.stamps = r.stamps
	r.conf.InternalMp.thaws = thawBook{}
}

// leadGroup has the election records name leader as the leader of the
// zone's group under in.
func (r *thawRig) leadGroup(in *Instructions, leader string) {
	m := zoneMakeUp(in)
	r.lem.mu.Lock()
	defer r.lem.mu.Unlock()
	r.lem.groupElections[ComputeGroupHash(m.voting, m.auditors, m.noRole)] = &LeaderElection{Leader: AgentId(leader), LeaderExpiry: time.Now().Add(time.Hour)}
}

// hearAt is hear for a member's start numbered epoch.
func (r *thawRig) hearAt(id string, epoch uint64, st InstrStamp) {
	r.seq++
	r.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		id: {Identity: id, Timestamp: time.Now(), Epoch: epoch, Seq: r.seq, Crypto: true, Instr: map[string]InstrStamp{r.zone: st}}}}, id, transport.MechanismDNS)
}

// unknownStamp is a member's telling with no active serial known, newest
// at in.
func unknownStamp(in *Instructions) InstrStamp {
	return InstrStamp{Newest: in.Serial, NewestDigest: in.Digest()}
}

// known is the active serial the agent knows, or 0 with none.
func (r *thawRig) known() uint32 {
	r.t.Helper()
	if st := status(r.t, r.store, r.zone); st.Active != nil {
		return st.Active.Serial
	}
	return 0
}

// voters3 is the zone with n a server too: three voting members.
func voters3(t *testing.T, serial uint32, suffix string) *Instructions {
	return freezeAt(t, serial, suffix, "a,b,n", "")
}

// An agent that restarts with its own enforced record knows the zone's
// active serial from it, before any telling, and the zone is not frozen.
func TestARestartedAgentTakesItsOwnRecord(t *testing.T) {
	r := newThawRig(t, "ownrecord.restart.example.", roleB)
	r.restart()
	if r.store.activeUnknown(r.zone) || r.known() != 41 {
		t.Fatalf("after the restart: %+v", status(t, r.store, r.zone))
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) > 0 {
		t.Errorf("frozen after a restart with its record: %v", why)
	}
	if _, ok := r.conf.restartView(r.zone, time.Now()); ok {
		t.Error("the restart rule runs for a zone with its own record")
	}
}

// The leader that restarts with its record keeps it, whatever a member
// tells.
func TestARestartedLeaderTakesItsOwnRecord(t *testing.T) {
	r := newThawRig(t, "leaderrecord.restart.example.", roleA)
	r.restart()
	r.store.Note(r.zone, r.v, nil)
	r.hear(roleB, tells(r.v, r.v), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatalf("the leader's active serial moved to %d on a member's telling", r.known())
	}
}

// A member with no record takes the leader's first-hand word, and with it
// the thaw it tells.
func TestAMemberWithNoRecordTakesOnlyTheLeadersWord(t *testing.T) {
	r := newThawRig(t, "leadersword.restart.example.", roleB)
	r.noRecord(r.n)
	r.leadGroup(r.n, roleB)
	st := tells(r.n, r.n)
	st.Thaw = &Thaw{From: SerialDigest{Serial: 40, Digest: "x"}, To: sd(r.n)}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	got := status(t, r.store, r.zone)
	if r.known() != 41 || got.LastThaw == nil || got.LastThaw.To != sd(r.n) {
		t.Fatalf("after the leader's word: %+v", got)
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) > 0 {
		t.Errorf("still frozen: %v", why)
	}
}

// A member with no record does not take another member's active serial:
// only the leader's.
func TestAMemberWithNoRecordIgnoresAnotherMembersActive(t *testing.T) {
	r := newThawRig(t, "notleader.restart.example.", roleB)
	r.noRecord(r.n)
	r.leadGroup(r.n, roleB)
	r.hear(roleN, tells(r.n, r.n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("a member's active serial was taken that is not the leader's")
	}
	if line := r.conf.thawLine(r.zone); line != "active not known since the start; waiting for the leader's word" {
		t.Errorf("the status: %q", line)
	}
}

// A leader with no record takes the active serial that every voting member
// with a record tells.
func TestALeaderWithNoRecordTakesWhatEveryVotingMemberWithARecordTells(t *testing.T) {
	r := newThawRig(t, "records.restart.example.", roleA)
	n := voters3(t, 41, "n")
	r.noRecord(n)
	r.hear(roleB, tells(n, n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("known before every voting member was heard")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, roleN+" (not heard)") {
		t.Errorf("the status does not name the member not heard: %q", line)
	}
	r.hear(roleN, tells(n, n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatalf("not known from the members' records: %+v", status(t, r.store, r.zone))
	}
}

// A voting member that tells no active serial is no objection.
func TestAMemberWithNoRecordCountsAsNoObjection(t *testing.T) {
	r := newThawRig(t, "noobjection.restart.example.", roleA)
	n := voters3(t, 41, "n")
	r.noRecord(n)
	r.hear(roleB, tells(n, n), true)
	r.hear(roleN, unknownStamp(n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatalf("a member with no record held the leader: %+v", status(t, r.store, r.zone))
	}
}

// Of a from-serial and its target, the last thaw told decides.
func TestTheLastThawToldBreaksATie(t *testing.T) {
	r := newThawRig(t, "tie.restart.example.", roleA)
	n, v := voters3(t, 41, "n"), voters3(t, 42, "v")
	r.noRecord(n, v)
	r.hear(roleB, tells(n, v), true)
	st := tells(v, v)
	st.Thaw = &Thaw{From: sd(n), To: sd(v)}
	r.hear(roleN, st, true)
	r.conf.thawTurn(r.zone)
	got := status(t, r.store, r.zone)
	if r.known() != 42 || got.LastThaw == nil || got.LastThaw.To != sd(v) {
		t.Fatalf("the thaw's target was not taken: %+v", got)
	}
}

// A leader and a member that both lack a record do not wait for each
// other: the member waits for the leader's word, and the leader counts the
// member as no objection (TestAMemberWithNoRecordCountsAsNoObjection).
func TestALeaderAndAMemberWithNoRecordDoNotWaitForEachOther(t *testing.T) {
	r := newThawRig(t, "nowait.restart.example.", roleB)
	r.noRecord(r.n)
	r.leadGroup(r.n, roleB)
	r.hear(roleB, unknownStamp(r.n), true) // the leader knows nothing yet either
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("known with no word")
	}
	r.hear(roleB, tells(r.n, r.n), true) // the leader knows it now
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatal("the leader's word was not taken")
	}
}

// Records that differ hold the leader, and its status names who tells what
// and the forget command.
func TestRecordsThatDifferNameTheForgetRemedy(t *testing.T) {
	r := newThawRig(t, "differ.restart.example.", roleA)
	n, x := voters3(t, 41, "n"), voters3(t, 43, "x")
	r.noRecord(n, x)
	r.hear(roleB, tells(n, x), true)
	r.hear(roleN, tells(x, x), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("known from records that differ")
	}
	want := "no record; the voting members with a record differ (" + roleB + " tells 41, " + roleN + " tells 43); to start over, run `agent zone instructions forget` at the agents that hold a record"
	if line := r.conf.thawLine(r.zone); line != want {
		t.Errorf("the status:\n got %q\nwant %q", line, want)
	}
}

// The auditor runs the rule of a member: its own record, or the leader's
// word, never another member's. It has no election manager: the leader is
// the one the gossip table's election records name.
func TestTheAuditorTakesItsRecordOrTheLeadersWord(t *testing.T) {
	r := newThawRig(t, "auditor.restart.example.", roleA)
	old := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPAuditor
	t.Cleanup(func() { tdns.Globals.App.Type = old })
	r.conf.InternalMp.LeaderElectionManager = nil
	r.restart()
	if r.known() != 41 {
		t.Fatal("the auditor did not take its own record")
	}
	r.noRecord(r.n)
	gst := NewGossipStateTable(roleN)
	m := zoneMakeUp(r.n)
	gst.Elections[ComputeGroupHash(m.voting, m.auditors, m.noRole)] = &GroupElectionState{Leader: roleB, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)}
	r.conf.InternalMp.AgentRegistry.GossipStateTable = gst
	r.hear(roleN, tells(r.n, r.n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("the auditor took a member's word")
	}
	r.hear(roleB, tells(r.n, r.n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatal("the auditor did not take the leader's word")
	}
}

// Until the active serial is known nothing starts: the zone is frozen, the
// leader's work at the parent is held, and the parts are handed nothing.
func TestAnAgentWithNoRecordStartsNothingUntilItKnowsTheActiveSerial(t *testing.T) {
	r := newThawRig(t, "startsnothing.restart.example.", roleA)
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Options[tdns.OptMultiProvider] = true
	r.noRecord(r.n)
	if why := r.conf.zoneFrozen(r.zone); len(why) != 1 || why[0] != "the active serial is not known" {
		t.Errorf("frozen: %v", why)
	}
	if held, _ := r.conf.syncHeld(r.zone, syncOther); !held {
		t.Error("the leader's sync is not held")
	}
	if h := r.conf.wantedHandover(r.zone); h != nil {
		t.Errorf("a hand-over is wanted: %+v", h)
	}
	r.hear(roleB, unknownStamp(r.n), true)
	r.conf.thawTurn(r.zone) // the common newest
	if r.known() != 41 {
		t.Fatal("not known")
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) > 0 {
		t.Errorf("frozen once known: %v", why)
	}
	if h := r.conf.wantedHandover(r.zone); h == nil || h.Serial != 41 {
		t.Errorf("the hand-over once known: %+v", h)
	}
}

// With no active serial known the agent still talks: it votes, tells its
// stamp, and asks its voting peers for the zone's state, by its newest
// serial.
func TestARestartedAgentStillVotesBeatsAndAsksForCatchUp(t *testing.T) {
	r := newThawRig(t, "talks.restart.example.", roleB)
	r.noRecord(r.n)
	if !votesInZone(ZoneName(r.zone), roleA) {
		t.Error("it does not vote")
	}
	entry := r.stamps.entryFor(roleB)
	if entry == nil {
		t.Fatal("no stamp in its beats")
	}
	st := entry.Members[roleA].Instr[r.zone]
	if st.Known || st.Newest != 41 || st.NewestDigest != r.n.Digest() {
		t.Errorf("its stamp: %+v", st)
	}
	if peers := votingPeers(ZoneName(r.zone), roleA); len(peers) != 1 || peers[0] != roleB {
		t.Errorf("the voting peers it asks: %v", peers)
	}
}

// Before the first load the zones are placed in their groups by the
// stored serials: the active reading, or with none known the newest.
func TestStartUpPlacesZonesInGroupsFromTheStoredReadings(t *testing.T) {
	r := newThawRig(t, "groups.restart.example.", roleA)
	pgm := NewProviderGroupManager(roleA)
	r.conf.InternalMp.AgentRegistry.ProviderGroupManager = pgm
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Ready = false
	t.Cleanup(func() { mpzd.Ready = true })
	r.conf.placeGroupsAtStart()
	pg := pgm.GetGroupForZone(ZoneName(r.zone))
	if pg == nil || !isAmong(pg.VotingMembers, roleA) || !isAmong(pg.VotingMembers, roleB) {
		t.Fatalf("by the active reading: %+v", pg)
	}
	r.noRecord(voters3(t, 41, "n"))
	r.conf.placeGroupsAtStart()
	if pg := pgm.GetGroupForZone(ZoneName(r.zone)); pg == nil || !isAmong(pg.VotingMembers, roleN) {
		t.Fatalf("by the newest serial: %+v", pg)
	}
}

// writeUnenforced writes the zone's record as S2 to S6 kept it: its active
// serial followed the copy, not enforced.
func (r *thawRig) writeUnenforced(in *Instructions) {
	r.t.Helper()
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		z.Active, z.Held, z.Enforced = &heldSerial{SerialDigest: sd(in), Reading: in, Since: time.Now()}, nil, false
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
}

// A record kept before S7 counts as none at the start: its serial is held,
// none active.
func TestRecordsWrittenBeforeEnforcementCountAsNone(t *testing.T) {
	r := newThawRig(t, "unenforced.restart.example.", roleA)
	r.writeUnenforced(r.n)
	r.restart()
	st := status(t, r.store, r.zone)
	if st.Active != nil || st.Newest == nil || *st.Newest != sd(r.n) || st.Phase != PhaseNotKnown {
		t.Fatalf("after the start: %+v", st)
	}
}

// The first start after the upgrade: nobody has a record, and the leader
// makes the newest serial every voting member tells active.
func TestTheFirstStartAfterTheUpgradeMakesTheCommonNewestActive(t *testing.T) {
	r := newThawRig(t, "upgrade.restart.example.", roleA)
	r.writeUnenforced(r.n)
	r.restart()
	r.store.Note(r.zone, r.v, nil)
	r.hear(roleB, unknownStamp(r.n), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("known while b's newest differs")
	}
	if line := r.conf.thawLine(r.zone); !strings.Contains(line, roleB+" (newest 41)") {
		t.Errorf("the status: %q", line)
	}
	r.hear(roleB, unknownStamp(r.v), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 42 {
		t.Fatalf("the common newest is not active: %+v", status(t, r.store, r.zone))
	}
}

// The first activation after the upgrade does not wait for a rollover: no
// serial is active to protect.
func TestTheFirstActivationAfterTheUpgradeIgnoresARolloverUnderWay(t *testing.T) {
	r := newThawRig(t, "rollover.restart.example.", roleA)
	r.noRecord(r.n)
	r.conf.InternalMp.MPTransport.pendingDnskeyPropagations["k"] = &PendingDnskeyPropagation{Zone: ZoneName(r.zone)}
	st := unknownStamp(r.n)
	st.Rollover = true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatal("a rollover held the first activation")
	}
}

// A copy below the highest serial held is not adopted after a restart
// either, active serial known or not.
func TestACopyBelowTheHighestHeldIsRefusedAfterARestart(t *testing.T) {
	r := newThawRig(t, "below.restart.example.", roleA)
	r.noRecord(r.v)
	r.restart()
	r.store.Note(r.zone, r.n, nil)
	st := status(t, r.store, r.zone)
	if st.Newest == nil || st.Newest.Serial != 42 || r.store.readingAt(r.zone, sd(r.n)) != nil {
		t.Fatalf("after an older copy: %+v", st)
	}
}

// A member whose copy is older than the active serial the leader tells
// fetches it, and starts nothing until it holds it.
func TestAMemberWhoseCopyIsOlderFetchesAndStartsNothing(t *testing.T) {
	r := newThawRig(t, "older.restart.example.", roleB)
	var fetched []string
	r.stamps.fetch = func(zone string) (string, bool) { fetched = append(fetched, zone); return zone, true }
	r.noRecord(r.n)
	r.leadGroup(r.v, roleB)
	r.hear(roleB, tells(r.v, r.v), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 {
		t.Fatal("known without holding the serial")
	}
	if len(fetched) != 1 || !r.fetchAsked(42, roleB) {
		t.Errorf("not fetched: the copy %v, the instructions asked %v", fetched, r.fetchAsked(42, roleB))
	}
	if line := r.conf.thawLine(r.zone); line != "active not known since the start; fetching serial 42 from "+roleB {
		t.Errorf("the status: %q", line)
	}
	if err := r.store.Hold(r.zone, r.v); err != nil {
		t.Fatal(err)
	}
	r.conf.thawTurn(r.zone)
	if r.known() != 42 {
		t.Fatal("not known once held")
	}
}

// A provider new under a serial, with no role in it, talks and starts
// nothing until it hears the active serial from the leader.
func TestANewcomerStartsNothingUntilItHearsTheActiveSerial(t *testing.T) {
	r := newThawRig(t, "newcomer.restart.example.", roleB)
	in := freezeAt(t, 41, "n", "b,n", "")
	r.noRecord(in)
	if votesInZone(ZoneName(r.zone), roleA) {
		t.Fatal("the newcomer votes")
	}
	r.leadGroup(in, roleB)
	r.conf.thawTurn(r.zone)
	if r.known() != 0 || len(r.conf.zoneFrozen(r.zone)) == 0 {
		t.Fatal("the newcomer started")
	}
	r.hear(roleB, tells(in, in), true)
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatal("the leader's word was not taken")
	}
}

// A member's tellings count only from its last start: a record it told
// before it restarted without one is no record.
func TestTellingsCountOnlyFromTheLastStart(t *testing.T) {
	r := newThawRig(t, "epoch.restart.example.", roleA)
	n, x := voters3(t, 41, "n"), voters3(t, 43, "x")
	r.noRecord(n)
	r.hearAt(roleB, 1, tells(x, x)) // from before b's restart
	r.hearAt(roleB, 2, unknownStamp(n))
	r.hearAt(roleN, 1, unknownStamp(n))
	r.conf.thawTurn(r.zone)
	if r.known() != 41 {
		t.Fatalf("b's earlier telling counted: %+v", status(t, r.store, r.zone))
	}
}

// An agent restarted with its record during agreeing, with a rollover
// under way at another signer, resumes: the thaw follows the rollover's
// end.
func TestARestartDuringAgreeingWithARolloverUnderWayDoesNotDeadlock(t *testing.T) {
	r := newThawRig(t, "agreeing.restart.example.", roleA)
	r.agree()
	r.restart()
	r.hold()
	st := r.agreeing()
	st.Rollover = true
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if r.active() != 41 {
		t.Fatal("thawed during the rollover")
	}
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatalf("no thaw after the rollover: %+v", r.view())
	}
}

// Every agent restarted at rest resumes from its records, at once.
func TestEveryAgentRestartedResumes(t *testing.T) {
	r := newThawRig(t, "resumes.restart.example.", roleA)
	r.restart()
	if r.known() != 41 || len(r.conf.zoneFrozen(r.zone)) > 0 {
		t.Fatalf("after the restart: %+v", status(t, r.store, r.zone))
	}
	r.agree()
	r.hold()
	r.hear(roleB, r.agreeing(), true)
	r.conf.thawTurn(r.zone)
	if r.active() != 42 {
		t.Fatal("no thaw after the restart")
	}
}

// While the zone's active serial is not known the answer time of its
// requests stands still; an answer that arrived and is kept stops it too.
// From when the active serial is known it runs again, for 30 s or two beat
// intervals, and a kept answer that is not handled in that time fails its
// request, which is asked again.
func TestArrivedStopsTheAnswerTime(t *testing.T) {
	const zone = "arrived.restart.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	unknown := true
	r.t.activeUnknown = func(ZoneName) bool { return unknown }
	r.t.beat = time.Minute
	r.t.Ask(zone, roleB, catchUpStart)
	now := time.Now()
	_, cu, _ := r.t.step(roleB, now)
	r.t.sent(zone, roleB, cu.Request, nil)
	if _, _, next := r.t.step(roleB, now.Add(time.Hour)); !next.IsZero() || r.entry(zone, roleB).State != catchUpSent {
		t.Fatalf("the answer time ran while the active serial was not known: %+v", r.entry(zone, roleB))
	}
	r.t.Arrived(zone, roleB, cu)
	unknown = false
	if r.t.step(roleB, now.Add(time.Hour)); r.entry(zone, roleB).State != catchUpSent {
		t.Fatal("the request of a kept answer failed")
	}
	r.t.activeChanged(zone)
	if e := r.entry(zone, roleB); e.arrived || time.Until(e.deadline) < 110*time.Second {
		t.Fatalf("the answer time from when the active serial is known: %+v", e)
	}
	r.t.step(roleB, time.Now().Add(3*time.Minute))
	if e := r.entry(zone, roleB); e.State != catchUpRetry {
		t.Errorf("a kept answer not handled in time did not fail its request: %+v", e)
	}
}

// A request whose answer came and is kept waits for nothing more from the
// peer: it leaves its place among the eight in flight, while the zone's
// active serial is not known as after.
func TestAKeptAnswerLeavesItsPlaceAmongTheRequestsInFlight(t *testing.T) {
	var zones []ZoneName
	for i := range catchUpInFlight + 1 {
		zone := "z" + string(rune('a'+i)) + ".inflight.restart.example."
		catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
		zones = append(zones, ZoneName(zone))
	}
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	r.t.activeUnknown = func(ZoneName) bool { return true }
	for _, zone := range zones {
		r.t.Ask(zone, roleB, catchUpStart)
	}
	now := time.Now()
	asked := map[ZoneName]*CatchUp{}
	for range catchUpInFlight {
		zone, cu, _ := r.t.step(roleB, now)
		if cu == nil {
			t.Fatalf("%d requests in flight; want %d", len(asked), catchUpInFlight)
		}
		r.t.sent(zone, roleB, cu.Request, nil)
		asked[zone] = cu
	}
	if zone, cu, _ := r.t.step(roleB, now); cu != nil {
		t.Fatalf("a ninth request in flight, for %s", zone)
	}
	r.t.Arrived(zones[0], roleB, asked[zones[0]])
	if zone, cu, _ := r.t.step(roleB, now); cu == nil || zone != zones[catchUpInFlight] {
		t.Errorf("after a kept answer the next request is %q; want %s", zone, zones[catchUpInFlight])
	}
}

// An acknowledgement that comes after the answer, kept, and after the
// active serial became known leaves the answer time that activeChanged gave
// the request.
func TestALateAcknowledgementLeavesTheAnswerTime(t *testing.T) {
	const zone = "lateack.restart.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	unknown := true
	r.t.activeUnknown = func(ZoneName) bool { return unknown }
	r.t.beat = time.Minute
	r.t.Ask(zone, roleB, catchUpStart)
	_, cu, _ := r.t.step(roleB, time.Now())
	r.t.Arrived(zone, roleB, cu)
	unknown = false
	r.t.activeChanged(zone)
	r.t.sent(zone, roleB, cu.Request, nil)
	if e := r.entry(zone, roleB); time.Until(e.deadline) < 110*time.Second {
		t.Errorf("the acknowledgement cut the answer time to %s: %+v", time.Until(e.deadline).Round(time.Second), e)
	}
}

// While the active serial is not known a catch-up answer is kept, whatever
// its sender's stamp, and its request's answer time stands still
// (Arrived); once the serial is known the answer is released and handled,
// and the request is answered.
func TestACatchUpAnswerIsKeptWhileTheActiveSerialIsUnknown(t *testing.T) {
	r := newReceiveRig(t, "catchup.restart.example.")
	tr := newCatchUpTracker(roleA, nil, time.Hour)
	tr.operational = func(AgentId) bool { return true }
	tr.activeUnknown = func(zone ZoneName) bool { return r.store.activeUnknown(string(zone)) }
	r.conf.InternalMp.CatchUp = tr
	if err := r.store.Forget(r.zone); err != nil {
		t.Fatal(err)
	}
	r.store.Note(r.zone, r.n, nil)
	tr.Ask(ZoneName(r.zone), roleB, catchUpStart)
	_, cu, _ := tr.step(roleB, time.Now())
	if cu == nil {
		t.Fatal("no request to send")
	}
	tr.sent(ZoneName(r.zone), roleB, cu.Request, nil)
	answer := completeAnswer(cu.Request)
	resp := make(chan *AgentMsgResponse, 1)
	r.conf.applyRemoteUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleB, UpdateType: "remote",
		Update:            &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleB, Operations: []core.RROperation{r.bNS("ns1.b.example.")}},
		OriginatingDistID: "a1", OriginatingInstr: &MsgStamp{Epoch: 1, Seq: stampSeq.Add(1), InstrStamp: unknownStamp(r.n)},
		Mechanism: "DNS", OriginatingTime: time.Now(), DeliveredBy: roleB, CatchUp: answer, Response: resp}, r.conf.InternalMp.MsgQs)
	if got := r.answered("a1"); len(got) != 1 || got[0].Status != "PENDING" || got[0].Message != "kept: this agent does not know its active serial yet, nor did the sender tell one" {
		t.Errorf("the answer to b: %+v", got)
	}
	if len(r.kept()) != 1 || len(r.nsOf(roleB)) != 0 {
		t.Fatalf("not kept: the kept list %+v, b's NS %v", r.kept(), r.nsOf(roleB))
	}
	if e := tr.peers[ZoneName(r.zone)][roleB]; e == nil || !e.arrived || e.Complete {
		t.Fatalf("the request: %+v, want its answer arrived and not handled", e)
	}
	r.cmds()
	r.conf.know(r.zone, sd(r.n), nil, roleB, knownFromLeader)
	if got := r.cmds(); !slices.Contains(got, "instr-activated") {
		t.Fatalf("knowing the serial asked the data engine for %v, want instr-activated", got)
	}
	r.activated()
	if got := r.nsOf(roleB); !slices.Equal(got, []string{"ns1.b.example."}) || len(r.kept()) != 0 {
		t.Errorf("after the release: b's NS %v, the kept list %+v", got, r.kept())
	}
	if e := tr.peers[ZoneName(r.zone)][roleB]; e == nil || !e.Complete || e.outstanding() {
		t.Errorf("the request after the release: %+v, want answered", e)
	}
}

// The leader's word keeps the thaw it tells only when the thaw ends at the
// serial taken, as the leader's own rule does: an older last thaw is not
// this serial's.
func TestALeadersOlderThawIsNotKeptWithTheSerialTaken(t *testing.T) {
	r := newThawRig(t, "olderthaw.restart.example.", roleB)
	r.noRecord(r.n)
	r.leadGroup(r.n, roleB)
	st := tells(r.n, r.n)
	st.Thaw = &Thaw{From: SerialDigest{Serial: 39, Digest: "x"}, To: SerialDigest{Serial: 40, Digest: "y"}}
	r.hear(roleB, st, true)
	r.conf.thawTurn(r.zone)
	if got := status(t, r.store, r.zone); r.known() != 41 || got.LastThaw != nil {
		t.Fatalf("after the leader's word with an older thaw: %+v", got)
	}
}

// A request whose kept answer fails it, when released and found not
// complete, waits for its next answer in that answer's own time: the mark
// of the kept answer goes with the failure.
func TestARequestWhoseKeptAnswerFailsWaitsForItsNextAnswer(t *testing.T) {
	const zone = "keptfail.restart.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	r.t.Ask(zone, roleB, catchUpStart)
	now := time.Now()
	_, cu, _ := r.t.step(roleB, now)
	r.t.sent(zone, roleB, cu.Request, nil)
	r.t.Arrived(zone, roleB, cu)
	r.t.Answered(zone, roleB, &CatchUp{Request: cu.Request, Why: "no-inventory"}) // released, not complete
	if e := r.entry(zone, roleB); e.State != catchUpRetry || e.arrived {
		t.Fatalf("after the kept answer failed the request: %+v", e)
	}
	_, again, _ := r.t.step(roleB, now.Add(time.Hour))
	if again == nil {
		t.Fatal("the request was not asked again")
	}
	r.t.sent(zone, roleB, again.Request, nil)
	r.t.step(roleB, now.Add(3*time.Hour))
	if e := r.entry(zone, roleB); e.State != catchUpRetry {
		t.Errorf("the request asked again never timed out: %+v", e)
	}
}

// A zone placed in its group before its first load names its members by
// the stored serials: a group election that calls through it before the
// zone is loaded reaches them, rather than failing on the zone's data.
func TestAGroupElectionReachesAZoneNotLoadedYet(t *testing.T) {
	r := newThawRig(t, "notloaded.restart.example.", roleA)
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Ready = false
	t.Cleanup(func() { mpzd.Ready = true })
	zad, err := r.conf.InternalMp.AgentRegistry.GetZoneAgentData(ZoneName(r.zone))
	if err != nil {
		t.Fatalf("the zone's agents before its first load: %v", err)
	}
	if len(zad.Agents) != 1 || zad.Agents[0].ID != AgentId(roleB) {
		t.Errorf("the zone's agents: %v", zad.Agents)
	}
}

// While the active serial is not known the agent hands its signer nothing
// new, but what the signer holds again with the hold set, so that no new
// rollover starts there (the project owner, 2026-10-29; the signer's side is
// S6's TestNoRolloverStartsUnderAHold). Once the serial is known the hold
// goes with the freeze.
func TestTheSignerIsHeldOnWhatItHoldsWhileTheActiveSerialIsNotKnown(t *testing.T) {
	r := newThawRig(t, "signerhold.restart.example.", roleA)
	q := r.withSigner()
	var msgs []handedMsg
	newest := func() *ActingHandover {
		msgs = append(msgs, q.take()...)
		return newestHanded(msgs)
	}
	r.conf.handOverToParts(r.zone)
	waitUntil(t, "the hand-over at 41", func() bool { h := newest(); return h != nil && h.Serial == 41 && !h.Sets.Hold })
	held := newest()
	r.conf.InternalMp.SignerHandover.learned(r.zone, held) // the signer holds it
	sets := held.Sets

	r.noRecord(r.n) // the record lost: the zone is frozen, no active serial known
	waitUntil(t, "the hold on what the signer holds", func() bool { h := newest(); return h != nil && h.Sets.Hold })
	h := newest()
	r.conf.InternalMp.SignerHandover.learned(r.zone, h) // the signer holds it, with the hold
	c := *h
	h = &c
	h.Sets.Hold = false
	if h.Serial != 41 || !h.sameAs(&ActingHandover{Zone: h.Zone, Serial: 41, Digest: held.Digest, Newest: held.Newest, Phase: held.Phase, Step: held.Step, Records: held.Records, Sets: sets}) {
		t.Errorf("the hold carries other than what the signer held: %+v", h)
	}

	r.hear(roleB, unknownStamp(r.n), true)
	r.conf.thawTurn(r.zone) // the common newest
	if r.known() != 41 {
		t.Fatal("not known")
	}
	waitUntil(t, "the hold let go once the serial is known", func() bool { h := newest(); return h != nil && !h.Sets.Hold })
}
