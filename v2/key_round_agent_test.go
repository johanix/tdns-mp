/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// What a key round's answers decide at the agent (step 7b), on a zone whose
// parent takes UPDATE: this agent and one other provider, both servers, so
// both vote.

type keyRoundRig struct {
	*holdRig
	zone  ZoneName
	them  AgentId
	us    AgentId
	alog  *lockedBuffer
	polls chan uint16
}

func newKeyRoundRig(t *testing.T, zone, scheme string) *keyRoundRig {
	t.Helper()
	// the agent's logger first, so that it is put back after the rig stops
	alog := &lockedBuffer{}
	saved := lgAgent
	lgAgent = slog.New(slog.NewTextHandler(alog, nil))
	t.Cleanup(func() { lgAgent = saved })
	h := newHoldRig(t, zone, scheme, false, repeat(time.Hour, 4)...)
	r := &keyRoundRig{holdRig: h, zone: ZoneName(h.mpzd.ZoneName), them: AgentId(h.peer.Identity), us: AgentId(h.notifyRig.us.Identity),
		alog: alog, polls: make(chan uint16, 8)}
	h.notifyRig.us.Bridge.combinerID = rigCombiner
	// the poll ends with the parent trusting the key, as tdns's records it
	h.conf.InternalMp.keyPoll = func(_ context.Context, _ ZoneName, keyName string, keyid uint16, _ uint8) {
		tdns.UpdateParentState(h.mpzd.KeyDB, keyName, keyid, edns0.KeyStateTrusted)
		r.polls <- keyid
	}
	h.parent.holdsNS("ns1."+h.mpzd.ZoneName, h.oldNS) // a sync has something to send
	return r
}

// publish puts these KEYs at the apex of the agent's copy of the zone.
func (r *keyRoundRig) publish(t *testing.T, keys ...sig0Row) {
	t.Helper()
	zd := r.mpzd.ZoneData
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		t.Fatal("the zone has no apex")
	}
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, k.key)
	}
	apex.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: rrs})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
}

func (r *keyRoundRig) active(t *testing.T) []uint16 {
	t.Helper()
	rows, err := activeSig0Rows(r.mpzd.KeyDB, r.zone)
	if err != nil {
		t.Fatal(err)
	}
	return keyIDs(rows)
}

func (r *keyRoundRig) decide(answers map[AgentId]keyReply) bool {
	return r.conf.decideZoneKey(r.ctx, r.zone, answers)
}

func (r *keyRoundRig) polled(t *testing.T, what string) uint16 {
	t.Helper()
	keyid, ok := recvWithin(r.polls, 5*time.Second)
	if !ok {
		t.Fatalf("%s: no poll of the zone's key ran\n%s", what, r.alog)
	}
	return keyid
}

func (r *keyRoundRig) notPolled(t *testing.T, what string) {
	t.Helper()
	if keyid, ok := recvWithin(r.polls, 200*time.Millisecond); ok {
		t.Fatalf("%s: a poll of key %d ran", what, keyid)
	}
}

func keyData(k sig0Row) map[string]string {
	return map[string]string{"algorithm": k.algorithm, "privatekey": k.privatekey, "keyrr": k.keyrr}
}

// A key handed over, the one the zone publishes, is imported; the leader
// publishes it and starts its poll. A member that does not lead imports it
// and publishes nothing.
func TestAHandedOverKeyIsImportedAndOnlyTheLeaderPublishesIt(t *testing.T) {
	for _, leads := range []bool{true, false} {
		t.Run(map[bool]string{true: "leads", false: "member"}[leads], func(t *testing.T) { handedOver(t, leads) })
	}
}

func handedOver(t *testing.T, leads bool) {
	{
		r := newKeyRoundRig(t, map[bool]string{true: "handed.leads.example.", false: "handed.member.example."}[leads], "UPDATE")
		k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
		r.publish(t, k)
		r.caughtUp()
		if !leads {
			r.leader(r.them)
		}
		if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyGot, data: keyData(k)}}) {
			t.Fatalf("leads %v: a round that brought the key did not end", leads)
		}
		if got := r.active(t); !slices.Equal(got, []uint16{k.keyid}) {
			t.Errorf("leads %v: the active keys are %v, want the handed-over key %d", leads, got, k.keyid)
		}
		if leads {
			if keyid := r.polled(t, "the leader"); keyid != k.keyid {
				t.Errorf("the leader polled key %d, want %d", keyid, k.keyid)
			}
		} else {
			r.notPolled(t, "a member that does not lead")
		}
	}
}

// A key is made only by the leader, once the zone is caught up, every agent
// asked has said "no key here", every voting member was asked, and the zone
// publishes no KEY.
func TestAKeyIsMadeOnlyWhenEveryoneSaysNoKeyAndNoneIsPublished(t *testing.T) {
	r := newKeyRoundRig(t, "made.key.example.", "UPDATE")
	r.caughtUp()
	none := map[AgentId]keyReply{r.them: {outcome: keyNone}}

	if r.decide(map[AgentId]keyReply{}) || len(r.active(t)) != 0 {
		t.Fatal("a key was made with a voting member not asked")
	}
	// an agent with no role said "no key here"; the voting member was not asked
	if r.decide(map[AgentId]keyReply{"roleless.agent.example.": {outcome: keyNone}}) || len(r.active(t)) != 0 {
		t.Fatal("a key was made on the word of an agent with no role, with a voting member not asked")
	}
	r.leader(r.them)
	if r.decide(none) || len(r.active(t)) != 0 {
		t.Fatal("a member that does not lead made a key")
	}
	r.leader(r.us)
	if !r.decide(none) {
		t.Fatal("the round in which everyone said no key did not end")
	}
	made := r.active(t)
	if len(made) != 1 {
		t.Fatalf("the active keys after the round: %v, want one made", made)
	}
	if keyid := r.polled(t, "the key made"); keyid != made[0] {
		t.Errorf("the poll is of key %d, want the one made, %d", keyid, made[0])
	}
}

// Silence, a refusal, a send not taken, an answer with no data and a key
// that was not imported are not "no key": no key is made.
func TestSilenceIsNotNoKey(t *testing.T) {
	r := newKeyRoundRig(t, "silence.key.example.", "UPDATE")
	r.caughtUp()
	for _, outcome := range []string{keySilent, keyRefused, keyNotTaken, keyNoData, keyNotImported} {
		if r.decide(map[AgentId]keyReply{r.them: {outcome: outcome}}) {
			t.Errorf("%s: the round ended", outcome)
		}
		if got := r.active(t); len(got) != 0 {
			t.Fatalf("%s: a key was made (%v)", outcome, got)
		}
	}
	r.notPolled(t, "no key made")
}

// Deciding that no key exists waits for the catch-up: a leader whose zone is
// not caught up makes none.
func TestALeaderMakesNoKeyBeforeItIsCaughtUp(t *testing.T) {
	r := newKeyRoundRig(t, "early.key.example.", "UPDATE")
	r.notCaughtUp()
	if r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}}) || len(r.active(t)) != 0 {
		t.Fatal("a key was made before the zone was caught up")
	}
	r.caughtUp()
	if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}}) || len(r.active(t)) != 1 {
		t.Fatal("once caught up, no key was made")
	}
}

// A zone that publishes a KEY nobody holds: an elected leader makes no key,
// nor does a round in which everyone said "no key here". The line says that
// an operator has to act.
func TestALostKeyIsReportedNotReplaced(t *testing.T) {
	r := newKeyRoundRig(t, "lost.key.example.", "UPDATE")
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); !errors.Is(err, errZoneKeyNotHeld) {
		t.Errorf("an elected leader that does not hold the published key: %v, want errZoneKeyNotHeld", err)
	}
	if r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}}) {
		t.Error("the round over a lost key ended")
	}
	if got := r.active(t); len(got) != 0 {
		t.Errorf("a key was made in place of the published one: %v", got)
	}
	if line := r.alog.String(); !strings.Contains(line, "an operator has to act") || !strings.Contains(line, "keyid="+strconv.Itoa(int(k.keyid))) {
		t.Errorf("no line says the key is lost:\n%s", line)
	}
}

// An active local key the zone does not publish is not the zone's key: the
// leader does not publish it, retires nothing, and its sync waits.
func TestALocalKeyTheZoneDoesNotPublishIsNotUsed(t *testing.T) {
	r := newKeyRoundRig(t, "local.key.example.", "UPDATE")
	local := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	r.publish(t, testSig0Key(t, newMPTestKeyDB(t), string(r.zone)))
	r.caughtUp()
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); !errors.Is(err, errZoneKeyNotHeld) {
		t.Errorf("the set-up with a key the zone does not publish: %v, want errZoneKeyNotHeld", err)
	}
	r.notPolled(t, "a local key the zone does not publish")
	if got := r.active(t); !slices.Equal(got, []uint16{local.keyid}) {
		t.Errorf("the active keys are %v, want the local key %d as it was", got, local.keyid)
	}
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
	if got, ok := recvWithin(resp, 2*time.Second); !ok || !strings.Contains(got.Msg, "(not held)") {
		t.Errorf("the sync's answer: %+v", got)
	}
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("%d UPDATEs reached the parent", n)
	}
}

// While the apex carries several KEYs a round imports none and makes none,
// and asks for no sync.
func TestSeveralPublishedKEYsMakeNoKeyAndImportNone(t *testing.T) {
	r := newKeyRoundRig(t, "several.round.example.", "UPDATE")
	k1 := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	k2 := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k1, k2)
	r.caughtUp()
	if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyGot, data: keyData(k1)}}) {
		t.Error("the round over several KEYs did not end: nothing it can ask decides which one")
	}
	if got := r.active(t); len(got) != 0 {
		t.Errorf("a key was taken or made while the apex carries two: %v", got)
	}
	r.notPolled(t, "several KEYs")
	if r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Error("a key is asked for while the apex carries two KEYs")
	}
	if !strings.Contains(r.alog.String(), "an operator has to leave one") {
		t.Errorf("no line says the apex carries several KEYs:\n%s", r.alog)
	}
}

// A sync asked for while the leader does not hold the zone's key waits, and
// asks nothing of the parent. When a round brings the key, it is published
// and polled, and the sync goes out when the poll ends: for an election and
// for an arrival alike.
func TestAKeyThatArrivesLaterAsksForTheSync(t *testing.T) {
	for _, elected := range []bool{true, false} {
		t.Run(map[bool]string{true: "election", false: "arrival"}[elected], func(t *testing.T) { keyArrivesLater(t, elected) })
	}
}

func keyArrivesLater(t *testing.T, elected bool) {
	{
		r := newKeyRoundRig(t, map[bool]string{true: "later.elected.example.", false: "later.arrival.example."}[elected], "UPDATE")
		k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
		r.publish(t, k)
		r.caughtUp()
		if err := r.conf.leaderKeySetup(r.ctx, r.zone, elected); !errors.Is(err, errZoneKeyNotHeld) {
			t.Fatalf("elected %v: the set-up without the key: %v", elected, err)
		}
		resp := make(chan tdns.DelegationSyncStatus, 1)
		r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
		if got, ok := recvWithin(resp, 2*time.Second); !ok || !strings.Contains(got.Msg, "waits for the zone's SIG(0) key") {
			t.Fatalf("elected %v: the sync without the key: %+v", elected, got)
		}
		time.Sleep(100 * time.Millisecond)
		if n := r.parent.updatesSeen(); n != 0 {
			t.Fatalf("elected %v: %d UPDATEs reached the parent without the key", elected, n)
		}
		if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyGot, data: keyData(k)}}) {
			t.Fatalf("elected %v: the round that brought the key did not end", elected)
		}
		r.polled(t, "the key brought")
		waitUntil(t, "the sync that waited for the key went out\n"+r.alog.String(), func() bool { return r.parent.updatesSeen() > 0 })
	}
}

// A voting member that holds the zone's key asks nothing, and its other
// active keys are retired; one that does not hold it asks. An auditor never
// asks, nor does an agent of a zone whose parent takes no UPDATE.
func TestWhoAsksForTheZonesKey(t *testing.T) {
	t.Run("voting", testAVotingMemberAsksUntilItHoldsTheKey)
	t.Run("auditor", testAnAuditorNeverAsks)
	t.Run("notify", testAZoneWhoseParentTakesNoUpdateAsksNothing)
}

func testAVotingMemberAsksUntilItHoldsTheKey(t *testing.T) {
	r := newKeyRoundRig(t, "wants.key.example.", "UPDATE")
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	if !r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Error("a voting member without the zone's key asks nothing")
	}
	if err := importSig0KeyFromPeer(NewHsyncDB(r.mpzd.KeyDB), string(r.zone), keyData(k)); err != nil {
		t.Fatal(err)
	}
	other := testSig0Key(t, r.mpzd.KeyDB, string(r.zone))
	// the rig's agent leads: it wants the key until the parent trusts it
	// (S14)
	trustKey(r.mpzd.KeyDB, string(r.zone), k.keyid)
	if r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Error("a voting member that holds the zone's key asks for it")
	}
	if got := r.active(t); !slices.Equal(got, []uint16{k.keyid}) {
		t.Errorf("the active keys are %v, want only the zone's key %d (%d retired)", got, k.keyid, other.keyid)
	}

}

func testAnAuditorNeverAsks(t *testing.T) {
	a := newKeyRoundRig(t, "auditor.key.example.", "UPDATE")
	zd := a.mpzd.ZoneData
	apex, _ := zd.Data.Get(zd.ZoneName)
	hp := &dns.PrivateRR{Hdr: dns.RR_Header{Name: zd.ZoneName, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600},
		Data: &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{
			&core.HSYNCPARAMServers{Servers: []string{shortLabel(string(a.them))}},
			&core.HSYNCPARAMAuditors{Auditors: []string{shortLabel(string(a.us))}}}}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{hp}})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
	if a.conf.wantsZoneKey(a.ctx, a.zone) {
		t.Error("an auditor asks for the zone's key")
	}
}

func testAZoneWhoseParentTakesNoUpdateAsksNothing(t *testing.T) {
	n := newKeyRoundRig(t, "notify.key.example.", "NOTIFY")
	if n.conf.wantsZoneKey(n.ctx, n.zone) {
		t.Error("a zone whose parent takes no UPDATE asks for a key")
	}
}

// tdns's delegation-sync setup does nothing for a multi-provider zone: it
// would make a key when none is held. The zone's key is the leader's key
// set-up's.
func TestTheSetupArmDoesNothingForAMultiProviderZone(t *testing.T) {
	r := newKeyRoundRig(t, "setup.arm.example.", "UPDATE")
	r.q <- tdns.DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData}
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
	if _, ok := recvWithin(resp, 2*time.Second); !ok {
		t.Fatal("the syncher did not take the request after the setup")
	}
	if got := r.active(t); len(got) != 0 {
		t.Errorf("tdns's setup made a key for a multi-provider zone: %v", got)
	}
}

// The agent's own hooks: a request's window for the key's hand-over is open
// from before the send until the answer, its delivery confirmation is let
// in, and the answer reaches the round through the waiters, matched on the
// sender as a canonical name.
func TestTheKeyRequestsWindowIsOpenUntilItsAnswer(t *testing.T) {
	conf := &Config{Config: &tdns.Config{}}
	tm := &MPTransportBridge{}
	msgQs := &MsgQs{}
	conf.InternalMp.MPTransport, conf.InternalMp.MsgQs = tm, msgQs
	f := newFakeKeyHooks(krB)
	hooks := conf.keyRoundHooks()
	fh := f.hooks()
	hooks.wants, hooks.peers, hooks.active, hooks.decide = fh.wants, fh.peers, fh.active, fh.decide
	sent := make(chan *keyReq, 1)
	hooks.send = func(_ context.Context, kr *keyReq) error { sent <- kr; return nil }

	tr := newKeyTrackerWith(t, hooks, krB)
	tr.keyCheck(krZone)
	kr, ok := recvWithin(sent, 5*time.Second)
	if !ok {
		t.Fatal("no key request was sent")
	}
	if !tm.keyAsks.open("B.Agent.Example.", string(krZone)) {
		t.Error("the window for the key's hand-over is not open while the request is out")
	}
	if !tm.keyAsks.confirmExpected(string(krB), kr.distID) {
		t.Error("the request's delivery confirmation is not let in")
	}
	if !msgQs.configWaiters.deliver(rfiWaitKey("B.AGENT.example.", string(krZone), "sig0key", kr.nonce), noKeyHere()) {
		t.Fatal("the answer found no waiter")
	}
	if d := decidedWithin(t, f, "the answer"); d.answers[krB].outcome != keyNone {
		t.Errorf("the answer reached the round as %+v", d.answers[krB])
	}
	waitUntil(t, "the window is closed after the answer", func() bool { return !tm.keyAsks.open(string(krB), string(krZone)) })
}

// A remote KEY operation that changed this agent's data checks the zone's
// key: the leader's replace reaches every member, and it is the first sign
// of a new key. Another operation checks nothing.
func TestARemoteKEYOperationChecksTheKey(t *testing.T) {
	const zone = "remote.key.example."
	var tr *catchUpTracker
	r := newEngineRigWith(t, zone, func(conf *Config) {
		tr = newCatchUpTracker(roleA, []string{zone}, time.Hour)
		conf.InternalMp.CatchUp = tr
		// b leads the zone: a KEY is taken from the leader only (S14)
		lem := NewLeaderElectionManager(roleA, time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
		t.Cleanup(func() { stopElectionTimers(lem) })
		lem.elections[ZoneName(zone)] = &LeaderElection{Zone: ZoneName(zone), Leader: roleB, LeaderExpiry: time.Now().Add(time.Hour)}
		conf.InternalMp.LeaderElectionManager = lem
	})
	checked := func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return tr.keyChecks[ZoneName(zone)]
	}
	ns := core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{zone + " 3600 IN NS ns.b.role.example."}}
	r.remote(t, roleB, time.Now(), "d-ns", nil, ns)
	if checked() {
		t.Error("an NS replace checked the zone's key")
	}
	k := testSig0Key(t, newMPTestKeyDB(t), zone)
	key := core.RROperation{Operation: "replace", RRtype: "KEY", Records: []string{k.key.String()}}
	r.remote(t, roleB, time.Now(), "d-key", nil, key)
	if !checked() {
		t.Errorf("a remote KEY replace did not check the zone's key; the repo holds %+v", r.repo(t))
	}
}

// A publication that failed keeps the leader's sync held: the key was
// neither published nor polled in this lead.
func TestAFailedPublicationKeepsTheSyncHeld(t *testing.T) {
	r := newKeyRoundRig(t, "failed.publish.example.", "UPDATE")
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	if err := importSig0KeyFromPeer(NewHsyncDB(r.mpzd.KeyDB), string(r.zone), keyData(k)); err != nil {
		t.Fatal(err)
	}
	r.caughtUp()
	r.notifyRig.us.Bridge.combinerID = "" // no combiner to publish to
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); err == nil {
		t.Fatal("the publication with no combiner did not fail")
	}
	r.notPolled(t, "a failed publication")
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why != "not published" {
		t.Errorf("after a failed publication the hold is %q, want not published", why)
	}
}

// While another active key cannot be retired, the zone's key is neither
// published nor polled: tdns's bootstrap would upload the first active key.
func TestAKeyIsNotPublishedWhileAnotherIsActive(t *testing.T) {
	r := newKeyRoundRig(t, "other.active.example.", "UPDATE")
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	if err := importSig0KeyFromPeer(NewHsyncDB(r.mpzd.KeyDB), string(r.zone), keyData(k)); err != nil {
		t.Fatal(err)
	}
	r.caughtUp()
	saved := retireOthers
	retireOthers = func(*tdns.KeyDB, ZoneName, *zoneKey) (bool, error) { return false, nil }
	t.Cleanup(func() { retireOthers = saved })
	if err := r.conf.leaderKeySetup(r.ctx, r.zone, true); !errors.Is(err, errOtherKeysActive) {
		t.Errorf("the set-up with another key active: %v, want errOtherKeysActive", err)
	}
	r.notPolled(t, "another key active")
	if why := r.conf.keyHoldReason(r.ctx, r.zone); why == "" {
		t.Error("the sync is not held while another key is active")
	}
}

// A parent whose DSYNC records cannot be read is not "no key needed": the
// member goes on asking, and no key is made until the parent is known to
// take UPDATE.
func TestAnUnreadableParentKeepsAskingAndMakesNoKey(t *testing.T) {
	r := newKeyRoundRig(t, "unknown.parent.example.", "UPDATE")
	r.caughtUp()
	imr := r.conf.Config.Internal.ImrEngine
	r.conf.Config.Internal.ImrEngine = nil // no resolver yet
	if !r.conf.wantsZoneKey(r.ctx, r.zone) {
		t.Error("a member stopped asking while the parent could not be looked up")
	}
	if r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}}) || len(r.active(t)) != 0 {
		t.Error("a key was made for a parent not known to take UPDATE")
	}
	r.conf.Config.Internal.ImrEngine = imr
	if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyNone}}) || len(r.active(t)) != 1 {
		t.Error("with the parent known, no key was made")
	}
}
