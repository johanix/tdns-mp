/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// The key rounds of step 7b on the tracker, with the agent's hooks stood in
// for: who wants the key, whom it asks, the send, the answers and the
// decision.

const (
	krZone  ZoneName = "rounds.key.example."
	krZone2 ZoneName = "other.rounds.key.example."
	krB     AgentId  = "b.agent.example."
	krC     AgentId  = "c.agent.example."
)

type keyDecision struct {
	zone    ZoneName
	answers map[AgentId]keyReply
}

// fakeKeyHooks stands in for the agent's parts of the rounds.
type fakeKeyHooks struct {
	mu      sync.Mutex
	wants   map[ZoneName]bool
	asked   map[ZoneName]int // calls of wants
	peers   []AgentId
	answers map[*keyReq]chan *ConfigResponseMsg
	sendErr map[AgentId]error
	block   map[AgentId]chan struct{}
	closed  map[*keyReq]int // closeAsk calls
	decide  bool
	hold    chan struct{} // when set, a decision ends only once it is closed

	sent    chan *keyReq
	decided chan keyDecision
}

func newFakeKeyHooks(peers ...AgentId) *fakeKeyHooks {
	return &fakeKeyHooks{wants: map[ZoneName]bool{krZone: true, krZone2: true}, asked: map[ZoneName]int{}, peers: peers,
		answers: map[*keyReq]chan *ConfigResponseMsg{}, sendErr: map[AgentId]error{}, block: map[AgentId]chan struct{}{},
		closed: map[*keyReq]int{}, sent: make(chan *keyReq, 64), decided: make(chan keyDecision, 64)}
}

func (f *fakeKeyHooks) hooks() *keyHooks {
	return &keyHooks{
		wants: func(_ context.Context, zone ZoneName) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.asked[zone]++
			return f.wants[zone]
		},
		peers: func(ZoneName) []AgentId {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]AgentId(nil), f.peers...)
		},
		prepare: func(kr *keyReq) {
			ch := make(chan *ConfigResponseMsg, 1)
			f.mu.Lock()
			f.answers[kr] = ch
			f.mu.Unlock()
			kr.answer = ch
			kr.closeAsk = func() {
				f.mu.Lock()
				f.closed[kr]++
				f.mu.Unlock()
			}
		},
		send: func(ctx context.Context, kr *keyReq) error {
			f.mu.Lock()
			block, err := f.block[kr.peer], f.sendErr[kr.peer]
			f.mu.Unlock()
			if block != nil {
				select {
				case <-block:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			f.sent <- kr
			return err
		},
		decide: func(_ context.Context, zone ZoneName, answers map[AgentId]keyReply) bool {
			f.mu.Lock()
			done, hold := f.decide, f.hold
			f.mu.Unlock()
			f.decided <- keyDecision{zone, answers}
			if hold != nil {
				<-hold
			}
			return done
		},
	}
}

// answer hands the request its answer, as the transport does.
func (f *fakeKeyHooks) answer(kr *keyReq, resp *ConfigResponseMsg) {
	f.mu.Lock()
	ch := f.answers[kr]
	f.mu.Unlock()
	ch <- resp
}

func (f *fakeKeyHooks) closes(kr *keyReq) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed[kr]
}

// wantsCalls: how often the rounds asked whether the zone is wanted, as a
// pass does for each check it takes.
func (f *fakeKeyHooks) wantsCalls(zone ZoneName) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked[zone]
}

// roundEnded waits until the zone's round is no longer out: its decision
// has ended and the next round is scheduled.
func roundEnded(t *testing.T, tr *catchUpTracker, zone ZoneName) {
	t.Helper()
	waitUntil(t, "the round of "+string(zone)+" ended", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		r := tr.keyWanted[zone]
		return r != nil && !r.out
	})
}

func noKeyHere() *ConfigResponseMsg {
	return &ConfigResponseMsg{ConfigData: map[string]string{"status": "no sig0 key for zone"}}
}

// newKeyTracker is a tracker running the rounds on f, with these peers
// OPERATIONAL.
func newKeyTracker(t *testing.T, f *fakeKeyHooks, operational ...AgentId) *catchUpTracker {
	t.Helper()
	return newKeyTrackerWith(t, f.hooks(), operational...)
}

// newKeyTrackerWith is newKeyTracker with these hooks.
func newKeyTrackerWith(t *testing.T, hooks *keyHooks, operational ...AgentId) *catchUpTracker {
	t.Helper()
	tr := newCatchUpTracker("a.agent.example.", nil, time.Hour)
	tr.notAPeer = func(AgentId) bool { return false }
	tr.operational = func(p AgentId) bool { return isAmong(agentIdStrings(operational), p) }
	tr.send = func(context.Context, ZoneName, AgentId, *CatchUp) error { return nil }
	tr.hooks = hooks
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tr.run(ctx, zdr)
	t.Cleanup(func() {
		cancel()
		done := make(chan struct{})
		go func() { tr.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the tracker's goroutines did not end with the test")
		}
	})
	return tr
}

func agentIdStrings(ids []AgentId) []string {
	var out []string
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

func sentWithin(t *testing.T, f *fakeKeyHooks, what string) *keyReq {
	t.Helper()
	kr, ok := recvWithin(f.sent, 5*time.Second)
	if !ok {
		t.Fatalf("%s: no key request was sent", what)
	}
	return kr
}

func decidedWithin(t *testing.T, f *fakeKeyHooks, what string) keyDecision {
	t.Helper()
	d, ok := recvWithin(f.decided, 5*time.Second)
	if !ok {
		t.Fatalf("%s: the round was not decided", what)
	}
	return d
}

func noDecision(t *testing.T, f *fakeKeyHooks, d time.Duration, what string) {
	t.Helper()
	if got, ok := recvWithin(f.decided, d); ok {
		t.Fatalf("%s: a decision ran: %+v", what, got)
	}
}

// shortKeyTimers shortens the rounds' timers for the test.
func shortKeyTimers(t *testing.T, answer, unsent time.Duration, delays ...time.Duration) {
	t.Helper()
	sa, su, sd, se, st := keyAnswerWait, keyUnsentWait, keyRoundDelays, keyRoundEvery, keyRoundTick
	keyAnswerWait, keyUnsentWait, keyRoundTick = answer, unsent, 10*time.Millisecond
	if len(delays) > 0 {
		keyRoundDelays, keyRoundEvery = delays, delays[len(delays)-1]
	}
	t.Cleanup(func() { keyAnswerWait, keyUnsentWait, keyRoundDelays, keyRoundEvery, keyRoundTick = sa, su, sd, se, st })
}

// A round asks every agent of zoneKeyPeers, and its decision runs once, on
// every answer. The window for each request ends with its answer.
func TestAKeyRoundAsksEveryPeerAndDecidesOnTheirAnswers(t *testing.T) {
	f := newFakeKeyHooks(krB, krC)
	tr := newKeyTracker(t, f, krB, krC)
	tr.keyCheck(krZone)

	reqs := map[AgentId]*keyReq{}
	for range 2 {
		kr := sentWithin(t, f, "the round")
		reqs[kr.peer] = kr
	}
	if reqs[krB] == nil || reqs[krC] == nil {
		t.Fatalf("the round asked %v, want B and C", reqs)
	}
	f.answer(reqs[krB], noKeyHere())
	noDecision(t, f, 100*time.Millisecond, "with one answer of two")
	f.answer(reqs[krC], &ConfigResponseMsg{ConfigData: map[string]string{"keyrr": "k", "privatekey": "p", "algorithm": "ED25519"}})
	d := decidedWithin(t, f, "both answers in")
	if d.zone != krZone || d.answers[krB].outcome != keyNone || d.answers[krC].outcome != keyGot {
		t.Errorf("the decision got %+v", d)
	}
	noDecision(t, f, 100*time.Millisecond, "after the decision")
	waitUntil(t, "the windows of the answered requests are closed", func() bool {
		return f.closes(reqs[krB]) == 1 && f.closes(reqs[krC]) == 1
	})
}

// The answers sort into the outcomes: only "no sig0 key for zone" says the
// peer holds none. An answer with no data is not "no key".
func TestAnAnswerWithNoDataIsNotNoKey(t *testing.T) {
	for _, c := range []struct {
		name string
		resp *ConfigResponseMsg
		want string
	}{
		{"no answer", nil, keySilent},
		{"a refusal", &ConfigResponseMsg{ConfigData: map[string]string{configRefusedKey: "denied"}}, keyRefused},
		{"no data", &ConfigResponseMsg{}, keyNoData},
		{"no key here", noKeyHere(), keyNone},
		{"several KEYs at the holder's apex", &ConfigResponseMsg{ConfigData: map[string]string{"status": sig0StatusSeveral}}, keySeveral},
		{"a key", &ConfigResponseMsg{ConfigData: map[string]string{"keyrr": "k"}}, keyGot},
	} {
		if got := classifyKeyAnswer(c.resp).outcome; got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A peer that is not OPERATIONAL is silence at once, and a send that failed
// is "not taken": neither is "no key".
func TestSilenceAndAFailedSendAreNotNoKey(t *testing.T) {
	f := newFakeKeyHooks(krB, krC)
	f.sendErr[krC] = errors.New("refused on the wire")
	tr := newKeyTracker(t, f, krC) // B is not OPERATIONAL
	tr.keyCheck(krZone)
	d := decidedWithin(t, f, "a silent peer and a failed send")
	if d.answers[krB].outcome != keySilent {
		t.Errorf("a peer that is not OPERATIONAL: %+v, want silence", d.answers[krB])
	}
	if a := d.answers[krC]; a.outcome != keyNotTaken || a.detail != "refused on the wire" {
		t.Errorf("a failed send: %+v, want not taken, with the error", a)
	}
}

// The answer is due keyAnswerWait after the sender's acknowledgement, not
// after the round started: a send that takes long still gets its answer.
// An answer that does not come in time is silence.
func TestTheAnswersDeadlineStartsAtTheAcknowledgement(t *testing.T) {
	shortKeyTimers(t, 300*time.Millisecond, 5*time.Second)
	f := newFakeKeyHooks(krB)
	f.block[krB] = make(chan struct{})
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	time.Sleep(500 * time.Millisecond) // longer than the answer's wait
	close(f.block[krB])
	kr := sentWithin(t, f, "the slow send")
	time.Sleep(100 * time.Millisecond)
	f.answer(kr, noKeyHere())
	if d := decidedWithin(t, f, "the slow send's answer"); d.answers[krB].outcome != keyNone {
		t.Errorf("an answer within the wait after a slow acknowledgement: %+v, want no key", d.answers[krB])
	}

	f.mu.Lock()
	f.wants[krZone2] = true
	f.mu.Unlock()
	tr.keyCheck(krZone2)
	sentWithin(t, f, "the second zone")
	if d := decidedWithin(t, f, "an unanswered request"); d.answers[krB].outcome != keySilent {
		t.Errorf("an unanswered request: %+v, want silence", d.answers[krB])
	}
}

// An answer that raced the deadline is not lost.
func TestAnAnswerThatRacesTheDeadlineIsNotLost(t *testing.T) {
	shortKeyTimers(t, time.Nanosecond, 5*time.Second)
	for i := range 20 {
		f := newFakeKeyHooks(krB)
		f.block[krB] = make(chan struct{})
		tr := newKeyTracker(t, f, krB)
		tr.keyCheck(krZone)
		var kr *keyReq
		waitUntil(t, "the request is queued", func() bool {
			tr.mu.Lock()
			defer tr.mu.Unlock()
			if q := tr.keyReqs[krB]; len(q) > 0 {
				kr = q[0]
			}
			return kr != nil
		})
		f.answer(kr, noKeyHere()) // in before the acknowledgement
		close(f.block[krB])
		if d := decidedWithin(t, f, "the raced answer"); d.answers[krB].outcome != keyNone {
			t.Fatalf("round %d: an answer in at the deadline was %+v, want no key", i, d.answers[krB])
		}
	}
}

// A request that waits for its sender longer than keyUnsentWait is silence,
// and is taken off the queue in the same step: it is never sent after.
func TestARequestNotSentInTimeIsSilenceAndLeavesTheQueue(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 200*time.Millisecond)
	f := newFakeKeyHooks(krB)
	f.block[krB] = make(chan struct{})
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	tr.keyCheck(krZone2) // one waits behind the other, whose send hangs
	var queued *keyReq
	waitUntil(t, "one request is sent and one queued", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		q := tr.keyReqs[krB]
		if len(q) != 2 || q[0].sent == q[1].sent {
			return false
		}
		queued = q[0]
		if q[0].sent {
			queued = q[1]
		}
		return true
	})
	d := decidedWithin(t, f, "the requests that were not sent")
	if d.answers[krB].outcome != keySilent {
		t.Errorf("a request not sent in time: %+v, want silence", d.answers[krB])
	}
	d2 := decidedWithin(t, f, "the second request")
	if d2.answers[krB].outcome != keySilent {
		t.Errorf("the second request: %+v, want silence", d2.answers[krB])
	}
	tr.mu.Lock()
	left := len(tr.keyReqs[krB])
	tr.mu.Unlock()
	if left != 0 {
		t.Errorf("%d key requests are left on the queue after they gave up", left)
	}
	close(f.block[krB])
	for {
		kr, ok := recvWithin(f.sent, 300*time.Millisecond)
		if !ok {
			break
		}
		if kr == queued {
			t.Error("a request that gave up was sent after")
		}
	}
}

// A round that does not end with the key held is asked again on the
// schedule, every peer again, also one that said "no key" before.
func TestARoundWithoutTheKeyIsAskedAgain(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, 50*time.Millisecond)
	f := newFakeKeyHooks(krB)
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	f.answer(sentWithin(t, f, "the first round"), noKeyHere())
	decidedWithin(t, f, "the first round")
	f.answer(sentWithin(t, f, "the second round"), noKeyHere())
	decidedWithin(t, f, "the second round")

	f.mu.Lock()
	f.decide = true // the key is held now
	f.mu.Unlock()
	f.answer(sentWithin(t, f, "the third round"), noKeyHere())
	decidedWithin(t, f, "the third round")
	if kr, ok := recvWithin(f.sent, 300*time.Millisecond); ok {
		t.Errorf("a round that ended with the key held was asked again: %+v", kr)
	}
	if z := tr.keyWantedZones(); len(z) != 0 {
		t.Errorf("the zones still wanted: %v", z)
	}
}

// The entry starts over when the zone's voting members change: an answer to
// the round that was out counts for nothing.
func TestARestartedEntryCountsNoAnswerOfTheEarlierRound(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, 50*time.Millisecond)
	f := newFakeKeyHooks(krB)
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	old := sentWithin(t, f, "the first round")
	tr.keyRestart(krZone)
	fresh := sentWithin(t, f, "the round after the restart")
	f.answer(old, &ConfigResponseMsg{ConfigData: map[string]string{"keyrr": "old"}})
	noDecision(t, f, 150*time.Millisecond, "an answer to the earlier round")
	f.answer(fresh, noKeyHere())
	if d := decidedWithin(t, f, "the new round"); d.answers[krB].outcome != keyNone {
		t.Errorf("the new round decided on %+v", d.answers[krB])
	}
}

// A peer that is forgotten while its request is out is silence in the
// round, and its waiter ends.
func TestAForgottenPeersKeyRequestIsSilence(t *testing.T) {
	f := newFakeKeyHooks(krB, krC)
	tr := newKeyTracker(t, f, krB, krC)
	tr.keyCheck(krZone)
	reqs := map[AgentId]*keyReq{}
	for range 2 {
		kr := sentWithin(t, f, "the round")
		reqs[kr.peer] = kr
	}
	f.answer(reqs[krC], noKeyHere())
	tr.Forget(krB)
	d := decidedWithin(t, f, "the forgotten peer")
	if a := d.answers[krB]; a.outcome != keySilent {
		t.Errorf("the forgotten peer's answer is %+v, want silence", a)
	}
	waitUntil(t, "the forgotten request's window is closed", func() bool { return f.closes(reqs[krB]) == 1 })
}

// While a round waits on a silent peer, the tracker's lock is free: a check
// of the key, the data engine's call, returns at once, and so do the
// catch-up's own calls.
func TestAKeyRoundDoesNotBlockTheTracker(t *testing.T) {
	f := newFakeKeyHooks(krB)
	f.block[krB] = make(chan struct{}) // silent: the send hangs
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	waitUntil(t, "the request is out", func() bool {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return len(tr.keyReqs[krB]) > 0 && tr.keyReqs[krB][0].sent
	})
	done := make(chan struct{})
	go func() {
		for range 100 {
			tr.keyCheck(krZone)
			tr.CaughtUp(krZone)
			tr.keyWantedZones()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the tracker's calls waited on a key round")
	}
}

// The zone's key is checked at its first load, on a refresh that changed the
// apex KEY, and at catch-up; a change of its voting members starts the
// entry over. Asking does not wait for catch-up.
func TestAVotingMemberAsksForAKeyItDoesNotHold(t *testing.T) {
	f := newFakeKeyHooks(krB)
	tr := newKeyTracker(t, f, krB)
	asked := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.asked[krZone]
	}
	tr.afterRefresh(krZone, &ZoneRefreshAnalysis{FirstLoad: true})
	waitUntil(t, "the first load checks the key", func() bool { return asked() > 0 })
	kr := sentWithin(t, f, "the first load, before catch-up")
	if ok, _ := tr.CaughtUp(krZone); ok {
		t.Fatal("precondition: the zone is caught up")
	}
	f.answer(kr, noKeyHere())
	decidedWithin(t, f, "the first round")

	n := asked()
	tr.afterRefresh(krZone, &ZoneRefreshAnalysis{KeyChanged: true})
	waitUntil(t, "a refresh that changed the apex KEY checks the key", func() bool { return asked() > n })

	n = asked()
	tr.mu.Lock()
	tr.keyCheckLocked(krZone) // what noteCaughtUpLocked does at catch-up
	tr.keyAskNowLocked(krZone)
	tr.mu.Unlock()
	waitUntil(t, "the catch-up checks the key", func() bool { return asked() > n })
}

// A zone that becomes caught up gets its next round at once.
func TestAZoneThatBecomesCaughtUpIsAskedAtOnce(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, time.Hour)
	f := newFakeKeyHooks(krB)
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	f.answer(sentWithin(t, f, "the first round"), noKeyHere())
	decidedWithin(t, f, "the first round")
	if kr, ok := recvWithin(f.sent, 100*time.Millisecond); ok {
		t.Fatalf("a round was asked before its time: %+v", kr)
	}
	tr.mu.Lock()
	tr.keyAskNowLocked(krZone)
	tr.mu.Unlock()
	sentWithin(t, f, "the round at catch-up")
}

// A zone this agent does not want the key for (it holds it, or it does not
// vote) gets no round, and an entry is dropped when it is no longer wanted.
func TestAZoneNotWantedIsNotAsked(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, 50*time.Millisecond)
	f := newFakeKeyHooks(krB)
	f.wants[krZone] = false
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	if kr, ok := recvWithin(f.sent, 200*time.Millisecond); ok {
		t.Fatalf("a zone not wanted was asked: %+v", kr)
	}

	f.mu.Lock()
	f.wants[krZone2] = true
	f.mu.Unlock()
	tr.keyCheck(krZone2)
	f.answer(sentWithin(t, f, "the wanted zone"), noKeyHere())
	decidedWithin(t, f, "the wanted zone")
	f.mu.Lock()
	f.wants[krZone2] = false // held now, by another path
	f.mu.Unlock()
	waitUntil(t, "the entry is dropped", func() bool { return len(tr.keyWantedZones()) == 0 })
}

// A window for the key's hand-over is ended once, however often its close is
// called: a second close never ends another request to the same peer for
// the same zone. Identities and zones compare as canonical names.
func TestAKeyAsksCloseIsIdempotent(t *testing.T) {
	var tab keyAskTable
	first := tab.start("B.Agent.Example.", "Rounds.Key.Example")
	second := tab.start("b.agent.example.", "rounds.key.example.")
	first()
	first()
	if !tab.open("b.AGENT.example", "ROUNDS.key.example.") {
		t.Fatal("closing one request twice closed the window of the other")
	}
	second()
	if tab.open("b.agent.example.", "rounds.key.example.") {
		t.Error("the window is open with no request out")
	}
	tab.expectConfirm("C.Agent.Example", "dist-1")
	if !tab.confirmExpected("c.agent.example.", "dist-1") {
		t.Error("a confirmation from the peer in another case is not let in")
	}
}

// More key requests to one peer than it has slots for all go out: an answer
// frees a slot, and the next request is sent then, not counted as silence.
func TestMoreKeyRequestsThanSlotsAreAllSent(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 2*time.Second)
	f := newFakeKeyHooks(krB)
	var zones []ZoneName
	for i := range 3 * keyInFlight / 2 {
		z := ZoneName(fmtZone(i))
		zones = append(zones, z)
		f.wants[z] = true
	}
	tr := newKeyTracker(t, f, krB)
	go func() {
		// the first answers wait until every slot is taken, so that the
		// requests after them wait for a slot
		var first []*keyReq
		full := false
		for kr := range f.sent {
			if !full {
				first = append(first, kr)
				if len(first) == keyInFlight {
					full = true
					time.Sleep(50 * time.Millisecond) // the sender has gone to sleep
					for _, h := range first {
						f.answer(h, noKeyHere())
					}
				}
				continue
			}
			f.answer(kr, noKeyHere())
		}
	}()
	for _, z := range zones {
		tr.keyCheck(z)
	}
	for range zones {
		d := decidedWithin(t, f, "a zone's round")
		if a := d.answers[krB]; a.outcome != keyNone {
			t.Errorf("%s: %+v, want the peer's answer", d.zone, a)
		}
	}
}

func fmtZone(i int) string {
	return "z" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".slots.example."
}

// A check of the key brings forward a round that is due later: a KEY
// operation or a changed apex KEY is a sign the key may be there now.
func TestACheckBringsTheNextRoundForward(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, time.Hour)
	f := newFakeKeyHooks(krB)
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	f.answer(sentWithin(t, f, "the first round"), noKeyHere())
	decidedWithin(t, f, "the first round")
	// the decision is told before the round ends: the check comes after
	roundEnded(t, tr, krZone)
	tr.keyCheck(krZone)
	sentWithin(t, f, "the round a check brings forward")
}

// A check that comes while a round is out is kept: the round's answers may
// have been given before the key came, so when it ends without the key the
// next round asks at once, not when it is due (#329).
func TestACheckWhileARoundIsOutAsksAgainWhenItEnds(t *testing.T) {
	shortKeyTimers(t, 5*time.Second, 5*time.Second, time.Hour)
	f := newFakeKeyHooks(krB)
	hold := make(chan struct{})
	f.hold = hold
	tr := newKeyTracker(t, f, krB)
	tr.keyCheck(krZone)
	f.answer(sentWithin(t, f, "the first round"), noKeyHere())
	decidedWithin(t, f, "the first round") // its decision waits for hold

	before := f.wantsCalls(krZone)
	tr.keyCheck(krZone)
	waitUntil(t, "a pass took the check", func() bool { return f.wantsCalls(krZone) > before })
	// a later pass has started once a later check is taken: the pass with
	// the check has ended, while the round was still out
	const unwanted ZoneName = "unwanted.rounds.key.example."
	tr.keyCheck(unwanted)
	waitUntil(t, "a later pass", func() bool { return f.wantsCalls(unwanted) > 0 })

	close(hold)
	sentWithin(t, f, "the round the check asked for")
}
