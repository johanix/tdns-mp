/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"

	"github.com/johanix/tdns-mp/v2/hsync"
)

// trackerRig is a catch-up tracker with the transport stood in for: it
// records what is sent, and says which peers are OPERATIONAL.
type trackerRig struct {
	t      *catchUpTracker
	mu     sync.Mutex
	sends  []trackerSend
	up     map[AgentId]bool
	fail   func(zone ZoneName, peer AgentId, cu *CatchUp) error
	answer func(zone ZoneName, peer AgentId, cu *CatchUp) // run in place of the peer, on its own goroutine
	cancel context.CancelFunc
	zdr    *ZoneDataRepo
}

type trackerSend struct {
	zone    ZoneName
	peer    AgentId
	request string
	reason  string
}

// newTrackerRig is a tracker for self, which started with startZones. It
// does not run until run is called.
func newTrackerRig(t *testing.T, self string, startZones ...string) *trackerRig {
	t.Helper()
	r := &trackerRig{up: map[AgentId]bool{}}
	r.t = newCatchUpTracker(AgentId(self), startZones, time.Hour)
	r.t.operational = func(id AgentId) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.up[id]
	}
	r.t.send = func(_ context.Context, zone ZoneName, peer AgentId, cu *CatchUp) error {
		r.mu.Lock()
		r.sends = append(r.sends, trackerSend{zone, peer, cu.Request, cu.Reason})
		fail, answer := r.fail, r.answer
		r.mu.Unlock()
		if answer != nil {
			go answer(zone, peer, cu)
		}
		if fail != nil {
			return fail(zone, peer, cu)
		}
		return nil
	}
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	r.zdr = zdr
	t.Cleanup(func() {
		if r.cancel != nil {
			r.cancel()
		}
		ended := make(chan struct{})
		go func() { r.t.wait(); close(ended) }()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Error("the tracker's senders did not end with the test")
		}
	})
	return r
}

// run starts the sending, as the data engine does once it runs its loop.
func (r *trackerRig) run() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.t.run(ctx, r.zdr)
}

func (r *trackerRig) setUp(peer AgentId, up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.up[peer] = up
}

func (r *trackerRig) sent() []trackerSend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]trackerSend(nil), r.sends...)
}

// waitSends waits until n requests are sent, and fails when more are.
func (r *trackerRig) waitSends(t *testing.T, n int) []trackerSend {
	t.Helper()
	waitUntil(t, fmt.Sprintf("%d requests were not sent", n), func() bool { return len(r.sent()) >= n })
	got := r.sent()
	if len(got) != n {
		t.Fatalf("%d requests were sent, want %d: %+v", len(got), n, got)
	}
	return got
}

// entry is a copy of the tracker's entry for the zone and peer.
func (r *trackerRig) entry(zone ZoneName, peer AgentId) *catchUpPeer {
	r.t.mu.Lock()
	defer r.t.mu.Unlock()
	e := r.t.peers[zone][peer]
	if e == nil {
		return nil
	}
	cp := *e
	return &cp
}

// complete is the complete answer to a request.
func completeAnswer(request string) *CatchUp {
	yes := true
	return &CatchUp{Request: request, Complete: &yes}
}

// catchUpZone is a loaded multi-provider zone in which this provider
// serves: servers vote, auditors are in auditors=, noRole have a record
// and no role.
func catchUpZone(t *testing.T, zone string, servers, auditors, noRole []string) {
	t.Helper()
	asMPAgent(t)
	zd := seedRoles(t, zone, servers, auditors, noRole)
	zd.Options[tdns.OptMultiProvider] = true
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true}
}

// shortTimers shortens the catch-up's timers for the test.
func shortTimers(t *testing.T, wait time.Duration, retries []time.Duration, every time.Duration) {
	t.Helper()
	savedWait, savedDelays, savedEvery, savedRecent := catchUpAnswerWait, catchUpRetryDelays, catchUpRetryEvery, catchUpRecent
	catchUpAnswerWait, catchUpRetryDelays, catchUpRetryEvery = wait, retries, every
	t.Cleanup(func() {
		catchUpAnswerWait, catchUpRetryDelays, catchUpRetryEvery, catchUpRecent = savedWait, savedDelays, savedEvery, savedRecent
	})
}

// One request is outstanding per zone and peer: another Ask for them makes
// none, another zone's does.
func TestOneRequestIsOutstandingPerZoneAndPeer(t *testing.T) {
	const z1, z2 = "one.outstanding.example.", "two.outstanding.example."
	catchUpZone(t, z1, []string{roleA, roleB}, nil, nil)
	catchUpZone(t, z2, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	if got := r.t.Ask(z1, roleB, catchUpStart); got != askRecorded {
		t.Fatalf("the first request: %v", got)
	}
	if got := r.t.Ask(z1, roleB, catchUpOutage); got != askOutstanding {
		t.Errorf("a second request while the first is outstanding: %v", got)
	}
	if got := r.t.AskZone(z1, catchUpJoin); got[roleB] != askOutstanding {
		t.Errorf("AskZone while a request is outstanding: %v", got)
	}
	if got := r.t.Ask(z2, roleB, catchUpStart); got != askRecorded {
		t.Errorf("another zone's request: %v", got)
	}
	sent := r.waitSends(t, 2)
	time.Sleep(50 * time.Millisecond)
	if n := len(r.sent()); n != 2 {
		t.Errorf("%d requests sent, want one per zone: %+v", n, sent)
	}
}

// A complete answer less than a minute old holds a new request back.
func TestNoRequestWithinAMinuteOfACompleteAnswer(t *testing.T) {
	const zone = "recent.answer.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	sent := r.waitSends(t, 1)
	r.t.Answered(zone, roleB, completeAnswer(sent[0].request))
	if got := r.t.Ask(zone, roleB, catchUpOutage); got != askRecent {
		t.Errorf("a request within a minute of the complete answer: %v", got)
	}
	catchUpRecent = 20 * time.Millisecond
	t.Cleanup(func() { catchUpRecent = time.Minute })
	time.Sleep(30 * time.Millisecond)
	if got := r.t.Ask(zone, roleB, catchUpOutage); got != askRecorded {
		t.Errorf("a request after the minute: %v", got)
	}
}

// A failed request is asked again after 5 s, 15 s, 30 s and 60 s, then
// every 5 minutes, with the same reason and a new name each time.
func TestTheRetrySchedule(t *testing.T) {
	const zone = "retry.schedule.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	r.t.Ask(zone, roleB, catchUpStart)
	now := time.Now()
	names := map[string]bool{}
	for i, want := range []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second, 5 * time.Minute, 5 * time.Minute} {
		z, cu, _ := r.t.step(roleB, now)
		if cu == nil || z != zone {
			t.Fatalf("attempt %d: nothing to send", i+1)
		}
		if cu.Reason != catchUpStart || names[cu.Request] {
			t.Errorf("attempt %d: reason %q, name %q (seen before: %v)", i+1, cu.Reason, cu.Request, names[cu.Request])
		}
		names[cu.Request] = true
		before := time.Now()
		r.t.sent(zone, roleB, cu.Request, errors.New("agent answered REJECTED"))
		e := r.entry(zone, roleB)
		if e.State != catchUpRetry {
			t.Fatalf("attempt %d: state %s after a failure", i+1, e.State)
		}
		if in := e.deadline.Sub(before); in < want || in > want+time.Second {
			t.Errorf("attempt %d: asked again in %s, want %s", i+1, in, want)
		}
		if z, cu, _ := r.t.step(roleB, e.deadline.Add(-time.Millisecond)); cu != nil {
			t.Errorf("attempt %d: sent again before its time (%s)", i+1, z)
		}
		now = e.deadline
	}
}

// A request that was acknowledged and gets no answer is asked again, with
// a new name.
func TestARequestWithNoAnswerIsAskedAgain(t *testing.T) {
	const zone = "no.answer.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	shortTimers(t, 30*time.Millisecond, []time.Duration{10 * time.Millisecond}, time.Hour)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	waitUntil(t, "the request was not asked again", func() bool { return len(r.sent()) >= 2 })
	got := r.sent()
	if got[0].request == got[1].request || got[1].reason != catchUpStart {
		t.Errorf("the second request: %+v after %+v, want a new name and the same reason", got[1], got[0])
	}
	if e := r.entry(zone, roleB); !strings.HasPrefix(catchUpCause(e.LastError), "no answer") {
		t.Errorf("the cause: %q", e.LastError)
	}
}

// A retry that finds its peer not OPERATIONAL sends nothing, and waits for
// the peer's next successful beat.
func TestARequestPausesWhileItsPeerIsNotOperational(t *testing.T) {
	const zone = "paused.request.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	shortTimers(t, time.Hour, []time.Duration{10 * time.Millisecond}, 10*time.Millisecond)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	// the send fails as the peer stops being operational
	r.fail = func(ZoneName, AgentId, *CatchUp) error { r.setUp(roleB, false); return errors.New("send failed") }
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	r.waitSends(t, 1)
	waitUntil(t, "the retry did not pause", func() bool { return r.entry(zone, roleB).State == catchUpPaused })
	time.Sleep(50 * time.Millisecond)
	if n := len(r.sent()); n != 1 {
		t.Fatalf("%d requests sent while the peer was not operational", n)
	}
	r.mu.Lock()
	r.fail = nil
	r.mu.Unlock()
	r.setUp(roleB, true)
	r.t.PeerOperational(roleB)
	got := r.waitSends(t, 2)
	if got[1].request == got[0].request || got[1].reason != catchUpStart {
		t.Errorf("the request after the pause: %+v", got[1])
	}
}

// An answer counts only when it names the request outstanding to its
// sender: not another one's, and not a request that timed out.
func TestAnAnswerThatNamesAnotherRequestDoesNotCount(t *testing.T) {
	const zone = "other.request.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	shortTimers(t, 30*time.Millisecond, []time.Duration{10 * time.Millisecond}, time.Hour)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	first := r.waitSends(t, 1)[0].request
	r.t.Answered(zone, roleB, completeAnswer("another"))
	if e := r.entry(zone, roleB); e.Complete {
		t.Fatal("an answer to another request counted")
	}
	waitUntil(t, "the request was not asked again", func() bool { return len(r.sent()) >= 2 })
	r.t.Answered(zone, roleB, completeAnswer(first)) // the one that timed out
	if e := r.entry(zone, roleB); e.Complete {
		t.Fatal("an answer to a request that timed out counted")
	}
	second := r.sent()[1].request
	r.t.Answered(zone, roleB, completeAnswer(second))
	if e := r.entry(zone, roleB); !e.Complete || e.outstanding() {
		t.Errorf("the answer to the outstanding request: %+v", e)
	}
}

// An answer to a request that has failed, and waits for its retry under the
// same name, counts for nothing: the request is asked again.
func TestAnAnswerToAFailedRequestDoesNotCount(t *testing.T) {
	const zone = "failed.request.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA) // not run: the test drives the sender's steps
	r.setUp(roleB, true)
	r.t.Ask(zone, roleB, catchUpStart)
	_, cu, _ := r.t.step(roleB, time.Now())
	r.t.sent(zone, roleB, cu.Request, errors.New("send failed"))
	r.t.Answered(zone, roleB, completeAnswer(cu.Request))
	if e := r.entry(zone, roleB); e.Complete || e.State != catchUpRetry {
		t.Errorf("an answer to a request that failed counted: %+v", e)
	}
}

// The 30 s are counted from the acknowledgement: a send that takes longer
// than the wait does not fail the request, and an answer after it counts.
func TestTheWaitForTheAnswerStartsAtTheAcknowledgement(t *testing.T) {
	const zone = "ack.wait.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	shortTimers(t, 400*time.Millisecond, []time.Duration{time.Hour}, time.Hour)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	// the send is acknowledged after 600 ms, the answer comes 200 ms later
	r.fail = func(ZoneName, AgentId, *CatchUp) error { time.Sleep(600 * time.Millisecond); return nil }
	r.answer = func(zone ZoneName, peer AgentId, cu *CatchUp) {
		time.Sleep(800 * time.Millisecond)
		r.t.Answered(zone, peer, completeAnswer(cu.Request))
	}
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	waitUntil(t, "the answer after the acknowledgement did not count", func() bool {
		e := r.entry(zone, roleB)
		return e != nil && e.Complete
	})
	if n := len(r.sent()); n != 1 {
		t.Errorf("%d requests sent", n)
	}
}

// Only a request of reason start is asked back, and only when both vote.
func TestOnlyAStartRequestIsAskedBack(t *testing.T) {
	const zone = "asked.back.example."
	catchUpZone(t, zone, []string{roleA, roleB}, []string{roleX}, []string{roleN})
	r := newTrackerRig(t, roleA)
	for _, reason := range []string{catchUpJoin, catchUpRole, catchUpOutage, catchUpManual, catchUpPeerStart, catchUpPeerRole} {
		r.t.Requested(zone, roleB, &CatchUp{Request: "q", Reason: reason})
		if e := r.entry(zone, roleB); e != nil {
			t.Fatalf("a request of reason %s was asked back: %+v", reason, e)
		}
	}
	r.t.Requested(zone, roleN, &CatchUp{Request: "q", Reason: catchUpStart})
	r.t.Requested(zone, roleX, &CatchUp{Request: "q", Reason: catchUpStart})
	if r.entry(zone, roleN) != nil || r.entry(zone, roleX) != nil {
		t.Error("an asker that does not vote was asked back")
	}
	r.t.Requested(zone, roleB, &CatchUp{Request: "q", Reason: catchUpStart})
	if e := r.entry(zone, roleB); e == nil || e.Reason != catchUpPeerStart {
		t.Errorf("a start request was not asked back with peer-start: %+v", e)
	}
	// where this agent has no role, it asks nobody back
	const noRole = "asked.back.norole.example."
	catchUpZone(t, noRole, []string{roleB}, nil, []string{roleA})
	r.t.Requested(noRole, roleB, &CatchUp{Request: "q", Reason: catchUpStart})
	if e := r.entry(noRole, roleB); e != nil {
		t.Errorf("an agent with no role in the zone asked back: %+v", e)
	}
}

// Two agents that start together ask each other at most twice: each asks
// at its zone's first load and at its first beat to the other, and is asked
// back (peer-start), which the minute does not hold.
func TestTwoAgentsThatStartTogetherAskEachOtherOnce(t *testing.T) {
	const zone = "together.start.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	a, b := newTrackerRig(t, roleA, zone), newTrackerRig(t, roleB, zone)
	a.setUp(roleB, true)
	b.setUp(roleA, true)
	// each answers the other's request, complete, and is told it answered
	a.answer = func(zone ZoneName, _ AgentId, cu *CatchUp) {
		b.t.Requested(zone, roleA, cu)
		a.t.Answered(zone, roleB, completeAnswer(cu.Request))
	}
	b.answer = func(zone ZoneName, _ AgentId, cu *CatchUp) {
		a.t.Requested(zone, roleB, cu)
		b.t.Answered(zone, roleA, completeAnswer(cu.Request))
	}
	a.run()
	b.run()
	first := &ZoneRefreshAnalysis{FirstLoad: true}
	a.t.afterRefresh(zone, first)
	b.t.afterRefresh(zone, first)
	a.t.PeerOperational(roleB)
	b.t.PeerOperational(roleA)
	waitUntil(t, "the two did not catch up", func() bool {
		ea, eb := a.entry(zone, roleB), b.entry(zone, roleA)
		return ea != nil && eb != nil && ea.Complete && eb.Complete && !ea.outstanding() && !eb.outstanding()
	})
	time.Sleep(50 * time.Millisecond)
	if na, nb := len(a.sent()), len(b.sent()); na < 1 || na > 2 || nb < 1 || nb > 2 {
		t.Errorf("a sent %+v, b sent %+v, want one or two requests each", a.sent(), b.sent())
	}
	for _, s := range append(a.sent(), b.sent()...) {
		if s.reason != catchUpStart && s.reason != catchUpPeerStart {
			t.Errorf("a request of reason %s", s.reason)
		}
	}
}

// A peer back after a gap above the outage time between two successful
// beats is asked, with outage; one beaten on time is not. A beat to the
// agent's own combiner is no peer's.
func TestAPeerBackAfterALongOutageIsAsked(t *testing.T) {
	const zone = "long.outage.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	catchUpZone(t, "norole.outage.example.", []string{roleA}, nil, []string{roleB}) // the peer has no role: not asked
	r := newTrackerRig(t, roleA)
	r.t.outage = 50 * time.Millisecond
	r.t.notAPeer = func(id AgentId) bool { return id == "combiner.a.role.example." }
	catchUpRecent = time.Millisecond
	t.Cleanup(func() { catchUpRecent = time.Minute })
	r.setUp(roleB, true)
	r.run()
	r.t.PeerOperational(roleB)
	sent := r.waitSends(t, 1)
	if sent[0].reason != catchUpStart || sent[0].zone != zone {
		t.Fatalf("the first beat asked %+v, want start", sent[0])
	}
	r.t.Answered(zone, roleB, completeAnswer(sent[0].request))
	time.Sleep(5 * time.Millisecond)
	r.t.PeerOperational(roleB)
	time.Sleep(20 * time.Millisecond)
	if n := len(r.sent()); n != 1 {
		t.Fatalf("a beat on time asked again: %+v", r.sent())
	}
	time.Sleep(60 * time.Millisecond)
	r.t.PeerOperational(roleB)
	if got := r.waitSends(t, 2); got[1].reason != catchUpOutage {
		t.Errorf("the beat after the outage asked %+v, want outage", got[1])
	}
	r.t.PeerOperational("combiner.a.role.example.")
	r.t.mu.Lock()
	_, seen := r.t.seen["combiner.a.role.example."]
	r.t.mu.Unlock()
	if seen {
		t.Error("a beat to the agent's own combiner was taken as a peer's")
	}
}

// A request to a peer that is not OPERATIONAL is noted, and goes out, under
// its name, at the peer's next successful beat.
func TestANotedRequestGoesOutAtPeerOperational(t *testing.T) {
	const zone = "noted.request.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.run()
	if got := r.t.Ask(zone, roleB, catchUpJoin); got != askNoted {
		t.Fatalf("a request to a peer that is not operational: %v", got)
	}
	name := r.entry(zone, roleB).Request
	time.Sleep(30 * time.Millisecond)
	if n := len(r.sent()); n != 0 {
		t.Fatalf("a noted request was sent: %+v", r.sent())
	}
	r.setUp(roleB, true)
	r.t.PeerOperational(roleB)
	got := r.waitSends(t, 1)
	if got[0].request != name || got[0].reason != catchUpJoin {
		t.Errorf("sent %+v, want the noted request %s", got[0], name)
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(r.sent()); n != 1 {
		t.Errorf("the first beat also asked with start: %+v", r.sent())
	}
}

// The operator's request is not held by the minute (decision 38).
func TestManualIsNotHeldByTheMinute(t *testing.T) {
	const zone = "manual.request.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	r.t.Answered(zone, roleB, completeAnswer(r.waitSends(t, 1)[0].request))
	if got := r.t.Ask(zone, roleB, catchUpOutage); got != askRecent {
		t.Fatalf("an outage request within the minute: %v", got)
	}
	if got := r.t.AskZone(zone, catchUpManual); got[roleB] != askRecorded {
		t.Errorf("the operator's request within the minute: %v", got)
	}
	if got := r.waitSends(t, 2); got[1].reason != catchUpManual {
		t.Errorf("sent %+v", got[1])
	}
}

// A peer that is removed is forgotten: it is asked again as a new peer when
// it is named again.
func TestARemovedPeerIsForgotten(t *testing.T) {
	const zone = "forgotten.peer.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.PeerOperational(roleB)
	r.t.Answered(zone, roleB, completeAnswer(r.waitSends(t, 1)[0].request))
	r.t.Forget(roleB)
	if e := r.entry(zone, roleB); e != nil {
		t.Fatalf("a forgotten peer's entry is kept: %+v", e)
	}
	r.t.mu.Lock()
	_, sending := r.t.senders[roleB]
	r.t.mu.Unlock()
	if sending {
		t.Error("a forgotten peer's sender is kept")
	}
	r.t.PeerOperational(roleB)
	if got := r.waitSends(t, 2); got[1].reason != catchUpStart {
		t.Errorf("a forgotten peer named again was asked with %s, want start", got[1].reason)
	}
}

// Nothing is sent before the data engine runs its loop: the requests are
// recorded, and go out when it does.
func TestNothingIsSentBeforeTheEngineRuns(t *testing.T) {
	const zone = "before.engine.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA, zone)
	r.setUp(roleB, true)
	r.t.afterRefresh(zone, &ZoneRefreshAnalysis{FirstLoad: true})
	r.t.PeerOperational(roleB)
	time.Sleep(30 * time.Millisecond)
	if n := len(r.sent()); n != 0 {
		t.Fatalf("%d requests sent before the engine runs", n)
	}
	r.run()
	if got := r.waitSends(t, 1); got[0].reason != catchUpStart {
		t.Errorf("sent %+v", got[0])
	}
}

// Eight requests to one peer wait for their answers at once; the ninth goes
// when one is answered.
func TestEightRequestsInFlightToOnePeer(t *testing.T) {
	var zones []ZoneName
	for i := range 10 {
		z := fmt.Sprintf("z%d.inflight.example.", i)
		catchUpZone(t, z, []string{roleA, roleB}, nil, nil)
		zones = append(zones, ZoneName(z))
	}
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	for _, z := range zones {
		r.t.Ask(z, roleB, catchUpStart)
	}
	sent := r.waitSends(t, 8)
	time.Sleep(50 * time.Millisecond)
	if n := len(r.sent()); n != 8 {
		t.Fatalf("%d requests in flight to one peer, want 8", n)
	}
	r.t.Answered(sent[0].zone, roleB, completeAnswer(sent[0].request))
	r.waitSends(t, 9)
}

// What a refresh asks for (afterRefresh), through MPPreRefresh and
// PostRefresh as tdns runs them on the agent.
type refreshRig struct {
	*trackerRig
	mpzd *MPZoneData
	tm   *MPTransportBridge
	mp   *MultiProviderConf
}

func newRefreshRig(t *testing.T, zone string, startZones ...string) *refreshRig {
	t.Helper()
	asMPAgent(t)
	ls := newLeaderSyncRig(t, zone)
	ls.mpzd.Ready = true
	ls.mpzd.SyncQ = make(chan SyncRequest, 8)
	r := &refreshRig{trackerRig: newTrackerRig(t, usAgent, startZones...), mpzd: ls.mpzd,
		mp: &MultiProviderConf{Role: "agent", Identity: usAgent}}
	r.tm = &MPTransportBridge{catchUp: r.t}
	return r
}

// serve puts the records in place as the served zone, with no refresh.
func (r *refreshRig) serve(t *testing.T, recs []h3rec, servers []string) {
	t.Helper()
	servedMembers(t, r.mpzd, recs, servers)
}

// refresh is a refresh that brings the records: first marks the zone's
// first load.
func (r *refreshRig) refresh(t *testing.T, first bool, recs []h3rec, servers []string) {
	t.Helper()
	z := r.mpzd.ZoneName
	incoming := refreshedZone(t, r.mpzd, h3RRs(z, recs, servers)...)
	r.mpzd.FirstZoneLoad = first
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.mp)
	servedMembers(t, r.mpzd, recs, servers)
	r.mpzd.FirstZoneLoad = false
	r.mpzd.PostRefresh(r.tm, nil)
}

// asked is the reason of each outstanding request of the zone.
func (r *refreshRig) asked() map[AgentId]string {
	r.t.mu.Lock()
	defer r.t.mu.Unlock()
	out := map[AgentId]string{}
	for peer, e := range r.t.peers[ZoneName(r.mpzd.ZoneName)] {
		if e.outstanding() {
			out[peer] = e.Reason
		}
	}
	return out
}

const thirdAgent = "agent.ap.example."

// A standing that rises asks: join for a record that arrives with its role,
// role for a role given later. Before the switch, nothing for a record that
// arrives with no role, no peer-role from an agent that does not vote in
// the zone, and nothing when the standing falls.
func TestAStandingThatRisesAsks(t *testing.T) {
	us, other, third := h3rec{usAgent, true}, h3rec{otherAgent, true}, h3rec{thirdAgent, true}
	for _, tc := range []struct {
		name            string
		served, refresh []h3rec
		before, after   []string
		want            map[AgentId]string
	}{
		{"a record that arrives with its role", []h3rec{other}, []h3rec{us, other}, []string{otherAgent}, []string{usAgent, otherAgent},
			map[AgentId]string{otherAgent: catchUpJoin}},
		{"a role given later", []h3rec{us, other}, []h3rec{us, other}, []string{otherAgent}, []string{usAgent, otherAgent},
			map[AgentId]string{otherAgent: catchUpRole}},
		{"a record that arrives with no role", []h3rec{other}, []h3rec{us, other}, []string{otherAgent}, []string{otherAgent},
			map[AgentId]string{}},
		{"a peer that gets its role where this agent does not vote", []h3rec{us, other, third}, []h3rec{us, other, third}, []string{otherAgent}, []string{otherAgent, thirdAgent},
			map[AgentId]string{}},
		{"a standing that falls", []h3rec{us, other}, []h3rec{us, other}, []string{usAgent, otherAgent}, []string{otherAgent},
			map[AgentId]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRefreshRig(t, "rises."+strings.ReplaceAll(tc.name, " ", "-")+".example.")
			r.serve(t, tc.served, tc.before)
			r.refresh(t, false, tc.refresh, tc.after)
			got := r.asked()
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("asked %v, want %v", got, tc.want)
			}
		})
	}
}

// An identity that gets its role in a zone in which this agent votes is
// asked, with peer-role.
func TestAPeerThatGetsARoleIsAsked(t *testing.T) {
	r := newRefreshRig(t, "peer.role.example.")
	recs := []h3rec{{usAgent, true}, {otherAgent, true}, {thirdAgent, true}}
	r.serve(t, recs, []string{usAgent, otherAgent})
	r.refresh(t, false, recs, []string{usAgent, otherAgent, thirdAgent})
	if got := r.asked(); len(got) != 1 || got[thirdAgent] != catchUpPeerRole {
		t.Errorf("asked %v, want the new voting member with peer-role", got)
	}
}

// A request is dropped when its peer no longer votes in the zone (at the
// refresh, and at a retry), or when this agent no longer holds the zone.
func TestARequestIsDroppedWhenItsZoneOrItsPeerNoLongerApplies(t *testing.T) {
	r := newRefreshRig(t, "dropped.request.example.")
	recs := []h3rec{{usAgent, true}, {otherAgent, true}, {thirdAgent, true}}
	r.serve(t, recs, []string{usAgent, otherAgent, thirdAgent})
	zone := ZoneName(r.mpzd.ZoneName)
	r.setUp(thirdAgent, true)
	r.t.Ask(zone, otherAgent, catchUpStart)
	r.t.Ask(zone, thirdAgent, catchUpStart)
	r.refresh(t, false, recs, []string{usAgent, thirdAgent})
	if got := r.asked(); len(got) != 1 || got[thirdAgent] == "" {
		t.Fatalf("after the peer lost its role: %v, want the third agent's request alone", got)
	}
	// a retry finds that its peer no longer votes
	_, cu, _ := r.t.step(thirdAgent, time.Now())
	if cu == nil {
		t.Fatal("the third agent's request was not sent")
	}
	r.t.sent(zone, thirdAgent, cu.Request, errors.New("refused"))
	r.serve(t, recs, []string{usAgent})
	r.t.step(thirdAgent, time.Now().Add(time.Minute))
	if e := r.entry(zone, thirdAgent); e != nil {
		t.Errorf("a retry whose peer no longer votes was kept: %+v", e)
	}
	// the zone is gone
	r.serve(t, recs, []string{usAgent, otherAgent})
	r.t.Ask(zone, otherAgent, catchUpStart)
	tdns.Zones.Remove(string(zone)) // as a reload takes it out: the wrapper Zones keeps stays
	r.t.prune(zone)
	if e := r.entry(zone, otherAgent); e != nil {
		t.Errorf("a request in a zone this agent no longer holds was kept: %+v", e)
	}
}

// A zone added to a running agent asks with join at its first load: it lost
// no queue, so no peer needs to ask back (decision 39).
func TestAZoneAddedToARunningAgentAsksWithJoin(t *testing.T) {
	r := newRefreshRig(t, "added.zone.example.") // the agent did not start with it
	r.run()
	r.refresh(t, true, []h3rec{{usAgent, true}, {otherAgent, true}}, []string{usAgent, otherAgent})
	if got := r.asked(); got[otherAgent] != catchUpJoin {
		t.Errorf("asked %v, want join", got)
	}
}

// A zone the agent started with asks with start at its first load, also
// when that comes after the data engine runs; and the first load is kept
// until a PostRefresh takes it.
func TestAZoneOfTheStartThatLoadsLateAsksWithStart(t *testing.T) {
	const zone = "late.start.example."
	r := newRefreshRig(t, zone, zone)
	r.run()
	recs := []h3rec{{usAgent, true}, {otherAgent, true}}
	// a first load whose PostRefresh tdns has not run yet, then another
	// refresh before it does
	incoming := refreshedZone(t, r.mpzd, h3RRs(zone, recs, []string{usAgent, otherAgent})...)
	r.mpzd.FirstZoneLoad = true
	r.mpzd.MPPreRefresh(incoming, nil, nil, r.mp)
	r.mpzd.FirstZoneLoad = false
	r.refresh(t, false, recs, []string{usAgent, otherAgent})
	if got := r.asked(); got[otherAgent] != catchUpStart {
		t.Errorf("asked %v, want start", got)
	}
}

// An agent with a record and no role asks nothing in that zone, while the
// peer is OPERATIONAL through another zone they share: the peer's
// admission, which goes by the roles, would refuse it (issue 158).
func TestAnAgentWithNoRoleAsksNothingWhileThePeerIsOperationalThroughAnotherZone(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{}) // real admission: no peer is authorized by configuration
	alice, bob := AgentId(env.Alice.Identity), AgentId(env.Bob.Identity)
	const noRole, shared = "norole.admission.example.", "shared.admission.example."
	catchUpZone(t, noRole, []string{string(bob)}, nil, []string{string(alice)})
	catchUpZone(t, shared, []string{string(alice), string(bob)}, nil, nil)
	if ok, _ := env.Bob.Bridge.IsPeerAuthorized(string(alice), noRole); ok {
		t.Fatal("the peer admits a request from an agent with no role in the zone")
	}
	if ok, _ := env.Bob.Bridge.IsPeerAuthorized(string(alice), ""); !ok {
		t.Fatal("the peer does not admit the agent through the zone they share")
	}
	r := newTrackerRig(t, string(alice), noRole, shared)
	r.setUp(bob, true)
	r.run()
	r.t.afterRefresh(noRole, &ZoneRefreshAnalysis{FirstLoad: true})
	r.t.afterRefresh(shared, &ZoneRefreshAnalysis{FirstLoad: true})
	r.t.PeerOperational(bob)
	got := r.waitSends(t, 1)
	if got[0].zone != shared {
		t.Errorf("asked %+v, want the shared zone alone", got[0])
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(r.sent()); n != 1 {
		t.Errorf("sent %+v", r.sent())
	}
}

// The zone is caught up once its own read is done and every voting member
// other than this agent has answered complete; the status names whom it
// waits for.
func TestTheZoneIsCaughtUpWhenEveryVotingMemberIsComplete(t *testing.T) {
	const zone = "caught.up.example."
	catchUpZone(t, zone, []string{roleA, roleB}, []string{roleX}, []string{roleN})
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	if ok, w := r.t.CaughtUp(zone); ok || w.OwnRead || len(w.Peers) != 1 || w.Peers[0] != roleB {
		t.Fatalf("before anything: caught up %v, waiting for %+v", ok, w)
	}
	r.zdr.markOwnState(zone, true, "")
	r.t.Ask(zone, roleB, catchUpStart)
	sent := r.waitSends(t, 1)
	if s := r.t.Status(zone); s.CaughtUp || s.WaitingFor != roleB || len(s.Peers) != 1 || s.Peers[0].Answer != "none" {
		t.Fatalf("waiting for the answer: %+v", s)
	}
	r.t.Answered(zone, roleB, &CatchUp{Request: sent[0].request, Complete: new(bool), Why: whyNoInventory})
	if s := r.t.Status(zone); s.CaughtUp || s.Peers[0].Answer != "not complete" || s.Peers[0].Note != whyNoInventory {
		t.Fatalf("after an answer that is not complete: %+v", s)
	}
	r.t.mu.Lock()
	r.t.peers[zone][roleB].deadline = time.Now()
	r.t.kickLocked(roleB)
	r.t.mu.Unlock()
	r.t.Ask(zone, roleB, catchUpManual) // outstanding: no new request
	waitUntil(t, "the request was not asked again", func() bool { return len(r.sent()) >= 2 })
	r.t.Answered(zone, roleB, completeAnswer(r.sent()[1].request))
	if ok, w := r.t.CaughtUp(zone); !ok {
		t.Errorf("after the complete answer: waiting for %+v", w)
	}
	// a zone with no other voting member waits for its own read alone
	const alone = "alone.caught.up.example."
	catchUpZone(t, alone, []string{roleA}, nil, nil)
	if ok, w := r.t.CaughtUp(alone); ok || w.OwnRead || len(w.Peers) != 0 {
		t.Errorf("before the own read: caught up %v, waiting for %+v", ok, w)
	}
	r.zdr.markOwnState(alone, true, "")
	if ok, _ := r.t.CaughtUp(alone); !ok {
		t.Error("after the own read, the zone with no other voting member is not caught up")
	}
	if s := r.t.Status(zone); !s.CaughtUp || s.Peers[0].Answer != "complete" || s.Peers[0].Reason != catchUpStart {
		t.Errorf("the status: %+v", s)
	}
}

// A provider in signers= has not read its own state until its signer's
// inventory is in: the zone is not caught up before (design 5.5).
func TestASignerIsNotCaughtUpWithoutItsInventory(t *testing.T) {
	const zone = "signer.caught.up.example."
	catchUpZone(t, zone, []string{roleA}, nil, nil)
	mpzd, _ := Zones.Get(zone)
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, WeAreSigner: true, ZoneSigned: true}
	r := newTrackerRig(t, roleA)
	r.run()
	r.zdr.markOwnState(zone, true, "")
	if ok, w := r.t.CaughtUp(zone); ok || w.OwnRead || w.OwnReadWhy != whyNoInventory {
		t.Fatalf("without the inventory: caught up %v, waiting for %+v", ok, w)
	}
	yes := true
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: zone, Inventory: []KeyInventoryItem{invItem(t, zone, 257, KeyStateActive, &yes)}, Received: time.Now()})
	if ok, w := r.t.CaughtUp(zone); !ok {
		t.Errorf("with the inventory: waiting for %+v", w)
	}
}

// An agent that does not vote in the zone asks nothing, and its status
// says so rather than naming the voting members it does not wait for.
func TestTheStatusOfAnAgentThatDoesNotVote(t *testing.T) {
	const zone = "status.novote.example."
	catchUpZone(t, zone, []string{roleB}, nil, []string{roleA})
	r := newTrackerRig(t, roleA)
	if s := r.t.Status(zone); s == nil || !s.NotVoting || len(s.Peers) != 0 {
		t.Errorf("the status: %+v", s)
	}
}

// A beat counts as successful as SendBeatWithFallback takes it: an answer
// that withholds its acknowledgement does not.
func TestABeatWithoutItsAcknowledgementIsNoSuccess(t *testing.T) {
	for _, tc := range []struct {
		resp *transport.BeatResponse
		err  error
		want bool
	}{
		{&transport.BeatResponse{Ack: true}, nil, true},
		{nil, nil, true},
		{&transport.BeatResponse{Ack: false}, nil, false},
		{&transport.BeatResponse{Ack: true}, errors.New("timeout"), false},
	} {
		if got := beatSucceeded(tc.resp, tc.err); got != tc.want {
			t.Errorf("beatSucceeded(%+v, %v) = %v", tc.resp, tc.err, got)
		}
	}
}

// The data engine lets the tracker send only once its start-up hydration is
// over: a request recorded while the hydration waits goes out after it.
func TestTheTrackerSendsOnceTheHydrationIsOver(t *testing.T) {
	const zone = "hydration.gate.example."
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	release := make(chan struct{})
	newEngineRigWith(t, zone, func(conf *Config) {
		zd, _ := Zones.Get(zone)
		zd.Options[tdns.OptMultiProvider] = true
		zd.EnsureMP()
		zd.MP.MPdata = &MPdata{WeAreProvider: true}
		conf.InternalMp.MPZoneNames = []string{zone}
		conf.InternalMp.CatchUp = r.t
		conf.InternalMp.editsRequest = func(ctx context.Context, _ *tdns.ZoneData, _ *MPTransportBridge, _ *MsgQs) (*EditsResponseMsg, time.Time, error) {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return &EditsResponseMsg{SenderID: "combiner.a.role.example.", Zone: zone, Message: editsLoaded}, time.Now(), nil
		}
	})
	r.t.Ask(zone, roleB, catchUpStart)
	time.Sleep(50 * time.Millisecond)
	if n := len(r.sent()); n != 0 {
		t.Fatalf("%d requests sent during the hydration", n)
	}
	close(release)
	r.waitSends(t, 1)
}

// The operator's resync --pull asks every voting member with manual,
// through the tracker, and says what became of each request; in a zone in
// which this agent does not vote it sends nothing, and says why.
func TestTheOperatorsResyncPullAsksTheVotingMembers(t *testing.T) {
	const zone, noRole = "pull.manual.example.", "pull.norole.example."
	catchUpZone(t, zone, []string{roleA, roleB}, []string{roleX}, []string{roleN})
	catchUpZone(t, noRole, []string{roleB}, nil, []string{roleA})
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: roleA},
		MPTransport: &MPTransportBridge{catchUp: r.t}}
	pull := func(zone string) *AgentMgmtResponse {
		resp := make(chan *AgentMgmtResponse, 1)
		ar.CommandHandler(&AgentMgmtPostPlus{AgentMgmtPost: AgentMgmtPost{Command: "send-rfi", RfiType: "SYNC", Zone: ZoneName(zone)}, Response: resp}, nil, nil)
		got, ok := recvWithin(resp, 5*time.Second)
		if !ok {
			t.Fatal("no answer")
		}
		return got
	}
	got := pull(zone)
	if got.Error || len(got.RfiResponse) != 1 || got.RfiResponse[roleB] == nil || got.RfiResponse[roleB].Msg != askRecorded.String() {
		t.Fatalf("the answer: %+v (%v)", got, got.RfiResponse)
	}
	if sent := r.waitSends(t, 1); sent[0].peer != roleB || sent[0].reason != catchUpManual {
		t.Errorf("sent %+v", sent[0])
	}
	if got := pull(zone); got.RfiResponse[roleB].Msg != askOutstanding.String() {
		t.Errorf("a second pull while the first is outstanding: %v", got.RfiResponse[roleB].Msg)
	}
	got = pull(noRole)
	if got.Error || len(got.RfiResponse) != 0 || !strings.Contains(got.Msg, "nothing is sent") {
		t.Errorf("a pull where this agent does not vote: %+v", got)
	}
	// this agent's identity configured in another case than the zone's
	// record names it: it votes all the same
	ar.LocalAgent = &MultiProviderConf{Identity: strings.ToUpper(roleA)}
	if got := pull(zone); strings.Contains(got.Msg, "nothing is sent") || got.RfiResponse[roleB] == nil {
		t.Errorf("a pull by an identity configured in another case: %+v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(r.sent()); n != 1 {
		t.Errorf("%d requests sent", n)
	}
}

// The parentsync status carries the zone's catch-up.
func TestTheParentSyncStatusCarriesTheCatchUp(t *testing.T) {
	const zone = "status.catchup.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.run()
	r.zdr.markOwnState(zone, true, "")
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: roleA},
		MPTransport: &MPTransportBridge{catchUp: r.t}}
	lem := NewLeaderElectionManager(roleA, time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	st := lem.GetParentSyncStatus(zone, nil, nil, nil, ar, nil)
	if st.CatchUp == nil || st.CatchUp.CaughtUp || st.CatchUp.WaitingFor != roleB || len(st.CatchUp.Peers) != 1 {
		t.Errorf("the status's catch-up: %+v", st.CatchUp)
	}
}

// A peer the hsync engine removes is forgotten by the tracker, through the
// engine's hook.
func TestTheEnginesRemovalOfAPeerForgetsIt(t *testing.T) {
	const zone = "removed.hook.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.t.Ask(zone, roleB, catchUpStart)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA})
	conf.InternalMp.AgentRegistry = &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.CatchUp = r.t
	deps, _ := buildHsyncEngineDeps(conf)
	deps.PeerHooks.OnPeerRemoved(&hsync.Peer{ID: hsync.PeerID(roleB)})
	if e := r.entry(zone, roleB); e != nil {
		t.Errorf("the removed peer's request is kept: %+v", e)
	}
}

// A peer that starts while a request to it is outstanding is asked again,
// under a new name: the answer its earlier process built, still on its
// way, names the replaced request and counts for nothing. A start that
// comes while the ask-back is outstanding leaves it as it is.
func TestAPeerStartReplacesTheOutstandingRequest(t *testing.T) {
	const zone = "replaced.start.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.setUp(roleB, true)
	r.run()
	r.t.Ask(zone, roleB, catchUpStart)
	first := r.waitSends(t, 1)[0]

	// the peer restarts, and asks at its start
	r.t.Requested(zone, roleB, &CatchUp{Request: "b-started", Reason: catchUpStart})
	again := r.waitSends(t, 2)[1]
	if again.reason != catchUpPeerStart || again.request == first.request {
		t.Fatalf("after the peer's start the agent asked %+v, want peer-start under a new name", again)
	}
	// the earlier process's answer arrives: it counts for nothing
	r.t.Answered(zone, roleB, completeAnswer(first.request))
	if e := r.entry(zone, roleB); e == nil || e.Complete || !e.outstanding() || e.Request != again.request {
		t.Errorf("the replaced request's answer counted: %+v", e)
	}
	// the same start request, delivered again, leaves the ask-back
	r.t.Requested(zone, roleB, &CatchUp{Request: "b-started", Reason: catchUpStart})
	time.Sleep(50 * time.Millisecond)
	if n := len(r.sent()); n != 2 {
		t.Errorf("the start request delivered again replaced the ask-back: %+v", r.sent())
	}
	r.t.Answered(zone, roleB, completeAnswer(again.request))
	if e := r.entry(zone, roleB); e == nil || !e.Complete || e.outstanding() {
		t.Errorf("the ask-back's answer did not end the request: %+v", e)
	}
}

// A peer that starts again while it is asked back is asked anew: the
// answer its process before built, still on its way, says nothing of what
// the peer lost at the second start, and counts for nothing. An ask-back
// that has not gone out yet goes to the process that runs now, and stands.
func TestAPeerThatStartsAgainWhileAskedBackIsAskedAnew(t *testing.T) {
	const zone = "twice.start.example."
	catchUpZone(t, zone, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.run()

	// the peer is not OPERATIONAL: the ask-back is noted, and a second
	// start leaves it
	r.t.Requested(zone, roleB, &CatchUp{Request: "b-first", Reason: catchUpStart})
	noted := r.entry(zone, roleB)
	if noted == nil || noted.State != catchUpNoted {
		t.Fatalf("the ask-back to a peer that is not OPERATIONAL: %+v", noted)
	}
	name := noted.Request
	r.t.Requested(zone, roleB, &CatchUp{Request: "b-second", Reason: catchUpStart})
	if e := r.entry(zone, roleB); e == nil || e.Request != name {
		t.Errorf("a second start replaced an ask-back that had not gone out: %+v", e)
	}

	r.setUp(roleB, true)
	r.t.PeerOperational(roleB)
	first := r.waitSends(t, 1)[0]
	if first.reason != catchUpPeerStart || first.request != name {
		t.Fatalf("the noted ask-back went out as %+v, want peer-start %s", first, name)
	}

	// the peer starts again while the ask-back is out
	r.t.Requested(zone, roleB, &CatchUp{Request: "b-third", Reason: catchUpStart})
	again := r.waitSends(t, 2)[1]
	if again.reason != catchUpPeerStart || again.request == first.request {
		t.Fatalf("after the peer's second start the agent asked %+v, want peer-start under a new name", again)
	}
	r.t.Answered(zone, roleB, completeAnswer(first.request))
	if e := r.entry(zone, roleB); e == nil || e.Complete || !e.outstanding() || e.Request != again.request {
		t.Errorf("the answer of the process before counted: %+v", e)
	}
	r.t.Answered(zone, roleB, completeAnswer(again.request))
	if e := r.entry(zone, roleB); e == nil || !e.Complete || e.outstanding() {
		t.Errorf("the answer to the new ask-back did not end the request: %+v", e)
	}
}

// A zone with HSYNC3 records and no HSYNCPARAM, in which every ON record
// votes, is not a multi-provider zone here: the load gives it no provider
// data, and no agent can answer for it complete. It is asked about neither
// at its load nor at a beat, first or after an outage; a zone with
// HSYNCPARAM beside it is.
func TestAZoneWithoutHSYNCPARAMIsNotAskedAtALoadOrABeat(t *testing.T) {
	const zone, mp = "legacy.beat.example.", "withparam.beat.example."
	asMPAgent(t)
	zd := seedZoneWithHSYNC3(t, zone, roleA, roleB)
	zd.Options[tdns.OptMultiProvider] = true
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = nil // populateMPdata takes it as no multi-provider zone
	catchUpZone(t, mp, []string{roleA, roleB}, nil, nil)
	r := newTrackerRig(t, roleA)
	r.t.outage = 50 * time.Millisecond
	catchUpRecent = time.Millisecond
	t.Cleanup(func() { catchUpRecent = time.Minute })
	r.setUp(roleB, true)
	r.run()
	if asked := r.t.AskZone(zone, catchUpStart); len(asked) != 0 {
		t.Errorf("the load asked about the zone without HSYNCPARAM: %v", asked)
	}
	r.t.PeerOperational(roleB)
	sent := r.waitSends(t, 1)
	if sent[0].zone != mp || sent[0].reason != catchUpStart {
		t.Fatalf("the first beat asked %+v, want start for the zone with HSYNCPARAM only", sent[0])
	}
	r.t.Answered(mp, roleB, completeAnswer(sent[0].request))
	time.Sleep(60 * time.Millisecond)
	r.t.PeerOperational(roleB)
	got := r.waitSends(t, 2)
	if got[1].zone != mp || got[1].reason != catchUpOutage {
		t.Errorf("the beat after the outage asked %+v, want outage for the zone with HSYNCPARAM only", got[1])
	}
	time.Sleep(50 * time.Millisecond)
	for _, s := range r.sent() {
		if s.zone == zone {
			t.Errorf("the zone without HSYNCPARAM was asked about: %+v", s)
		}
	}
}
