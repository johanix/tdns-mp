/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// scriptedBeats is a transport whose beats fail while failing is set, or once
// when failOnce is. A beat that succeeds stamps the peer as the MP bridge
// does: OPERATIONAL, with the time of the success, which is what the liveness
// decay reads. It notes when each beat left.
type scriptedBeats struct {
	*d25Transport
	failing  atomic.Bool
	failOnce atomic.Bool
	// gate, when set, holds every beat until it is closed.
	gate chan struct{}

	mu    sync.Mutex
	calls []time.Time
	// to: the peer object each beat was sent through.
	to []*Peer
}

func newScriptedBeats() *scriptedBeats {
	return &scriptedBeats{d25Transport: newD25Transport()}
}

func (s *scriptedBeats) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, time.Now())
	s.to = append(s.to, peer)
	s.mu.Unlock()
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return false, "", ctx.Err()
		}
	}
	if s.failing.Load() || s.failOnce.CompareAndSwap(true, false) {
		return false, "", errors.New("connection refused")
	}
	p := s.reg.GetOrCreate(string(peer.ID))
	p.SetMechanismState(TransportDNS, transport.PeerStateOperational, "beat acknowledged")
	p.SetMechanismLastBeatSent(TransportDNS, time.Now())
	return true, TransportDNS, nil
}

func (s *scriptedBeats) beats() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.calls...)
}

func (s *scriptedBeats) sentTo() []*Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Peer(nil), s.to...)
}

func (s *scriptedBeats) waitBeats(t *testing.T, n int, d time.Duration) []time.Time {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if b := s.beats(); len(b) >= n {
			return b
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%d beat(s) within %v, want %d", len(s.beats()), d, n)
	return nil
}

// operationalDNSPeer registers a peer the engine holds OPERATIONAL over DNS,
// with a successful beat just now.
func operationalDNSPeer(e *Engine, s *scriptedBeats) *Peer {
	peer := knownDNSPeer(e, s.d25Transport)
	p := s.reg.GetOrCreate(string(peer.ID))
	p.SetMechanismState(TransportDNS, transport.PeerStateOperational, "test seed")
	p.SetMechanismLastBeatSent(TransportDNS, time.Now())
	return peer
}

func retryConfig(fast, steady time.Duration) Config {
	cfg := DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = fast, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	return cfg
}

// A beat that fails is sent again to that peer after the fast interval, not at
// the next round, and a success ends the retries.
func TestAFailedBeatIsRetriedAtTheFastInterval(t *testing.T) {
	const fast, steady = 30 * time.Millisecond, 600 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	s.failOnce.Store(true)
	e.sendBeatToPeer(context.Background(), peer)
	b := s.waitBeats(t, 2, time.Second)
	if gap := b[1].Sub(b[0]); gap < fast*2/3 || gap > steady/2 {
		t.Errorf("the retry came %v after the failed beat, want about %v", gap, fast)
	}
	time.Sleep(6 * fast)
	if got := len(s.beats()); got != 2 {
		t.Errorf("%d beats after the retry succeeded, want 2 and no more", got)
	}
}

// The retries back off and stop when the gap reaches the beat interval. A
// peer that stays down gets that one episode: a later failed beat starts none,
// until a beat has succeeded again.
func TestBeatRetriesBackOffAndComeOncePerOutage(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 200 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	// Gaps of 20, 40, 80 and 160 ms; the next would be 320, past the interval.
	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), peer)
	b := s.waitBeats(t, 5, 2*time.Second)
	if early, late := b[2].Sub(b[1]), b[4].Sub(b[3]); late < 2*early {
		t.Errorf("the retries did not back off: %v between the first two, %v between the last two", early, late)
	}
	time.Sleep(steady + 3*fast)
	if got := len(s.beats()); got != 5 {
		t.Fatalf("%d beats in the outage's first episode, want the failed one and 4 retries", got)
	}

	// Still down: the next round's beat fails too and starts no retries.
	e.sendBeatToPeer(context.Background(), peer)
	time.Sleep(steady / 2)
	if got := len(s.beats()); got != 6 {
		t.Fatalf("%d beats after a second failed round, want 6: no second episode in one outage", got)
	}

	// Back, then down again: a new outage, a new episode.
	s.failing.Store(false)
	e.sendBeatToPeer(context.Background(), peer)
	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), peer)
	s.waitBeats(t, 9, 2*time.Second)
}

// A beat from a round that succeeds while a retry waits ends the retries: the
// retrier wakes, finds the peer no longer failing, and sends nothing.
func TestASuccessfulBeatEndsTheRetries(t *testing.T) {
	const fast, steady = 150 * time.Millisecond, 2 * time.Second
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	s.failOnce.Store(true)
	e.sendBeatToPeer(context.Background(), peer) // fails; the retry waits 150 ms
	e.sendBeatToPeer(context.Background(), peer) // a round's beat, which succeeds
	time.Sleep(3 * fast)
	if got := len(s.beats()); got != 2 {
		t.Errorf("%d beats, want 2: the retrier beat a peer that was no longer failing", got)
	}
}

// With the fixed pace there is no fast interval to retry at: a failed beat
// waits for the next round, as before.
func TestNoBeatRetryOnTheFixedPace(t *testing.T) {
	const steady = 100 * time.Millisecond
	for _, fast := range []time.Duration{0, steady} {
		s := newScriptedBeats()
		e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
		peer := operationalDNSPeer(e, s)
		s.failing.Store(true)
		e.sendBeatToPeer(context.Background(), peer)
		time.Sleep(3 * steady)
		if got := len(s.beats()); got != 1 {
			t.Errorf("fast interval %v: %d beats, want the failed one only", fast, got)
		}
	}
}

// BeatPeer sends one beat to a peer past its hello, and none to a peer the
// engine does not know, one still at KNOWN, or an infrastructure peer.
func TestBeatPeer(t *testing.T) {
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(20*time.Millisecond, time.Second))

	e.BeatPeer("stranger.example.")
	known := NewPeer("known.example.")
	known.DnsMethod = true
	e.registry.S.Set(known.ID, known)
	s.seed(string(known.ID), TransportDNS, transport.PeerStateKnown)
	e.BeatPeer(known.ID)
	infra := NewPeer("combiner.example.")
	infra.DnsMethod, infra.IsInfraPeer = true, true
	e.registry.S.Set(infra.ID, infra)
	s.seed(string(infra.ID), TransportDNS, transport.PeerStateOperational)
	e.BeatPeer(infra.ID)
	time.Sleep(100 * time.Millisecond)
	if got := len(s.beats()); got != 0 {
		t.Fatalf("%d beats to peers that get none", got)
	}

	peer := operationalDNSPeer(e, s)
	e.BeatPeer(peer.ID)
	s.waitBeats(t, 1, time.Second)
	time.Sleep(100 * time.Millisecond)
	if got := len(s.beats()); got != 1 {
		t.Errorf("%d beats for one BeatPeer, want 1", got)
	}
}

// A peer whose hellos come faster than a beat returns gets one beat at a time:
// while one is on its way, BeatPeer does nothing.
func TestBeatPeerSendsOneBeatAtATime(t *testing.T) {
	s := newScriptedBeats()
	s.gate = make(chan struct{})
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(20*time.Millisecond, time.Second))
	peer := operationalDNSPeer(e, s)

	for i := 0; i < 5; i++ {
		e.BeatPeer(peer.ID)
	}
	s.waitBeats(t, 1, time.Second)
	time.Sleep(100 * time.Millisecond)
	if got := len(s.beats()); got != 1 {
		t.Fatalf("%d beats on their way for five calls, want 1", got)
	}

	close(s.gate) // the beat returns
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.beatMu.Lock()
		busy := e.beatingBack[peer.ID]
		e.beatMu.Unlock()
		if !busy {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	e.BeatPeer(peer.ID)
	s.waitBeats(t, 2, time.Second)
}

// A beat that fails in the moment between a retrier's success and its exit
// finds a retrier still on the books and starts none, though it opens a new
// outage. The retrier's exit starts the retries for it. A retrier that ran out
// of retries exits and starts none: that outage has had its episode.
func TestARetrierThatEndsPicksUpANewFailure(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 400 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	// A retrier is on the books, its outage over; a new failure was noted.
	e.beatMu.Lock()
	e.beatRetrying[peer.ID] = true
	e.beatFailing[peer.ID] = true
	e.beatMu.Unlock()
	e.endBeatRetrier(peer, true)
	s.waitBeats(t, 1, time.Second) // the new outage's first retry, which succeeds

	// The same, but the retrier ran out: no further retries. The retrier
	// above must be off the books first: its exit, coming after the setup
	// below, would see a peer failing again and start the retries anew.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		e.beatMu.Lock()
		running := e.beatRetrying[peer.ID]
		e.beatMu.Unlock()
		if !running {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	n := len(s.beats())
	e.beatMu.Lock()
	e.beatRetrying[peer.ID] = true
	e.beatFailing[peer.ID] = true
	e.beatMu.Unlock()
	e.endBeatRetrier(peer, false)
	time.Sleep(5 * fast)
	if got := len(s.beats()); got != n {
		t.Errorf("%d beat(s) after a retrier ran out of retries, want none", got-n)
	}
}

// The case from a running fleet: one of a round's beats fails, as when the
// peer is restarting, and the peer must not read DEGRADED for it. Without the
// retry the next round comes two intervals after the last success, and its
// refresh of the rows, which runs before its beats, reads the peer as
// DEGRADED. With it the beat is sent again after the fast interval, and the
// peer reads OPERATIONAL throughout. The liveness interval is in whole
// seconds, so the rounds here are a second apart.
func TestOneFailedBeatDoesNotReadAsDegraded(t *testing.T) {
	const fast, steady = 100 * time.Millisecond, time.Second
	s := newScriptedBeats()

	var mu sync.Mutex
	var rounds []time.Time
	var seen []transport.PeerState
	failedAt := -1
	var e *Engine
	e = NewEngine(Deps{
		LocalID:   "local.example.",
		Transport: s,
		Host: HostCallbacks{BeforeHeartbeats: func() {
			// What the host's row refresh reads, at the point it reads it.
			p, _ := s.reg.Get("remote.example.")
			mu.Lock()
			defer mu.Unlock()
			now := time.Now()
			seen = append(seen, p.EffectiveState())
			// At the steady pace, fail this round's beat, once.
			if failedAt < 0 && len(rounds) > 0 && now.Sub(rounds[len(rounds)-1]) > steady*9/10 {
				failedAt = len(rounds)
				s.failOnce.Store(true)
			}
			rounds = append(rounds, now)
		}},
	}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	p, _ := s.reg.Get(string(peer.ID))
	p.SetLivenessInterval(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, MsgChannels{Hello: make(chan *InboundReport), Beat: make(chan *InboundReport), Msg: make(chan *InboundMsg)})

	// Until two rounds after the one whose beat failed.
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		done := failedAt >= 0 && len(rounds) >= failedAt+3
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the engine did not reach two rounds past the failed beat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, st := range seen {
		if st != transport.PeerStateOperational {
			t.Errorf("round %d (the beat of round %d failed) read the peer as %v, want OPERATIONAL throughout", i, failedAt, st)
		}
	}
}

// outageWithTheRetriesSpent leaves the peer in an outage whose one episode of
// retries is over: a beat failed, every retry failed, and nothing but the
// rounds would beat the peer now. It returns the number of beats so far.
func outageWithTheRetriesSpent(t *testing.T, e *Engine, s *scriptedBeats, peer *Peer) int {
	t.Helper()
	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), peer)
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.beatMu.Lock()
		running := e.beatRetrying[peer.ID]
		e.beatMu.Unlock()
		if !running {
			return len(s.beats())
		}
		if time.Now().After(deadline) {
			t.Fatal("the beat retrier did not run out of retries")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitBeatBackDone waits until no beat back is on its way to the peer or
// waiting to be sent again.
func waitBeatBackDone(t *testing.T, e *Engine, id PeerID) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.beatMu.Lock()
		busy := e.beatingBack[id]
		e.beatMu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the beat back did not end")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A returning peer can refuse the beat sent in the moment its hello is
// processed. With an outage on the books that beat back starts no retrier, so
// it is sent again after the fast interval, and the peer is healthy again
// without waiting for a round (#128).
func TestARefusedBeatBackIsSentAgainAfterTheFastInterval(t *testing.T) {
	const fast, steady = 40 * time.Millisecond, 300 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	n := outageWithTheRetriesSpent(t, e, s, peer)

	// The peer is back, and refuses one more beat.
	s.failing.Store(false)
	s.failOnce.Store(true)
	e.BeatPeer(peer.ID)
	b := s.waitBeats(t, n+2, time.Second)
	if gap := b[n+1].Sub(b[n]); gap < fast*2/3 || gap > steady/2 {
		t.Errorf("the beat back was sent again %v after it was refused, want about %v", gap, fast)
	}
	waitBeatBackDone(t, e, peer.ID)
	if e.beatStillFailing(peer.ID) {
		t.Error("the peer still counts as failing after the beat back was acknowledged")
	}
	p, _ := s.reg.Get(string(peer.ID))
	if st, _ := p.MechanismEffectiveState(TransportDNS); st != transport.PeerStateOperational {
		t.Errorf("the peer reads %v after the beat back was acknowledged, want OPERATIONAL", st)
	}
	time.Sleep(4 * fast)
	if got := len(s.beats()) - n; got != 2 {
		t.Errorf("%d beats for a beat back refused once, want 2 and no more", got)
	}
}

// A peer that keeps refusing gets the beat back and its two retries, a fast
// interval apart, and then no more. While they run, further hellos start no
// second beat back beside them; the next hello after they have ended gets a
// beat back of its own.
func TestABeatBackIsRetriedTwiceAtMostAndOneAtATime(t *testing.T) {
	const fast, steady = 40 * time.Millisecond, 300 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	n := outageWithTheRetriesSpent(t, e, s, peer)

	// The peer says hello and goes on refusing. Its hellos keep coming while
	// the beat back waits to be sent again.
	e.BeatPeer(peer.ID)
	s.waitBeats(t, n+1, time.Second)
	for i := 0; i < 5; i++ {
		e.BeatPeer(peer.ID)
		time.Sleep(fast / 4)
	}
	b := s.waitBeats(t, n+1+beatBackRetries, time.Second)
	for i := n + 1; i < len(b); i++ {
		if gap := b[i].Sub(b[i-1]); gap < fast*2/3 {
			t.Errorf("beat %d of the beat back came %v after the one before, want about %v", i-n, gap, fast)
		}
	}
	waitBeatBackDone(t, e, peer.ID)
	time.Sleep(4 * fast)
	if got := len(s.beats()) - n; got != 1+beatBackRetries {
		t.Fatalf("%d beats to a peer that refuses every one, want the beat back and %d retries", got, beatBackRetries)
	}

	e.BeatPeer(peer.ID)
	s.waitBeats(t, n+1+beatBackRetries+1, time.Second)
}

// A beat back that fails with no outage on the books is the first failure
// since a success, and starts the peer's beat retrier. The retries are then
// the retrier's: after the fast interval, then at doubling gaps. The beat back
// sends none beside them, so a peer that goes on refusing gets one beat per
// slot of the retrier, not two.
func TestAFailedBeatBackDoesNotRetryBesideTheRetrier(t *testing.T) {
	const fast, steady = 200 * time.Millisecond, 4 * time.Second
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	// The retrier's slots are 200 and 600 ms after the failure. A beat back
	// retrying beside it would add beats at 200 and 400 ms.
	s.failing.Store(true)
	e.BeatPeer(peer.ID)
	b := s.waitBeats(t, 2, time.Second)
	if gap := b[1].Sub(b[0]); gap < fast*2/3 || gap > fast*2 {
		t.Errorf("the retry came %v after the failed beat back, want about %v", gap, fast)
	}
	time.Sleep(time.Until(b[0].Add(fast * 5 / 2)))
	if got := len(s.beats()); got != 2 {
		t.Errorf("%d beats in the first 500 ms after a beat back that opened an outage, want 2: the beat back and the retrier's first retry", got)
	}
	s.failing.Store(false)
}

// A beat from a round that succeeds while the beat back waits to be sent
// again ends it: the peer is no longer failing, and no retry is sent.
func TestASuccessfulBeatEndsTheBeatBackRetries(t *testing.T) {
	const fast, steady = 150 * time.Millisecond, 600 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	n := outageWithTheRetriesSpent(t, e, s, peer)

	e.BeatPeer(peer.ID) // refused; the retry waits 150 ms
	s.waitBeats(t, n+1, time.Second)
	s.failing.Store(false)
	e.sendBeatToPeer(context.Background(), peer) // a round's beat, which succeeds
	waitBeatBackDone(t, e, peer.ID)
	time.Sleep(2 * fast)
	if got := len(s.beats()) - n; got != 2 {
		t.Errorf("%d beats, want 2: the beat back retried to a peer that was no longer failing", got)
	}
}

// With the fixed pace there is no fast interval: a beat back that fails is not
// sent again.
func TestNoBeatBackRetryOnTheFixedPace(t *testing.T) {
	const steady = 100 * time.Millisecond
	for _, fast := range []time.Duration{0, steady} {
		s := newScriptedBeats()
		e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
		peer := operationalDNSPeer(e, s)
		s.failing.Store(true)
		e.BeatPeer(peer.ID)
		s.waitBeats(t, 1, time.Second)
		time.Sleep(3 * steady)
		if got := len(s.beats()); got != 1 {
			t.Errorf("fast interval %v: %d beats, want the beat back only", fast, got)
		}
	}
}

// The case from a running fleet: a peer restarts, a round's beat to it fails,
// and it is back late in the beat interval, after the retries that fall
// before the next round. Its hello gets a beat back, which it refuses, being
// barely up. Without a retry of the beat back nothing beats the peer before
// the next round, whose refresh of the rows reads a last success two
// intervals old: DEGRADED. With it the peer reads OPERATIONAL throughout. The
// liveness interval is in whole seconds, so the rounds here are a second
// apart.
func TestAPeerBackLateInTheIntervalDoesNotReadAsDegraded(t *testing.T) {
	const fast, steady = 100 * time.Millisecond, time.Second
	s := newScriptedBeats()

	var mu sync.Mutex
	var rounds []time.Time
	var seen []transport.PeerState
	failedAt := -1
	var e *Engine
	e = NewEngine(Deps{
		LocalID:   "local.example.",
		Transport: s,
		Host: HostCallbacks{BeforeHeartbeats: func() {
			p, _ := s.reg.Get("remote.example.")
			mu.Lock()
			defer mu.Unlock()
			now := time.Now()
			seen = append(seen, p.EffectiveState())
			// At the steady pace, the peer goes away just before a round.
			if failedAt < 0 && len(rounds) > 0 && now.Sub(rounds[len(rounds)-1]) > steady*9/10 {
				failedAt = len(rounds)
				s.failing.Store(true)
				// It is back 800 ms later, after the retries at 100, 300 and
				// 700 ms. It says hello, and refuses the beat that answers.
				time.AfterFunc(steady*8/10, func() {
					s.failOnce.Store(true)
					s.failing.Store(false)
					e.BeatPeer("remote.example.")
				})
			}
			rounds = append(rounds, now)
		}},
	}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	p, _ := s.reg.Get(string(peer.ID))
	p.SetLivenessInterval(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx, MsgChannels{Hello: make(chan *InboundReport), Beat: make(chan *InboundReport), Msg: make(chan *InboundMsg)})

	// Until two rounds after the one whose beat failed.
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		done := failedAt >= 0 && len(rounds) >= failedAt+3
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the engine did not reach two rounds past the failed beat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, st := range seen {
		if st != transport.PeerStateOperational {
			t.Errorf("round %d (the beat of round %d failed) read the peer as %v, want OPERATIONAL throughout", i, failedAt, st)
		}
	}
}

// waitNotBeatingBack waits until no beat back to the peer is on its way.
func waitNotBeatingBack(t *testing.T, e *Engine, id PeerID) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		e.beatMu.Lock()
		busy := e.beatingBack[id]
		e.beatMu.Unlock()
		if !busy {
			return
		}
	}
	t.Fatal("the beat back did not end")
}

// A peer that repeats its hello faster than the fast interval gets one beat
// back per fast interval, not one per hello (#131): a call less than one fast
// interval after the last beat back started does nothing, also once that
// beat back has returned.
func TestRepeatedHellosGetOneBeatBackPerFastInterval(t *testing.T) {
	const fast, steady = 80 * time.Millisecond, time.Second
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	e.BeatPeer(peer.ID)
	s.waitBeats(t, 1, time.Second)
	waitNotBeatingBack(t, e, peer.ID)
	for i := 0; i < 3; i++ {
		e.BeatPeer(peer.ID)
	}
	time.Sleep(fast / 4)
	if got := len(s.beats()); got != 1 {
		t.Fatalf("%d beats for hellos within one fast interval, want 1", got)
	}

	time.Sleep(fast)
	e.BeatPeer(peer.ID)
	s.waitBeats(t, 2, time.Second)
}

// With the fixed pace there is no fast interval: one beat back per beat
// interval.
func TestRepeatedHellosOnTheFixedPaceGetOneBeatBackPerInterval(t *testing.T) {
	const steady = 300 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(0, steady))
	peer := operationalDNSPeer(e, s)

	e.BeatPeer(peer.ID)
	s.waitBeats(t, 1, time.Second)
	waitNotBeatingBack(t, e, peer.ID)
	time.Sleep(steady / 3)
	e.BeatPeer(peer.ID)
	time.Sleep(steady / 6)
	if got := len(s.beats()); got != 1 {
		t.Fatalf("%d beats for two hellos within one beat interval, want 1", got)
	}
	time.Sleep(steady)
	e.BeatPeer(peer.ID)
	s.waitBeats(t, 2, time.Second)
}

// The engine keeps no beat back from before a restart: the first one after it
// goes at once.
func TestTheFirstBeatBackAfterARestartIsNotDelayed(t *testing.T) {
	const fast, steady = 200 * time.Millisecond, 2 * time.Second
	s := newScriptedBeats()
	before := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(before, s)
	before.BeatPeer(peer.ID)
	s.waitBeats(t, 1, time.Second)

	// the agent restarts: a new engine, the same peer
	after := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	after.registry.S.Set(peer.ID, peer)
	start := time.Now()
	after.BeatPeer(peer.ID)
	b := s.waitBeats(t, 2, time.Second)
	if wait := b[1].Sub(start); wait > fast/2 {
		t.Errorf("the first beat back after a restart left %v after the hello, want at once", wait)
	}
}

// A beat back that is refused is sent again after the fast interval: its
// retries are its own, and the bound on new beats back does not cut them
// short. A hello in between starts no second one.
func TestARetriedBeatBackIsNotCutShort(t *testing.T) {
	const fast, steady = 40 * time.Millisecond, 300 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)
	n := outageWithTheRetriesSpent(t, e, s, peer)

	s.failing.Store(false)
	s.failOnce.Store(true)
	e.BeatPeer(peer.ID)
	s.waitBeats(t, n+1, time.Second)
	e.BeatPeer(peer.ID)
	s.waitBeats(t, n+2, time.Second)
	waitBeatBackDone(t, e, peer.ID)
	time.Sleep(2 * fast)
	if got := len(s.beats()) - n; got != 2 {
		t.Errorf("%d beats for a beat back refused once, with a hello in between; want 2", got)
	}
}

// A peer that RemovePeer took out is not beaten again: not by the retrier its
// failed beat started, not by a round, not by a beat back, and not by a
// round's beat from a list taken before the removal (#132).
func TestARemovedPeerIsNotBeatenAgain(t *testing.T) {
	const fast, steady = 30 * time.Millisecond, 600 * time.Millisecond
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	peer := operationalDNSPeer(e, s)

	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), peer)
	s.waitBeats(t, 1, time.Second)
	e.RemovePeer(peer.ID)
	e.sendHeartbeats()
	e.BeatPeer(peer.ID)
	e.sendBeatToPeer(context.Background(), peer)
	time.Sleep(6 * fast)
	if got := len(s.beats()); got != 1 {
		t.Errorf("%d beat(s) after the peer was removed, want none", got-1)
	}
}

// A beat on its way when the peer is removed does not store the peer again.
func TestABeatOnItsWayDoesNotPutARemovedPeerBack(t *testing.T) {
	s := newScriptedBeats()
	s.gate = make(chan struct{})
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(30*time.Millisecond, time.Second))
	peer := operationalDNSPeer(e, s)

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.sendBeatToPeer(context.Background(), peer)
	}()
	s.waitBeats(t, 1, time.Second)
	e.RemovePeer(peer.ID)
	close(s.gate)
	<-done
	if _, ok := e.registry.S.Get(peer.ID); ok {
		t.Fatal("the beat stored the removed peer again")
	}
}

// gatedHellos holds each hello until gate is closed, and says on sent when
// one has left.
type gatedHellos struct {
	*d25Transport
	sent chan struct{}
	gate chan struct{}
}

func (g *gatedHellos) SendHello(ctx context.Context, peer *Peer, sharedZones []string) error {
	g.sent <- struct{}{}
	<-g.gate
	return nil
}

// A hello on its way when the peer is removed does not store the peer again.
func TestAHelloOnItsWayDoesNotPutARemovedPeerBack(t *testing.T) {
	tb := &gatedHellos{d25Transport: newD25Transport(), sent: make(chan struct{}, 1), gate: make(chan struct{})}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())
	peer := knownDNSPeer(e, tb.d25Transport)

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.sendHelloToPeer(peer)
	}()
	<-tb.sent
	e.RemovePeer(peer.ID)
	close(tb.gate)
	<-done
	if _, ok := e.registry.S.Get(peer.ID); ok {
		t.Fatal("the hello stored the removed peer again")
	}
}

// RemovePeer drops what the engine noted of the peer's beats. A new peer
// under the same identity starts clean: its first beat back goes at once.
func TestARemovedPeerLeavesNoFailureMarker(t *testing.T) {
	const fast, steady = 150 * time.Millisecond, 3 * time.Second
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	old := operationalDNSPeer(e, s)

	e.BeatPeer(old.ID)
	s.waitBeats(t, 1, time.Second)
	waitNotBeatingBack(t, e, old.ID)
	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), old)
	e.RemovePeer(old.ID)
	e.beatMu.Lock()
	failing := e.beatFailing[old.ID]
	_, stamped := e.beatBackAt[old.ID]
	e.beatMu.Unlock()
	if failing || stamped {
		t.Fatalf("after the removal: failing %v, beat back time kept %v; want neither", failing, stamped)
	}

	// A failed beat on its way at the removal leaves no marker either.
	s.gate = nil
	successor := operationalDNSPeer(e, s)
	e.sendBeatToPeer(context.Background(), old)
	e.beatMu.Lock()
	failing = e.beatFailing[old.ID]
	e.beatMu.Unlock()
	if failing {
		t.Fatal("a failed beat through the removed object marked its successor as failing")
	}

	s.failing.Store(false)
	n := len(s.beats())
	e.BeatPeer(successor.ID)
	s.waitBeats(t, n+1, fast/2)
}

// The beats after a removal go to the object the registry holds. A retrier
// started for the removed object stops, and the successor's failures, which
// found that retrier on the books and started none, get their retries when it
// ends (#132).
func TestAReplacedPeerIsNotBeatenThroughTheOldObject(t *testing.T) {
	const fast, steady = 40 * time.Millisecond, time.Second
	s := newScriptedBeats()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: s}, retryConfig(fast, steady))
	old := operationalDNSPeer(e, s)

	s.failing.Store(true)
	e.sendBeatToPeer(context.Background(), old)
	s.waitBeats(t, 1, time.Second)
	e.RemovePeer(old.ID)
	successor := operationalDNSPeer(e, s)
	e.sendBeatToPeer(context.Background(), successor)
	s.waitBeats(t, 4, time.Second)
	for i, p := range s.sentTo()[1:] {
		if p != successor {
			t.Fatalf("beat %d after the removal went through the removed object", i+1)
		}
	}
}

// The hello retrier of a removed object, when it ends, leaves alone the
// registration of its successor's retrier: a second one cannot start beside
// it.
func TestTheHelloRetrierOfARemovedPeerLeavesItsSuccessorsAlone(t *testing.T) {
	tb := newD25Transport()
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())
	old := knownDNSPeer(e, tb)
	if _, ok := e.registry.registerHello(old); !ok {
		t.Fatal("no hello retrier could be registered")
	}
	e.RemovePeer(old.ID)
	successor := knownDNSPeer(e, tb)
	if _, ok := e.registry.registerHello(successor); !ok {
		t.Fatal("the removal left the old retrier registered")
	}
	e.registry.clearHelloCancel(old)
	if _, ok := e.registry.registerHello(successor); ok {
		t.Fatal("the old retrier's exit cleared its successor's registration")
	}
}

// slowCapabilities answers MechanismSupported after a pause, which MarkNeeded
// asks between its look for a stored peer and its store of a new one: the
// callers below all find none, and all try to store one.
type slowCapabilities struct {
	*discoveryCounter
}

func (s *slowCapabilities) MechanismSupported(name string) bool {
	time.Sleep(5 * time.Millisecond)
	return true
}

// A new peer marked from many places at once is stored once, with every
// zone, and looked up once.
func TestANewPeerMarkedFromManyPlacesAtOnceIsStoredOnce(t *testing.T) {
	tb := &slowCapabilities{&discoveryCounter{d25Transport: newD25Transport(), asked: map[string]int{}}}
	e := NewEngine(Deps{LocalID: "local.example.", Transport: tb}, DefaultConfig())
	const id, callers = PeerID("new.example."), 32
	var ready, wg sync.WaitGroup
	ready.Add(1)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ready.Wait()
			e.MarkNeeded(id, ZoneName(fmt.Sprintf("z%d.example.", i)), nil)
		}(i)
	}
	ready.Done()
	wg.Wait()

	peer, ok := e.registry.S.Get(id)
	if !ok {
		t.Fatal("the peer was not stored")
	}
	peer.Mu.RLock()
	zones := len(peer.Zones)
	peer.Mu.RUnlock()
	if zones != callers {
		t.Errorf("the stored peer has %d zones, want %d", zones, callers)
	}
	deadline := time.Now().Add(time.Second)
	for tb.count(string(id)) == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := tb.count(string(id)); got != 1 {
		t.Errorf("%d discoveries of one new peer, want 1", got)
	}
}

// A zone added to, or taken off, a peer the registry does not hold stores
// nothing.
func TestAZoneChangeForAPeerThatIsGoneStoresNothing(t *testing.T) {
	e := NewEngine(Deps{LocalID: "local.example.", Transport: newD25Transport()}, DefaultConfig())
	const id = PeerID("gone.example.")
	if e.registry.AddZoneToPeer(id, "z.example.") {
		t.Error("AddZoneToPeer reported a zone added to a peer that is not stored")
	}
	e.registry.RemovePeerFromZone("z.example.", id)
	if _, ok := e.registry.S.Get(id); ok {
		t.Fatal("a zone change stored a peer that was gone")
	}
}
