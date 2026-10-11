/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"errors"
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
}

func newScriptedBeats() *scriptedBeats {
	return &scriptedBeats{d25Transport: newD25Transport()}
}

func (s *scriptedBeats) SendBeat(ctx context.Context, peer *Peer, sequence uint64) (bool, string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, time.Now())
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

	// The same, but the retrier ran out: no further retries.
	time.Sleep(3 * fast)
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
