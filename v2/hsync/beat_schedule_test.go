/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// The rounds start at the fast interval, double while the view holds still,
// stop at the beat interval, and start over on a change.
func TestBeatScheduleBacksOffAndStartsOver(t *testing.T) {
	const fast, steady = 2 * time.Second, 30 * time.Second
	t0 := time.Unix(1_000_000, 0)
	s := newBeatSchedule(fast, steady, t0)
	if got := s.untilNext(t0); got != fast {
		t.Fatalf("first round in %v, want %v", got, fast)
	}

	now := t0.Add(fast)
	var gaps []time.Duration
	for i := 0; i < 7; i++ {
		s.roundDone(now, "all operational")
		gap := s.untilNext(now)
		gaps = append(gaps, gap)
		now = now.Add(gap)
	}
	// The first round sees a view the schedule had not seen: fast again.
	want := []time.Duration{2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if gaps[i] != w*time.Second {
			t.Fatalf("gaps %v, want %v seconds", gaps, want)
		}
	}

	s.roundDone(now, "a peer degraded")
	if got := s.untilNext(now); got != fast {
		t.Errorf("after a change the next round is in %v, want %v", got, fast)
	}
}

// A kick between rounds brings the next round to one fast interval after the
// last, or to now if that has passed, and restarts the fast pace.
func TestBeatScheduleKick(t *testing.T) {
	const fast, steady = 2 * time.Second, 30 * time.Second
	t0 := time.Unix(1_000_000, 0)
	s := newBeatSchedule(fast, steady, t0)
	s.roundDone(t0, "v")
	s.roundDone(t0, "v")
	s.roundDone(t0, "v") // gap 8 s
	if got := s.untilNext(t0); got != 8*time.Second {
		t.Fatalf("setup: next round in %v, want 8s", got)
	}

	if !s.kick(t0.Add(time.Second)) {
		t.Fatal("a kick one second after a round did not move the next one")
	}
	if got := s.untilNext(t0.Add(time.Second)); got != time.Second {
		t.Errorf("after a kick the next round is in %v, want 1s (fast interval after the last round)", got)
	}

	s.roundDone(t0.Add(2*time.Second), "v")
	if got := s.untilNext(t0.Add(2 * time.Second)); got != 4*time.Second {
		t.Errorf("after the kicked round the gap is %v, want 4s (the pace started over)", got)
	}

	// Long after the last round, a kick means now.
	late := t0.Add(5 * time.Second)
	s.kick(late)
	if got := s.untilNext(late); got != 0 {
		t.Errorf("a late kick leaves %v to the next round, want 0", got)
	}

	// A kick never moves a round later.
	s2 := newBeatSchedule(fast, steady, t0)
	s2.roundDone(t0, "v")
	if s2.kick(t0) {
		t.Error("a kick right after a round moved the round due one fast interval later")
	}
}

// With no fast interval, or one at or above the beat interval, every round
// is a beat interval apart, the first one interval after the start, and a
// kick changes nothing: the engine as it was.
func TestBeatScheduleFixedPace(t *testing.T) {
	const steady = 30 * time.Second
	t0 := time.Unix(1_000_000, 0)
	for _, fast := range []time.Duration{0, steady, 2 * steady} {
		s := newBeatSchedule(fast, steady, t0)
		if got := s.untilNext(t0); got != steady {
			t.Errorf("fast %v: first round in %v, want %v", fast, got, steady)
		}
		if s.kick(t0.Add(time.Second)) {
			t.Errorf("fast %v: a kick moved a round", fast)
		}
		s.roundDone(t0, "a")
		s.roundDone(t0, "b")
		if got := s.untilNext(t0); got != steady {
			t.Errorf("fast %v: after a change the gap is %v, want %v", fast, got, steady)
		}
	}
	if s := newBeatSchedule(0, 0, t0); s.untilNext(t0) != DefaultConfig().BeatInterval {
		t.Errorf("no beat interval: first round in %v, want the default %v", s.untilNext(t0), DefaultConfig().BeatInterval)
	}
}

// roundClock records when the engine's beat rounds ran.
type roundClock struct {
	mu     sync.Mutex
	rounds []time.Time
}

func (c *roundClock) tick() {
	c.mu.Lock()
	c.rounds = append(c.rounds, time.Now())
	c.mu.Unlock()
}

func (c *roundClock) snapshot() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.rounds...)
}

func (c *roundClock) waitFor(t *testing.T, n int, d time.Duration) []time.Time {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if r := c.snapshot(); len(r) >= n {
			return r
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%d round(s) within %v, want %d", len(c.snapshot()), d, n)
	return nil
}

func runEngine(t *testing.T, cfg Config, tb TransportBridge) (*Engine, *roundClock, chan *InboundReport) {
	t.Helper()
	clock := &roundClock{}
	e := NewEngine(Deps{
		LocalID:   "local.example.",
		Transport: tb,
		Host:      HostCallbacks{BeforeHeartbeats: clock.tick},
	}, cfg)
	hello := make(chan *InboundReport, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.Run(ctx, MsgChannels{Hello: hello, Beat: make(chan *InboundReport), Msg: make(chan *InboundMsg)})
	return e, clock, hello
}

// The running engine: the first round comes after the fast interval, the gap
// grows while nothing changes, and an inbound hello brings the next round
// back to the fast interval.
func TestEngineBeatRoundsAreFastThenSteady(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 320 * time.Millisecond
	cfg := DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = fast, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	start := time.Now()
	_, clock, hello := runEngine(t, cfg, newD25Transport())

	rounds := clock.waitFor(t, 5, 3*time.Second)
	if first := rounds[0].Sub(start); first > steady/2 {
		t.Errorf("the first round came %v after the start, want about %v", first, fast)
	}
	if early, later := rounds[1].Sub(rounds[0]), rounds[4].Sub(rounds[3]); later < 3*early {
		t.Errorf("gaps did not grow: %v early, %v later", early, later)
	}

	// Wait until the pace is steady, then a hello arrives.
	clock.waitFor(t, 7, 3*time.Second)
	n := len(clock.snapshot())
	kicked := time.Now()
	hello <- &InboundReport{MessageType: MsgHello, Identity: "remote.example."}
	after := clock.waitFor(t, n+1, 3*time.Second)
	if got := after[n].Sub(kicked); got > steady/2 {
		t.Errorf("the round after an inbound hello came %v later, want about %v", got, fast)
	}
}

// With the fast interval off, the first round comes one beat interval after
// the start, as before.
func TestEngineBeatRoundsFixedPace(t *testing.T) {
	const steady = 150 * time.Millisecond
	cfg := DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = 0, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	start := time.Now()
	_, clock, _ := runEngine(t, cfg, newD25Transport())

	rounds := clock.waitFor(t, 2, 3*time.Second)
	if first := rounds[0].Sub(start); first < steady*9/10 {
		t.Errorf("the first round came %v after the start, want one beat interval, %v", first, steady)
	}
	if gap := rounds[1].Sub(rounds[0]); gap < steady*9/10 {
		t.Errorf("rounds %v apart, want %v", gap, steady)
	}
}

// A beat that makes a peer OPERATIONAL is a change: the round after it comes
// at the fast interval even though the pace had backed off.
func TestEngineABeatThatChangesAPeerKicksTheRounds(t *testing.T) {
	const fast, steady = 20 * time.Millisecond, 400 * time.Millisecond
	cfg := DefaultConfig()
	cfg.BeatIntervalMin, cfg.BeatInterval = fast, steady
	cfg.RetryInterval, cfg.ReconcileInterval = time.Hour, time.Hour
	h := newHandshakeTransport()
	e, clock, _ := runEngine(t, cfg, h)
	peer := knownDNSPeer(e, h.d25Transport)

	clock.waitFor(t, 6, 3*time.Second) // backed off by now
	n := len(clock.snapshot())
	h.seed(string(peer.ID), TransportDNS, transport.PeerStateIntroducing)
	kicked := time.Now()
	e.sendBeatToPeer(context.Background(), peer) // INTRODUCING -> OPERATIONAL
	after := clock.waitFor(t, n+1, 3*time.Second)
	if got := after[n].Sub(kicked); got > steady/2 {
		t.Errorf("the round after a peer became OPERATIONAL came %v later, want about %v", got, fast)
	}
}
