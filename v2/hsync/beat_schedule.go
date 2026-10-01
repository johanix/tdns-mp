/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import "time"

// beatSchedule paces the engine's beat rounds. While the engine's view of its
// peers changes, rounds come every fast interval; each round that finds the
// view as the previous one left it doubles the gap, up to the configured beat
// interval, the steady pace. A change, seen by a round or reported by a kick,
// starts the fast pace over. This is the shape of Trickle (RFC 6206): fast
// while there is news, quiet once there is none.
//
// The pace resets on a change, not on a state: a peer that stays unreachable
// does not hold the engine at the fast pace, it backs off like everything
// else. And the gap never exceeds the beat interval, so the liveness decay,
// which keys on that interval, reads beats exactly as before.
//
// A fast interval of zero, or one at or above the beat interval, gives a
// fixed pace at the beat interval with the first round one interval after the
// start, and kicks change nothing: the engine as it was.
type beatSchedule struct {
	min, max time.Duration
	interval time.Duration // the gap the last round set
	last     time.Time     // when the last round ran; zero before the first
	next     time.Time     // when the next round is due
	view     string        // the view the last round saw
}

func newBeatSchedule(min, max time.Duration, start time.Time) *beatSchedule {
	if max <= 0 {
		max = DefaultConfig().BeatInterval
	}
	if min <= 0 || min > max {
		min = max
	}
	return &beatSchedule{min: min, max: max, interval: min, next: start.Add(min)}
}

// fixed reports whether the schedule has no fast pace.
func (s *beatSchedule) fixed() bool { return s.min >= s.max }

// roundDone records a round that ran at now and saw view.
func (s *beatSchedule) roundDone(now time.Time, view string) {
	if view != s.view {
		s.interval = s.min
	} else {
		s.interval = min(2*s.interval, s.max)
	}
	s.view = view
	s.last = now
	s.next = now.Add(s.interval)
}

// kick reports a change seen between rounds: the next round comes one fast
// interval after the last one, or at once if that has passed, and the pace
// starts over. It reports whether the next round moved earlier.
func (s *beatSchedule) kick(now time.Time) bool {
	if s.fixed() {
		return false
	}
	s.interval = s.min
	due := s.last.Add(s.min)
	if due.Before(now) {
		due = now
	}
	if due.Before(s.next) {
		s.next = due
		return true
	}
	return false
}

// untilNext is the wait from now to the next round.
func (s *beatSchedule) untilNext(now time.Time) time.Duration {
	if d := s.next.Sub(now); d > 0 {
		return d
	}
	return 0
}
