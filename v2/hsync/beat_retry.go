/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package hsync

import (
	"context"
	"time"
)

// One lost beat must not cost a peer its OPERATIONAL reading.
//
// A mechanism reads DEGRADED when its last successful beat is more than two
// beat intervals old, and the rounds beat each peer once per interval. After a
// single failed beat the next round therefore came two intervals after the
// last success, and its refresh of the gossip rows, which runs before the
// round's beats, read the peer as DEGRADED moments before the beat that would
// have cleared it. A member that restarted, or one dropped connection, made
// every member of its groups lose mutual OPERATIONAL, and the group's leader
// with it (#123).
//
// So the beats to one peer do not wait for the rounds in two cases:
//
//   - a beat that fails is retried to that peer alone (beatRetrier), after the
//     fast interval and then at doubling gaps, until one succeeds or the gap
//     reaches the beat interval, where the rounds take over;
//   - a peer that introduces itself again gets one beat back at once
//     (BeatPeer): it restarted, and our reading of it is from before. A beat
//     back that fails is sent again after the fast interval, beatBackRetries
//     times at most (#128).
//
// Neither touches the pace of the rounds, and both are bounded per peer: only
// the first failure after a success starts the retries, so a peer that stays
// down gets one episode of them and then the rounds' beats only.

// fastBeatsOn reports whether the engine has a fast interval to retry at. With
// the fixed pace (beatSchedule.fixed) a failed beat waits for the next round,
// as it always did.
func (e *Engine) fastBeatsOn() bool {
	return e.cfg.BeatIntervalMin > 0 && e.cfg.BeatIntervalMin < e.cfg.BeatInterval
}

// baseCtx is the context Run was given, for work that outlives one beat round;
// before Run, the background context.
func (e *Engine) baseCtx() context.Context {
	e.beatMu.Lock()
	defer e.beatMu.Unlock()
	if e.runCtx == nil {
		return context.Background()
	}
	return e.runCtx
}

// noteBeatFailed records a failed beat to peer and starts the peer's retrier
// when it is the first failure since a success. It reports whether it started
// the retrier.
func (e *Engine) noteBeatFailed(peer *Peer) bool {
	e.beatMu.Lock()
	first := !e.beatFailing[peer.ID]
	e.beatFailing[peer.ID] = true
	start := first && !e.beatRetrying[peer.ID] && e.fastBeatsOn()
	if start {
		e.beatRetrying[peer.ID] = true
	}
	e.beatMu.Unlock()
	if start {
		go e.beatRetrier(peer)
	}
	return start
}

// noteBeatSucceeded ends the peer's episode of failed beats.
func (e *Engine) noteBeatSucceeded(peer *Peer) {
	e.beatMu.Lock()
	delete(e.beatFailing, peer.ID)
	e.beatMu.Unlock()
}

// beatStillFailing reports whether the peer's last beat failed.
func (e *Engine) beatStillFailing(id PeerID) bool {
	e.beatMu.Lock()
	defer e.beatMu.Unlock()
	return e.beatFailing[id]
}

// beatRetrier beats one peer again after a failed beat: after the fast
// interval, then at doubling gaps. It stops when a beat succeeds (its own, or a
// round's), when the gap reaches the beat interval, when the peer is gone or
// no longer past its hello, or when the engine stops.
func (e *Engine) beatRetrier(peer *Peer) {
	// The outage this retrier was started for is over once a beat has
	// succeeded, its own or a round's.
	over := false
	defer func() { e.endBeatRetrier(peer, over) }()
	ctx := e.baseCtx()
	for wait := e.cfg.BeatIntervalMin; wait < e.cfg.BeatInterval; wait *= 2 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if !e.beatStillFailing(peer.ID) {
			over = true
			return
		}
		if _, ok := e.registry.S.Get(peer.ID); !ok || !e.peerAnyTransportReady(peer) {
			return
		}
		beatCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ok := e.beatPeerOnce(beatCtx, peer)
		cancel()
		if ok {
			over = true
			e.runDeferredTasks(peer)
			return
		}
	}
}

// endBeatRetrier takes the peer's retrier off the books. A beat can fail in
// the moment between this retrier's success and its exit: noteBeatFailed then
// saw a retrier still running and started none, though the failure opens a new
// outage. When the old outage is over and the peer is failing again, the
// retries for the new one start here.
func (e *Engine) endBeatRetrier(peer *Peer, over bool) {
	e.beatMu.Lock()
	delete(e.beatRetrying, peer.ID)
	again := over && e.beatFailing[peer.ID] && e.fastBeatsOn()
	if again {
		e.beatRetrying[peer.ID] = true
	}
	e.beatMu.Unlock()
	if again {
		go e.beatRetrier(peer)
	}
}

// beatBackRetries is how many times a beat back that fails is sent again, a
// fast interval apart. The peer's hello says that it is back, so a retry soon
// is well spent, and a few are enough: a returning agent has been seen to
// refuse a beat sent in the second its hello was processed and to acknowledge
// the next one a second later, which the first retry covers; the second is for
// a peer that needs longer than one fast interval. A peer that refuses three
// beats in a row is not back in the sense its hello suggested, and the rounds
// have it from there.
const beatBackRetries = 2

// BeatPeer beats one peer now, outside the rounds and without touching their
// pace. The host calls it for a hello from a peer whose mechanism is already
// introduced: the peer restarted, or never got our accept, and is introducing
// itself again. Our reading of it is from before, so nothing else would beat
// it until the next round, and a beat that failed while it was away would by
// then be two intervals behind the last success. A peer that repeats its hello
// costs one beat back for each, to that peer alone, and never more than one at
// a time: while one is on its way, or waits to be sent again (beatBack), a
// further call does nothing, so hellos that come faster than a beat returns
// cannot pile beats up. A peer the engine does not know, or one not past its
// hello, gets none.
func (e *Engine) BeatPeer(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, ok := e.registry.S.Get(id)
	if !ok || peer.IsInfraPeer || !e.peerAnyTransportReady(peer) {
		return
	}
	e.beatMu.Lock()
	busy := e.beatingBack[id]
	if !busy {
		e.beatingBack[id] = true
	}
	e.beatMu.Unlock()
	if busy {
		return
	}
	go func() {
		defer func() {
			e.beatMu.Lock()
			delete(e.beatingBack, id)
			e.beatMu.Unlock()
		}()
		e.beatBack(peer)
	}()
}

// beatBack sends the beat back to peer and, when it fails, sends it again
// after the fast interval, beatBackRetries times at most. A returning peer can
// refuse the beat sent in the moment its hello is processed, and with an
// outage on the books nothing else beats it before the next round: the peer's
// beat retrier, if it still runs, waits for a slot that may lie beyond that
// round (#128).
//
// The beat back does not retry beside the retrier. A failed beat back that is
// the first failure since a success starts the retrier, whose first retry
// comes after the fast interval: that is the retry, and the beat back is done.
// Otherwise the retries are sent from here, and a beat that succeeds in
// between, a round's or the retrier's, ends them. With the fixed pace there is
// no fast interval and no retry.
func (e *Engine) beatBack(peer *Peer) {
	if e.deps.Transport == nil {
		return
	}
	base := e.baseCtx()
	for try := 0; ; try++ {
		ctx, cancel := context.WithTimeout(base, 10*time.Second)
		ok := e.beatPeerOnce(ctx, peer)
		cancel()
		e.runDeferredTasks(peer)
		if ok {
			return
		}
		// The failure goes on the books as any failed beat's does.
		if e.noteBeatFailed(peer) || try >= beatBackRetries || !e.fastBeatsOn() {
			return
		}
		select {
		case <-base.Done():
			return
		case <-time.After(e.cfg.BeatIntervalMin):
		}
		if !e.beatStillFailing(peer.ID) {
			return
		}
		if _, ok := e.registry.S.Get(peer.ID); !ok || !e.peerAnyTransportReady(peer) {
			return
		}
	}
}
