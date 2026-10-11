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
//     (BeatPeer): it restarted, and our reading of it is from before.
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
// when it is the first failure since a success.
func (e *Engine) noteBeatFailed(peer *Peer) {
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
	defer func() {
		e.beatMu.Lock()
		delete(e.beatRetrying, peer.ID)
		e.beatMu.Unlock()
	}()
	ctx := e.baseCtx()
	for wait := e.cfg.BeatIntervalMin; wait < e.cfg.BeatInterval; wait *= 2 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if !e.beatStillFailing(peer.ID) {
			return
		}
		if _, ok := e.registry.S.Get(peer.ID); !ok || !e.peerAnyTransportReady(peer) {
			return
		}
		beatCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ok := e.beatPeerOnce(beatCtx, peer)
		cancel()
		if ok {
			e.runDeferredTasks(peer)
			return
		}
	}
}

// BeatPeer beats one peer now, outside the rounds and without touching their
// pace. The host calls it for a hello from a peer whose mechanism is already
// introduced: the peer restarted, or never got our accept, and is introducing
// itself again. Our reading of it is from before, so nothing else would beat
// it until the next round, and a beat that failed while it was away would by
// then be two intervals behind the last success. A peer that repeats its hello
// costs one beat for each, to that peer alone. A peer the engine does not
// know, or one not past its hello, gets none.
func (e *Engine) BeatPeer(id PeerID) {
	if e == nil || e.registry == nil {
		return
	}
	peer, ok := e.registry.S.Get(id)
	if !ok || peer.IsInfraPeer || !e.peerAnyTransportReady(peer) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(e.baseCtx(), 10*time.Second)
		defer cancel()
		e.sendBeatToPeer(ctx, peer)
		e.runDeferredTasks(peer)
	}()
}
