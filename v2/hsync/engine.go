/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"
	"sync"
	"time"
)

// Engine is the shared HSYNC protocol loop (discovery, HELLO, BEAT, gossip, dispatch).
type Engine struct {
	deps        Deps
	cfg         Config
	registry    *Registry
	onMsg       InboundHandler
	discSem     chan struct{}
	discSemOnce sync.Once
	// kick carries changes seen between beat rounds to Run (KickBeats).
	kick chan struct{}

	// beatMu guards the three below (beat_retry.go).
	beatMu sync.Mutex
	// runCtx is Run's context, for the beat retriers.
	runCtx context.Context
	// beatFailing: the peers whose last beat failed.
	beatFailing map[PeerID]bool
	// beatRetrying: the peers a beat retrier is running for.
	beatRetrying map[PeerID]bool
}

// NewEngine constructs an Engine. Gossip table may be nil until wired.
func NewEngine(deps Deps, cfg Config) *Engine {
	reg := NewRegistry(deps.LocalID, deps.Transport)
	// D0: no built-in gossip table. deps.Gossip is the application's port
	// (nil-guarded wherever it is used).
	e := &Engine{
		deps:     deps,
		cfg:      cfg,
		registry: reg,
		kick:     make(chan struct{}, 1),

		beatFailing:  make(map[PeerID]bool),
		beatRetrying: make(map[PeerID]bool),
	}
	if deps.Gossip != nil && deps.Host.OnGroupOperational != nil {
		deps.Gossip.SetOnGroupOperational(deps.Host.OnGroupOperational)
	}
	if deps.Gossip != nil && deps.Host.OnGroupDegraded != nil {
		deps.Gossip.SetOnGroupDegraded(deps.Host.OnGroupDegraded)
	}
	if deps.Gossip != nil && deps.Host.OnElectionGossip != nil {
		deps.Gossip.SetOnElectionUpdate(deps.Host.OnElectionGossip)
	}
	return e
}

// Registry returns the peer registry owned by this engine.
func (e *Engine) Registry() *Registry {
	return e.registry
}

// SetHandler installs the host's handler for application messages.
func (e *Engine) SetHandler(h InboundHandler) { e.onMsg = h }

// KickBeats tells Run that a peer's state changed between beat rounds, so
// that the next round comes soon (beatSchedule.kick). It never blocks: one
// pending kick covers any number.
//
// It is for a change, never for an event that left every state where it was:
// each kick starts the fast pace over, so a caller that kicked on, say, every
// hello a peer repeats would hold the engine off the beat interval for as
// long as the peer kept repeating it. The engine kicks after a hello or a
// beat it sent moved the peer; the host kicks where an inbound message moved
// one.
func (e *Engine) KickBeats() {
	if e == nil || e.kick == nil {
		return
	}
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// Run owns the protocol select loop until ctx is cancelled. Beat rounds are
// paced by a beatSchedule: fast while the view of the peers changes, at the
// beat interval once it holds still.
func (e *Engine) Run(ctx context.Context, ch MsgChannels) {
	e.beatMu.Lock()
	e.runCtx = ctx
	e.beatMu.Unlock()

	go e.runDiscoveryRetry(ctx)
	go e.runReconcile(ctx)

	sched := newBeatSchedule(e.cfg.BeatIntervalMin, e.cfg.BeatInterval, time.Now())
	beatTimer := time.NewTimer(sched.untilNext(time.Now()))
	defer beatTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case report, ok := <-ch.Hello:
			if ok && report != nil {
				e.helloHandler(report)
			}

		case report, ok := <-ch.Beat:
			if ok && report != nil {
				e.heartbeatHandler(report)
			}

		case msg, ok := <-ch.Msg:
			if ok && msg != nil && e.onMsg != nil {
				e.onMsg(msg)
			}

		case <-e.kick:
			if sched.kick(time.Now()) {
				beatTimer.Reset(sched.untilNext(time.Now()))
			}

		case <-beatTimer.C:
			now := time.Now()
			sched.roundDone(now, e.sendHeartbeats())
			beatTimer.Reset(sched.untilNext(time.Now()))
		}
	}
}
