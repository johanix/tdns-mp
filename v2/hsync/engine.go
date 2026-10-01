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
	// kick carries changes seen between beat rounds to Run (kickBeats).
	kick chan struct{}
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

// kickBeats tells Run that a peer's state changed between beat rounds, so
// that the next round comes soon (beatSchedule.kick). It never blocks: one
// pending kick covers any number.
func (e *Engine) kickBeats() {
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
