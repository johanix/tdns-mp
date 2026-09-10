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
	onSync      SyncHandler
	onElection  ElectionHandler
	onKeyState  KeyStateHandler
	discSem     chan struct{}
	discSemOnce sync.Once
}

// NewEngine constructs an Engine. Gossip table may be nil until wired.
func NewEngine(deps Deps, cfg Config) *Engine {
	reg := NewRegistry(deps.LocalID, deps.Transport)
	if deps.Gossip == nil && deps.LocalID != "" {
		deps.Gossip = NewGossipStateTable(string(deps.LocalID))
	}
	e := &Engine{
		deps:     deps,
		cfg:      cfg,
		registry: reg,
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

func (e *Engine) SetSyncHandler(h SyncHandler)         { e.onSync = h }
func (e *Engine) SetElectionHandler(h ElectionHandler) { e.onElection = h }
func (e *Engine) SetKeyStateHandler(h KeyStateHandler) { e.onKeyState = h }

// Run owns the protocol select loop until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, ch MsgChannels) {
	go e.runDiscoveryRetry(ctx)
	go e.runReconcile(ctx)

	beatTicker := time.NewTicker(e.cfg.BeatInterval)
	defer beatTicker.Stop()

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
			if ok && msg != nil {
				e.dispatchByType(msg)
			}

		case <-beatTicker.C:
			e.sendHeartbeats()
		}
	}
}
