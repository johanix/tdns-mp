/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"sync"
)

// identityReadiness is the gate the agent's first hello waits on: closed until
// the identity zone is published, open for good after (tdns #653). A peer that
// receives a hello looks the sender up at once, and before the publish there
// is nothing to find.
type identityReadiness struct {
	ch   chan struct{}
	once sync.Once
}

func newIdentityReadiness() *identityReadiness {
	return &identityReadiness{ch: make(chan struct{})}
}

// Publish opens the gate. Idempotent.
func (r *identityReadiness) Publish() {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.ch) })
}

// Wait blocks until the gate is open or ctx ends, and reports which. A nil
// gate is open: a role that sets no identity up waits for nothing.
func (r *identityReadiness) Wait(ctx context.Context) bool {
	if r == nil {
		return true
	}
	select {
	case <-r.ch:
		return true
	case <-ctx.Done():
		return false
	}
}
