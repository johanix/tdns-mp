/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// The engine's request fields are unexported, so a test here cannot make a
// real request. A request without a zone still goes through the engine's loop:
// it gets an error result and, having no response channel, no reply.
//
// The queue is unbuffered, so a send completes only when something receives
// it. A request cannot pass by sitting in a buffer, which is exactly how the
// missing engine went unnoticed. The second send shows the engine went back to
// the queue after the first.
func TestStartDSEngineServesTheQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kdb := &tdns.KeyDB{DSEngineQ: make(chan tdns.DSEngineRequest)}
	startDSEngine(ctx, kdb)

	for i := 1; i <= 2; i++ {
		select {
		case kdb.DSEngineQ <- tdns.DSEngineRequest{}:
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d: nothing is serving the DS engine queue", i)
		}
	}
}

// With no KeyDB, or a KeyDB without a queue, there is nothing to serve.
func TestStartDSEngineWithoutAQueue(t *testing.T) {
	startDSEngine(context.Background(), nil)
	startDSEngine(context.Background(), &tdns.KeyDB{})
}
