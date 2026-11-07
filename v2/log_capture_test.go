/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
)

// A test reads a package logger's output by handing the logger a handler of
// its own (logTo), never by writing the logger variable: a goroutine that an
// earlier test started, such as a key poll, may still be running and read
// the variable (#276). TestMain gives each logger a test captures a
// swapHandler, once, before any test runs; the variables are not written
// after that.

// swapHandler forwards every record to the handler in to, which a test may
// swap. The attributes and groups added to it (with) are applied to that
// handler as the record is handled, so that a logger derived from the
// package logger follows the swap too.
type swapHandler struct {
	to   *atomic.Pointer[slog.Handler]
	with []func(slog.Handler) slog.Handler
}

func newSwapHandler(h slog.Handler) *swapHandler {
	s := &swapHandler{to: &atomic.Pointer[slog.Handler]{}}
	s.to.Store(&h)
	return s
}

func (s *swapHandler) current() slog.Handler {
	h := *s.to.Load()
	for _, w := range s.with {
		h = w(h)
	}
	return h
}

func (s *swapHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return s.current().Enabled(ctx, level)
}

func (s *swapHandler) Handle(ctx context.Context, r slog.Record) error {
	return s.current().Handle(ctx, r)
}

func (s *swapHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return s.derive(func(h slog.Handler) slog.Handler { return h.WithAttrs(attrs) })
}

func (s *swapHandler) WithGroup(name string) slog.Handler {
	return s.derive(func(h slog.Handler) slog.Handler { return h.WithGroup(name) })
}

func (s *swapHandler) derive(w func(slog.Handler) slog.Handler) *swapHandler {
	with := append(append([]func(slog.Handler) slog.Handler{}, s.with...), w)
	return &swapHandler{to: s.to, with: with}
}

// swappable gives l a swapHandler over its own handler. TestMain only.
func swappable(l *slog.Logger) *slog.Logger {
	return slog.New(newSwapHandler(l.Handler()))
}

// logTo has l write to h for the rest of the test; the handler before is
// put back after it. l is one of the loggers TestMain made swappable.
func logTo(t *testing.T, l *slog.Logger, h slog.Handler) {
	t.Helper()
	s, ok := l.Handler().(*swapHandler)
	if !ok {
		t.Fatal("logTo: the logger was not made swappable in TestMain")
	}
	prev := s.to.Swap(&h)
	t.Cleanup(func() { s.to.Store(prev) })
}
