/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Routing of RFI EDITS, CONFIG and AUDIT answers to the request that asked.
 */

package tdnsmp

import (
	"slices"
	"sync"

	"github.com/miekg/dns"
)

// rfiWaiters hands the answer to a two-phase RFI (EDITS, CONFIG, AUDIT) to
// the request that asked for it. The answer arrives as a message of its own,
// so it is matched on what it carries: sender, zone and, for CONFIG, subtype.
// Requests with the same key get the answers in the order they asked. An
// answer no request waits for, such as one that arrives after its request
// timed out, is dropped.
type rfiWaiters[T any] struct {
	mu      sync.Mutex
	waiting map[string][]chan T
}

// rfiWaitKey is the key an answer and its request share. Subtype is "" for
// RFI types that have none.
func rfiWaitKey(sender, zone, subtype string) string {
	return dns.CanonicalName(sender) + " " + dns.CanonicalName(zone) + " " + subtype
}

// register adds a waiter for key. Call it before the RFI is sent, so that an
// early answer finds it, and call cancel when the wait is over.
func (w *rfiWaiters[T]) register(key string) (answer <-chan T, cancel func()) {
	ch := make(chan T, 1)
	w.mu.Lock()
	if w.waiting == nil {
		w.waiting = make(map[string][]chan T)
	}
	w.waiting[key] = append(w.waiting[key], ch)
	w.mu.Unlock()
	return ch, func() { w.remove(key, ch) }
}

func (w *rfiWaiters[T]) remove(key string, ch chan T) {
	w.mu.Lock()
	defer w.mu.Unlock()
	q := slices.DeleteFunc(w.waiting[key], func(c chan T) bool { return c == ch })
	if len(q) == 0 {
		delete(w.waiting, key)
	} else {
		w.waiting[key] = q
	}
}

// deliver hands msg to the oldest waiter for key, and reports false when
// there is none.
func (w *rfiWaiters[T]) deliver(key string, msg T) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	q := w.waiting[key]
	if len(q) == 0 {
		return false
	}
	if len(q) == 1 {
		delete(w.waiting, key)
	} else {
		w.waiting[key] = q[1:]
	}
	q[0] <- msg // buffered for one; each waiter gets one answer
	return true
}
