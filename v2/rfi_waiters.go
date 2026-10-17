/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Routing of RFI CONFIG and RFI AUDIT answers to the request that asked.
 */

package tdnsmp

import (
	"crypto/rand"
	"slices"
	"sync"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// rfiWaiters hands the answer to a two-phase RFI (CONFIG, AUDIT) to the
// request that asked for it. The answer arrives as a message of its own, so
// it is matched on what it carries: the sender the transport established,
// the zone, for CONFIG the subtype, and the nonce of the RFI it answers.
// Each request sends a nonce of its own, so an answer to an earlier request
// that timed out does not answer a later one. An answer no request waits
// for is dropped.
type rfiWaiters[T any] struct {
	mu      sync.Mutex
	waiting map[string][]chan T
}

// rfiWaitKey is the key an answer and its request share. Subtype is "" for
// RFI types that have none.
func rfiWaitKey(sender, zone, subtype, nonce string) string {
	return dns.CanonicalName(sender) + " " + dns.CanonicalName(zone) + " " + subtype + " " + nonce
}

// rfiAnswerSender returns the sender a CONFIG or AUDIT answer is matched on:
// the one the transport established. The identity the payload names is a
// claim. An answer that names an agent other than the one that sent it, or
// that came with no transport sender, is not matched (ok is false).
func rfiAnswerSender(msg *transport.IncomingMessage, named string) (sender string, ok bool) {
	if msg.TransportSender == "" {
		return "", false
	}
	if named != "" && dns.CanonicalName(named) != dns.CanonicalName(msg.TransportSender) {
		return msg.TransportSender, false
	}
	return msg.TransportSender, true
}

// newRfiNonce returns the nonce a request sends in its RFI (128 random bits).
func newRfiNonce() string {
	return rand.Text()
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
