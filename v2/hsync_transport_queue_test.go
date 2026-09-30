/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A confirmation settles the reliable queue's copy of the message it
 * answers: a final word closes it, a PENDING keeps it waiting.
 */
package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
)

func TestAConfirmationSettlesTheQueuedMessage(t *testing.T) {
	q := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})
	queued := func(id string) {
		t.Helper()
		if err := q.Enqueue(&transport.OutgoingMessage{DistributionID: id, RecipientID: "p2", Zone: "z.example."}); err != nil {
			t.Fatal(err)
		}
	}
	state := func(id string) string {
		for _, m := range q.GetPendingMessages() {
			if m.DistributionID == id {
				return m.State
			}
		}
		return "gone"
	}

	// A PENDING keeps the message, waiting for the final word.
	queued("d1")
	settleQueuedMessage(q, "d1", "p2", transport.ConfirmPending)
	if got := state("d1"); got != transport.MessageAwaitingConfirm.String() {
		t.Fatalf("after a PENDING the message is %s, want it awaiting the final confirmation", got)
	}

	// Every final word closes it, PARTIAL included: the recipient did what it will do.
	for i, final := range []transport.ConfirmStatus{transport.ConfirmSuccess, transport.ConfirmFailed, transport.ConfirmRejected, transport.ConfirmIgnored, transport.ConfirmPartial} {
		id := string(rune('a' + i))
		queued(id)
		settleQueuedMessage(q, id, "p2", final)
		if got := state(id); got != "gone" {
			t.Errorf("after %s the message is still %s", final, got)
		}
	}
	settleQueuedMessage(q, "d1", "p2", transport.ConfirmSuccess)
	if got := state("d1"); got != "gone" {
		t.Errorf("the final word after a PENDING left the message %s", got)
	}

	// An answer from someone else leaves another recipient's copy alone.
	queued("d2")
	settleQueuedMessage(q, "d2", "p3", transport.ConfirmSuccess)
	if got := state("d2"); got == "gone" {
		t.Error("another recipient's SUCCESS closed the message")
	}
}
