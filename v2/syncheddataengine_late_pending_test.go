/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A recipient sends two confirmations for a distribution: "PENDING" at once,
// and its final answer when it is done. They leave the recipient on different
// goroutines, and a recipient that is done at once can have its final answer
// arrive first. The late "PENDING" must not be written over it: the origin
// would wait for a confirmation that has already come, and the operation
// would stay pending for good.
func TestALatePendingConfirmationDoesNotUndoTheFinalOne(t *testing.T) {
	const (
		zone    = ZoneName("late.pending.example.")
		us      = AgentId("agent.us.example.")
		first   = "combiner.us.example."
		quick   = "auditor.example."
		distID  = "6acd35f5"
		another = "0badc0de"
	)
	rr, err := dns.NewRR("late.pending.example. 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	newRepo := func() (*ZoneDataRepo, *TrackedRR) {
		zdr, err := NewZoneDataRepo()
		if err != nil {
			t.Fatal(err)
		}
		set := &TrackedRRset{Tracked: []TrackedRR{{
			RR:                 rr,
			State:              RRStatePending,
			DistributionID:     distID,
			ExpectedRecipients: []string{first, quick},
		}}}
		zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeNS: set}}
		return zdr, &set.Tracked[0]
	}
	final := func(source string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: distID, Zone: zone, Source: source, Status: "ok", AppliedRecords: []string{rr.String()}}
	}
	pending := func(source, id string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: id, Zone: zone, Source: source, Status: "PENDING"}
	}

	t.Run("the final answer first, the pending one after it", func(t *testing.T) {
		zdr, tr := newRepo()
		zdr.ProcessConfirmation(final(quick), nil)
		zdr.ProcessConfirmation(pending(quick, distID), nil)
		if got := tr.Confirmations[quick].Status; got != "accepted" {
			t.Fatalf("after the late PENDING the recipient's confirmation reads %q, want the accepted it had", got)
		}
		zdr.ProcessConfirmation(pending(first, distID), nil)
		zdr.ProcessConfirmation(final(first), nil)
		if tr.State != RRStateAccepted {
			t.Fatalf("with both recipients' final answers in, the record's state is %v, want accepted: confirmations %v", tr.State, tr.Confirmations)
		}
	})

	t.Run("the usual order still works", func(t *testing.T) {
		zdr, tr := newRepo()
		zdr.ProcessConfirmation(pending(quick, distID), nil)
		if got := tr.Confirmations[quick].Status; got != "pending" {
			t.Fatalf("after PENDING the recipient's confirmation reads %q, want pending", got)
		}
		if tr.State != RRStatePending {
			t.Fatalf("after one PENDING the record's state is %v, want pending", tr.State)
		}
		zdr.ProcessConfirmation(final(quick), nil)
		zdr.ProcessConfirmation(final(first), nil)
		if tr.State != RRStateAccepted {
			t.Fatalf("the record's state is %v, want accepted", tr.State)
		}
	})

	t.Run("a pending one for another distribution touches nothing", func(t *testing.T) {
		zdr, tr := newRepo()
		zdr.ProcessConfirmation(final(quick), nil)
		zdr.ProcessConfirmation(pending(quick, another), nil)
		if got := tr.Confirmations[quick].Status; got != "accepted" {
			t.Fatalf("the recipient's confirmation reads %q, want accepted", got)
		}
	})
}

// A record that every recipient has accepted is then deleted, in a new
// distribution. What the recipients said about the addition says nothing
// about the delete, and the record starts the new distribution with no
// confirmations. Left in place, the old answers counted: the delete read as
// confirmed by everybody as soon as the first recipient confirmed it, and the
// guard against a late "pending" kept them there.
func TestADeleteWaitsForItsOwnConfirmationsNotTheAdditions(t *testing.T) {
	const (
		zone   = ZoneName("delete.after.add.example.")
		us     = AgentId("agent.us.example.")
		first  = "combiner.us.example."
		quick  = "auditor.example."
		addID  = "11111111"
		delID  = "22222222"
		absent = "33333333"
	)
	rr, err := dns.NewRR("delete.after.add.example. 3600 IN NS ns9.provider.example.")
	if err != nil {
		t.Fatal(err)
	}
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	set := &TrackedRRset{Tracked: []TrackedRR{{
		RR:                 rr,
		State:              RRStatePending,
		DistributionID:     addID,
		ExpectedRecipients: []string{first, quick},
	}}}
	zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{us: {dns.TypeNS: set}}
	tr := &set.Tracked[0]

	// The addition, confirmed by both.
	for _, source := range []string{first, quick} {
		zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: addID, Zone: zone, Source: source, Status: "ok",
			AppliedRecords: []string{rr.String()}}, nil)
	}
	if tr.State != RRStateAccepted {
		t.Fatalf("precondition: the record's state after both accepted it is %v", tr.State)
	}

	// The delete, a new distribution to the same two recipients.
	del := dns.Copy(rr)
	del.Header().Class = dns.ClassNONE
	zdr.markDeletePending(set, del, delID, time.Now())
	zdr.setExpectedRecipients(zone, us, delID, []string{first, quick})
	if len(tr.Confirmations) != 0 {
		t.Fatalf("the record starts the delete with the confirmations of the addition: %v", tr.Confirmations)
	}
	removed := func(source string) *ConfirmationDetail {
		return &ConfirmationDetail{DistributionID: delID, Zone: zone, Source: source, Status: "ok", RemovedRecords: []string{rr.String()}}
	}

	// One recipient confirms the delete, its final answer before its
	// "pending". The other has said nothing about the delete yet.
	zdr.ProcessConfirmation(removed(quick), nil)
	zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: delID, Zone: zone, Source: quick, Status: "PENDING"}, nil)
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("after one of two recipients confirmed the delete the record's state is %v, want it still pending removal: confirmations %v",
			tr.State, tr.Confirmations)
	}
	if got := tr.Confirmations[quick].Status; got != "removed" {
		t.Errorf("the recipient that confirmed the delete reads %q, want removed", got)
	}

	// The other one: "pending", then its final answer. Now it is removed.
	zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: delID, Zone: zone, Source: first, Status: "PENDING"}, nil)
	if got := tr.Confirmations[first].Status; got != "pending" {
		t.Errorf("the other recipient's PENDING for the delete reads %q, want pending", got)
	}
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("after a PENDING the record's state is %v, want pending removal", tr.State)
	}
	zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: absent, Zone: zone, Source: first, Status: "PENDING"}, nil)
	zdr.ProcessConfirmation(removed(first), nil)
	if tr.State != RRStateRemoved {
		t.Fatalf("with both recipients' confirmations of the delete in, the record's state is %v, want removed: confirmations %v",
			tr.State, tr.Confirmations)
	}
}
