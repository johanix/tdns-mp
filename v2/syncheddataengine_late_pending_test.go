/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"

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
