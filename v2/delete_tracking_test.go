/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A delete of the agent's own record is followed at its origin (#194). The
 * delete goes out as a REPLACE of the type's set without the record. A record
 * the REPLACE leaves out waits for its recipients as PENDING_REMOVAL, under the
 * REPLACE's distribution, and is removed once every recipient with a vote has
 * removed it; a rejection puts it back to ACCEPTED. It was dropped at once,
 * so nothing waited for a recipient that was down, and no rejection was seen.
 */
package tdnsmp

import (
	"slices"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// delRig is this agent's data in a zone: its NS records, accepted.
type delRig struct {
	zdr  *ZoneDataRepo
	zone ZoneName
	self AgentId
}

func newDelRig(t *testing.T, zone string, self AgentId, records ...dns.RR) *delRig {
	t.Helper()
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	r := &delRig{zdr: zdr, zone: ZoneName(zone), self: self}
	for _, rr := range records {
		zdr.AddConfirmedRR(r.zone, self, rr)
	}
	return r
}

func nsRR(t *testing.T, zone, target string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(zone + " 3600 IN NS " + target)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// send is the agent's local REPLACE of its NS set with keep, as `agent zone
// delrr` (with del) or `addrr` builds it, applied to the data and marked
// under distID as the data engine does (applyLocalUpdate).
func (r *delRig) send(t *testing.T, distID string, recipients []string, del []dns.RR, keep ...dns.RR) {
	t.Helper()
	records := make([]string, 0, len(keep))
	for _, rr := range keep {
		records = append(records, rr.String())
	}
	zu := &ZoneUpdate{
		Zone:       r.zone,
		AgentId:    r.self,
		RRsets:     map[uint16]core.RRset{},
		Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: records}},
	}
	for _, rr := range del {
		none := dns.Copy(rr)
		none.Header().Class = dns.ClassNONE
		zu.RRs = append(zu.RRs, none)
	}
	u := &SynchedDataUpdate{Zone: r.zone, AgentId: r.self, UpdateType: "local", Update: zu}
	if _, _, err := r.zdr.ProcessUpdate(u); err != nil {
		t.Fatal(err)
	}
	r.zdr.MarkRRsPending(r.zone, r.self, zu, distID, recipients)
}

func (r *delRig) confirm(distID, from string, change func(*ConfirmationDetail)) {
	d := &ConfirmationDetail{DistributionID: distID, Zone: r.zone, Source: from, Status: "ok"}
	change(d)
	r.zdr.ProcessConfirmation(d, nil)
}

func (r *delRig) tracked(t *testing.T, rr dns.RR) *TrackedRR {
	t.Helper()
	tr := r.zdr.trackedRR(r.zone, r.self, dns.TypeNS, rr.String())
	if tr == nil {
		t.Fatalf("%s is not tracked", rr)
	}
	return tr
}

// held: the agent's data holds rr, and so what it sends next (a REPLACE from
// `addrr` or `delrr`, a resync, a catch-up answer) names it.
func (r *delRig) held(rr dns.RR) bool {
	ar, ok := r.zdr.Get(r.zone)
	if !ok {
		return false
	}
	nod, ok := ar.Get(r.self)
	if !ok {
		return false
	}
	rrset, ok := nod.RRtypes.Get(dns.TypeNS)
	return ok && slices.ContainsFunc(rrset.RRs, func(o dns.RR) bool { return dns.IsDuplicate(o, rr) })
}

func removedOf(rr dns.RR) func(*ConfirmationDetail) {
	return func(d *ConfirmationDetail) { d.RemovedRecords = []string{rr.String()} }
}

func appliedOf(rrs ...dns.RR) func(*ConfirmationDetail) {
	return func(d *ConfirmationDetail) {
		for _, rr := range rrs {
			d.AppliedRecords = append(d.AppliedRecords, rr.String())
		}
	}
}

// A delete is followed to PENDING_REMOVAL under its distribution, with no
// confirmation from before (#192), and the record is removed only when every
// expected recipient has removed it. What the agent sends from then on does
// not name it.
func TestADeleteIsFollowedUntilEveryRecipientHasRemovedIt(t *testing.T) {
	const zone = "delfollowed.example."
	ns1, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	r := newDelRig(t, zone, roleA, ns1, ns9)
	r.tracked(t, ns9).Confirmations = map[string]RRConfirmation{freezeCombiner: {Status: "accepted"}}
	recipients := []string{freezeCombiner, roleB, roleN}

	r.send(t, "d", recipients, []dns.RR{ns9}, ns1)
	tr := r.tracked(t, ns9)
	if tr.State != RRStatePendingRemoval || tr.DistributionID != "d" {
		t.Fatalf("after the delete: %v under %q, want PENDING_REMOVAL under d", tr.State, tr.DistributionID)
	}
	if !slices.Equal(tr.ExpectedRecipients, recipients) {
		t.Errorf("the delete waits for %v, want %v", tr.ExpectedRecipients, recipients)
	}
	if len(tr.Confirmations) != 0 {
		t.Errorf("the delete starts with the confirmations %v of the add", tr.Confirmations)
	}
	if r.held(ns9) {
		t.Errorf("what the agent sends next still names %s", ns9)
	}
	if s := r.tracked(t, ns1); s.State != RRStateAccepted {
		t.Errorf("the record the delete keeps: %v, want ACCEPTED", s.State)
	}

	r.confirm("d", freezeCombiner, removedOf(ns9))
	r.confirm("d", roleB, removedOf(ns9))
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("with n not answered: %v, want PENDING_REMOVAL", tr.State)
	}
	r.confirm("d", roleN, removedOf(ns9))
	if tr.State != RRStateRemoved {
		t.Errorf("when every recipient has removed it: %v, want REMOVED", tr.State)
	}
}

// The same for the last record of the type: the REPLACE is empty.
func TestADeleteOfTheLastRecordIsFollowed(t *testing.T) {
	const zone = "dellast.example."
	ns9 := nsRR(t, zone, "ns9.provider.example.")
	r := newDelRig(t, zone, roleA, ns9)

	r.send(t, "d", []string{freezeCombiner, roleB}, []dns.RR{ns9})
	tr := r.tracked(t, ns9)
	if tr.State != RRStatePendingRemoval || tr.DistributionID != "d" {
		t.Fatalf("after the delete: %v under %q, want PENDING_REMOVAL under d", tr.State, tr.DistributionID)
	}
	if r.held(ns9) {
		t.Errorf("what the agent sends next still names %s", ns9)
	}
	r.confirm("d", freezeCombiner, removedOf(ns9))
	r.confirm("d", roleB, removedOf(ns9))
	if tr.State != RRStateRemoved {
		t.Errorf("when every recipient has removed it: %v, want REMOVED", tr.State)
	}
}

// A recipient that refuses the delete is seen: the record goes back to
// ACCEPTED, and the reason says the delete was rejected.
func TestARejectedDeleteIsSeen(t *testing.T) {
	const zone = "delrejected.example."
	ns1, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	r := newDelRig(t, zone, roleA, ns1, ns9)

	r.send(t, "d", []string{freezeCombiner, roleB}, []dns.RR{ns9}, ns1)
	r.confirm("d", freezeCombiner, removedOf(ns9))
	r.confirm("d", roleB, func(d *ConfirmationDetail) {
		d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: ns9.String(), Reason: "refused"}}
	})
	tr := r.tracked(t, ns9)
	if tr.State != RRStateAccepted || !strings.Contains(tr.Reason, "delete rejected") {
		t.Errorf("after b rejected the delete: %v (%q), want ACCEPTED, delete rejected", tr.State, tr.Reason)
	}
}

// A later REPLACE of the type (an add of another record) does not bring the
// record back: it is not named, and it stays PENDING_REMOVAL under its own
// delete, whose recipients will not name it again under the add. Their answers
// to the delete still remove it.
func TestALaterReplaceDoesNotBringADeletedRecordBack(t *testing.T) {
	const zone = "delnotback.example."
	ns1, ns2, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns2.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	r := newDelRig(t, zone, roleA, ns1, ns9)
	recipients := []string{freezeCombiner, roleB}

	r.send(t, "d", recipients, []dns.RR{ns9}, ns1)
	r.confirm("d", freezeCombiner, removedOf(ns9))
	r.send(t, "e", recipients, nil, ns1, ns2)
	tr := r.tracked(t, ns9)
	if tr.State != RRStatePendingRemoval || tr.DistributionID != "d" {
		t.Fatalf("after the add: %v under %q, want PENDING_REMOVAL under d", tr.State, tr.DistributionID)
	}
	if r.held(ns9) {
		t.Errorf("after the add, what the agent sends next names %s again", ns9)
	}
	if c := tr.Confirmations[freezeCombiner].Status; c != "removed" {
		t.Errorf("after the add, the combiner's word on the delete reads %q, want removed", c)
	}
	if s := r.tracked(t, ns2); s.State != RRStatePending || s.DistributionID != "e" {
		t.Errorf("the added record: %v under %q, want PENDING under e", s.State, s.DistributionID)
	}

	r.confirm("e", freezeCombiner, appliedOf(ns1, ns2))
	r.confirm("d", roleB, removedOf(ns9))
	if tr.State != RRStateRemoved {
		t.Errorf("when every recipient has removed it: %v, want REMOVED", tr.State)
	}
}

// An add of the record again, while its delete waits, is an add: the record is
// sent, and PENDING under the add.
func TestAnAddAgainWhileADeleteWaitsIsAnAdd(t *testing.T) {
	const zone = "deladdagain.example."
	ns1, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	r := newDelRig(t, zone, roleA, ns1, ns9)
	recipients := []string{freezeCombiner, roleB}

	r.send(t, "d", recipients, []dns.RR{ns9}, ns1)
	r.send(t, "e", recipients, nil, ns1, ns9)
	tr := r.tracked(t, ns9)
	if tr.State != RRStatePending || tr.DistributionID != "e" {
		t.Errorf("after the add again: %v under %q, want PENDING under e", tr.State, tr.DistributionID)
	}
	if !r.held(ns9) {
		t.Errorf("after the add again, what the agent sends next does not name %s", ns9)
	}
}

// A provider is down when the agent deletes its own record: the delete waits
// for it, and settles when the provider loses its vote, with no answer from it
// (#376). An answer from a member with no vote decides nothing, though it names
// the record as applied, as an auditor's does (auditorConfirms).
func TestADeleteWaitsForAStoppedProviderUntilItLosesItsVote(t *testing.T) {
	r := newLostVoteRig(t, "delstopped.reconcile.example.")
	ns1 := nsRR(t, string(r.zone), "ns1.provider.example.")
	d := newDelRig(t, string(r.zone), r.us, ns1, r.rr)
	recipients := []string{freezeCombiner, roleB, roleN}

	r.activate(t, freezeAt(t, 42, "v", "a,b,n", ""))
	d.send(t, "d", recipients, []dns.RR{r.rr}, ns1)
	d.confirm("d", freezeCombiner, removedOf(r.rr))
	d.confirm("d", roleB, removedOf(r.rr))
	r.conf.instrActivated(t.Context(), d.zdr, r.zone)
	tr := d.tracked(t, r.rr)
	if tr.State != RRStatePendingRemoval {
		t.Fatalf("with n down and still voting: %v, want PENDING_REMOVAL", tr.State)
	}

	r.activate(t, freezeAt(t, 43, "w", "a,b", ""))
	r.conf.instrActivated(t.Context(), d.zdr, r.zone)
	if tr.State != RRStateRemoved {
		t.Errorf("when n has lost its vote: %v, want REMOVED", tr.State)
	}

	// n an auditor: its answer names the record as applied
	r.activate(t, freezeAt(t, 44, "x", "a,b", "n"))
	ns8 := nsRR(t, string(r.zone), "ns8.provider.example.")
	d = newDelRig(t, string(r.zone), r.us, ns1, ns8)
	d.send(t, "f", recipients, []dns.RR{ns8}, ns1)
	d.confirm("f", roleN, appliedOf(ns1, ns8))
	d.confirm("f", freezeCombiner, removedOf(ns8))
	d.confirm("f", roleB, removedOf(ns8))
	if tr := d.tracked(t, ns8); tr.State != RRStateRemoved {
		t.Errorf("with n an auditor that named the record as applied: %v, want REMOVED", tr.State)
	}
}

// sendDelete is an explicit delete of rr, as the leader's withdrawal sends
// one: it names the record. Marked under distID.
func (r *delRig) sendDelete(distID string, recipients []string, rr dns.RR) {
	zu := &ZoneUpdate{
		Zone:       r.zone,
		AgentId:    r.self,
		RRsets:     map[uint16]core.RRset{},
		Operations: []core.RROperation{{Operation: "delete", RRtype: "NS", Records: []string{rr.String()}}},
	}
	r.zdr.MarkRRsPending(r.zone, r.self, zu, distID, recipients)
}

// A recipient that holds none of the record drops nothing in a REPLACE without
// it, and names nothing as removed. Its answer in full to the delete, which
// leaves the record out, counts as its removal. The delete waited for it until
// it lost its vote, and for good if no recipient had removed the record.
func TestAnAnswerInFullThatLeavesTheRecordOutRemovesIt(t *testing.T) {
	const zone = "delholdsnone.example."
	ns1, ns2, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns2.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	recipients := []string{freezeCombiner, roleB}
	for _, c := range []struct {
		name      string
		pending   bool // the add of the record still waits for b when it is deleted
		overtaken bool // a later REPLACE reaches b before the delete
		answer    func(*ConfirmationDetail)
	}{
		{"a provider that does not sign: its combiner ignores the type", false, false, func(d *ConfirmationDetail) {
			d.Status, d.IgnoredRecords = "IGNORED", []string{ns1.String()}
		}},
		{"a recipient that never had the record", true, false, appliedOf(ns1)},
		{"the delete sent again, already in place", false, false, appliedOf(ns1)},
		{"the delete overtaken by a later REPLACE", false, true, appliedOf(ns1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newDelRig(t, zone, roleA, ns1)
			if c.pending {
				r.send(t, "a", recipients, nil, ns1, ns9)
				r.confirm("a", freezeCombiner, appliedOf(ns1, ns9))
			} else {
				r.zdr.AddConfirmedRR(r.zone, r.self, ns9)
			}
			r.send(t, "d", recipients, []dns.RR{ns9}, ns1)
			if c.overtaken {
				r.send(t, "e", recipients, nil, ns1, ns2)
			}
			r.confirm("d", freezeCombiner, removedOf(ns9))
			tr := r.tracked(t, ns9)
			if tr.State != RRStatePendingRemoval {
				t.Fatalf("before b answers: %v, want PENDING_REMOVAL", tr.State)
			}
			r.confirm("d", roleB, c.answer)
			if tr.State != RRStateRemoved {
				t.Errorf("after b's answer: %v, want REMOVED", tr.State)
			}
			if s := tr.Confirmations[roleB].Status; s != "removed" {
				t.Errorf("b's answer is recorded as %q, want removed", s)
			}
		})
	}
}

// An answer that may leave out a record its sender still holds says nothing of
// the record, and the delete waits for that recipient as before. So does any
// answer to an explicit delete that leaves the record out.
func TestAnAnswerThatMayLeaveOutAHeldRecordDoesNotRemoveIt(t *testing.T) {
	const zone = "delstillheld.example."
	ns1, ns9 := nsRR(t, zone, "ns1.provider.example."), nsRR(t, zone, "ns9.provider.example.")
	recipients := []string{freezeCombiner, roleB}
	for _, c := range []struct {
		name     string
		explicit bool // an explicit delete, which names the record
		answer   func(*ConfirmationDetail)
	}{
		{"PARTIAL", false, func(d *ConfirmationDetail) { d.Status = "PARTIAL"; appliedOf(ns1)(d) }},
		{"FAILED", false, func(d *ConfirmationDetail) { d.Status = "FAILED" }},
		{"the REPLACE refused", false, func(d *ConfirmationDetail) {
			d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: "(replace NS)", Reason: "replace failed"}}
		}},
		{"a refusal that names only the kept records", false, func(d *ConfirmationDetail) {
			d.Status, d.RejectedItems = "REJECTED", []RejectedItemInfo{{Record: ns1.String(), Reason: "refused"}}
		}},
		{"truncated", false, func(d *ConfirmationDetail) { d.Truncated = true; appliedOf(ns1)(d) }},
		{"at other instructions", false, func(d *ConfirmationDetail) { d.NotYet = true; appliedOf(ns1)(d) }},
		{"the record named as held", false, appliedOf(ns1, ns9)},
		{"the record named as ignored", false, func(d *ConfirmationDetail) {
			d.Status, d.IgnoredRecords = "IGNORED", []string{ns1.String(), ns9.String()}
		}},
		{"an explicit delete", true, appliedOf(ns1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newDelRig(t, zone, roleA, ns1, ns9)
			if c.explicit {
				r.sendDelete("d", recipients, ns9)
			} else {
				r.send(t, "d", recipients, []dns.RR{ns9}, ns1)
			}
			r.confirm("d", freezeCombiner, removedOf(ns9))
			r.confirm("d", roleB, c.answer)
			tr := r.tracked(t, ns9)
			if tr.State != RRStatePendingRemoval {
				t.Errorf("after b's answer: %v, want PENDING_REMOVAL", tr.State)
			}
			if got, ok := tr.Confirmations[roleB]; ok {
				t.Errorf("b's answer is recorded as %q", got.Status)
			}
		})
	}
}

// An answer from a member with no vote does not count as a removal: an
// auditor's answer names only what a REPLACE keeps (auditorConfirms), and such
// a member holds no record's state.
func TestAnAnswerInFullFromAMemberWithNoVoteDoesNotCount(t *testing.T) {
	r := newLostVoteRig(t, "delnovote.reconcile.example.")
	ns1 := nsRR(t, string(r.zone), "ns1.provider.example.")
	d := newDelRig(t, string(r.zone), r.us, ns1, r.rr)

	r.activate(t, freezeAt(t, 42, "v", "a,b", "n"))
	d.send(t, "d", []string{freezeCombiner, roleB, roleN}, []dns.RR{r.rr}, ns1)
	d.confirm("d", roleN, func(c *ConfirmationDetail) { c.Status = "SUCCESS"; appliedOf(ns1)(c) })
	tr := d.tracked(t, r.rr)
	if got, ok := tr.Confirmations[roleN]; ok {
		t.Errorf("the auditor's answer is recorded as %q", got.Status)
	}
	d.confirm("d", freezeCombiner, removedOf(r.rr))
	d.confirm("d", roleB, removedOf(r.rr))
	if tr.State != RRStateRemoved {
		t.Errorf("when every recipient with a vote has removed it: %v, want REMOVED", tr.State)
	}
}
