package tdnsmp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// S5c (design §6; transition table O7, E13, T18): a KSK's promotion waits
// for the parent. The driver on one provider with the fake wire and the fake
// clock, as the T3.4 scenarios run.

// bootstrapKSK: a fresh owned zone gets its active KSK and ZSK through the
// machine, against a parent that serves no DS (O2: promoted at once).
func bootstrapKSK(t *testing.T, r *driverRig) (uint16, uint16) {
	t.Helper()
	r.tick("mint")
	for _, k := range append(r.keysIn(KeyStateMpdist, "KSK"), r.keysIn(KeyStateMpdist, "ZSK")...) {
		if _, _, err := r.l.Confirm(k, "p2", "applied", ""); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("propagated")
	ksk, zsk := r.keysIn(KeyStateActive, "KSK"), r.keysIn(KeyStateActive, "ZSK")
	if len(ksk) != 1 || len(zsk) != 1 {
		t.Fatalf("after the bootstrap %d active KSKs and %d active ZSKs, want one each", len(ksk), len(zsk))
	}
	return ksk[0], zsk[0]
}

// rollToStandby: a KSK rollover requested, its key minted, confirmed and
// propagated to standby, with the parent serving the old key's DS only.
func rollToStandby(t *testing.T, r *driverRig, old uint16) uint16 {
	t.Helper()
	r.wire.parentDS[old] = true
	r.l.RequestRollover("KSK")
	r.tick("roll requested")
	pend := r.keysIn(KeyStateMpdist, "KSK")
	if len(pend) != 1 {
		t.Fatalf("after the request %d KSKs in mpdist, want the one minted for the roll", len(pend))
	}
	if _, _, err := r.l.Confirm(pend[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new key propagated")
	if st := r.state(pend[0]); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with its DS not at the parent, want standby (O7)", st)
	}
	return pend[0]
}

func TestAKSKIsPromotedOnceTheParentHasServedItsDSForTheTTL(t *testing.T) {
	r := newDriverRig(t, "wait.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	// the parent gets the new DS: seen on this tick and noted (E13, T18),
	// the promotion still waits for the DS TTL
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s the tick its DS was first seen, want standby for the DS TTL (O7)", st)
	}
	if _, ok := r.l.dsPresent[b]; !ok {
		t.Fatal("the parent's DS was not noted for the new KSK (T18)")
	}
	r.clock.Advance(30 * time.Minute)
	r.tick("half the DS TTL")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s after half the DS TTL, want standby", st)
	}
	r.clock.Advance(31 * time.Minute)
	r.tick("the DS TTL passed")
	if st, c := r.state(b), r.cols(b); st != KeyStateActive || c != "111" {
		t.Errorf("the new KSK is %s (%s) after the DS TTL, want active (111)", st, c)
	}
	if st := r.state(old); st != KeyStateRetired {
		t.Errorf("the old KSK is %s, want retired (T10 in the same step)", st)
	}
	if _, ok := r.l.dsPresent[b]; ok {
		t.Error("the parent's DS note outlived the promotion")
	}
	r.check("after the roll")
}

func TestAKSKWaitsWhileTheParentIsUnknown(t *testing.T) {
	r := newDriverRig(t, "unknown.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	// the parent serves the new DS, noted; then it cannot be asked any
	// more: not "no DS", and not the TTL having passed either, however old
	// the note. The key waits (E7's rule, O7).
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	if _, ok := r.l.dsPresent[b]; !ok {
		t.Fatal("the parent's DS was not noted")
	}
	r.wire.parentOff = true
	r.clock.Advance(2 * time.Hour)
	r.tick("the resolver is down")
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with the parent unknown, want standby (O7: unknown is not no DS, nor the TTL passed)", st)
	}
	if _, ok := r.l.dsPresent[b]; !ok {
		t.Fatal("the note was lost while the parent was unknown; an unknown answer is not the DS going away")
	}
	r.wire.parentOff = false
	r.tick("the resolver is back and the parent serves the DS")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s once the parent answers again, its DS served for longer than the TTL, want active", st)
	}
}

// S1 of the review: the signer's own lookup must hand the driver a parent
// that serves no DS as known and empty (O2), and only a lookup that fails
// as unknown (O7). tdns's RRset fetcher turns a NODATA into an error, so
// the answer is read here.
func TestTheSignerReadsTheParentsAnswerForTheDriver(t *testing.T) {
	ds := func(tag uint16, ttl uint32) dns.RR {
		return &dns.DS{Hdr: dns.RR_Header{Name: "child.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: ttl}, KeyTag: tag, Algorithm: dns.ED25519, DigestType: dns.SHA256, Digest: "00"}
	}
	served, ttl, known := parentDSFromAnswer(&core.RRset{RRs: []dns.RR{ds(1, 3600), ds(2, 300)}}, dns.RcodeSuccess, nil)
	if !known || !served[1] || !served[2] || len(served) != 2 || ttl != 300*time.Second {
		t.Errorf("two DS: served %v ttl %s known %v, want both, the shortest TTL, known", served, ttl, known)
	}
	if served, _, known := parentDSFromAnswer(nil, dns.RcodeSuccess, nil); !known || len(served) != 0 {
		t.Errorf("NODATA: served %v known %v, want known and empty (O2)", served, known)
	}
	if served, _, known := parentDSFromAnswer(&core.RRset{}, dns.RcodeSuccess, nil); !known || len(served) != 0 {
		t.Errorf("an empty RRset: served %v known %v, want known and empty", served, known)
	}
	if served, _, known := parentDSFromAnswer(nil, dns.RcodeNameError, nil); !known || len(served) != 0 {
		t.Errorf("NXDOMAIN: served %v known %v, want known and empty", served, known)
	}
	if _, _, known := parentDSFromAnswer(nil, dns.RcodeServerFailure, nil); known {
		t.Error("SERVFAIL read as known")
	}
	if _, _, known := parentDSFromAnswer(nil, dns.RcodeSuccess, errors.New("timeout")); known {
		t.Error("a failed lookup read as known")
	}
}

func TestADSThatGoesAwayAgainStartsTheWaitAfresh(t *testing.T) {
	r := newDriverRig(t, "flap.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	r.clock.Advance(50 * time.Minute)
	delete(r.wire.parentDS, b)
	r.tick("the parent dropped the new DS")
	if _, ok := r.l.dsPresent[b]; ok {
		t.Fatal("the parent's DS note survived the DS going away")
	}
	r.wire.parentDS[b] = true
	r.tick("the parent serves it again")
	r.clock.Advance(20 * time.Minute)
	r.tick("70 minutes after the first sighting, 20 after the second")
	if st := r.state(b); st != KeyStateStandby {
		t.Errorf("the new KSK is %s 20 minutes after its DS came back, want standby: the wait started afresh", st)
	}
	r.clock.Advance(41 * time.Minute)
	r.tick("the DS TTL since the second sighting passed")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s after the DS TTL since the second sighting, want active", st)
	}
}

func TestTheParentWaitSurvivesARestart(t *testing.T) {
	r := newDriverRig(t, "restart.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	since := r.l.dsPresent[b].Since
	// the process restarts (T15): a new driver on the same store reads the
	// note back, and the wait runs from the first sighting, not from now
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatal(err)
	}
	// the note is kept at second precision
	if got, ok := r.l.dsPresent[b]; !ok || got.Since.Unix() != since.Unix() || got.TTL != time.Hour {
		t.Fatalf("after the restart the note is %+v (found %v), want since %s ttl 1h", got, ok, since.UTC().Format(time.RFC3339))
	}
	// the rollover request itself is not persisted (a request made before a
	// restart is forgotten; seen here, not S5c's), so the operator asks
	// again; the note makes the promotion come at once, the TTL having
	// passed since the first sighting, where without it another TTL would
	// pass first
	r.clock.Advance(61 * time.Minute)
	r.l.RequestRollover("KSK")
	r.tick("the DS TTL passed, counted from before the restart")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s after the restart and the DS TTL, want active", st)
	}
	if st := r.state(old); st != KeyStateRetired {
		t.Errorf("the old KSK is %s, want retired", st)
	}
}

// CodeRabbit on #96: a persisted note whose time cannot be read must not
// come back as a note with the zero time, which parentDSWaitMet never
// takes as met; it is dropped, and the next sighting notes the DS afresh.
func TestAnUnreadableParentDSNoteIsDroppedAtARestart(t *testing.T) {
	r := newDriverRig(t, "unreadable.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	r.wire.parentDS[b] = true
	r.tick("the parent serves the new DS")
	if _, ok := r.l.dsPresent[b]; !ok {
		t.Fatal("no note of the parent's DS")
	}
	if _, err := r.kdb.DB.Exec(`UPDATE MPParentDS SET since='' WHERE zonename=? AND keyid=?`, r.l.Zone, int(b)); err != nil {
		t.Fatal(err)
	}
	r.l = NewZoneKeyLifecycle(r.l.Zone, r.kdb, r.clock, driverPolicy, r.wire)
	if err := r.l.Reload(); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.l.dsPresent[b]; ok {
		t.Fatalf("the unreadable note came back as %+v", got)
	}
	var rows int
	if err := r.kdb.DB.QueryRow(`SELECT count(*) FROM MPParentDS WHERE zonename=? AND keyid=?`, r.l.Zone, int(b)).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("the unreadable note is still stored (%d rows, err %v)", rows, err)
	}
	// the DS is still served: the next tick notes it afresh, and the wait
	// runs from now
	r.tick("the parent still serves the DS")
	got, ok := r.l.dsPresent[b]
	if !ok || got.Since.IsZero() || got.TTL != time.Hour {
		t.Fatalf("after the restart the note is %+v (found %v), want a fresh note with ttl 1h", got, ok)
	}
	// the rollover request is not persisted either: asked again after the
	// TTL since the fresh note, the promotion comes
	r.clock.Advance(61 * time.Minute)
	r.l.RequestRollover("KSK")
	r.tick("the DS TTL since the fresh note passed")
	if st := r.state(b); st != KeyStateActive {
		t.Errorf("the new KSK is %s after the DS TTL since the fresh note, want active", st)
	}
}

func TestAKSKWaitingOnTheParentIsReportedAfterThreeMargins(t *testing.T) {
	r := newDriverRig(t, "report.owned.example.", driverPolicy, "p2")
	old, _ := bootstrapKSK(t, r)
	b := rollToStandby(t, r, old)
	before := len(r.wire.reports)
	// the parent never gets the new DS (the leader's sync is broken): the
	// operator hears once after three margins, and the key keeps waiting
	for i := 0; i < 4; i++ {
		r.clock.Advance(driverPolicy.Margin)
		r.tick("waiting")
	}
	if st := r.state(b); st != KeyStateStandby {
		t.Fatalf("the new KSK is %s with its DS never at the parent, want standby", st)
	}
	var waits int
	for _, rep := range r.wire.reports[before:] {
		if strings.Contains(rep, "waits for the parent to serve its DS") {
			waits++
		}
	}
	if waits != 1 {
		t.Errorf("%d reports of the KSK waiting on the parent, want exactly one: %v", waits, r.wire.reports[before:])
	}
}

func TestAZSKRollDoesNotWaitForTheParent(t *testing.T) {
	r := newDriverRig(t, "zsk.owned.example.", driverPolicy, "p2")
	r.wire.parentTTL = time.Hour
	ksk, zsk := bootstrapKSK(t, r)
	r.wire.parentDS[ksk] = true // the parent serves the KSK's DS: not empty
	r.l.RequestRollover("ZSK")
	r.tick("ZSK roll requested")
	pend := r.keysIn(KeyStateMpdist, "ZSK")
	if len(pend) != 1 {
		t.Fatalf("after the request %d ZSKs in mpdist, want one", len(pend))
	}
	if _, _, err := r.l.Confirm(pend[0], "p2", "applied", ""); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(driverPolicy.PropagationDelay + r.wire.ttl + time.Second)
	r.tick("the new ZSK propagated")
	if st := r.state(pend[0]); st != KeyStateActive {
		t.Errorf("the new ZSK is %s, want active: a ZSK has no DS to wait for", st)
	}
	if st := r.state(zsk); st != KeyStateRetired {
		t.Errorf("the old ZSK is %s, want retired", st)
	}
}
