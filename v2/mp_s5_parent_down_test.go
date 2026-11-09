/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// chainFailures is the zone's count of failed syncs in a row.
func chainFailures(conf *Config, zone string) int {
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch := c.zones[zone]; ch != nil {
		return ch.failures
	}
	return 0
}

// A parent whose delegation cannot be analysed (all its servers down): the
// leader's sync is owed, and asked for again at every pass while the zone is
// caught up. That is its retry; a failed analysis is no failed sync, so a
// long outage grows no backoff, and is logged once an hour, not once a try.
// When the parent comes back and the sync then fails at the send (here, as
// in the lab, the sync plan cannot be built: the parent's DSYNC record is
// not served yet), that is failure 1, asked again at the first delay, not
// the delay that a count grown during the outage would give.
func TestAFailedAnalysisIsOwedAndGrowsNoBackoff(t *testing.T) {
	zlog := &lockedBuffer{}
	logTo(t, lg, slog.NewTextHandler(zlog, nil))
	h := newHoldRig(t, "down.parent.example.", "UPDATE", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	// the zone's SIG(0) key, so that nothing but the parent holds the sync
	if _, err := h.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, h.mpzd.KeyDB, z)
	h.parent.holdsNS("ns1."+z, h.oldNS) // a difference for the sync to send
	h.caughtUp()
	h.parent.quiet(true)

	const passes = 6 // more than the failure delays: the old count gave up
	for i := range passes {
		before := h.parent.queriesSeen()
		if i == 0 {
			h.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: h.mpzd.ZoneData}
		} else {
			h.askOwed() // the ticker's pass
		}
		waitUntil(t, "the sync asked the parent", func() bool { return h.parent.queriesSeen() > before })
		h.waitOwed(t, "the failed analysis")
	}
	if n := chainFailures(h.conf, z); n != 0 {
		t.Errorf("%d failed analyses grew the chain's count to %d, want 0", passes, n)
	}
	if n := strings.Count(zlog.String(), "the parent's delegation cannot be analysed"); n != 1 {
		t.Errorf("the failed analysis was logged %d times in %d passes, want once (then hourly)", n, passes)
	}
	if down, since, lastErr := h.tr.parentDownState(ZoneName(z)); !down || since.IsZero() || lastErr == "" {
		t.Errorf("the parent-down note: down %v, since %v, last error %q", down, since, lastErr)
	}

	// The parent answers again, and its DSYNC record is not served yet: the
	// sync plan cannot be built, and the sync fails at the send: failure 1.
	h.parent.quiet(false)
	withdrawDSYNC(t, h)
	h.askOwed()
	waitUntil(t, "the send's failure was counted\n"+h.log.String(), func() bool { return chainFailures(h.conf, z) > 0 })
	if n := chainFailures(h.conf, z); n != 1 {
		t.Errorf("the first send failure after the outage is failure %d, want 1", n)
	}
	if !strings.Contains(h.log.String(), "failure=1 in="+delegationSyncFailureDelays[0].String()) {
		t.Errorf("the send failure is not asked again at the first delay:\n%s", h.log)
	}
	if !strings.Contains(zlog.String(), "the parent's delegation can be analysed again") {
		t.Errorf("no line says the parent answers again:\n%s", zlog)
	}
	if down, _, _ := h.tr.parentDownState(ZoneName(z)); down {
		t.Error("the parent-down note outlived the parent's answer")
	}
}

// The status of a leader whose parent does not answer says since when the
// sync is owed, and why.
func TestTheStatusSaysSinceWhenTheParentIsDown(t *testing.T) {
	r, tr := owedRig(t, "status.down.example.", true)
	z := ZoneName(r.mpzd.ZoneName)
	tr.oweAfterFailedAnalysis(z, errTestParentDown)
	down, since, lastErr := tr.parentDownState(z)
	if !down || lastErr != errTestParentDown.Error() || time.Since(since) > time.Minute {
		t.Fatalf("the note: down %v, since %v, last error %q", down, since, lastErr)
	}
	if logIt, _ := tr.oweAfterFailedAnalysis(z, errTestParentDown); logIt {
		t.Error("a second failure within the hour is logged again")
	}
	tr.clearOwed(z)
	if down, _, _ := tr.parentDownState(z); down {
		t.Error("the note outlived the end of the zone's chain")
	}
}

var errTestParentDown = &testErr{"all of the parent's servers time out"}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

// withdrawDSYNC makes the rig's resolver find no DSYNC record for the zone,
// as a parent whose server has not re-served its zone yet.
func withdrawDSYNC(t *testing.T, h *holdRig) {
	t.Helper()
	zlabels := dns.SplitDomainName(h.mpzd.ZoneName)
	parentZone := dns.Fqdn(strings.Join(zlabels[1:], "."))
	name := zlabels[0] + "._dsync." + parentZone
	imr := h.conf.Config.Internal.ImrEngine
	imr.Cache.Set(name, core.TypeDSYNC, &cache.CachedRRset{Name: name, RRtype: core.TypeDSYNC, Context: cache.ContextNoErrNoAns,
		State: cache.ValidationStateSecure, Ttl: 3600, Expiration: time.Now().Add(time.Hour)})
}

// An analysis that could not read all it asked the parent (here its server
// fails the questions about the glue, or about the DS, while the delegation
// is in step) is a failed one, though it says in sync (#267, the review of
// #378): it does not end the NOTIFY's chain, tell the peers the sync is
// done, or clear the owed mark; it is owed, and the parent noted as down.
// Once the parent answers in full, the owed sync's ask does all three.
func TestAnIncompleteAnalysisIsAFailedOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rrtype uint16
		unread func(zone string) string
	}{
		{"glue", dns.TypeA, func(zone string) string { return "ns1." + zone + " A" }},
		{"ds", dns.TypeDS, func(string) string { return "DS" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHoldRig(t, "unread-"+tc.name+".parent.example.", "NOTIFY", false, repeat(time.Hour, 4)...)
			z := h.mpzd.ZoneName
			h.caughtUp()
			h.parent.holdsDS() // the parent has no DS
			h.inventory(h.ksk) // the DS set changes: the sync goes as a NOTIFY(CDS)
			h.notified(t, "the sync", dns.TypeCDS)
			if sent, _ := h.chainNotified(z); sent == "" {
				t.Fatal("the chain has no NOTIFY out after the sync")
			}

			// the parent installs the DS, and its server fails some questions
			h.parent.holdsDS(h.ds)
			h.parent.failsQuestions(tc.rrtype)
			got := h.explicit(t)
			if want := "no answer for " + tc.unread(z); !got.Error || !strings.Contains(got.ErrorMsg, want) {
				t.Errorf("the answer: error %v %q, want one naming %q", got.Error, got.ErrorMsg, want)
			}
			if !h.owed() {
				t.Error("an incomplete analysis left the sync not owed")
			}
			if sent, _ := h.chainNotified(z); sent == "" {
				t.Error("an incomplete analysis ended the chain's NOTIFY")
			}
			if down, _, _ := h.tr.parentDownState(ZoneName(z)); !down {
				t.Error("an incomplete analysis did not note the parent as down")
			}
			h.untold(t, 200*time.Millisecond, "after an incomplete analysis")

			// the parent answers in full again
			h.parent.failsQuestions()
			h.askOwed()
			h.told(t, "the parent read in full")
			waitUntil(t, "the owed sync was not cleared\n"+h.log.String(), func() bool { return !h.owed() })
			if sent, _ := h.chainNotified(z); sent != "" {
				t.Errorf("the chain still has NOTIFY(%s) out after the parent was read in full and found in step", sent)
			}
		})
	}
}

// By the UPDATE scheme an incomplete analysis sends nothing, though it found
// a difference: the UPDATE would be built from part of the parent's data.
// Once the parent answers in full, the owed sync's ask sends it.
func TestAnIncompleteAnalysisSendsNoUpdate(t *testing.T) {
	h := newHoldRig(t, "unread.update.example.", "UPDATE", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	if _, err := h.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	trustActiveKeys(t, h.mpzd.KeyDB, z)
	h.parent.holdsNS("ns1."+z, h.oldNS) // a difference for the sync to send
	h.caughtUp()
	h.parent.failsQuestions(dns.TypeA)

	got := h.explicit(t)
	if !got.Error || !strings.Contains(got.ErrorMsg, "no answer for ns1."+z+" A") {
		t.Errorf("the answer: error %v %q, want one naming the unread glue", got.Error, got.ErrorMsg)
	}
	if n := h.parent.updatesSeen(); n != 0 {
		t.Errorf("an incomplete analysis sent %d UPDATEs, want none", n)
	}
	if !h.owed() {
		t.Error("an incomplete analysis left the sync not owed")
	}
	h.untold(t, 200*time.Millisecond, "after an incomplete analysis")

	h.parent.failsQuestions()
	h.askOwed()
	h.told(t, "the UPDATE answered")
	if n := h.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one", n)
	}
	waitUntil(t, "the owed sync was not cleared\n"+h.log.String(), func() bool { return !h.owed() })
}
