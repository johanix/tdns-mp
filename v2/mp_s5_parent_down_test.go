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
	saved := lg
	lg = slog.New(slog.NewTextHandler(zlog, nil))
	t.Cleanup(func() { lg = saved })
	h := newHoldRig(t, "down.parent.example.", "UPDATE", false, repeat(time.Hour, 4)...)
	z := h.mpzd.ZoneName
	// the zone's SIG(0) key, so that nothing but the parent holds the sync
	if _, err := h.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
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
