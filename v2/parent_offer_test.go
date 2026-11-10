/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A parent that publishes no DSYNC, or none with a scheme the child can
// use, is the common case (Johan, 2026-11-09): one warning per zone, no
// ERROR, nothing sent, no retry; a usable scheme that appears later is
// picked up; a real failure on a usable scheme is still an ERROR.

const (
	msgNoScheme      = "delegation sync: the parent offers no scheme this zone can use; nothing is sent to it, and it is looked at again quietly"
	msgStillNoScheme = "delegation sync: the parent still offers no scheme this zone can use"
	msgNowScheme     = "delegation sync: the parent now offers a scheme this zone can use"
	msgNoUpdate      = "delegation sync: the parent offers no UPDATE scheme; the zone's SIG(0) key is not bootstrapped with it"
	msgStillNoUpdate = "delegation sync: the parent still offers no UPDATE scheme"
	msgNothingSent   = "DelegationSyncher: nothing sent"
	msgSyncError     = "DelegationSyncher: error from SyncZoneDelegation"
)

// zonesLog captures the syncher's logger ("zones", where the notices go)
// as JSON, debug lines included, for the rest of the test.
func zonesLog(t *testing.T) *lockedBuffer {
	t.Helper()
	b := &lockedBuffer{}
	logTo(t, lg, slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return b
}

// logLines is the captured lines at the level whose message is msg; level
// "" counts every level, msg "" every message.
func logLines(t *testing.T, b fmt.Stringer, level, msg string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(b.String(), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if (level == "" || rec.Level == level) && (msg == "" || rec.Msg == msg) {
			n++
		}
	}
	return n
}

// waitLines waits until the captured log has at least n such lines.
func waitLines(t *testing.T, b fmt.Stringer, level, msg string, n int) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if logLines(t, b, level, msg) >= n {
			return
		}
	}
	t.Fatalf("the log has %d %s lines %q, want %d\n%s", logLines(t, b, level, msg), level, msg, n, b)
}

// noDsyncRig is the notify rig for a zone whose parent publishes no DSYNC
// at all: the resolver's cache answers both of the discovery's names with
// no data, as a parent without DSYNC does. The parent lacks the DS of the
// zone's KSK, which the signer's key report asks for, so the report and
// each explicit sync after it find something to send.
func noDsyncRig(t *testing.T, zone string) *notifyRig {
	t.Helper()
	r := newNotifyRigWith(t, zone, "", false, func(r *notifyRig) {
		cacheDsync(t, r, "_dsync."+r.mpzd.GetParent())
	}, repeat(30*time.Millisecond, 400)...)
	r.parent.holdsDS()
	r.inventory(r.ksk) // the first sync
	return r
}

// cacheDsync has the rig's resolver answer name's DSYNC query with the
// given records, or with no data when there are none.
func cacheDsync(t *testing.T, r *notifyRig, name string, rdata ...string) {
	t.Helper()
	c := &cache.CachedRRset{Name: name, RRtype: core.TypeDSYNC, Context: cache.ContextNoErrNoAns,
		State: cache.ValidationStateSecure, Ttl: 3600, Expiration: time.Now().Add(time.Hour)}
	if len(rdata) > 0 {
		var rrs []dns.RR
		for _, rd := range rdata {
			rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN DSYNC %s", name, rd))
			if err != nil {
				t.Fatalf("the DSYNC record %q: %v", rd, err)
			}
			rrs = append(rrs, rr)
		}
		c.Context = cache.ContextAnswer
		c.RRset = &core.RRset{Name: name, Class: dns.ClassINET, RRtype: core.TypeDSYNC, RRs: rrs}
	}
	r.conf.Config.Internal.ImrEngine.Cache.Set(name, core.TypeDSYNC, c)
}

// perChildDsyncName is the name the discovery looks for the zone's DSYNC
// under first: <label>._dsync.<parent>.
func perChildDsyncName(r *notifyRig) string {
	return dns.SplitDomainName(r.mpzd.ZoneName)[0] + "._dsync." + r.mpzd.GetParent()
}

// The leader of a multi-provider zone whose parent publishes no DSYNC asks
// for the zone's sync again and again, as elections, refreshes and its
// signer's key reports do. The parent is warned about once; the later asks
// are DEBUG; nothing is logged as an ERROR, nothing goes to the parent, and
// no failure chain is started, so nothing asks again by itself.
func TestAParentWithNoDsyncIsWarnedAboutOnce(t *testing.T) {
	logs := zonesLog(t)
	r := noDsyncRig(t, "nodsync.leader.example.")
	const asks = 5
	waitLines(t, logs, "DEBUG", msgNothingSent, 1)
	for i := 2; i <= asks; i++ {
		r.ask()
		waitLines(t, logs, "DEBUG", msgNothingSent, i)
	}
	if n := logLines(t, logs, "WARN", msgNoScheme); n != 1 {
		t.Errorf("the no-DSYNC warning was logged %d times over %d syncs, want once\n%s", n, asks, logs)
	}
	if n := logLines(t, logs, "DEBUG", msgStillNoScheme); n != asks-1 {
		t.Errorf("%d DEBUG lines for the later syncs, want %d", n, asks-1)
	}
	if n := logLines(t, logs, "ERROR", ""); n != 0 {
		t.Errorf("%d ERROR lines for a parent that publishes no DSYNC\n%s", n, logs)
	}
	if strings.Contains(r.log.String(), "level=ERROR") || strings.Contains(r.log.String(), "the delegation sync failed") {
		t.Errorf("the engine logged a failure for a parent that publishes no DSYNC\n%s", r.log)
	}
	if n := r.chains(); n != 0 {
		t.Errorf("%d failure chains for a parent that publishes no DSYNC, want none", n)
	}
	r.quiet(t, 100*time.Millisecond, "a parent with no DSYNC")
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("the parent got %d UPDATEs, want none", n)
	}
	// What the warning says: the parent, and what was found there.
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, msgNoScheme) && (!strings.Contains(line, `"parent":"leader.example."`) ||
			!strings.Contains(line, "publishes no DSYNC records")) {
			t.Errorf("the warning does not name the parent and what was found: %s", line)
		}
	}
}

// A parent that starts publishing a usable scheme is found by the next
// quiet look (recheckParentOffers): the change is logged at INFO, and the
// sync goes out through the new scheme.
func TestAUsableSchemeThatAppearsLaterIsPickedUp(t *testing.T) {
	logs := zonesLog(t)
	r := noDsyncRig(t, "later.leader.example.")
	waitLines(t, logs, "DEBUG", msgNothingSent, 1)
	hdb := &HsyncDB{KeyDB: r.mpzd.KeyDB}

	// A look while the parent still has nothing: DEBUG, and nothing queued.
	if !r.conf.recheckParentOffersOnce(r.ctx, hdb, r.q) {
		t.Fatal("the look ended early")
	}
	if n := logLines(t, logs, "DEBUG", msgStillNoScheme); n != 1 {
		t.Errorf("%d DEBUG lines for the quiet look, want 1\n%s", n, logs)
	}
	r.quiet(t, 100*time.Millisecond, "while the parent publishes no DSYNC")

	// The parent publishes NOTIFY targets.
	target := fmt.Sprintf("%d dsync.%s", r.parent.port, r.mpzd.GetParent())
	cacheDsync(t, r, perChildDsyncName(r), "CDS NOTIFY "+target, "CSYNC NOTIFY "+target)
	if !r.conf.recheckParentOffersOnce(r.ctx, hdb, r.q) {
		t.Fatal("the look ended early")
	}
	waitLines(t, logs, "INFO", msgNowScheme, 1)
	r.notified(t, "the sync through the scheme that appeared", dns.TypeCDS)
	if n := logLines(t, logs, "WARN", msgNoScheme); n != 1 {
		t.Errorf("the no-DSYNC warning was logged %d times, want once", n)
	}
	if n := logLines(t, logs, "ERROR", ""); n != 0 {
		t.Errorf("%d ERROR lines\n%s", n, logs)
	}
	// Picked up once: a later look has nothing to do for the zone.
	if got := r.conf.InternalMp.parentNotices.rechecked(&r.conf.InternalMp.parentNotices.noScheme); len(got) != 0 {
		t.Errorf("zones still on the quiet look: %v", got)
	}
}

// A parent that offers a usable scheme and fails the sync is a real
// failure, logged as an ERROR as before, and not taken for a parent that
// offers nothing.
func TestARealFailureOnAUsableSchemeIsStillAnError(t *testing.T) {
	failureDelays(t, time.Hour) // one failure, no retry within the test
	logs := zonesLog(t)
	r := updateRig(t, "refused.leader.example.")
	r.parent.holdsNS("ns1."+r.mpzd.ZoneName, r.oldNS) // the parent has a nameserver the zone no longer lists
	r.parent.fails(dns.RcodeNotAuth)
	r.ask()
	waitLines(t, logs, "ERROR", msgSyncError, 1)
	if n := r.parent.updatesSeen(); n == 0 {
		t.Error("the UPDATE did not reach the parent")
	}
	if n := logLines(t, logs, "", msgNoScheme) + logLines(t, logs, "", msgNothingSent); n != 0 {
		t.Errorf("a failed UPDATE was taken for a parent that offers nothing\n%s", logs)
	}
}

// The SIG(0) setup of a zone that is not multi-provider, for a parent that
// advertises no UPDATE target: one warning, no ERROR, and no key bootstrap
// is tried, however often the setup is asked for.
func TestASetupForAParentWithNoUpdateSchemeIsWarnedAboutOnce(t *testing.T) {
	logs := zonesLog(t)
	r := newNotifyRig(t, "noupdate.single.example.", "NOTIFY")
	r.mpzd.Options[tdns.OptMultiProvider] = false
	for i := 1; i <= 3; i++ {
		r.q <- tdns.DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: r.mpzd.ZoneName, ZoneData: r.mpzd.ZoneData}
		if i > 1 {
			waitLines(t, logs, "DEBUG", msgStillNoUpdate, i-1)
		}
	}
	waitLines(t, logs, "DEBUG", msgStillNoUpdate, 2)
	if n := logLines(t, logs, "WARN", msgNoUpdate); n != 1 {
		t.Errorf("the no-UPDATE warning was logged %d times, want once\n%s", n, logs)
	}
	if n := logLines(t, logs, "ERROR", ""); n != 0 {
		t.Errorf("%d ERROR lines\n%s", n, logs)
	}
	if n := r.parent.updatesSeen(); n != 0 {
		t.Errorf("the parent got %d UPDATEs (a bootstrap), want none", n)
	}
	sak, err := r.mpzd.KeyDB.GetSig0Keys(r.mpzd.ZoneName, tdns.Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 0 {
		t.Errorf("%d SIG(0) keys were made for a bootstrap that cannot happen", len(sak.Keys))
	}
}

// offerSequence answers the identity sync's looks at its parent: none
// usable for the first `none` looks, then offer.
func offerSequence(none int, offer parentOffer) (func(ctx context.Context, zd *tdns.ZoneData) (parentOffer, error), *atomic.Int32) {
	var looks atomic.Int32
	return func(ctx context.Context, zd *tdns.ZoneData) (parentOffer, error) {
		if int(looks.Add(1)) <= none {
			return parentOffer{parent: "example.", found: "no usable scheme; all skipped (parent example. publishes no DSYNC records)",
				schemes: "no DSYNC records"}, nil
		}
		return offer, nil
	}, &looks
}

// The identity zone's sync asks nothing of a parent that offers no scheme:
// it warns once, looks again quietly at the recheck pace, and asks for the
// sync when a usable scheme appears, which it logs at INFO.
func TestTheIdentitySyncWaitsQuietlyForAParentScheme(t *testing.T) {
	logs := zonesLog(t)
	pace := identitySyncPace{fast: identitySync.fast, interval: time.Millisecond, max: 8 * time.Millisecond,
		remind: time.Hour, recheck: 2 * time.Millisecond}
	const none = 5
	offer, looks := offerSequence(none, parentOffer{parent: "example.", found: "will try NOTIFY", usable: true, schemes: "NOTIFY"})
	r := newIdentitySyncRigWith(t, "agent.waits.example.", pace, []string{"notify"}, offer)
	req := r.next(t)
	if n := looks.Load(); n != none+1 {
		t.Errorf("the first ask came after %d looks at the parent, want %d", n, none+1)
	}
	req.Response <- tdns.DelegationSyncStatus{InSync: true}
	r.ended(t, "after the parent was in sync")
	if r.asks != 1 {
		t.Errorf("%d asks, want 1: none while the parent offered nothing", r.asks)
	}
	for _, c := range []struct {
		level, msg string
		want       int
	}{
		{"WARN", msgNoScheme, 1},
		{"DEBUG", msgStillNoScheme, none - 1},
		{"INFO", msgNowScheme, 1},
		{"ERROR", "", 0},
	} {
		if n := logLines(t, logs, c.level, c.msg); n != c.want {
			t.Errorf("%d %s lines %q, want %d\n%s", n, c.level, c.msg, c.want, logs)
		}
	}
	if n := logLines(t, &r.log, "ERROR", ""); n != 0 {
		t.Errorf("the identity sync logged %d ERROR lines\n%s", n, r.log.String())
	}
}

// The identity zone's SIG(0) setup is queued only when the parent
// advertises the UPDATE target the bootstrap goes to. A parent with other
// schemes and no UPDATE gets one warning, and the sync goes on through the
// other schemes with no setup.
func TestTheIdentitySetupWaitsForTheParentsUpdateScheme(t *testing.T) {
	pace := identitySyncPace{fast: identitySync.fast, interval: time.Millisecond, max: 8 * time.Millisecond,
		remind: time.Hour, recheck: time.Millisecond}
	for i, tc := range []struct {
		name      string
		update    bool
		wantSetup bool
	}{
		{"the parent offers UPDATE", true, true},
		{"the parent offers API only", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := zonesLog(t)
			offer, _ := offerSequence(0, parentOffer{parent: "example.", found: "will try API", usable: true, update: tc.update, schemes: "API"})
			r := newIdentitySyncRigWith(t, fmt.Sprintf("agent.setup%d.example.", i), pace, []string{"api", "update"}, offer)
			take := func() tdns.DelegationSyncRequest {
				t.Helper()
				select {
				case req := <-r.q:
					return req
				case <-time.After(5 * time.Second):
					t.Fatal("nothing queued")
				}
				return tdns.DelegationSyncRequest{}
			}
			req := take()
			if tc.wantSetup {
				if req.Command != "DELEGATION-SYNC-SETUP" {
					t.Fatalf("first request %q, want the setup", req.Command)
				}
				req = take()
			}
			if req.Command != "EXPLICIT-SYNC-DELEGATION" {
				t.Fatalf("request %q, want the explicit sync", req.Command)
			}
			// refused once: the next round looks at the parent again
			req.Response <- tdns.DelegationSyncStatus{Error: true, ErrorMsg: "the API call failed"}
			req = take()
			if req.Command != "EXPLICIT-SYNC-DELEGATION" {
				t.Fatalf("request %q after a refusal, want the explicit sync again (the setup once at most)", req.Command)
			}
			req.Response <- tdns.DelegationSyncStatus{InSync: true}
			r.ended(t, "after the parent was in sync")
			wantWarn := 1
			if tc.update {
				wantWarn = 0
			}
			if n := logLines(t, logs, "WARN", msgNoUpdate); n != wantWarn {
				t.Errorf("the no-UPDATE warning was logged %d times, want %d\n%s", n, wantWarn, logs)
			}
			if n := logLines(t, logs, "ERROR", ""); n != 0 {
				t.Errorf("%d ERROR lines\n%s", n, logs)
			}
		})
	}
}

// The hourly look reads the notice maps only under the lock: note makes a
// map on a zone's first note, from the syncher or the identity loop, while
// the look may be running. This shows its race only under -race (make
// test-race).
func TestTheQuietLookReadsTheNoticesUnderTheLock(t *testing.T) {
	conf := &Config{Config: &tdns.Config{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := make(chan tdns.DelegationSyncRequest, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200 && ctx.Err() == nil; i++ {
			conf.recheckParentOffersOnce(ctx, nil, q)
		}
	}()
	off := parentOffer{parent: "parent.example.", found: "no DSYNC"}
	for i := 0; i < 50; i++ {
		zone := fmt.Sprintf("child%d.parent.example.", i)
		conf.noteParentOffer(zone, off, false)
		conf.noteUpdateOffer(zone, off, false)
	}
	<-done
	if got := conf.InternalMp.parentNotices.rechecked(&conf.InternalMp.parentNotices.noScheme); len(got) != 0 {
		t.Errorf("zones on the quiet look without asking for it: %v", got)
	}
}
