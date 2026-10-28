/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
)

// hostPrefix decides both the transfer ACL entry for a notify target and
// whether SetupAgentAutoZone accepts the target at all: "" (not an IP literal)
// is refused, since the ACL cannot name a host.
func TestHostPrefix(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"192.0.2.1:53", "192.0.2.1/32"},
		{"192.0.2.1", "192.0.2.1/32"},
		{"[2001:db8::1]:53", "2001:db8::1/128"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"ns.example.:53", ""},
		{"ns.example.", ""},
	} {
		if got := hostPrefix(tc.addr); got != tc.want {
			t.Errorf("hostPrefix(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// The identity zone needs its SIG(0) key only as a parentsync child that may
// reach its parent by UPDATE; the scheme name is matched case-insensitively.
func TestIdentityZoneUsesUpdate(t *testing.T) {
	parentsync := map[tdns.ZoneOption]bool{tdns.OptParentSync: true}
	for _, tc := range []struct {
		name    string
		options map[tdns.ZoneOption]bool
		schemes []string
		want    bool
	}{
		{"parentsync, update", parentsync, []string{"update"}, true},
		{"parentsync, notify and UPDATE", parentsync, []string{"notify", "UPDATE"}, true},
		{"parentsync, notify only", parentsync, []string{"notify"}, false},
		{"parentsync, no schemes", parentsync, nil, false},
		{"no parentsync, update", nil, []string{"update"}, false},
	} {
		zd := &tdns.ZoneData{ZoneName: "agent.example.", Options: tc.options}
		if got := identityZoneUsesUpdate(zd, tc.schemes); got != tc.want {
			t.Errorf("%s: identityZoneUsesUpdate = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// newIdentityTestZone builds a parentsync identity zone the way
// SetupAgentAutoZone does, on a real keystore whose UpdateQ is buffered so the
// records posted for publication can be read back.
func newIdentityTestZone(t *testing.T, name string) (*tdns.ZoneData, *tdns.KeyDB, chan tdns.UpdateRequest) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	q := make(chan tdns.UpdateRequest, 8)
	kdb.UpdateQ = q
	zd, err := kdb.CreateAutoZone(name, nil, []string{"ns1.example."})
	if err != nil {
		t.Fatalf("CreateAutoZone(%s): %v", name, err)
	}
	zd.Options[tdns.OptParentSync] = true
	return zd, kdb, q
}

// publishedKEYs drains q and returns the KEY records posted, by owner name.
func publishedKEYs(q chan tdns.UpdateRequest) map[string][]*dns.KEY {
	out := map[string][]*dns.KEY{}
	for {
		select {
		case ur := <-q:
			for _, rr := range ur.Actions {
				if k, ok := rr.(*dns.KEY); ok {
					out[k.Header().Name] = append(out[k.Header().Name], k)
				}
			}
		default:
			return out
		}
	}
}

// The DSYNC UPDATE scheme signs with the SIG(0) key named after the zone
// (SendDelegationUpdate looks it up under zd.ZoneName), so that is the key
// AgentSig0KeyPrep generates and publishes, at the apex, and not at dns.<zone>.
func TestAgentSig0KeyPrepNamesKeyAfterZone(t *testing.T) {
	zd, kdb, q := newIdentityTestZone(t, "agent.keyname.example.")
	ps := tdns.ParentSyncConf{Schemes: []string{"notify", "update"}}
	ps.Update.Keygen.Algorithm = "ED25519"

	if err := AgentSig0KeyPrep(zd, ps, NewHsyncDB(kdb)); err != nil {
		t.Fatalf("AgentSig0KeyPrep: %v", err)
	}

	sak, err := kdb.GetSig0Keys(zd.ZoneName, tdns.Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys(%s): %v", zd.ZoneName, err)
	}
	if len(sak.Keys) != 1 {
		t.Fatalf("active SIG(0) keys for %s = %d, want 1", zd.ZoneName, len(sak.Keys))
	}
	if got := sak.Keys[0].KeyRR.Algorithm; got != dns.ED25519 {
		t.Errorf("key algorithm = %d, want ED25519 (%d)", got, dns.ED25519)
	}
	host := "dns." + zd.ZoneName
	if hsak, err := kdb.GetSig0Keys(host, tdns.Sig0StateActive); err != nil {
		t.Fatalf("GetSig0Keys(%s): %v", host, err)
	} else if len(hsak.Keys) != 0 {
		t.Errorf("active SIG(0) keys for %s = %d, want 0", host, len(hsak.Keys))
	}

	published := publishedKEYs(q)
	if len(published[zd.ZoneName]) != 1 {
		t.Fatalf("KEY RRs posted at %s = %d, want 1", zd.ZoneName, len(published[zd.ZoneName]))
	}
	if got, want := published[zd.ZoneName][0].KeyTag(), sak.Keys[0].KeyRR.KeyTag(); got != want {
		t.Errorf("published keytag = %d, keystore keytag = %d", got, want)
	}
	if n := len(published[host]); n != 0 {
		t.Errorf("KEY RRs posted at %s = %d, want 0", host, n)
	}
}

// Without UPDATE among the schemes nothing is ever signed with the key, so none
// is generated or published.
func TestAgentSig0KeyPrepSkipsWithoutUpdate(t *testing.T) {
	zd, kdb, q := newIdentityTestZone(t, "agent.notifyonly.example.")
	ps := tdns.ParentSyncConf{Schemes: []string{"notify"}}

	if err := AgentSig0KeyPrep(zd, ps, NewHsyncDB(kdb)); err != nil {
		t.Fatalf("AgentSig0KeyPrep: %v", err)
	}
	sak, err := kdb.GetSig0Keys(zd.ZoneName, tdns.Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys(%s): %v", zd.ZoneName, err)
	}
	if len(sak.Keys) != 0 {
		t.Errorf("active SIG(0) keys for %s = %d, want 0", zd.ZoneName, len(sak.Keys))
	}
	if published := publishedKEYs(q); len(published) != 0 {
		t.Errorf("KEY RRs posted = %v, want none", published)
	}
}

// With UPDATE among the schemes, syncIdentityDelegation first prepares the
// zone's SIG(0) key and only then queues the SIG(0) setup (the bootstrap with
// the parent) ahead of the first explicit sync, because tdns does not queue the
// setup for an identity zone. The syncher is already running when the identity
// zone is set up, so a key prepared anywhere else could race the setup into a
// second key. Without UPDATE there is no key and the first request is the sync.
func TestSyncIdentityDelegationQueuesSetupFirst(t *testing.T) {
	for _, tc := range []struct {
		name      string
		zone      string
		schemes   []string
		wantSetup bool
	}{
		{"notify and update", "agent.syncupdate.example.", []string{"notify", "update"}, true},
		{"notify only", "agent.syncnotify.example.", []string{"notify"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &Config{Config: &tdns.Config{}}
			q := make(chan tdns.DelegationSyncRequest, 4)
			conf.Config.Internal.DelegationSyncQ = q
			conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
			conf.Config.Internal.ImrReady.Publish()
			conf.Config.ParentSync.Schemes = tc.schemes
			zd, kdb, _ := newIdentityTestZone(t, tc.zone)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				conf.syncIdentityDelegation(ctx, zd)
				close(done)
			}()

			next := func() tdns.DelegationSyncRequest {
				t.Helper()
				select {
				case r := <-q:
					return r
				case <-time.After(5 * time.Second):
					t.Fatal("no delegation sync request queued")
					return tdns.DelegationSyncRequest{}
				}
			}

			r := next()
			// The key is already in the keystore when the first request arrives:
			// prepared before anything was queued, so the setup finds it.
			sak, err := kdb.GetSig0Keys(zd.ZoneName, tdns.Sig0StateActive)
			if err != nil {
				t.Fatalf("GetSig0Keys(%s): %v", zd.ZoneName, err)
			}
			wantKeys := 0
			if tc.wantSetup {
				wantKeys = 1
			}
			if len(sak.Keys) != wantKeys {
				t.Fatalf("active SIG(0) keys for %s when the first request arrived = %d, want %d", zd.ZoneName, len(sak.Keys), wantKeys)
			}
			if tc.wantSetup {
				if r.Command != "DELEGATION-SYNC-SETUP" || r.ZoneData != zd || r.ZoneName != zd.ZoneName {
					t.Fatalf("first request = %q for %q, want DELEGATION-SYNC-SETUP for %q", r.Command, r.ZoneName, zd.ZoneName)
				}
				r = next()
			}
			if r.Command != "EXPLICIT-SYNC-DELEGATION" || r.Response == nil {
				t.Fatalf("request = %q (response channel %v), want EXPLICIT-SYNC-DELEGATION with a response channel", r.Command, r.Response != nil)
			}
			r.Response <- tdns.DelegationSyncStatus{InSync: true}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("syncIdentityDelegation did not return after the parent was in sync")
			}
			// The parent is not guessed from the labels: a parent set on the zone
			// is used as the UPDATE zone as it stands, and the name one label up
			// need not be a zone cut. tdns resolves it through the resolver.
			if got := zd.GetParent(); got != "" {
				t.Errorf("parent = %q, want it left unset for tdns to resolve", got)
			}
		})
	}
}

// identitySyncRig runs the real syncIdentityDelegation for a notify-only
// identity zone (no SIG(0) setup: every request is an explicit sync) at the
// given pace, against a fake syncher: the test reads the delegation sync
// queue, which is unbuffered, and answers each ask itself. The agent's log is
// captured with its debug lines, which carry every attempt and the interval
// to the next.
type identitySyncRig struct {
	q      chan tdns.DelegationSyncRequest
	done   chan struct{}
	cancel context.CancelFunc
	log    bytes.Buffer // read once done is closed
	asks   int
}

func newIdentitySyncRig(t *testing.T, zone string, pace identitySyncPace) *identitySyncRig {
	t.Helper()
	r := &identitySyncRig{q: make(chan tdns.DelegationSyncRequest), done: make(chan struct{})}
	savedLog, savedPace := lgAgent, identitySync
	lgAgent = slog.New(slog.NewJSONHandler(&r.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	identitySync = pace
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.DelegationSyncQ = r.q
	conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
	conf.Config.Internal.ImrReady.Publish()
	conf.Config.ParentSync.Schemes = []string{"notify"}
	zd, _, _ := newIdentityTestZone(t, zone)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		conf.syncIdentityDelegation(ctx, zd)
		close(r.done)
	}()
	// The goroutine reads the logger and the pace: they are put back once
	// it has ended.
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("syncIdentityDelegation is still running after its context ended")
		}
		lgAgent, identitySync = savedLog, savedPace
	})
	return r
}

// next is the syncher's next ask. The test ends here if the sync stopped
// asking, or asks for something else than an explicit sync with an answer.
func (r *identitySyncRig) next(t *testing.T) tdns.DelegationSyncRequest {
	t.Helper()
	select {
	case req := <-r.q:
		r.asks++
		if req.Command != "EXPLICIT-SYNC-DELEGATION" || req.Response == nil {
			t.Fatalf("ask %d = %q (response channel %v), want EXPLICIT-SYNC-DELEGATION with a response channel", r.asks, req.Command, req.Response != nil)
		}
		return req
	case <-r.done:
		t.Fatalf("syncIdentityDelegation ended after %d asks with the parent not in sync", r.asks)
	case <-time.After(5 * time.Second):
		t.Fatalf("no ask after the first %d", r.asks)
	}
	return tdns.DelegationSyncRequest{}
}

// refuse answers the next n asks the way a parent that is down, or says no,
// makes both synchers answer: an error with the reason in its text. The
// parent's rcode is not passed on; Rcode stays 0.
func (r *identitySyncRig) refuse(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		r.next(t).Response <- tdns.DelegationSyncStatus{Error: true,
			ErrorMsg: "every available sync scheme failed: UPDATE failed: parent REFUSED the delegation UPDATE"}
	}
}

// ended waits for syncIdentityDelegation to return.
func (r *identitySyncRig) ended(t *testing.T, when string) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("syncIdentityDelegation did not return %s", when)
	}
}

// identitySyncLine is one logged attempt.
type identitySyncLine struct {
	Level   string        `json:"level"`
	Msg     string        `json:"msg"`
	Attempt int           `json:"attempt"`
	Next    time.Duration `json:"next"`
	line    string
}

// says: the line's log message is this one.
func (l identitySyncLine) says(message string) bool {
	return l.Msg == "identity zone: "+message
}

// logged returns the attempts in the captured log, in order.
func (r *identitySyncRig) logged(t *testing.T) []identitySyncLine {
	t.Helper()
	var out []identitySyncLine
	for _, line := range strings.Split(r.log.String(), "\n") {
		if line == "" {
			continue
		}
		l := identitySyncLine{line: line}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if l.Attempt > 0 {
			out = append(out, l)
		}
	}
	return out
}

// A parent that is unreachable, or refuses the DS, for longer than the fast
// attempts used to end the sync for the life of the process: twelve attempts,
// "gave up", and nothing queued another (tdns-mp #74). Now the sync goes on
// past them, at an interval that doubles up to the cap and no further, until
// the analysis says the parent is in sync; and it does not write a warning
// per attempt.
func TestSyncIdentityDelegationKeepsAskingUntilInSync(t *testing.T) {
	// The real number of fast attempts, at a thousandth of the real pace or
	// less: 1 ms between them, then 2, 4 and 8 ms, the cap; a reminder is
	// due after four intervals at the cap.
	pace := identitySyncPace{fast: identitySync.fast, interval: time.Millisecond, max: 8 * time.Millisecond, remind: 32 * time.Millisecond}
	const refusals = 30
	r := newIdentitySyncRig(t, "agent.keepsasking.example.", pace)
	r.refuse(t, refusals)
	r.next(t).Response <- tdns.DelegationSyncStatus{InSync: true}
	r.ended(t, "after the parent was in sync")
	if r.asks != refusals+1 {
		t.Errorf("%d asks, want one per refusal and the one answered in sync (%d)", r.asks, refusals+1)
	}

	lines := r.logged(t)
	if len(lines) != refusals+1 {
		t.Fatalf("%d attempts in the log, want %d:\n%s", len(lines), refusals+1, r.log.String())
	}
	var warned []int
	for i, l := range lines[:refusals] {
		attempt := i + 1
		want := pace.max
		switch {
		case attempt < pace.fast:
			want = pace.interval
		case attempt == pace.fast:
			want = 2 * pace.interval
		case attempt == pace.fast+1:
			want = 4 * pace.interval
		}
		if l.Attempt != attempt || l.Next != want {
			t.Errorf("log entry %d: attempt %d with %s to the next, want attempt %d and %s", attempt, l.Attempt, l.Next, attempt, want)
		}
		if l.Next > pace.max {
			t.Errorf("attempt %d: %s to the next, over the cap of %s", attempt, l.Next, pace.max)
		}
		switch l.Level {
		case "WARN":
			warned = append(warned, attempt)
		case "DEBUG":
		default:
			t.Errorf("attempt %d is logged at %s: %s", attempt, l.Level, l.line)
		}
	}
	if last := lines[refusals-1]; last.Next != pace.max {
		t.Errorf("after %d refusals the interval is %s, want the cap of %s", refusals, last.Next, pace.max)
	}
	// The first refusal; the last of the fast attempts; then 2+4+8+8+8+8 ms
	// of waiting take it past the 32 ms to the next reminder, at attempt 18,
	// and four intervals of 8 ms to each one after that.
	if fmt.Sprint(warned) != fmt.Sprint([]int{1, pace.fast, 18, 22, 26, 30}) {
		t.Errorf("warnings at attempts %v, want %v: the first refusal, the end of the fast attempts, then one per %s of waiting",
			warned, []int{1, pace.fast, 18, 22, 26, 30}, pace.remind)
	}
	if last := lines[refusals]; last.Level != "INFO" || last.Attempt != refusals+1 || !last.says("delegation in sync with the parent") {
		t.Errorf("the last log entry is %s, want the parent in sync at attempt %d, at info level", last.line, refusals+1)
	}
}

// An answer without an error is a sync the parent accepted. The synchers
// send the scheme's message with it; the sync must not need one to tell an
// acceptance from a refusal, which comes as an error. Either way the first
// one is told at info level, as sent, and no warning is written.
func TestSyncIdentityDelegationTellsAnAcceptedSyncAsSent(t *testing.T) {
	pace := identitySyncPace{fast: identitySync.fast, interval: time.Millisecond, max: 8 * time.Millisecond, remind: time.Hour}
	for i, tc := range []struct {
		name   string
		answer tdns.DelegationSyncStatus
	}{
		{"with the scheme's message", tdns.DelegationSyncStatus{Msg: "SendUpdate(example.) returned rcode NOERROR"}},
		{"with no message", tdns.DelegationSyncStatus{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIdentitySyncRig(t, fmt.Sprintf("agent.accepted%d.example.", i), pace)
			r.next(t).Response <- tc.answer
			r.next(t).Response <- tdns.DelegationSyncStatus{InSync: true}
			r.ended(t, "after the parent was in sync")
			lines := r.logged(t)
			if len(lines) != 2 {
				t.Fatalf("%d attempts in the log, want 2:\n%s", len(lines), r.log.String())
			}
			if l := lines[0]; l.Level != "INFO" || l.Attempt != 1 || !l.says("delegation sent to the parent") {
				t.Errorf("the accepted sync is logged as %s, want \"delegation sent to the parent\" at info level", l.line)
			}
			if l := lines[1]; l.Level != "INFO" || l.Attempt != 2 || !l.says("delegation in sync with the parent") {
				t.Errorf("the second attempt is logged as %s, want the parent in sync at info level", l.line)
			}
		})
	}
}

// The sync runs for as long as the parent disagrees, so it must end with
// its context wherever it is waiting: for the next attempt, for the syncher
// to take its ask, or for the syncher's answer.
func TestSyncIdentityDelegationStopsWhenItsContextEnds(t *testing.T) {
	quick := identitySyncPace{fast: identitySync.fast, interval: time.Millisecond, max: 8 * time.Millisecond, remind: time.Hour}
	hourly := identitySyncPace{fast: identitySync.fast, interval: time.Hour, max: time.Hour, remind: time.Hour}
	for i, tc := range []struct {
		name     string
		pace     identitySyncPace
		refusals int
		then     func(t *testing.T, r *identitySyncRig) // what the syncher does before the context ends
	}{
		{"an hour to the second attempt", hourly, 1, nil},
		{"past the fast attempts, between two asks", quick, quick.fast + 1, nil},
		{"past the fast attempts, the syncher takes no ask", quick, quick.fast + 1,
			func(t *testing.T, r *identitySyncRig) { time.Sleep(50 * time.Millisecond) }},
		{"past the fast attempts, the syncher gives no answer", quick, quick.fast + 1,
			func(t *testing.T, r *identitySyncRig) { r.next(t) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newIdentitySyncRig(t, fmt.Sprintf("agent.stops%d.example.", i), tc.pace)
			r.refuse(t, tc.refusals)
			if tc.then != nil {
				tc.then(t, r)
			}
			r.cancel()
			r.ended(t, "when its context ended")
			for _, l := range r.logged(t) {
				if l.Level == "INFO" {
					t.Errorf("the sync logged %s; the parent never was in sync, and nothing was accepted", l.line)
				}
			}
		})
	}
}

// The identity zone becomes a parentsync child only when a scheme is configured
// and the resolver is running: without it the parent and its DSYNC records
// cannot be found, and the sync would wait for a readiness that never comes.
func TestIdentityZoneParentSync(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name    string
		schemes []string
		active  *bool
		want    bool
	}{
		{"schemes, imrengine active by default", []string{"notify"}, nil, true},
		{"schemes, imrengine active", []string{"update"}, &on, true},
		{"schemes, imrengine off", []string{"update"}, &off, false},
		{"no schemes", nil, &on, false},
	} {
		conf := &Config{Config: &tdns.Config{}}
		conf.Config.ParentSync.Schemes = tc.schemes
		conf.Config.Imr.Active = tc.active
		if got := conf.identityZoneParentSync(); got != tc.want {
			t.Errorf("%s: identityZoneParentSync = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// configListedIdentityZone is an agent whose identity zone is listed in the
// config: registered by the config parser, not loaded yet, and named among
// the configured zones SetupAgent is handed.
func configListedIdentityZone(t *testing.T, zone string) (*Config, *tdns.ZoneData) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.InternalMp.IdentityReady = newIdentityReadiness()
	mp := &MultiProviderConf{Role: "agent", Identity: zone, SupportedMechanisms: []string{"dns"}}
	mp.Dns.Addresses.Listen = []string{"127.0.0.1:5300"}
	conf.SetMpConfig(mp)
	zd := &tdns.ZoneData{
		ZoneName:  zone,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{},
		KeyDB:     kdb,
	}
	tdns.Zones.Set(zone, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(zone)
		Zones.Invalidate(zone)
	})
	return conf, zd
}

// notSyncedWarnings is the warnings in a captured agent log that tell the
// operator a config-listed identity zone is not synced with its parent.
func notSyncedWarnings(t *testing.T, logs fmt.Stringer, zone string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
			Zone  string `json:"zone"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec.Msg != configIdentityZoneNotSynced {
			continue
		}
		if rec.Level != "WARN" || rec.Zone != zone {
			t.Errorf("the warning was logged at level %s for zone %q, want WARN for %q", rec.Level, rec.Zone, zone)
		}
		n++
	}
	return n
}

// tdns-mp #73: only the identity zone the daemon builds becomes a parentsync
// child. One listed in the config does not, and with a parentsync: block
// configured that used to pass in silence: no CDS, no DS at the parent, and a
// TLSA no validating peer trusts. Now the set-up says so, once, in the log
// only, under the condition that makes a daemon-built zone a parentsync
// child, and under no other. The daemon starts all the same.
func TestAConfigListedIdentityZoneIsWarnedAbout(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name    string
		zone    string
		schemes []string
		imr     *bool
		want    bool
	}{
		{"parentsync configured", "agent.listed-sync.example.", []string{"notify", "update"}, nil, true},
		{"no parentsync", "agent.listed-plain.example.", nil, nil, false},
		// A daemon-built zone would not be synced here either.
		{"parentsync without the resolver", "agent.listed-noimr.example.", []string{"notify", "update"}, &off, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, zd := configListedIdentityZone(t, tc.zone)
			conf.Config.ParentSync.Schemes = tc.schemes
			conf.Config.Imr.Active = tc.imr
			logs := captureAgentLog(t)

			if err := conf.SetupAgent(context.Background(), []string{tc.zone}); err != nil {
				t.Fatalf("SetupAgent: %v", err)
			}

			want := 0
			if tc.want {
				want = 1
			}
			if n := notSyncedWarnings(t, logs, tc.zone); n != want {
				t.Errorf("the warning was logged %d time(s), want %d; log: %s", n, want, logs)
			}
			var onZone []string
			for _, e := range zd.ErrorList() {
				if e.Type != tdns.ConfigWarning {
					t.Errorf("the zone carries a %s: %s", tdns.ErrorTypeToString[e.Type], e.Msg)
					continue
				}
				onZone = append(onZone, e.Msg)
			}
			// The warning is the log's alone: an entry on the zone would keep
			// the operator from bumping its serial by hand.
			if len(onZone) != 0 {
				t.Errorf("the zone's warnings: %q, want none: the warning goes to the log only", onZone)
			}
			if tc.want {
				// What is not done, what that costs, and what to do about it.
				for _, part := range []string{"no CDS", "no DS is sent", "not synced", "TLSA", "daemon builds it", "by hand"} {
					if !strings.Contains(configIdentityZoneNotSynced, part) {
						t.Errorf("the warning does not say %q: %s", part, configIdentityZoneNotSynced)
					}
				}
			}

			// A warning and nothing else: the zone is still served, it has not
			// been made a parentsync child behind the operator's back, and its
			// first-load callbacks are in place as before.
			if zd.HasServiceImpactingError() {
				t.Errorf("the zone is taken out of service: %v", zd.ErrorList())
			}
			if zd.Options[tdns.OptParentSync] {
				t.Error("the config-listed zone was given the parentsync option")
			}
			if zdp, ok := Zones.Get(tc.zone); !ok || len(zdp.OnFirstLoad) == 0 {
				t.Error("no first-load callback registered on the config-listed identity zone")
			}
		})
	}

	// The zone the daemon builds is the supported path: it becomes the
	// parentsync child, and there is nothing to warn about.
	t.Run("built by the daemon", func(t *testing.T) {
		kdb := newMPTestKeyDB(t)
		conf, _ := identityTestConfig(t, kdb)
		ctx := startIdentityUpdater(t, kdb)
		conf.Config.ParentSync.Schemes = []string{"notify", "update"}
		// The resolver is active and never ready: the delegation sync waits
		// for it and stops with the test.
		conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
		conf.Config.Internal.DelegationSyncQ = make(chan tdns.DelegationSyncRequest, 8)
		logs := captureAgentLog(t)

		if err := conf.SetupAgent(ctx, nil); err != nil {
			t.Fatalf("SetupAgent: %v", err)
		}
		zd, ok := tdns.Zones.Get(identityTestZone)
		if !ok {
			t.Fatal("the identity zone is not registered")
		}
		if !zd.Options[tdns.OptParentSync] {
			t.Error("the daemon-built identity zone is not a parentsync child")
		}
		if n := notSyncedWarnings(t, logs, identityTestZone); n != 0 {
			t.Errorf("the warning was logged %d time(s) for a daemon-built zone; log: %s", n, logs)
		}
		if zd.HasError(tdns.ConfigWarning) {
			t.Errorf("the daemon-built zone carries a warning: %v", zd.ErrorList())
		}
	})
}

const (
	keygenWarning = `"msg":"unknown keygen algorithm, using default"`

	// The deprecated spelling, which tdns still accepts: the delegationsync:
	// wrapper, here with keys beside the algorithm that tdns does not model.
	deprecatedParentSyncConfig = `delegationsync:
   leader-election-ttl: 60m
   child:
      schemes:     [ notify, update ]
      update:
         keygen:
            mode:       internal
            algorithm:  %s
`
	parentSyncConfig = `parentsync:
   schemes:     [ notify, update ]
   update:
      keygen:
         algorithm:  %s
`
)

// installParentSync runs a config file through the tdns steps that produce the
// parentsync: block: the daemon's raw loader, a decode on the yaml tags, the
// fold of the deprecated delegationsync: wrapper and the install that
// ParentSyncConfig() reads. It returns the folded block, which the agent hands
// AgentSig0KeyPrep as conf.Config.ParentSync. The previous blocks are put back
// when the test ends.
func installParentSync(t *testing.T, config string) tdns.ParentSyncConf {
	t.Helper()
	prevCS, prevPS := *tdns.ChildSyncConfig(), *tdns.ParentSyncConfig()
	t.Cleanup(func() { _ = tdns.SetDelegationSyncConfig(prevCS, prevPS) })

	file := filepath.Join(t.TempDir(), "tdns-mpagent.yaml")
	if err := os.WriteFile(file, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	raw, _, err := tdns.LoadRawConfigMap(file)
	if err != nil {
		t.Fatalf("LoadRawConfigMap: %v", err)
	}
	conf := &tdns.Config{}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "yaml", Result: conf})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	if err := dec.Decode(raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := conf.FoldDeprecatedDelegationSync(); err != nil {
		t.Fatalf("FoldDeprecatedDelegationSync: %v", err)
	}
	if err := tdns.SetDelegationSyncConfig(conf.ChildSync, conf.ParentSync); err != nil {
		t.Fatalf("SetDelegationSyncConfig: %v", err)
	}
	return conf.ParentSync
}

// captureAgentLog points lgAgent at a buffer for the rest of the test.
func captureAgentLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	saved := lgAgent
	lgAgent = slog.New(slog.NewJSONHandler(&buf, nil))
	t.Cleanup(func() { lgAgent = saved })
	return &buf
}

// An absent algorithm is the default and not a problem; only a name that is
// set and is not an algorithm is, and the warning names it.
func TestKeygenAlgorithm(t *testing.T) {
	logbuf := captureAgentLog(t)
	for _, tc := range []struct {
		algstr   string
		want     uint8
		wantWarn bool
	}{
		{"", dns.ED25519, false},
		{"ED25519", dns.ED25519, false},
		{"ecdsap256sha256", dns.ECDSAP256SHA256, false},
		{"NOSUCHALG", dns.ED25519, true},
	} {
		logbuf.Reset()
		if got := keygenAlgorithm(tc.algstr, dns.ED25519); got != tc.want {
			t.Errorf("keygenAlgorithm(%q) = %s, want %s", tc.algstr, dns.AlgorithmToString[got], dns.AlgorithmToString[tc.want])
		}
		log := logbuf.String()
		if warned := strings.Contains(log, keygenWarning); warned != tc.wantWarn {
			t.Errorf("keygenAlgorithm(%q): warned = %v, want %v; log: %s", tc.algstr, warned, tc.wantWarn, log)
		}
		if tc.wantWarn && !strings.Contains(log, tc.algstr) {
			t.Errorf("keygenAlgorithm(%q): the warning does not name the value; log: %s", tc.algstr, log)
		}
	}
}

// Leader election generates a zone's SIG(0) key where no ParentSyncConf is in
// hand, and takes the algorithm from the installed parentsync: block in either
// spelling. It used to read the viper key
// delegationsync.child.update.keygen.algorithm, which a parentsync: block never
// sets.
func TestParentSyncKeygenAlgorithm(t *testing.T) {
	logbuf := captureAgentLog(t)

	for _, tc := range []struct {
		name     string
		config   string
		want     uint8
		wantWarn bool
	}{
		{"algorithm not set", "parentsync:\n   schemes: [ update ]\n", dns.ED25519, false},
		{"parentsync", fmt.Sprintf(parentSyncConfig, "ECDSAP256SHA256"), dns.ECDSAP256SHA256, false},
		{"deprecated delegationsync.child", fmt.Sprintf(deprecatedParentSyncConfig, "ECDSAP384SHA384"), dns.ECDSAP384SHA384, false},
		{"not an algorithm", fmt.Sprintf(parentSyncConfig, "NOSUCHALG"), dns.ED25519, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installParentSync(t, tc.config)
			logbuf.Reset()

			if got := parentSyncKeygenAlgorithm(); got != tc.want {
				t.Errorf("algorithm = %s, want %s", dns.AlgorithmToString[got], dns.AlgorithmToString[tc.want])
			}
			if warned := strings.Contains(logbuf.String(), keygenWarning); warned != tc.wantWarn {
				t.Errorf("warned = %v, want %v; log: %s", warned, tc.wantWarn, logbuf.String())
			}
		})
	}
}

// The configured algorithm, in either spelling, is the algorithm of the key
// AgentSig0KeyPrep generates and of the KEY it publishes. ED25519 is also the
// default, so the cases use other algorithms.
func TestAgentSig0KeyPrepUsesParentSyncAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		zone   string
		config string
		want   uint8
	}{
		{"parentsync", "agent.keygen-parentsync.example.", fmt.Sprintf(parentSyncConfig, "ECDSAP256SHA256"), dns.ECDSAP256SHA256},
		{"deprecated delegationsync.child", "agent.keygen-delegationsync.example.", fmt.Sprintf(deprecatedParentSyncConfig, "ECDSAP384SHA384"), dns.ECDSAP384SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps := installParentSync(t, tc.config)
			zd, kdb, q := newIdentityTestZone(t, tc.zone)

			if err := AgentSig0KeyPrep(zd, ps, NewHsyncDB(kdb)); err != nil {
				t.Fatalf("AgentSig0KeyPrep: %v", err)
			}

			sak, err := kdb.GetSig0Keys(zd.ZoneName, tdns.Sig0StateActive)
			if err != nil {
				t.Fatalf("GetSig0Keys(%s): %v", zd.ZoneName, err)
			}
			if len(sak.Keys) != 1 {
				t.Fatalf("active SIG(0) keys for %s = %d, want 1", zd.ZoneName, len(sak.Keys))
			}
			if got := sak.Keys[0].KeyRR.Algorithm; got != tc.want {
				t.Errorf("stored key algorithm = %s, want %s", dns.AlgorithmToString[got], dns.AlgorithmToString[tc.want])
			}
			keys := publishedKEYs(q)[zd.ZoneName]
			if len(keys) != 1 {
				t.Fatalf("KEY RRs posted at %s = %d, want 1", zd.ZoneName, len(keys))
			}
			if got := keys[0].Algorithm; got != tc.want {
				t.Errorf("published KEY algorithm = %s, want %s", dns.AlgorithmToString[got], dns.AlgorithmToString[tc.want])
			}
		})
	}
}
