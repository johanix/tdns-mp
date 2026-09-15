/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"bytes"
	"context"
	"fmt"
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
