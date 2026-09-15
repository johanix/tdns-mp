/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
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
