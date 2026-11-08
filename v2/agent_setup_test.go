/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
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

// An identity zone listed in the config may carry the parentsync option,
// which the zone the daemon builds never has. It gets no delegation sync all
// the same (tdns-mp #391): the first load's election passes it by, while a
// zone with the same option that is not the identity elects; and the syncher
// answers every request for it without analysing or sending anything.
func TestAConfigListedIdentityZoneWithParentSyncIsNotSynced(t *testing.T) {
	const zone = "agent.listed-sync.example."
	parentsync := func(name string) *tdns.ZoneData {
		return &tdns.ZoneData{ZoneName: name, Options: map[tdns.ZoneOption]bool{tdns.OptParentSync: true}}
	}

	t.Run("no election at the first load", func(t *testing.T) {
		lem, rec := newRoleLEM(t, zone, time.Minute)
		lem.electAtFirstLoad(parentsync(zone))
		lem.electAtFirstLoad(parentsync("listed-other.example."))
		waitFor(t, "the other zone's leader setup", func() bool { return rec.setups() > 0 })
		if leader, ok := lem.GetLeader(ZoneName(zone)); ok {
			t.Errorf("an election for the identity zone made %q its leader", leader)
		}
		if n := rec.setups(); n != 1 {
			t.Errorf("the leader's setup ran %d times, want once, for the other zone", n)
		}
	})

	t.Run("the syncher sends nothing", func(t *testing.T) {
		conf := &Config{Config: &tdns.Config{}}
		conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: zone})
		q := make(chan tdns.DelegationSyncRequest)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_ = (&HsyncDB{}).DelegationSyncher(ctx, q, nil, conf)
			close(done)
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("the delegation syncher did not stop")
			}
		})
		zd := parentsync(zone)
		for _, cmd := range []string{"DELEGATION-SYNC-SETUP", "SYNC-DELEGATION", "EXPLICIT-SYNC-DELEGATION", "DELEGATION-STATUS"} {
			resp := make(chan tdns.DelegationSyncStatus, 1)
			q <- tdns.DelegationSyncRequest{Command: cmd, ZoneName: zone, ZoneData: zd, Response: resp}
			select {
			case st := <-resp:
				if st.Msg != identityZoneNoSync || st.Error || st.InSync {
					t.Errorf("%s: answered %+v, want %q with no error and not in sync", cmd, st, identityZoneNoSync)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: no answer", cmd)
			}
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
// ParentSyncConfig() reads. The previous blocks are put back when the test
// ends.
func installParentSync(t *testing.T, config string) {
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
}

// captureAgentLog points lgAgent at a buffer for the rest of the test. The
// buffer is locked: a goroutine an earlier test left may write to it (#276).
func captureAgentLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	logTo(t, lgAgent, slog.NewJSONHandler(buf, nil))
	return buf
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
