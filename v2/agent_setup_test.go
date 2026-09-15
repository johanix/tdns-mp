/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// An absent algorithm is the default and not a problem; only a name that is
// set and is not an algorithm is.
func TestKeygenAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		algstr string
		want   uint8
		wantOK bool
	}{
		{"", dns.ED25519, true},
		{"ED25519", dns.ED25519, true},
		{"ecdsap256sha256", dns.ECDSAP256SHA256, true},
		{"NOSUCHALG", dns.ED25519, false},
	} {
		if got, ok := keygenAlgorithm(tc.algstr, dns.ED25519); got != tc.want || ok != tc.wantOK {
			t.Errorf("keygenAlgorithm(%q) = %d, %v; want %d, %v", tc.algstr, got, ok, tc.want, tc.wantOK)
		}
	}
}

const (
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

// installParentSync runs a config file through the tdns steps that produce
// ParentSyncConfig(): the daemon's raw loader, a decode on the yaml tags, the
// fold of the deprecated delegationsync: wrapper and the install. The previous
// blocks are put back when the test ends.
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

// captureAgentLog points lgAgent at a buffer for the rest of the test.
func captureAgentLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	saved := lgAgent
	lgAgent = slog.New(slog.NewJSONHandler(&buf, nil))
	t.Cleanup(func() { lgAgent = saved })
	return &buf
}

// The agent's SIG(0) algorithm comes from the parentsync: block in either
// spelling. It used to be read from agent.update.keygen.algorithm, which no
// config writes, so every start warned and every configured algorithm was
// ignored.
func TestParentSyncKeygenAlgorithm(t *testing.T) {
	logbuf := captureAgentLog(t)
	const warning = `"msg":"unknown keygen algorithm, using default"`

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
			log := logbuf.String()
			if warned := strings.Contains(log, warning); warned != tc.wantWarn {
				t.Errorf("warned = %v, want %v; log: %s", warned, tc.wantWarn, log)
			}
			if tc.wantWarn && !strings.Contains(log, "NOSUCHALG") {
				t.Errorf("the warning does not name the configured value; log: %s", log)
			}
		})
	}
}

// The configured algorithm reaches the key AgentSig0KeyPrep generates and the
// KEY RR it publishes, not only the resolver.
func TestAgentSig0KeyPrepUsesParentSyncAlgorithm(t *testing.T) {
	installParentSync(t, fmt.Sprintf(parentSyncConfig, "ECDSAP256SHA256"))

	const zone = "agent.example."
	name := "dns." + zone
	kdb := newMPTestKeyDB(t)
	kdb.UpdateQ = make(chan tdns.UpdateRequest, 1)
	zd := &tdns.ZoneData{
		ZoneName:  zone,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptParentSync: true},
		KeyDB:     kdb,
	}
	zonetext := fmt.Sprintf("%[1]s 3600 IN SOA ns1.%[1]s hostmaster.%[1]s 1 7200 1800 604800 7200\n"+
		"%[1]s 3600 IN NS ns1.%[1]s\nns1.%[1]s 3600 IN A 192.0.2.1\n", zone)
	if _, _, err := zd.ReadZoneData(zonetext, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	// What the refresh engine does after a first load: publish the snapshot
	// GetOwner reads, which also marks the zone Ready.
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if !zd.Ready {
		t.Fatal("zone not Ready after InstallInitialSnapshot")
	}

	if err := AgentSig0KeyPrep(zd, name, NewHsyncDB(kdb)); err != nil {
		t.Fatalf("AgentSig0KeyPrep: %v", err)
	}

	sak, err := kdb.GetSig0Keys(name, tdns.Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 1 {
		t.Fatalf("%d active SIG(0) keys for %s, want 1", len(sak.Keys), name)
	}
	if got := sak.Keys[0].KeyRR.Algorithm; got != dns.ECDSAP256SHA256 {
		t.Errorf("stored key algorithm = %s, want ECDSAP256SHA256", dns.AlgorithmToString[got])
	}

	select {
	case req := <-kdb.UpdateQ:
		if len(req.Actions) != 1 {
			t.Fatalf("published %d RRs, want the one KEY", len(req.Actions))
		}
		key, ok := req.Actions[0].(*dns.KEY)
		if !ok {
			t.Fatalf("published %T, want *dns.KEY", req.Actions[0])
		}
		if key.Algorithm != dns.ECDSAP256SHA256 {
			t.Errorf("published KEY algorithm = %s, want ECDSAP256SHA256", dns.AlgorithmToString[key.Algorithm])
		}
	default:
		t.Fatal("no KEY publication was queued")
	}
}
