package configure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	core "github.com/johanix/tdns/v2/core"
)

// The generated configs are only worth something if the daemons load
// them. These tests render every template into a temporary tree and run
// the result through the same code the daemons use: tdns's ValidateConfig
// (strict decode, required sections, zone peers and ACLs) and tdns-mp's
// multi-provider parser. On top of that they decode every block into the
// structs that read it and fail on any key those structs do not know --
// the daemon logs such a key and ignores it, so a key that moves shows up
// here as soon as the pin moves past the move. Then they check that what
// one role dials is what another role binds.

// mpOwnedKeys are the top-level blocks tdns-mp parses itself.
var mpOwnedKeys = map[string]bool{"multi-provider": true, "audit": true}

// mpcliRoleNames are the apiservers names tdns-mpcli looks the built-in
// command words up by (v2/cli/roles.go), and the config file each names.
var mpcliRoleNames = map[string]string{
	"tdns-mpagent":    "tdns-mpagent.yaml",
	"tdns-mpsigner":   "tdns-mpsigner.yaml",
	"tdns-mpcombiner": "tdns-mpcombiner.yaml",
	"tdns-mpauditor":  "tdns-mpauditor.yaml",
}

func testLayout(root string) fsLayout {
	return fsLayout{
		ConfigDir:  filepath.Join(root, "etc"),
		ZoneDir:    filepath.Join(root, "etc", "zones"),
		DbDir:      filepath.Join(root, "db"),
		LogDir:     filepath.Join(root, "log"),
		LibexecDir: filepath.Join(root, "libexec"),
	}
}

func testValues(root, internalIP, publicIP string, withAuditor bool) CoordinatedValues {
	cv := CoordinatedValues{
		Global: GlobalValues{
			KeysDir:    filepath.Join(root, "keys"),
			CertsDir:   filepath.Join(root, "certs"),
			PublicIP:   publicIP,
			InternalIP: internalIP,
		},
		Agent: AgentValues{
			Identity:         "agent.alpha.example.",
			ApiKey:           "key-a",
			LocalNameservers: []string{"ns1.alpha.example."},
			LocalNotify:      []string{net.JoinHostPort(publicIP, "53")},
		},
		Signer:   SignerValues{Identity: "signer.alpha.example.", ApiKey: "key-s"},
		Combiner: CombinerValues{Identity: "combiner.alpha.example.", ApiKey: "key-c"},
	}
	if withAuditor {
		cv.Auditor = AuditorValues{Identity: "auditor.alpha.example.", ApiKey: "key-au"}
	}
	return cv
}

// selfSignedPEM returns a throwaway certificate and key; ValidateConfig
// loads the apiserver's pair.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// renderToDisk writes the rendered configs and the material they name:
// JOSE keys (the multi-provider parser checks they exist), a TLS pair per
// role and the example zone file.
func renderToDisk(t *testing.T, cv CoordinatedValues, l fsLayout) map[string]string {
	t.Helper()
	out, err := renderAllIn(cv, l)
	if err != nil {
		t.Fatalf("renderAllIn: %v", err)
	}
	for path, body := range out {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{l.DbDir, l.LogDir, cv.Global.CertsDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := makeRolePaths(cv.Global.KeysDir, cv.Global.CertsDir)
	privs := []string{p.AgentJosePriv, p.SignerJosePriv, p.CombinerJosePriv}
	pairs := [][2]string{{p.AgentCert, p.AgentKey}, {p.SignerCert, p.SignerKey}, {p.CombinerCert, p.CombinerKey}}
	if cv.Auditor.Identity != "" {
		privs = append(privs, p.AuditorJosePriv)
		pairs = append(pairs, [2]string{p.AuditorCert, p.AuditorKey})
	}
	for _, priv := range privs {
		if _, _, _, err := EnsureJoseKeypair(priv); err != nil {
			t.Fatalf("EnsureJoseKeypair(%s): %v", priv, err)
		}
	}
	certPEM, keyPEM := selfSignedPEM(t)
	for _, pair := range pairs {
		if err := os.WriteFile(pair[0], certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pair[1], keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if gen, err := ensureExampleZone(cv, l, io.Discard); err != nil || !gen {
		t.Fatalf("ensureExampleZone: generated=%v err=%v", gen, err)
	}
	return out
}

// decodeKnownKeys decodes one config block into the struct that reads it
// and reports every key the struct does not know.
func decodeKnownKeys(t *testing.T, what string, block interface{}, result interface{}) {
	t.Helper()
	var md mapstructure.Metadata
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:    "yaml",
		Result:     result,
		Metadata:   &md,
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(block); err != nil {
		t.Fatalf("%s: decode: %v", what, err)
	}
	if len(md.Unused) > 0 {
		t.Errorf("%s: keys nothing reads (the daemon would ignore them): %v", what, md.Unused)
	}
}

// checkKnownKeys runs a raw daemon config through decodeKnownKeys: the
// multi-provider block against tdns-mp's struct, the rest against tdns's.
func checkKnownKeys(t *testing.T, name string, raw map[string]interface{}) *tdns.Config {
	t.Helper()
	tdnsOwned := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if !mpOwnedKeys[k] {
			tdnsOwned[k] = v
		}
	}
	conf := &tdns.Config{}
	decodeKnownKeys(t, name, tdnsOwned, conf)
	if block, ok := raw["multi-provider"]; ok {
		decodeKnownKeys(t, name+" multi-provider", block, &tdnsmp.MultiProviderConf{})
	}
	return conf
}

// loadDaemonConfig validates a rendered daemon config the way the daemon
// does and returns what tdns and tdns-mp make of it.
func loadDaemonConfig(t *testing.T, path string) (*tdns.Config, *tdnsmp.MultiProviderConf) {
	t.Helper()
	name := filepath.Base(path)
	if err := tdns.ValidateConfig(nil, path); err != nil {
		t.Fatalf("%s: tdns.ValidateConfig: %v", name, err)
	}
	raw, _, err := tdns.LoadRawConfigMap(path)
	if err != nil {
		t.Fatalf("%s: LoadRawConfigMap: %v", name, err)
	}
	mp, err := tdnsmp.ParseMultiProviderConfig(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if mp == nil {
		t.Fatalf("%s: no multi-provider block", name)
	}
	return checkKnownKeys(t, name, raw), mp
}

// mpcliFile is a tdns-mpcli config, decoded into tdns's own ApiDetails.
type mpcliFile struct {
	Include    []string             `yaml:"include"`
	Apiservers []tdnscli.ApiDetails `yaml:"apiservers"`
	Log        struct {
		File  string `yaml:"file"`
		Level string `yaml:"level"`
	} `yaml:"log"`
}

func decodeMpcli(t *testing.T, name string, body []byte) mpcliFile {
	t.Helper()
	var f mpcliFile
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, e := range f.Apiservers {
		if _, known := mpcliRoleNames[e.Name]; !known && e.Role == "" {
			t.Errorf("%s: apiserver %q is neither a name tdns-mpcli looks up nor an instance with role:", name, e.Name)
		}
	}
	return f
}

// listensOn reports whether conf's listeners bind dial's port on its host,
// or on the wildcard of its address family.
func listensOn(t *testing.T, conf *tdns.Config, dial string) bool {
	t.Helper()
	host, port, err := net.SplitHostPort(dial)
	if err != nil {
		t.Fatalf("not host:port: %q", dial)
	}
	for _, a := range conf.Listeners.Addresses {
		lhost, lport, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatalf("listener not host:port: %q", a)
		}
		if lport != port {
			continue
		}
		wildcard := "0.0.0.0"
		if isIPv6(host) {
			wildcard = "::"
		}
		if lhost == host || lhost == wildcard {
			return true
		}
	}
	return false
}

// zonePeers returns a zone's primaries and notify addresses, taking each
// list from the zone's template when the zone does not set it.
func zonePeers(t *testing.T, conf *tdns.Config, zone string) (primaries, notify []string) {
	t.Helper()
	for _, z := range conf.Zones {
		if z.Name != zone {
			continue
		}
		prim, noti := z.Primaries, z.Notify
		for _, tmpl := range conf.Templates {
			if tmpl.Name != z.Template {
				continue
			}
			if len(prim) == 0 {
				prim = tmpl.Primaries
			}
			if len(noti) == 0 {
				noti = tmpl.Notify
			}
		}
		for _, pc := range prim {
			primaries = append(primaries, pc.Addr)
		}
		for _, pc := range noti {
			notify = append(notify, pc.Addr)
		}
		return primaries, notify
	}
	t.Fatalf("zone %s not configured", zone)
	return nil, nil
}

func checkExampleZone(t *testing.T, cv CoordinatedValues, l fsLayout) {
	t.Helper()
	f, err := os.Open(l.exampleZoneFile())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	labels := map[string]string{} // identity -> HSYNC3 label
	var param string
	zp := dns.NewZoneParser(f, exampleZone, l.exampleZoneFile())
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		prr, isPrivate := rr.(*dns.PrivateRR)
		if !isPrivate {
			continue
		}
		switch d := prr.Data.(type) {
		case *core.HSYNC3:
			labels[d.Identity] = strings.TrimSuffix(d.Label, ".")
		case *core.HSYNCPARAM:
			param = prr.String()
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("example zone: %v", err)
	}
	provider := labels[cv.Agent.Identity]
	if provider == "" {
		t.Fatalf("example zone: no HSYNC3 record names agent %s", cv.Agent.Identity)
	}
	want := []string{`servers="` + provider + `"`, `signers="` + provider + `"`}
	if cv.Auditor.Identity != "" {
		aud := labels[cv.Auditor.Identity]
		if aud == "" {
			t.Fatalf("example zone: no HSYNC3 record names auditor %s", cv.Auditor.Identity)
		}
		want = append(want, `auditors="`+aud+`"`)
	}
	for _, w := range want {
		if !strings.Contains(param, w) {
			t.Errorf("example zone: HSYNCPARAM %q lacks %s", param, w)
		}
	}
}

func checkMpcli(t *testing.T, l fsLayout, out map[string]string, cv CoordinatedValues) {
	t.Helper()
	cli := decodeMpcli(t, "tdns-mpcli.yaml", []byte(out[l.mpcli()]))
	seen := map[string]bool{}
	for _, e := range cli.Apiservers {
		file := mpcliRoleNames[e.Name]
		seen[e.Name] = true
		if filepath.Base(e.ConfigFile) != file {
			t.Errorf("mpcli %s: config-file %q, want .../%s", e.Name, e.ConfigFile, file)
		}
		daemon, rendered := out[e.ConfigFile]
		if !rendered {
			t.Errorf("mpcli %s: config-file %q was not generated", e.Name, e.ConfigFile)
			continue
		}
		u, err := url.Parse(e.BaseURL)
		if err != nil {
			t.Fatalf("mpcli %s: baseurl %q: %v", e.Name, e.BaseURL, err)
		}
		var d struct {
			APIServer struct {
				Addresses []string `yaml:"addresses"`
			} `yaml:"apiserver"`
		}
		if err := yaml.Unmarshal([]byte(daemon), &d); err != nil {
			t.Fatal(err)
		}
		if len(d.APIServer.Addresses) == 0 || d.APIServer.Addresses[0] != u.Host {
			t.Errorf("mpcli %s dials %s; the daemon's apiserver binds %v", e.Name, u.Host, d.APIServer.Addresses)
		}
	}
	if seen["tdns-mpauditor"] != (cv.Auditor.Identity != "") {
		t.Errorf("mpcli tdns-mpauditor entry present=%v, auditor configured=%v", seen["tdns-mpauditor"], cv.Auditor.Identity != "")
	}
}

func TestRenderedConfigsLoad(t *testing.T) {
	for _, tc := range []struct {
		name        string
		internalIP  string
		publicIP    string
		withAuditor bool
	}{
		{"ipv4 with auditor", "127.0.0.1", "203.0.113.5", true},
		{"ipv4 without auditor", "192.0.2.5", "203.0.113.5", false},
		{"ipv6 with auditor", "::1", "2001:db8::5", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			l := testLayout(root)
			cv := testValues(root, tc.internalIP, tc.publicIP, tc.withAuditor)
			out := renderToDisk(t, cv, l)

			if _, rendered := out[l.mpauditor()]; rendered != tc.withAuditor {
				t.Fatalf("auditor config rendered=%v, want %v", rendered, tc.withAuditor)
			}

			agent, agentMP := loadDaemonConfig(t, l.mpagent())
			signer, _ := loadDaemonConfig(t, l.mpsigner())
			combiner, combinerMP := loadDaemonConfig(t, l.mpcombiner())

			// Where one role dials another, the other listens.
			if !listensOn(t, combiner, agentMP.Combiner.Address) {
				t.Errorf("agent dials the combiner at %s; combiner listens on %v", agentMP.Combiner.Address, combiner.Listeners.Addresses)
			}
			if !listensOn(t, signer, agentMP.Signer.Address) {
				t.Errorf("agent dials the signer at %s; signer listens on %v", agentMP.Signer.Address, signer.Listeners.Addresses)
			}
			if !listensOn(t, agent, combinerMP.Agents[0].Address) {
				t.Errorf("combiner dials the agent at %s; agent listens on %v", combinerMP.Agents[0].Address, agent.Listeners.Addresses)
			}
			for _, listen := range agentMP.Dns.Addresses.Listen {
				_, p, _ := net.SplitHostPort(listen)
				if !listensOn(t, agent, listen) || p != strconv.Itoa(int(agentMP.Dns.Port)) {
					t.Errorf("agent multi-provider.dns listen %s / port %d does not match listeners %v", listen, agentMP.Dns.Port, agent.Listeners.Addresses)
				}
			}

			// The example zone flows combiner -> signer -> agent.
			signerPrim, signerNotify := zonePeers(t, signer, exampleZone)
			agentPrim, _ := zonePeers(t, agent, exampleZone)
			_, combinerNotify := zonePeers(t, combiner, exampleZone)
			if len(signerPrim) == 0 || len(agentPrim) == 0 || len(signerNotify) == 0 {
				t.Errorf("example zone peers missing: signer primaries %v, agent primaries %v, signer notify %v", signerPrim, agentPrim, signerNotify)
			}
			for _, dial := range signerPrim {
				if !listensOn(t, combiner, dial) {
					t.Errorf("signer pulls %s from %s; combiner listens on %v", exampleZone, dial, combiner.Listeners.Addresses)
				}
			}
			for _, dial := range agentPrim {
				if !listensOn(t, signer, dial) {
					t.Errorf("agent pulls %s from %s; signer listens on %v", exampleZone, dial, signer.Listeners.Addresses)
				}
			}
			for _, dial := range signerNotify {
				if !listensOn(t, agent, dial) {
					t.Errorf("signer notifies %s; agent listens on %v", dial, agent.Listeners.Addresses)
				}
			}
			if len(combinerNotify) == 0 || !listensOn(t, signer, combinerNotify[0]) {
				t.Errorf("combiner notifies %v; signer listens on %v", combinerNotify, signer.Listeners.Addresses)
			}

			if tc.withAuditor {
				auditor, auditorMP := loadDaemonConfig(t, l.mpauditor())
				auditorPrim, _ := zonePeers(t, auditor, exampleZone)
				if len(auditorPrim) == 0 {
					t.Errorf("auditor has no primaries for %s", exampleZone)
				}
				for _, dial := range auditorPrim {
					if !listensOn(t, combiner, dial) {
						t.Errorf("auditor pulls %s from %s; combiner listens on %v", exampleZone, dial, combiner.Listeners.Addresses)
					}
				}
				for _, listen := range auditorMP.Dns.Addresses.Listen {
					if !listensOn(t, auditor, listen) {
						t.Errorf("auditor multi-provider.dns listen %s is not in listeners %v", listen, auditor.Listeners.Addresses)
					}
				}
				notifiesAuditor := false
				for _, dial := range combinerNotify {
					if listensOn(t, auditor, dial) {
						notifiesAuditor = true
					}
				}
				if !notifiesAuditor {
					t.Errorf("combiner notifies %v, none of them the auditor (listens on %v)", combinerNotify, auditor.Listeners.Addresses)
				}
			}

			checkExampleZone(t, cv, l)
			checkMpcli(t, l, out, cv)
		})
	}
}

// The sample configs under cmd/ document the same schema. A key spelled
// in a way nothing reads would mislead whoever copies it.
func TestSampleConfigsUseKnownKeys(t *testing.T) {
	cmdDir := filepath.Join("..", "..", "..", "cmd")
	for _, name := range []string{
		"mpagent/tdns-mpagent.sample.yaml",
		"mpcombiner/tdns-mpcombiner.sample.yaml",
		"mpsigner/tdns-mpsigner.sample.yaml",
		"mpauditor/tdns-mpauditor.sample.yaml",
	} {
		raw, _, err := tdns.LoadRawConfigMap(filepath.Join(cmdDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkKnownKeys(t, name, raw)
	}
	body, err := os.ReadFile(filepath.Join(cmdDir, "mpcli", "tdns-mpcli.sample.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	decodeMpcli(t, "tdns-mpcli.sample.yaml", body)
}
