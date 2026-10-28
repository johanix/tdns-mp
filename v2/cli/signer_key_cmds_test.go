/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// printed is what f writes to the standard output.
func printed(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = saved
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// tdns-mp #134: `signer key policy` showed 10000h0m0s for a role whose
// policy says `lifetime: forever`, the number tdns stores for the word. The
// whole way here: the policy from tdns's parser, bound to a zone the
// signer's key machine runs, the machine's answer on /signer/key, and the
// command's own printer.
func TestSignerKeyPolicyShowsForever(t *testing.T) {
	const zone = "policy.owned.example."
	var dp tdns.DnssecPolicyConf
	if err := yaml.Unmarshal([]byte("algorithm: ED25519\nksk:\n   lifetime: forever\nzsk:\n   lifetime: 30d\ncsk:\n   lifetime: none\n"+
		"sigvalidity:\n   default: 6h\n   dnskey: 6h\n   ds: 6h\n"), &dp); err != nil {
		t.Fatalf("the policy's yaml: %v", err)
	}
	pol, err := tdns.ParseDnssecPolicyConfQuiet("default", &dp)
	if err != nil {
		t.Fatalf("the policy: %v", err)
	}

	// a multi-provider zone this provider signs (label "us") beside p2
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := tdns.NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	zd := &tdns.ZoneData{
		ZoneName:         zone,
		ZoneStore:        tdns.MapZone,
		ZoneType:         tdns.Primary,
		Logger:           log.New(io.Discard, "", 0),
		Options:          map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true, tdns.OptInlineSigning: true},
		KeyDB:            kdb,
		DnssecPolicy:     pol,
		DnssecPolicyName: "default",
	}
	if _, _, err := zd.ReadZoneData(fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n",
		zone, zone, zone, zone, zone, zone), true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	apex, err := zd.OwnerForAnalysis(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: zone, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMSigners{Signers: []string{"us", "p2"}}, &core.HSYNCPARAMSerial{Value: 1}}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	h3 := &core.HSYNC3{State: 1, Label: "us", Identity: "agent.us.example.", Upstream: "."}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: h3}}})
	zd.Data.Set(zone, *apex)
	zd.InstallInitialSnapshot()
	tdns.Zones.Set(zone, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(zone)
		tdnsmp.Zones.Invalidate(zone)
	})

	conf := &tdnsmp.Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.SetMpConfig(&tdnsmp.MultiProviderConf{Identity: "signer.example.", Role: "signer", Agents: []*tdnsmp.PeerConf{{Identity: "agent.us.example."}}})
	owner := tdnsmp.NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	conf.InternalMp.KeyLifecycleOwner, conf.InternalMp.KeyLifecycle = owner, tdnsmp.NewKeyLifecycleEngine(conf, owner)
	owner.Take(zone)

	// what the command does: the request, the answer decoded, the printer
	body, err := json.Marshal(tdnsmp.SignerKeyPost{Command: "policy", Zone: zone})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	conf.APIsignerKey()(w, httptest.NewRequest(http.MethodPost, "/signer/key", bytes.NewReader(body)))
	var resp tdnsmp.SignerKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%q)", err, w.Body.String())
	}
	if resp.Error || resp.Status == nil {
		t.Fatalf("policy: %+v", resp)
	}
	out := printed(t, func() { printSignerKeyPolicy(resp.Status) })
	shown := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if name, value, ok := strings.Cut(line, " lifetime"); ok {
			shown[name] = strings.TrimSpace(value)
		}
	}
	if shown["KSK"] != "forever" {
		t.Errorf("the KSK lifetime of a `lifetime: forever` policy is shown as %q, want forever:\n%s", shown["KSK"], out)
	}
	if shown["ZSK"] != "720h0m0s" {
		t.Errorf("the ZSK lifetime of a `lifetime: 30d` policy is shown as %q, want 720h0m0s:\n%s", shown["ZSK"], out)
	}
}
