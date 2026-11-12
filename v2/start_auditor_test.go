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

// tdns-mp #170: the auditor builds and signs its identity zone through the
// set-up it shares with the agent, and that set-up puts the zone on the
// resigner's queue for periodic re-signing. The agent's start runs the engine
// that reads the queue; the auditor's start ran none, so the zone was signed
// once, when it was built, and never again. The test runs the auditor's own
// start, StartMPAuditor, on a configuration with nothing to listen on and no
// peers.

const auditorTestZone = "auditor.identity.example."

// startTestAuditor is an auditor's start, as its main does it: the role's
// initialisation, then StartMPAuditor. It returns once the identity zone is
// published. The engines stop when the test ends.
func startTestAuditor(t *testing.T) (*Config, *tdns.ZoneData) {
	t.Helper()
	kdb := newMPTestKeyDB(t)
	kdb.UpdateQ = make(chan tdns.UpdateRequest, 50)

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.Config.Internal.StopCh = make(chan struct{})
	// The queue as tdns's MainInit makes it.
	conf.Config.Internal.ResignQ = make(chan tdns.ResignRequest, 10)
	conf.Config.Internal.DnssecPolicies = map[string]tdns.DnssecPolicy{
		"default": {
			Mode:         tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
			SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		},
	}
	// No resolver: the auditor has nobody to discover here.
	off := false
	conf.Config.Imr.Active = &off

	// The API mechanism alone, with no address to publish or to listen on:
	// no listener is opened, and no handler is registered with tdns for the
	// life of the test binary.
	mp := &MultiProviderConf{Role: "auditor", Identity: auditorTestZone, SupportedMechanisms: []string{"api"}}
	mp.Local.Nameservers = []string{"ns1.example."}
	mp.Dns.Addresses.Listen = []string{"127.0.0.1:5300"}
	conf.SetMpConfig(mp)
	if err := conf.initMPAuditor(mp); err != nil {
		t.Fatalf("initMPAuditor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		close(conf.Config.Internal.StopCh)
		tdns.Zones.Remove(auditorTestZone)
		Zones.Invalidate(auditorTestZone)
		Zones.SetOnNew(nil) // the start installs the auditor's zone hooks
	})
	if err := conf.StartMPAuditor(ctx, nil); err != nil {
		t.Fatalf("StartMPAuditor: %v", err)
	}
	zd, ok := tdns.Zones.Get(auditorTestZone)
	if !ok || !zd.Ready {
		t.Fatalf("the auditor's identity zone after its start: registered=%v", ok)
	}
	return conf, zd
}

// wantApexSigned checks that the zone's apex RRsets are served signed.
func wantApexSigned(t *testing.T, zd *tdns.ZoneData) {
	t.Helper()
	for _, rrtype := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY} {
		rrset, err := zd.GetRRset(zd.ZoneName, rrtype)
		if err != nil || rrset == nil || len(rrset.RRs) == 0 {
			t.Fatalf("%s %s: %v", zd.ZoneName, dns.TypeToString[rrtype], err)
		}
		if len(rrset.RRSIGs) == 0 {
			t.Errorf("%s %s is served unsigned", zd.ZoneName, dns.TypeToString[rrtype])
		}
	}
}

// The auditor's start runs the resigner, and the identity zone is one it
// signs. The identity set-up puts the zone on the resigner's watchlist
// (tdns's KeepRenewed), which only that engine reads.
//
// The periodic pass that renews ageing signatures cannot be had sooner than
// the engine's shortest interval, a minute, so it is not waited for here. A
// key-state request goes to the same engine and is acted on at once: it is
// used to see that the engine is running and that this zone is one it signs.
func TestTheAuditorsStartRunsTheResigner(t *testing.T) {
	conf, zd := startTestAuditor(t)
	q := conf.Config.Internal.ResignQ

	// Asked to replace the zone's signatures, the resigner publishes the zone
	// anew, signed. Nothing else publishes the zone here: its set-up is done.
	wantApexSigned(t, zd)
	atStart := servedSerial(t, zd, auditorTestZone)
	select {
	case q <- tdns.ResignRequest{Zd: zd, Reason: tdns.ResignKeyStateChanged}:
	case <-time.After(5 * time.Second):
		t.Fatal("the resigner's queue does not take a request")
	}
	deadline := time.Now().Add(10 * time.Second)
	for servedSerial(t, zd, auditorTestZone) == atStart {
		if time.Now().After(deadline) {
			t.Fatalf("the identity zone is still at serial %d: the resigner did not sign it", atStart)
		}
		time.Sleep(20 * time.Millisecond)
	}
	wantApexSigned(t, zd)
}
