/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/cli/configure"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The identity zone's first content is one publish: step 2 of tdns's
// docs/2026-09-17-publish-gate-and-transactions.md, for tdns #653. The agent
// used to publish its identity one record at a time, seven serials inside a
// second, and a secondary served an intermediate serial to the peer that was
// looking the agent up. Now the zone is created held, filled, and committed
// once, and the first hello waits for that commit.

const identityTestZone = "agent.identity.example."

// identityTestConfig is an agent configuration with a DNS transport to
// publish, a notify target (so the publish sends a NOTIFY, and the zone gets a
// transfer ACL), a JOSE key for the JWK record, and the default DNSSEC policy
// the identity zone signs with.
func identityTestConfig(t *testing.T, kdb *tdns.KeyDB) (*Config, chan tdns.NotifyRequest) {
	t.Helper()
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.Config.Internal.DnssecPolicies = map[string]tdns.DnssecPolicy{
		"default": {
			Mode:         tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm: dns.ED25519,
			ZSKAlgorithm: dns.ED25519,
			SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
		},
	}
	conf.InternalMp.SyncQ = make(chan SyncRequest, 10)
	conf.InternalMp.IdentityReady = newIdentityReadiness()

	josePriv := filepath.Join(t.TempDir(), "agent-jose.key")
	if _, _, _, err := configure.EnsureJoseKeypair(josePriv); err != nil {
		t.Fatalf("EnsureJoseKeypair: %v", err)
	}
	mp := &MultiProviderConf{Role: "agent", Identity: identityTestZone, SupportedMechanisms: []string{"dns"}}
	mp.Local.Notify = []string{"192.0.2.53:5300"}
	mp.Local.Nameservers = []string{"ns1.example."}
	mp.Dns.Addresses.Listen = []string{"127.0.0.1:5300"}
	mp.Dns.Addresses.Publish = []string{"192.0.2.10"}
	mp.Dns.BaseUrl = "dns://{TARGET}:{PORT}"
	mp.Dns.Port = 5300
	mp.LongTermJosePrivKey = josePriv
	conf.SetMpConfig(mp)

	notifyq := make(chan tdns.NotifyRequest, 16)
	prev := tdns.Conf.Internal.NotifyQ
	tdns.Conf.Internal.NotifyQ = notifyq
	t.Cleanup(func() {
		tdns.Conf.Internal.NotifyQ = prev
		tdns.Zones.Remove(identityTestZone)
	})
	return conf, notifyq
}

// startIdentityUpdater runs the real zone updater on the key store's queue,
// buffered as the daemon's is, so the identity's records and its commit travel
// the way they do in the daemon.
func startIdentityUpdater(t *testing.T, kdb *tdns.KeyDB) context.Context {
	t.Helper()
	kdb.UpdateQ = make(chan tdns.UpdateRequest, 50)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = kdb.ZoneUpdaterEngine(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the zone updater did not stop")
		}
	})
	return ctx
}

func notifiesFor(q chan tdns.NotifyRequest, zone string) int {
	n := 0
	for {
		select {
		case nr := <-q:
			if nr.ZoneName == zone {
				n++
			}
		default:
			return n
		}
	}
}

// The zone is created held: registered, pending, with no snapshot, and the
// transaction that holds it is returned to the creator, who commits it once
// the records are in.
func TestTheIdentityZoneIsCreatedHeld(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf, notifyq := identityTestConfig(t, kdb)
	ctx := startIdentityUpdater(t, kdb)

	zd, txid, err := conf.SetupAgentAutoZone(ctx, identityTestZone)
	if err != nil {
		t.Fatalf("SetupAgentAutoZone: %v", err)
	}
	if txid == "" {
		t.Fatal("no transaction returned for the held zone")
	}
	if zd.Ready || zd.Status != tdns.ZoneStatusPending {
		t.Fatalf("a zone created held is Ready=%v status=%v; want not Ready and pending", zd.Ready, zd.Status)
	}
	if _, err := zd.GetRRset(identityTestZone, dns.TypeSOA); err == nil {
		t.Fatal("the held zone answers for its apex")
	}
	if n := notifiesFor(notifyq, identityTestZone); n != 0 {
		t.Fatalf("%d NOTIFY(s) sent by a zone created held", n)
	}

	// The transaction is the zone's: committing it publishes the zone.
	if err := zd.CommitTx(txid); err != nil {
		t.Fatalf("CommitTx(%s): %v", txid, err)
	}
	if !zd.Ready {
		t.Fatal("the zone is not Ready after its commit")
	}
}

// The join, through the real producer: SetupAgent creates the zone held,
// publishes the transport records through the update queue, commits behind
// them, and returns once the zone is published. The zone has one serial, with
// every record and every signature in it, sends one NOTIFY, and the hello gate
// is open.
func TestTheIdentityZoneIsPublishedOnce(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf, notifyq := identityTestConfig(t, kdb)
	ctx := startIdentityUpdater(t, kdb)

	if err := conf.SetupAgent(ctx, nil); err != nil {
		t.Fatalf("SetupAgent: %v", err)
	}
	zd, ok := tdns.Zones.Get(identityTestZone)
	if !ok {
		t.Fatal("the identity zone is not registered")
	}
	if !zd.Ready || zd.Status != tdns.ZoneStatusReady {
		t.Fatalf("after SetupAgent: Ready=%v status=%v", zd.Ready, zd.Status)
	}
	if n := len(zd.IxfrChain); n != 0 {
		t.Errorf("the identity zone was published %d time(s) after its first snapshot; want one publish", n)
	}
	if n := notifiesFor(notifyq, identityTestZone); n != 1 {
		t.Errorf("%d NOTIFY(s) for the identity zone, want 1", n)
	}

	for _, c := range []struct {
		owner  string
		rrtype uint16
	}{
		{identityTestZone, dns.TypeSOA},
		{identityTestZone, dns.TypeDNSKEY},
		{"_dns._tcp." + identityTestZone, dns.TypeURI},
		{identityTestZone, dns.TypeA},
		{identityTestZone, dns.TypeSVCB},
		{"dns." + identityTestZone, core.TypeJWK},
	} {
		rrset, err := zd.GetRRset(c.owner, c.rrtype)
		if err != nil {
			t.Errorf("%s %s: %v", c.owner, dns.TypeToString[c.rrtype], err)
			continue
		}
		if rrset == nil || len(rrset.RRs) == 0 {
			t.Errorf("%s %s is not in the published zone", c.owner, typeToString(c.rrtype))
			continue
		}
		if len(rrset.RRSIGs) == 0 {
			t.Errorf("%s %s is published unsigned", c.owner, typeToString(c.rrtype))
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !conf.InternalMp.IdentityReady.Wait(waitCtx) {
		t.Error("the hello gate is still closed after the identity was published")
	}
}

// A commit the updater refuses fails the set-up, loudly, and leaves the hello
// gate closed: a daemon whose identity is not published does not introduce
// itself.
func TestARefusedCommitFailsTheSetup(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf, _ := identityTestConfig(t, kdb)
	ctx := startIdentityUpdater(t, kdb)

	zd, _, err := conf.SetupAgentAutoZone(ctx, identityTestZone)
	if err != nil {
		t.Fatalf("SetupAgentAutoZone: %v", err)
	}
	if err := conf.commitIdentityZone(ctx, zd, "no-such-transaction"); err == nil {
		t.Fatal("a refused commit reported success")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if conf.InternalMp.IdentityReady.Wait(waitCtx) {
		t.Error("the hello gate opened although the identity was not published")
	}
}

// The gate the hello waits on: closed until published, open for good after,
// and absent (nil) where no identity is set up.
func TestTheIdentityGate(t *testing.T) {
	var none *identityReadiness
	if !none.Wait(context.Background()) {
		t.Error("a nil gate blocks")
	}
	g := newIdentityReadiness()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if g.Wait(ctx) {
		t.Error("an unpublished gate let a waiter through")
	}
	g.Publish()
	g.Publish() // idempotent
	if !g.Wait(context.Background()) {
		t.Error("a published gate blocks")
	}
}

func typeToString(rrtype uint16) string {
	if s, ok := dns.TypeToString[rrtype]; ok {
		return s
	}
	return dns.Type(rrtype).String()
}

// Both roles that set an identity up through SetupAgent, the agent and the
// auditor, hold their first hello for it: the gate exists once the role is
// initialised, before the sync engine that reads it is built, and it is
// closed until SetupAgent opens it.
func TestEveryRoleThatSetsUpAnIdentityHasAHelloGate(t *testing.T) {
	for _, c := range []struct {
		role string
		init func(*Config, *MultiProviderConf) error
	}{
		{"agent", (*Config).initMPAgent},
		{"auditor", (*Config).initMPAuditor},
	} {
		t.Run(c.role, func(t *testing.T) {
			conf := &Config{Config: &tdns.Config{}}
			conf.Config.Internal.StopCh = make(chan struct{})
			t.Cleanup(func() { close(conf.Config.Internal.StopCh) })
			mp := &MultiProviderConf{Role: c.role, Identity: c.role + ".gate.example."}
			conf.SetMpConfig(mp)
			if err := c.init(conf, mp); err != nil {
				t.Fatalf("init: %v", err)
			}
			if conf.InternalMp.IdentityReady == nil {
				t.Fatalf("the %s has no hello gate after its initialisation", c.role)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if conf.InternalMp.IdentityReady.Wait(ctx) {
				t.Fatalf("the %s's hello gate is open before its identity is published", c.role)
			}
		})
	}
}

// The identity zone's parentsync work reads the zone through accessors that
// need it Ready: the CDS is synthesised from the published apex, and the
// SIG(0) key preparation reads the apex too. Under the hold there is no
// snapshot, so both must wait for the commit. Seen on the rig on 2026-09-29:
// "could not publish CDS ... zone data is not yet ready", the key preparation
// failing the same way, and the delegation sync setup it had queued ignored.
func TestTheIdentityZonesParentSyncStartsAfterItsCommit(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf, _ := identityTestConfig(t, kdb)
	ctx := startIdentityUpdater(t, kdb)
	conf.Config.ParentSync.Schemes = []string{"notify", "update"}
	conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
	conf.Config.Internal.ImrReady.Publish()
	syncq := make(chan tdns.DelegationSyncRequest, 8)
	conf.Config.Internal.DelegationSyncQ = syncq
	logs := captureAgentLog(t)

	if err := conf.SetupAgent(ctx, nil); err != nil {
		t.Fatalf("SetupAgent: %v", err)
	}
	zd, ok := tdns.Zones.Get(identityTestZone)
	if !ok {
		t.Fatal("the identity zone is not registered")
	}

	// The CDS goes out after the commit, through the queue: a serial of its
	// own, on a zone that is already complete for discovery.
	deadline := time.Now().Add(5 * time.Second)
	var cds *core.RRset
	for time.Now().Before(deadline) {
		if rrset, err := zd.GetRRset(identityTestZone, dns.TypeCDS); err == nil && rrset != nil && len(rrset.RRs) > 0 {
			cds = rrset
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if cds == nil {
		t.Error("the identity zone has no CDS after its set-up")
		// Which of the two silent ways: no SEP key in the published DNSKEY
		// RRset (nothing to synthesise), or the update's publish refused (a
		// zone that signs marks itself DnssecError).
		sep := 0
		if rrset, err := zd.GetRRset(identityTestZone, dns.TypeDNSKEY); err == nil && rrset != nil {
			for _, rr := range rrset.RRs {
				if k, ok := rr.(*dns.DNSKEY); ok && k.Flags&dns.SEP != 0 {
					sep++
				}
			}
		}
		t.Logf("  published DNSKEY RRset: %d SEP key(s); zone error=%v type=%v msg=%q", sep, zd.Error, zd.ErrorType, zd.ErrorMsg)
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "CDS") || strings.Contains(line, "cds") || strings.Contains(line, "refus") {
				t.Logf("  %s", line)
			}
		}
	}
	for _, bad := range []string{"could not publish CDS", "could not prepare the SIG(0) key"} {
		if strings.Contains(logs.String(), bad) {
			t.Errorf("the set-up logged %q: parentsync work ran on the held zone", bad)
		}
	}

	// The delegation sync setup is queued once the key exists, as before.
	select {
	case r := <-syncq:
		if r.Command != "DELEGATION-SYNC-SETUP" {
			t.Errorf("first delegation sync request = %q, want DELEGATION-SYNC-SETUP", r.Command)
		}
		sak, err := kdb.GetSig0Keys(identityTestZone, tdns.Sig0StateActive)
		if err != nil || len(sak.Keys) != 1 {
			t.Errorf("active SIG(0) keys when the setup was queued = %d (err %v), want 1", len(sak.Keys), err)
		}
	case <-time.After(5 * time.Second):
		t.Error("no delegation sync request was queued")
	}
}

// A config-defined identity zone is not held (step 2 is the auto zone), but
// its hello waits too: the gate opens from the last of the zone's first-load
// callbacks, once the zone is served and its transport records are queued,
// and not before the zone has loaded at all.
func TestAConfigDefinedIdentityZoneOpensTheGateWhenItLoads(t *testing.T) {
	const zone = "agent.config.example."
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.InternalMp.IdentityReady = newIdentityReadiness()
	mp := &MultiProviderConf{Role: "agent", Identity: zone, SupportedMechanisms: []string{"dns"}}
	mp.Dns.Addresses.Listen = []string{"127.0.0.1:5300"} // no addresses to publish: no transport callbacks
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
	t.Cleanup(func() { tdns.Zones.Remove(zone) })

	if err := conf.SetupAgent(context.Background(), []string{zone}); err != nil {
		t.Fatalf("SetupAgent: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if conf.InternalMp.IdentityReady.Wait(ctx) {
		t.Fatal("the hello gate opened before the config-defined identity zone loaded")
	}
	zdp, ok := Zones.Get(zone)
	if !ok || len(zdp.OnFirstLoad) == 0 {
		t.Fatal("no first-load callback registered on the config-defined identity zone")
	}
	for _, cb := range zdp.OnFirstLoad {
		cb(zd)
	}
	if !conf.InternalMp.IdentityReady.Wait(context.Background()) {
		t.Fatal("the hello gate is still closed after the zone's first-load callbacks")
	}
}
