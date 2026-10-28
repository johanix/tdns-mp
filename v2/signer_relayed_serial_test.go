/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// tdns-mp #144: a provider that does not sign a signed multi-provider zone
// serves the SOA it received, serial and RRSIG together. The signer used to
// count a serial of its own for such a zone, at every refresh, and served it
// under the upstream signer's RRSIG: an SOA that does not validate.
//
// The zones here are loaded and refreshed by tdns's RefreshEngine from a
// server on a local port, with the signer's own refresh callbacks
// (RegisterMPRefreshCallbacks, MPPreRefresh) deciding from the incoming
// zone's HSYNCPARAM whether this provider signs.

const (
	relayUs    = "agent.beta.example."  // this provider's HSYNC3 identity
	relayOther = "agent.alpha.example." // the other provider's
)

// asMPDaemon runs the rest of the test as one of the tdns-mp daemons, the way
// its main() sets the app type.
func asMPDaemon(t *testing.T, app tdns.AppType) {
	t.Helper()
	prev := tdns.Globals.App.Type
	tdns.Globals.App.Type = app
	t.Cleanup(func() { tdns.Globals.App.Type = prev })
}

// mpUpstream serves one multi-provider zone on a local port and lets the test
// publish a new version of it. signers is the zone's HSYNCPARAM signers= list.
// With a key, each version carries the key's DNSKEY and its RRSIG over the SOA,
// as the zone of a provider that signs does.
type mpUpstream struct {
	zone    string
	signers string
	without string   // a label whose HSYNC3 record the zone leaves out
	extra   []string // more records, in zone file form
	key     *dns.DNSKEY
	priv    crypto.Signer
	addr    string
	cur     atomic.Pointer[tdns.ZoneData]
}

func (u *mpUpstream) zoneText(t *testing.T, serial uint32) string {
	t.Helper()
	z := u.zone
	var b strings.Builder
	soa := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s %d 7200 1800 604800 7200", z, z, z, serial)
	fmt.Fprintln(&b, soa)
	fmt.Fprintf(&b, "%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\nwww.%s 3600 IN A 192.0.2.2\n", z, z, z, z)
	if u.without != "alpha" {
		fmt.Fprintf(&b, "%s 300 IN HSYNC3 ON alpha %s .\n", z, relayOther)
	}
	if u.without != "beta" {
		fmt.Fprintf(&b, "%s 300 IN HSYNC3 ON beta %s .\n", z, relayUs)
	}
	fmt.Fprintf(&b, "%s 300 IN HSYNCPARAM servers=\"alpha,beta\" signers=\"%s\"\n", z, u.signers)
	for _, rr := range u.extra {
		fmt.Fprintln(&b, rr)
	}
	if u.key != nil {
		soaRR, err := dns.NewRR(soa)
		if err != nil {
			t.Fatalf("SOA: %v", err)
		}
		now := time.Now()
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: z, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeSOA,
			Algorithm:   u.key.Algorithm,
			Labels:      uint8(dns.CountLabel(z)),
			OrigTtl:     3600,
			Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
			Inception:   uint32(now.Add(-time.Hour).Unix()),
			KeyTag:      u.key.KeyTag(),
			SignerName:  z,
		}
		if err := sig.Sign(u.priv, []dns.RR{soaRR}); err != nil {
			t.Fatalf("signing the upstream's SOA: %v", err)
		}
		fmt.Fprintln(&b, u.key.String())
		fmt.Fprintln(&b, sig.String())
	}
	return b.String()
}

// publish makes the upstream serve the zone at serial.
func (u *mpUpstream) publish(t *testing.T, serial uint32) {
	t.Helper()
	pzd := &tdns.ZoneData{
		ZoneName:    u.zone,
		ZoneStore:   tdns.MapZone,
		ZoneType:    tdns.Primary,
		Logger:      log.New(io.Discard, "", 0),
		Ready:       true,
		Status:      tdns.ZoneStatusReady,
		Downstreams: []tdns.AclEntry{{Prefix: "127.0.0.0/8", Key: tdns.NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(u.zoneText(t, serial), true); err != nil {
		t.Fatalf("upstream ReadZoneData: %v", err)
	}
	pzd.InstallInitialSnapshot()
	t.Cleanup(pzd.StopPublisher)
	u.cur.Store(pzd)
}

// startMPUpstream starts the upstream at serial. signed says whether its zone
// is signed, by a key of its own.
func startMPUpstream(t *testing.T, zone, signers string, signed bool, serial uint32) *mpUpstream {
	t.Helper()
	u := &mpUpstream{zone: zone, signers: signers}
	if signed {
		u.key = &dns.DNSKEY{
			Hdr:   dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: 257, Protocol: 3, Algorithm: dns.ED25519,
		}
		priv, err := u.key.Generate(256)
		if err != nil {
			t.Fatalf("the upstream's key: %v", err)
		}
		u.priv = priv.(crypto.Signer)
	}
	u.publish(t, serial)

	// One port for TCP and UDP. The system picks the TCP port, and something
	// else on the machine may hold that number for UDP: try another one.
	var (
		ln net.Listener
		pc *net.UDPConn
	)
	for try := 1; ; try++ {
		var err error
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err == nil {
			break
		}
		ln.Close()
		if try == 10 {
			t.Fatalf("listen udp on the tcp port: %v", err)
		}
	}
	u.addr = ln.Addr().String()

	srvCtx, srvCancel := context.WithCancel(t.Context())
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		pzd := u.cur.Load()
		if len(r.Question) == 1 {
			switch r.Question[0].Qtype {
			case dns.TypeAXFR, dns.TypeIXFR:
				_, _ = pzd.ZoneTransferOut(srvCtx, w, r, nil)
				return
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if soa, err := pzd.GetSOA(); err == nil && soa != nil {
			m.Answer = append(m.Answer, soa)
		}
		_ = w.WriteMsg(m)
	})
	var started sync.WaitGroup
	started.Add(2)
	tcpSrv := &dns.Server{Listener: ln, Handler: mux, MsgAcceptFunc: tdns.MsgAcceptFunc, NotifyStartedFunc: started.Done}
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: started.Done}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	go func() { _ = udpSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		srvCancel()
		_ = tcpSrv.Shutdown()
		_ = udpSrv.Shutdown()
	})
	done := make(chan struct{})
	go func() { started.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream did not start")
	}
	return u
}

// mpServedZone is a multi-provider zone in a running RefreshEngine, as one of
// the daemons holds it: a secondary with the multi-provider option, with the
// daemon's refresh callbacks on it.
type mpServedZone struct {
	zd   *tdns.ZoneData
	conf *Config
	up   *mpUpstream
	// halt stops the engine and takes the zone away, as a stop of the daemon
	// does; the keystore stays. Run at the end of the test if not before.
	halt func()
}

// startMPServedZone pre-registers the zone the way ParseZones leaves it,
// attaches tdns-mp's refresh callbacks as the daemons' starts do, starts the
// engine and loads the zone with the config refresher. policy, when not nil,
// is the zone's bound DNSSEC policy. setup runs after the refresh callbacks
// are attached and before the engine starts, for what a daemon's start adds.
func startMPServedZone(t *testing.T, kdb *tdns.KeyDB, up *mpUpstream, mp *MultiProviderConf, policy *tdns.DnssecPolicy, setup ...func(*Config, *tdns.ZoneData)) *mpServedZone {
	t.Helper()
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.Config.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 1)
	conf.Config.Internal.BumpZoneCh = make(chan tdns.BumperData, 1)
	prevMp := WiredMpConfig()
	conf.SetMpConfig(mp)
	t.Cleanup(func() { wiredMpConfig.Store(prevMp) })

	zd := &tdns.ZoneData{
		ZoneName:      up.zone,
		Logger:        log.New(io.Discard, "", 0),
		Options:       map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		DnssecPolicy:  policy,
		FirstZoneLoad: true,
	}
	tdns.Zones.Set(up.zone, zd)
	conf.InternalMp.MPZoneNames = []string{up.zone}
	conf.RegisterMPRefreshCallbacks()
	if len(zd.OnZonePreRefresh) == 0 {
		t.Fatal("RegisterMPRefreshCallbacks attached no pre-refresh callback to the zone")
	}
	for _, f := range setup {
		f(conf, zd)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); tdns.RefreshEngine(ctx, conf.Config) }()
	var once sync.Once
	halt := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("RefreshEngine did not shut down")
			}
			zd.StopPublisher()
			tdns.Zones.Remove(up.zone)
			Zones.Invalidate(up.zone)
		})
	}
	t.Cleanup(halt)

	z := &mpServedZone{zd: zd, conf: conf, up: up, halt: halt}
	conf.Config.Internal.RefreshZoneCh <- z.configRefresher()
	deadline := time.Now().Add(10 * time.Second)
	for !zd.HasPublishedData() || !z.ready() {
		if time.Now().After(deadline) {
			t.Fatalf("the zone did not load: published=%v ready=%v", zd.HasPublishedData(), z.ready())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return z
}

func (z *mpServedZone) ready() bool {
	z.zd.Lock()
	defer z.zd.Unlock()
	return z.zd.Ready
}

// signsInline says whether inline-signing is on for the zone.
func (z *mpServedZone) signsInline() bool {
	z.zd.Lock()
	defer z.zd.Unlock()
	return z.zd.Options[tdns.OptInlineSigning]
}

// configRefresher is the refresher ParseZones builds from the zone's
// configuration; its options are the configured ones, a fresh map each time.
func (z *mpServedZone) configRefresher() tdns.ZoneRefresher {
	return tdns.ZoneRefresher{
		Name:          z.up.zone,
		ZoneType:      tdns.Secondary,
		ZoneStore:     tdns.MapZone,
		PrimariesConf: []tdns.PeerConf{{Addr: z.up.addr}},
		Primaries:     []tdns.PeerConf{{Addr: z.up.addr}},
		Options:       map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		ConfigUpdate:  true,
	}
}

func (z *mpServedZone) run(t *testing.T, zr tdns.ZoneRefresher) {
	t.Helper()
	zr.Wait = true
	zr.Response = make(chan tdns.RefresherResponse, 1)
	z.conf.Config.Internal.RefreshZoneCh <- zr
	select {
	case resp := <-zr.Response:
		if resp.Error {
			t.Fatalf("refresh: %s", resp.ErrorMsg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the refresh was not answered")
	}
}

// notified runs the refresh a NOTIFY from the upstream starts.
func (z *mpServedZone) notified(t *testing.T) {
	t.Helper()
	z.run(t, tdns.ZoneRefresher{Name: z.up.zone, ZoneStore: tdns.MapZone})
}

// reloaded runs the refresh `config reload-zones` queues for the zone: forced,
// so the zone is fetched again whether its serial moved or not.
func (z *mpServedZone) reloaded(t *testing.T) {
	t.Helper()
	zr := z.configRefresher()
	zr.Force = true
	z.run(t, zr)
}

// servedSOA is the SOA the zone answers with, and its RRSIGs.
func (z *mpServedZone) servedSOA(t *testing.T) (*dns.SOA, []dns.RR) {
	t.Helper()
	apex, err := z.zd.GetOwner(z.zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	rrset := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(rrset.RRs) != 1 {
		t.Fatalf("the apex has %d SOA records", len(rrset.RRs))
	}
	return rrset.RRs[0].(*dns.SOA), rrset.RRSIGs
}

// soaValidates reports why no RRSIG over the served SOA verifies with one of
// keys, or nil when one does.
func (z *mpServedZone) soaValidates(t *testing.T, keys []*dns.DNSKEY) error {
	t.Helper()
	soa, sigs := z.servedSOA(t)
	if len(sigs) == 0 {
		return fmt.Errorf("the SOA at serial %d carries no RRSIG", soa.Serial)
	}
	var last error
	for _, rr := range sigs {
		sig := rr.(*dns.RRSIG)
		for _, key := range keys {
			if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(key, []dns.RR{soa}); err != nil {
				last = fmt.Errorf("the RRSIG by key %d does not verify over the SOA at serial %d: %v", sig.KeyTag, soa.Serial, err)
				continue
			}
			return nil
		}
	}
	if last == nil {
		last = fmt.Errorf("no RRSIG over the SOA at serial %d is by a key the zone serves", soa.Serial)
	}
	return last
}

func (z *mpServedZone) servedDNSKEYs(t *testing.T) []*dns.DNSKEY {
	t.Helper()
	apex, err := z.zd.GetOwner(z.zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	var keys []*dns.DNSKEY
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
		keys = append(keys, rr.(*dns.DNSKEY))
	}
	return keys
}

func signerConfBeta() *MultiProviderConf {
	return &MultiProviderConf{Role: "signer", Active: true, Identity: "signer.beta.example.",
		Agents: []*PeerConf{{Identity: relayUs}}}
}

// A zone another provider signs: this provider's signer relays it. After the
// first load, after refreshes and after a forced re-fetch of an unchanged
// serial (`config reload-zones`), the SOA it serves is the upstream's, at the
// upstream's serial, and it validates with the DNSKEY the zone carries.
func TestSignerRelaysTheUpstreamSOAOfAZoneItDoesNotSign(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	// the sample configuration's mode
	kdb.SetOutboundSoaSerial(tdns.OutboundSoaSerialPersist)

	up := startMPUpstream(t, "relayed.example.", "alpha", true, 40)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), nil)
	if z.signsInline() {
		t.Fatal("inline-signing is on for a zone whose HSYNCPARAM does not name this provider as a signer")
	}

	check := func(when string, want uint32) {
		t.Helper()
		if err := z.soaValidates(t, z.servedDNSKEYs(t)); err != nil {
			t.Fatalf("%s: the relayed SOA does not validate: %v (the upstream signer is at serial %d)", when, err, want)
		}
		if soa, _ := z.servedSOA(t); soa.Serial != want {
			t.Fatalf("%s: the signer serves serial %d, the upstream signer has %d", when, soa.Serial, want)
		}
	}
	check("after the first load", 40)

	up.publish(t, 41)
	z.notified(t)
	check("after one refresh", 41)

	// two upstream changes reach the provider in one refresh
	up.publish(t, 43)
	z.notified(t)
	check("after a refresh that carried two upstream changes", 43)

	z.reloaded(t)
	check("after a forced re-fetch of an unchanged serial", 43)
	z.reloaded(t)
	check("after a second forced re-fetch", 43)

	up.publish(t, 44)
	z.notified(t)
	check("after a refresh that followed the re-fetches", 44)
}

// A zone this provider signs keeps a serial of its own: HSYNCPARAM names the
// provider as a signer, MPPreRefresh switches inline-signing on, and the
// signer counts by itself at every refresh and forced re-fetch, whatever
// serial its combiner has. The SOA it serves is signed by its own key over
// that serial.
func TestSignerKeepsItsOwnSerialForAZoneItSigns(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	const zone = "signed-here.example."
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}

	// the provider's combiner: an unsigned zone, a serial of its own
	up := startMPUpstream(t, zone, "beta", false, 7)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !z.signsInline() {
		t.Fatal("inline-signing is off for a zone whose HSYNCPARAM names this provider as a signer")
	}

	ownKeys := func() []*dns.DNSKEY {
		t.Helper()
		inv, err := tdns.GetKeyInventory(kdb, zone)
		if err != nil {
			t.Fatalf("GetKeyInventory: %v", err)
		}
		var keys []*dns.DNSKEY
		for _, it := range inv {
			rr, err := dns.NewRR(it.KeyRR)
			if err != nil {
				t.Fatalf("key %d: %v", it.KeyTag, err)
			}
			keys = append(keys, rr.(*dns.DNSKEY))
		}
		return keys
	}
	served := func(when string) uint32 {
		t.Helper()
		soa, _ := z.servedSOA(t)
		if err := z.soaValidates(t, ownKeys()); err != nil {
			t.Fatalf("%s: the SOA the signer serves is not signed by its own key: %v", when, err)
		}
		return soa.Serial
	}
	first := served("after the first load")

	// The combiner moves far ahead: the signer does not take its serial.
	up.publish(t, 500)
	z.notified(t)
	second := served("after a refresh")
	if second != first+1 {
		t.Fatalf("after a refresh the signing zone serves %d, want %d: one past the %d it served, not the combiner's 500", second, first+1, first)
	}
	z.reloaded(t)
	third := served("after a forced re-fetch")
	if third != second+1 {
		t.Fatalf("after a forced re-fetch the signing zone serves %d, want %d: its own count", third, second+1)
	}
}

// A provider turns from server to signer, and its signer is restarted in
// between: it relayed the zone from the other provider's signer, and comes
// back with the zone's HSYNCPARAM naming it as the signer and its own combiner
// as the upstream. The combiner counts a serial of its own, here far below the
// one the signer was relaying. The provider's nameservers hold the relayed
// serial and do not transfer a lower one, so the signer goes on from past it,
// with an SOA signed by its own key.
func TestSignerThatStartsToSignAcrossARestartGoesOnPastTheSerialItRelayed(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	// the sample configuration's mode
	kdb.SetOutboundSoaSerial(tdns.OutboundSoaSerialPersist)
	const zone = "turned.example."

	other := startMPUpstream(t, zone, "alpha", true, 40)
	z := startMPServedZone(t, kdb, other, signerConfBeta(), nil)
	other.publish(t, 43)
	z.notified(t)
	if soa, _ := z.servedSOA(t); soa.Serial != 43 {
		t.Fatalf("relayed: the signer serves serial %d, the upstream signer has 43", soa.Serial)
	}
	if err := z.soaValidates(t, z.servedDNSKEYs(t)); err != nil {
		t.Fatalf("relayed: %v", err)
	}
	z.halt()

	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	combiner := startMPUpstream(t, zone, "beta", false, 7)
	again := startMPServedZone(t, kdb, combiner, signerConfBeta(), policy)
	if !again.signsInline() {
		t.Fatal("inline-signing is off for a zone whose HSYNCPARAM names this provider as a signer")
	}
	soa, _ := again.servedSOA(t)
	t.Logf("after the restart the signer serves serial %d", soa.Serial)
	// RFC 1982 order; the signer may publish more than once while it loads
	// and signs, so "past 43" and not one fixed serial.
	if d := soa.Serial - 43; d == 0 || d > 10 {
		t.Fatalf("after the restart the signer serves serial %d, want one shortly past the 43 it relayed, not its combiner's 7", soa.Serial)
	}
	inv, err := tdns.GetKeyInventory(kdb, zone)
	if err != nil {
		t.Fatalf("GetKeyInventory: %v", err)
	}
	var own []*dns.DNSKEY
	for _, it := range inv {
		rr, err := dns.NewRR(it.KeyRR)
		if err != nil {
			t.Fatalf("key %d: %v", it.KeyTag, err)
		}
		own = append(own, rr.(*dns.DNSKEY))
	}
	if err := again.soaValidates(t, own); err != nil {
		t.Fatalf("after the restart the SOA is not signed by the signer's own key: %v", err)
	}
}

// `config reload-zones`, a zone reload: a config update replaces the zone's
// options with the configured ones, and the signer's switch is in no
// configuration. It must stay on for a zone the signer signs, also when no
// transfer follows the update to set it again: without it the zone is, to
// tdns, one this daemon only relays.
func TestSignerKeepsSigningAcrossAConfigUpdate(t *testing.T) {
	asMPDaemon(t, AppTypeMPSigner)
	kdb := newMPTestKeyDB(t)
	const zone = "reloaded.example."
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "KSK")
	mpGenKey(t, kdb, zone, tdns.DnskeyStateActive, "ZSK")
	policy := &tdns.DnssecPolicy{
		Mode:         tdns.DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
		SigValidity:  tdns.PolicySigValidity{Default: 14 * 86400, DNSKEY: 14 * 86400, DS: 14 * 86400},
	}
	up := startMPUpstream(t, zone, "beta", false, 7)
	z := startMPServedZone(t, kdb, up, signerConfBeta(), policy)
	if !z.signsInline() {
		t.Fatal("inline-signing is off for a zone whose HSYNCPARAM names this provider as a signer")
	}
	before, _ := z.servedSOA(t)

	// A config update with nothing new at the combiner: the options come
	// from the configuration, and no transfer follows.
	z.run(t, z.configRefresher())
	if !z.signsInline() {
		t.Fatal("a config update switched inline-signing off for a zone this provider signs")
	}
	if after, _ := z.servedSOA(t); after.Serial != before.Serial {
		t.Fatalf("a config update with nothing new moved the serial from %d to %d", before.Serial, after.Serial)
	}

	// The combiner far ahead, and a refresh: still the signer's own count.
	up.publish(t, 500)
	z.notified(t)
	if soa, _ := z.servedSOA(t); soa.Serial != before.Serial+1 {
		t.Fatalf("after the update and a refresh the signer serves %d, want %d: its own count, not the combiner's 500", soa.Serial, before.Serial+1)
	}

	// And the other way: a zone this provider only relays does not start
	// to sign because of a config update.
	other := startMPUpstream(t, "relayed-reloaded.example.", "alpha", true, 40)
	r := startMPServedZone(t, kdb, other, signerConfBeta(), nil)
	r.run(t, r.configRefresher())
	if r.signsInline() {
		t.Fatal("a config update switched inline-signing on for a zone this provider only relays")
	}
	if soa, _ := r.servedSOA(t); soa.Serial != 40 {
		t.Fatalf("after a config update the relayed zone serves %d, want the upstream's 40", soa.Serial)
	}
}

// The guard: only the signer follows the rule. The combiner changes the zones
// it holds as a secondary and counts its own serial for them; the agent and
// the auditor keep their own rules too. Each of them, holding the same
// relayed zone, goes on counting as it did.
func TestOnlyTheSignerRelaysTheUpstreamSerial(t *testing.T) {
	for _, d := range []struct {
		name string
		app  tdns.AppType
		mp   *MultiProviderConf
	}{
		{"combiner", AppTypeMPCombiner, &MultiProviderConf{Role: "combiner", Identity: "combiner.beta.example.", Agents: []*PeerConf{{Identity: relayUs}}}},
		{"agent", AppTypeMPAgent, &MultiProviderConf{Role: "agent", Identity: relayUs}},
		{"auditor", AppTypeMPAuditor, &MultiProviderConf{Role: "auditor", Identity: relayUs}},
	} {
		t.Run(d.name, func(t *testing.T) {
			asMPDaemon(t, d.app)
			kdb := newMPTestKeyDB(t)
			up := startMPUpstream(t, d.name+".guard.example.", "alpha", true, 40)
			z := startMPServedZone(t, kdb, up, d.mp, nil)
			if soa, _ := z.servedSOA(t); soa.Serial != 40 {
				t.Fatalf("after the first load: %d, want 40", soa.Serial)
			}
			z.reloaded(t)
			if soa, _ := z.servedSOA(t); soa.Serial != 41 {
				t.Fatalf("after a forced re-fetch the %s serves %d, want 41: its own count, as before", d.name, soa.Serial)
			}
			up.publish(t, 50)
			z.notified(t)
			if soa, _ := z.servedSOA(t); soa.Serial != 42 {
				t.Fatalf("after a refresh the %s serves %d, want 42: its own count, not the upstream's 50", d.name, soa.Serial)
			}
		})
	}
}
