package tdnsmp

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// The refresh side of tdns-mp #171. A refresh of a provider zone replaces the
// zone with what its upstream has, and the upstream has none of the _signal
// KEYs: they are the combiner's writes. The combiner puts them onto the
// incoming zone. The tests here take the zones through tdns's own refresh: the
// refresh engine, a secondary with an upstream on a local port, the SOA probe
// and the transfer, and the combiner's first-load and refresh callbacks
// registered as its start registers them. The agent's updates go through
// CombinerProcessUpdate, as in the consent tests.

// refreshUpstream is the side the combiner transfers from: a nameserver on a
// local port that answers the SOA probe and gives out each zone as it has
// last been handed it.
type refreshUpstream struct {
	t     *testing.T
	addr  string
	ctx   context.Context
	mu    sync.Mutex
	zones map[string]*tdns.ZoneData
}

func startRefreshUpstream(t *testing.T) *refreshUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		ln.Close()
		t.Fatalf("listen udp on the tcp port: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &refreshUpstream{t: t, addr: ln.Addr().String(), ctx: ctx, zones: map[string]*tdns.ZoneData{}}

	var started sync.WaitGroup
	started.Add(2)
	tcpSrv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(u.serve), MsgAcceptFunc: tdns.MsgAcceptFunc, NotifyStartedFunc: started.Done}
	udpSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(u.serve), NotifyStartedFunc: started.Done}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	go func() { _ = udpSrv.ActivateAndServe() }()
	up := make(chan struct{})
	go func() { started.Wait(); close(up) }()
	select {
	case <-up:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream did not start")
	}
	t.Cleanup(func() {
		cancel()
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = tcpSrv.ShutdownContext(sctx)
		_ = udpSrv.ShutdownContext(sctx)
		u.mu.Lock()
		defer u.mu.Unlock()
		for _, pzd := range u.zones {
			pzd.StopPublisher()
		}
	})
	return u
}

func (u *refreshUpstream) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	u.mu.Lock()
	pzd := u.zones[strings.ToLower(r.Question[0].Name)]
	u.mu.Unlock()
	if pzd == nil {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	switch r.Question[0].Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		_, _ = pzd.ZoneTransferOut(u.ctx, w, r, nil)
		return
	}
	if soa, err := pzd.GetSOA(); err == nil && soa != nil {
		m.Authoritative = true
		m.Answer = append(m.Answer, soa)
	}
	_ = w.WriteMsg(m)
}

// publish makes text what the upstream has for the zone. The zone data is
// tdns's own, served by its transfer-out, and it is not registered: the
// combiner's zone of the same name is the one in the registry.
func (u *refreshUpstream) publish(zone, text string) {
	u.t.Helper()
	pzd := &tdns.ZoneData{
		ZoneName:    zone,
		ZoneStore:   tdns.MapZone,
		ZoneType:    tdns.Primary,
		Logger:      log.New(io.Discard, "", 0),
		Ready:       true,
		Status:      tdns.ZoneStatusReady,
		Downstreams: []tdns.AclEntry{{Prefix: "127.0.0.0/8", Key: tdns.NOKEY}},
	}
	if _, _, err := pzd.ReadZoneData(text, true); err != nil {
		u.t.Fatalf("upstream ReadZoneData(%s): %v", zone, err)
	}
	pzd.InstallInitialSnapshot()
	u.mu.Lock()
	old := u.zones[zone]
	u.zones[zone] = pzd
	u.mu.Unlock()
	if old != nil {
		old.StopPublisher()
	}
}

// atSerial is a zone text of the consent tests with another SOA serial.
func atSerial(text string, serial uint32) string {
	return strings.Replace(text, " 1 7200 1800 ", fmt.Sprintf(" %d 7200 1800 ", serial), 1)
}

// refreshCombiner is the consent tests' combiner with its zones behind tdns's
// refresh engine: configured as secondaries of the upstream, loaded and
// refreshed by the engine, with the callbacks StartMPCombiner registers.
type refreshCombiner struct {
	*consentCombiner
	conf *Config
	up   *refreshUpstream
}

func newRefreshCombiner(t *testing.T, zones ...string) *refreshCombiner {
	t.Helper()
	prevApp := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPCombiner
	t.Cleanup(func() { tdns.Globals.App.Type = prevApp })

	c := &refreshCombiner{consentCombiner: newConsentCombiner(t), up: startRefreshUpstream(t)}
	pendingSignalKeys.mu.Lock()
	pendingSignalKeys.built = false
	pendingSignalKeys.entries = nil
	pendingSignalKeys.mu.Unlock()

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = c.kdb
	conf.Config.Internal.RefreshZoneCh = make(chan tdns.ZoneRefresher, 8)
	conf.SetMpConfig(c.mp)
	c.conf = conf
	// The zones as the config parser leaves them: registered, nothing loaded.
	for _, name := range zones {
		c.drop(name)
		c.names[name] = true
		tdns.Zones.Set(name, &tdns.ZoneData{
			ZoneName:      name,
			Logger:        log.New(io.Discard, "", 0),
			FirstZoneLoad: true,
			Options:       map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		})
		conf.InternalMp.MPZoneNames = append(conf.InternalMp.MPZoneNames, name)
	}
	// What StartMPCombiner registers, and the engine it starts.
	conf.RegisterCombinerOnFirstLoad()
	conf.RegisterMPRefreshCallbacks()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tdns.RefreshEngine(ctx, conf.Config)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the refresh engine did not stop")
		}
	})
	return c
}

// ask sends the refresh engine a request and waits for its answer.
func (c *refreshCombiner) ask(zr tdns.ZoneRefresher) {
	c.t.Helper()
	resp := make(chan tdns.RefresherResponse, 1)
	zr.Response = resp
	select {
	case c.conf.Config.Internal.RefreshZoneCh <- zr:
	case <-time.After(10 * time.Second):
		c.t.Fatalf("the refresh engine does not take a request for %s", zr.Name)
	}
	select {
	case r := <-resp:
		if r.Error {
			c.t.Fatalf("refresh of %s: %s", zr.Name, r.ErrorMsg)
		}
	case <-time.After(20 * time.Second):
		c.t.Fatalf("no answer to the refresh of %s", zr.Name)
	}
}

// load is the zone's first load: the request the config parser queues for a
// secondary, answered once the engine has transferred the zone, published it
// and run its first-load callbacks.
func (c *refreshCombiner) load(zone string) *MPZoneData {
	c.t.Helper()
	primary := []tdns.PeerConf{{Addr: c.up.addr, Key: tdns.NOKEY}}
	c.ask(tdns.ZoneRefresher{
		Name:          zone,
		ZoneType:      tdns.Secondary,
		ZoneStore:     tdns.MapZone,
		PrimariesConf: primary,
		Primaries:     primary,
		Options:       map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		ConfigUpdate:  true,
		Force:         true,
	})
	mpzd, ok := Zones.Get(zone)
	if !ok || !mpzd.HasPublishedData() {
		c.t.Fatalf("zone %s is not served after its first load", zone)
	}
	return mpzd
}

// refresh is a later refresh of a loaded zone, as a NOTIFY or the zone's
// refresh timer asks for it: the SOA probe, and the transfer when the
// upstream's serial has moved. With force it is an operator's forced
// retransfer, which replaces the zone whatever the serial. It returns once
// the refresh is done.
func (c *refreshCombiner) refresh(zone string, force bool) {
	c.t.Helper()
	c.ask(tdns.ZoneRefresher{Name: zone, Force: force, Wait: true})
}

// wantServed checks an RRset of the zone's own, from its upstream.
func (c *refreshCombiner) wantServed(when string, mpzd *MPZoneData, owner string, rrtype uint16, want int) {
	c.t.Helper()
	if got := servedNames(c.t, mpzd.ZoneData, owner, rrtype); len(got) != want {
		c.t.Errorf("%s: %s %s in %s: %v, want %d record(s)", when, owner, dns.TypeToString[rrtype], mpzd.ZoneName, got, want)
	}
}

// The provider changes something else in its zone, and the combiner's
// refresh takes the new content. The signal names the combiner had published
// there are served after it, as before it. The same after a refresh that
// finds nothing new, and after a forced retransfer of an unchanged zone.
func TestARefreshOfAProviderZoneKeepsTheSignalKeys(t *testing.T) {
	const zone = "refresh.customer.example."
	const www = "www." + consentProviderZone
	both := []string{consentNS1, consentNS2}
	c := newRefreshCombiner(t, consentProviderZone, zone)
	c.up.publish(consentProviderZone, consentProviderText())
	c.up.publish(zone, consentCustomerText(zone, true))
	prov := c.load(consentProviderZone)
	c.load(zone)
	c.sendKey(zone)
	c.addNS(zone, consentNS2)
	c.wantSignalKey("before the refresh", zone, both...)
	c.wantServed("before the refresh", prov, www, dns.TypeA, 0)

	c.up.publish(consentProviderZone, atSerial(consentProviderText(www+" 3600 IN A 192.0.2.80"), 2))
	c.refresh(consentProviderZone, false)
	c.wantServed("a refresh that changed something else", prov, www, dns.TypeA, 1)
	c.wantSignalKey("a refresh that changed something else", zone, both...)
	c.wantStored("a refresh that changed something else", zone, []string{"at-apex", "at-ns"}, both)

	c.refresh(consentProviderZone, false)
	c.wantSignalKey("a refresh that found nothing new", zone, both...)

	c.refresh(consentProviderZone, true)
	c.wantServed("a forced retransfer", prov, www, dns.TypeA, 1)
	c.wantSignalKey("a forced retransfer", zone, both...)
	c.wantServed("a forced retransfer", prov, consentProviderZone, dns.TypeNS, 1)
}

// A refresh of a provider zone asks for the customer's consent before it puts
// the held signal names onto the incoming zone, as a start and a re-apply do.
// Three customers have a name in the provider zone. One says pubkey and keeps
// its name. One has taken pubkey away and nothing has acted on its stored
// instruction since: the refresh retracts its name instead of putting it
// back. One had its names withdrawn before the refresh: they stay away.
func TestARefreshOfAProviderZoneBringsBackNoSignalKeyWithoutConsent(t *testing.T) {
	const says, lacks, gone = "says.refresh.example.", "lacks.refresh.example.", "gone.refresh.example."
	const www = "www." + consentProviderZone
	c := newRefreshCombiner(t, consentProviderZone, says, lacks, gone)
	c.up.publish(consentProviderZone, consentProviderText())
	prov := c.load(consentProviderZone)
	for _, zone := range []string{says, lacks, gone} {
		c.up.publish(zone, consentCustomerText(zone, true))
		c.load(zone)
		c.sendKey(zone)
		c.wantSignalKey("with pubkey", zone, consentNS1)
	}

	// The owners of two of the zones take pubkey away. For one of them an NS
	// change follows, which withdraws its names; for the other nothing does.
	for _, zone := range []string{lacks, gone} {
		c.up.publish(zone, atSerial(consentCustomerText(zone, false), 2))
		c.refresh(zone, false)
	}
	c.addNS(gone, consentNS2)
	c.wantNoSignalKey("withdrawn by an NS change", gone, consentNS1, consentNS2)
	if served, held, _ := c.signalKey(lacks, consentNS1); !served || !held {
		t.Fatalf("the name of %s is gone before the provider zone refreshes (served=%v held=%v), and the test shows nothing", lacks, served, held)
	}

	c.up.publish(consentProviderZone, atSerial(consentProviderText(www+" 3600 IN A 192.0.2.80"), 2))
	c.refresh(consentProviderZone, false)
	c.wantServed("the provider zone's refresh", prov, www, dns.TypeA, 1)
	c.wantSignalKey("the provider zone's refresh", says, consentNS1)
	c.wantStored("the provider zone's refresh", says, []string{"at-apex", "at-ns"}, []string{consentNS1})
	c.wantNoSignalKey("the provider zone's refresh", lacks, consentNS1)
	c.wantStored("the provider zone's refresh", lacks, []string{"at-apex"}, nil)
	c.wantNoSignalKey("the provider zone's refresh", gone, consentNS1, consentNS2)
	c.wantStored("the provider zone's refresh", gone, []string{"at-apex"}, nil)

	// A forced retransfer of the same content brings nothing back either.
	c.refresh(consentProviderZone, true)
	c.wantSignalKey("a forced retransfer", says, consentNS1)
	c.wantNoSignalKey("a forced retransfer", lacks, consentNS1)
	c.wantNoSignalKey("a forced retransfer", gone, consentNS1, consentNS2)
	for _, zone := range []string{says, lacks, gone} {
		cust, _ := Zones.Get(zone)
		c.wantApexKey("a forced retransfer", cust)
	}
}

// A customer zone's refresh is what it was: the owner's new content, with the
// agent's contributions combined onto it, the KEY at the apex and the NS
// added to the owner's. The provider zone, which did not refresh, serves the
// signal names as before.
func TestARefreshOfACustomerZoneCombinesAsBefore(t *testing.T) {
	const zone = "combined.refresh.example."
	const www = "www." + zone
	both := []string{consentNS1, consentNS2}
	c := newRefreshCombiner(t, consentProviderZone, zone)
	c.up.publish(consentProviderZone, consentProviderText())
	c.up.publish(zone, consentCustomerText(zone, true))
	c.load(consentProviderZone)
	cust := c.load(zone)
	c.sendKey(zone)
	c.addNS(zone, consentNS2)
	c.wantApexKey("before the refresh", cust)
	c.wantServed("before the refresh", cust, zone, dns.TypeNS, 2)

	c.up.publish(zone, atSerial(consentCustomerText(zone, true)+www+" 3600 IN A 192.0.2.81\n", 2))
	c.refresh(zone, false)
	c.wantServed("the customer zone's refresh", cust, www, dns.TypeA, 1)
	c.wantApexKey("the customer zone's refresh", cust)
	c.wantServed("the customer zone's refresh", cust, zone, dns.TypeNS, 2)
	c.wantSignalKey("the customer zone's refresh", zone, both...)
	c.wantStored("the customer zone's refresh", zone, []string{"at-apex", "at-ns"}, both)
}
