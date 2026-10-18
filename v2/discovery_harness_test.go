/*
 * Discovery for the transport-boundary harness: a resolver a bridge can
 * discover its peers through, and the records it finds.
 *
 * The harness of transport_harness_test.go has no resolver, so a discovery
 * there fails before its first query. The scenarios that are about discovery
 * itself (a peer found without an address, a peer whose key record changed)
 * need the real thing: the transport's own lookups, through a real resolver
 * and its cache, of records a test can change while it runs.
 *
 * discoveryZone is a stand-in for the authoritative servers of the agents'
 * identity zones. It answers from a table of RRsets that the test sets, and
 * counts the queries it gets. harnessImr is a resolver with that server as
 * the stub for everything under harnessIdentitySuffix; each peer of an
 * environment made with integEnvConfig.Discovery has one of its own, as each
 * agent has.
 */

package tdnsmp

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/crypto"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// harnessIdentitySuffix is the zone the harness peers' identities live in
// ("alice.agent.example.", "bob.agent.example.").
const harnessIdentitySuffix = "agent.example."

// discoveryZone answers queries for names under harnessIdentitySuffix from
// a table of RRsets, over UDP and TCP on one loopback port.
type discoveryZone struct {
	addr string // the server's IP address
	port string

	mu      sync.Mutex
	rrsets  map[string][]dns.RR // key: owner name and type
	queries map[string]int      // same key: how often it was asked for
	// denialTTL is how long a resolver may cache the answer that a record
	// is not there, in seconds (cacheDenials).
	denialTTL uint32
}

func rrsetKey(name string, rrtype uint16) string {
	return dns.CanonicalName(name) + "/" + dns.TypeToString[rrtype]
}

// newDiscoveryZone starts the server; it stops with the test.
func newDiscoveryZone(t *testing.T) *discoveryZone {
	t.Helper()
	// One port for UDP and TCP. The system picks the UDP port, and something
	// else on the machine may hold that number for TCP: try another one.
	var (
		pc         *net.UDPConn
		ln         net.Listener
		host, port string
	)
	for try := 1; ; try++ {
		var err error
		pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("discovery zone: listen: %v", err)
		}
		host, port, _ = net.SplitHostPort(pc.LocalAddr().String())
		ln, err = net.Listen("tcp", net.JoinHostPort(host, port))
		if err == nil {
			break
		}
		pc.Close()
		if try == 10 {
			t.Fatalf("discovery zone: listen tcp: %v", err)
		}
	}
	z := &discoveryZone{addr: host, port: port, rrsets: map[string][]dns.RR{}, queries: map[string]int{}}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		z.mu.Lock()
		z.queries[rrsetKey(q.Name, q.Qtype)]++
		rrs := z.rrsets[rrsetKey(q.Name, q.Qtype)]
		denialTTL := z.denialTTL
		z.mu.Unlock()
		// The SOA's TTL and minimum are what a denial is cached for. They
		// are 0 unless the test says otherwise (cacheDenials): a denial is
		// not cached, and a record that a test publishes is found by the
		// next lookup. An answer is cached for its own TTL.
		soa := &dns.SOA{
			Hdr: dns.RR_Header{Name: harnessIdentitySuffix, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: denialTTL},
			Ns:  "ns." + harnessIdentitySuffix, Mbox: "hostmaster." + harnessIdentitySuffix,
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: denialTTL,
		}
		switch {
		case len(rrs) > 0:
			m.Answer = append(m.Answer, rrs...)
		case q.Qtype == dns.TypeSOA && dns.CanonicalName(q.Name) == harnessIdentitySuffix:
			m.Answer = append(m.Answer, soa)
		case q.Qtype == dns.TypeNS && dns.CanonicalName(q.Name) == harnessIdentitySuffix:
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: harnessIdentitySuffix, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns." + harnessIdentitySuffix,
			})
		default:
			// No data: every name the harness asks for exists.
			m.Ns = append(m.Ns, soa)
		}
		_ = w.WriteMsg(m)
	})
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Handler: handler},
		{Listener: ln, Handler: handler},
	} {
		srv := srv
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(integTestTimeout):
			t.Fatal("discovery zone: server did not start")
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
			defer cancel()
			_ = srv.ShutdownContext(ctx)
		})
	}
	return z
}

// set publishes rrs as the RRset of their owner name and type.
func (z *discoveryZone) set(rrs ...dns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	seen := map[string]bool{}
	for _, rr := range rrs {
		key := rrsetKey(rr.Header().Name, rr.Header().Rrtype)
		if !seen[key] {
			seen[key] = true
			z.rrsets[key] = nil
		}
		z.rrsets[key] = append(z.rrsets[key], rr)
	}
}

// cacheDenials has the zone's denials cached for ttl seconds from now on: a
// resolver that was told that a record is not there goes on saying so for
// that long, also after the record has been published.
func (z *discoveryZone) cacheDenials(ttl uint32) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.denialTTL = ttl
}

// asked reports how many queries for name and rrtype have reached the
// server: lookups the resolver did not answer from its cache.
func (z *discoveryZone) asked(name string, rrtype uint16) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.queries[rrsetKey(name, rrtype)]
}

// harnessImr returns a resolver that asks zone for everything under
// harnessIdentitySuffix. It does not require validated answers: the zone is
// not signed.
func harnessImr(t *testing.T, zone *discoveryZone) *Imr {
	t.Helper()
	c := cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	// The stub's servers are reached through the cache's shared clients,
	// which dial a fixed port.
	c.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, zone.port, nil)
	c.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, zone.port, nil)
	if err := c.AddStub(harnessIdentitySuffix, []cache.AuthServer{
		{Name: "ns." + harnessIdentitySuffix, Addrs: []string{zone.addr}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("harness resolver: AddStub: %v", err)
	}
	return &Imr{Imr: &tdns.Imr{
		Cache:         c,
		Quiet:         true,
		FamilyTracker: cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, 30*time.Second, 5),
	}}
}

// harnessKey is one long-term key pair of a harness peer.
type harnessKey struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	// jwk is the public key as a JWK record carries it.
	jwk string
}

// newHarnessKey generates a key pair with the default payload-crypto backend.
func newHarnessKey(t *testing.T) *harnessKey {
	t.Helper()
	backend, err := cryptoBackend(nil)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := backend.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	// The record carries the bare key, as AgentJWKKeyPrep publishes it.
	data, err := backend.SerializePublicKey(pub)
	if err != nil {
		t.Fatalf("serialize public key: %v", err)
	}
	var parsed jose.JSONWebKey
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	ecdsaPub, ok := parsed.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is a %T, want an ECDSA key", parsed.Key)
	}
	jwk, _, err := core.EncodePublicKeyToJWK(ecdsaPub, "")
	if err != nil {
		t.Fatalf("encode JWK: %v", err)
	}
	return &harnessKey{priv: priv, pub: pub, jwk: jwk}
}

// payloadCrypto returns payload crypto with key as the local key pair and no
// peer keys: those come from discovery, or from the test.
func (key *harnessKey) payloadCrypto(t *testing.T) *transport.PayloadCrypto {
	t.Helper()
	backend, err := cryptoBackend(nil)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{Backend: backend, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pc.SetLocalKeys(key.priv, key.pub)
	return pc
}

// dnsURIRecord is the URI record that names identity's DNS endpoint.
func dnsURIRecord(identity string, port int) dns.RR {
	return &dns.URI{
		Hdr:      dns.RR_Header{Name: "_dns._tcp." + identity, Rrtype: dns.TypeURI, Class: dns.ClassINET, Ttl: 60},
		Priority: 10, Weight: 1,
		Target: "dns://dns." + identity + ":" + strconv.Itoa(port) + "/",
	}
}

// dnsSVCBRecord is the SVCB record that gives identity's DNS endpoint its
// address.
func dnsSVCBRecord(identity, address string) dns.RR {
	return &dns.SVCB{
		Hdr:      dns.RR_Header{Name: "dns." + identity, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
		Priority: 1, Target: ".",
		Value: []dns.SVCBKeyValue{&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(address)}}},
	}
}

// jwkRecord is the JWK record that publishes identity's long-term key.
func jwkRecord(identity string, key *harnessKey) dns.RR {
	return &dns.PrivateRR{
		Hdr:  dns.RR_Header{Name: "dns." + identity, Rrtype: core.TypeJWK, Class: dns.ClassINET, Ttl: 60},
		Data: &core.JWK{JWKData: key.jwk},
	}
}

// dnsDiscoveryRecords is what a peer publishes for its DNS mechanism: where
// it listens and the key it uses.
func dnsDiscoveryRecords(identity string, listener net.Addr, key *harnessKey) []dns.RR {
	host, port, _ := net.SplitHostPort(listener.String())
	p, _ := strconv.Atoi(port)
	return []dns.RR{dnsURIRecord(identity, p), dnsSVCBRecord(identity, host), jwkRecord(identity, key)}
}

// harnessIntervals are the hsync engine's intervals for a discovery
// scenario: short enough that a retry is a matter of milliseconds.
func harnessIntervals() hsync.Config {
	cfg := hsync.DefaultConfig()
	cfg.RetryInterval = 50 * time.Millisecond
	cfg.ReconcileInterval = time.Hour
	cfg.BeatIntervalMin, cfg.BeatInterval = 50*time.Millisecond, time.Second
	cfg.HelloFastSpacing, cfg.HelloRetryInterval = 50*time.Millisecond, 100*time.Millisecond
	return cfg
}

// startHarnessEngine gives pe the hsync engine an agent runs, on the peer's
// own bridge and fed from the peer's queues, and starts it. It stops with
// the test. A scenario that needs more than that adjusts the engine's
// dependencies with with.
func startHarnessEngine(t *testing.T, env *integEnv, pe *peerEnv, cfg hsync.Config, with ...func(*hsync.Deps)) *hsync.Engine {
	t.Helper()
	ar := pe.Registry
	deps := hsync.Deps{
		LocalID:   hsync.PeerID(pe.Identity),
		Transport: &mpHsyncBridge{ar: ar, tm: pe.Bridge},
		PeerHooks: hsync.PeerHooks{
			OnPeerStored:  func(peer *hsync.Peer) { ar.materializeAgentView(peer) },
			OnPeerRemoved: func(peer *hsync.Peer) { ar.removePeerView(peer.ID) },
		},
	}
	for _, adjust := range with {
		adjust(&deps)
	}
	engine := hsync.NewEngine(deps, cfg)
	ar.HsyncEngine = engine
	ar.Registry = engine.Registry()
	go engine.Run(env.ctx, hsync.MsgChannels{
		Hello: adaptHelloReports(env.ctx, pe.MsgQs.Hello, nil, nil, ar),
		Beat:  adaptBeatReports(env.ctx, pe.MsgQs.Beat, nil, ar),
		Msg:   adaptInboundMsgs(env.ctx, pe.MsgQs.Msg),
	})
	return engine
}

// listenDNS has pe answer NOTIFY(CHUNK) on a loopback port, through its
// receive pipeline, and returns the address it listens on.
func listenDNS(t *testing.T, env *integEnv, pe *peerEnv) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for %s: %v", pe.Identity, err)
	}
	pe.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, pe)
	return ln.Addr()
}

// dnsState is the raw state of the DNS mechanism that pe holds for peer.
func dnsState(pe *peerEnv, peer string) transport.PeerState {
	p, ok := pe.Bridge.PeerRegistry.Get(peer)
	if !ok {
		return transport.PeerStateNeeded
	}
	st, _ := p.MechanismRawState(transport.MechanismDNS)
	return st
}

// waitForDNSState waits until pe holds peer's DNS mechanism in state want.
func waitForDNSState(t *testing.T, pe *peerEnv, peer string, want transport.PeerState, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for dnsState(pe, peer) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s holds the DNS mechanism of %s at %v after %v, want %v", pe.Identity, peer, dnsState(pe, peer), d, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
