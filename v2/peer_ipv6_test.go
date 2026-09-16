/*
 * Peers at IPv6 addresses: the endpoint strings carry the host in
 * brackets, and `peer ping` reaches such a peer over DNS instead of
 * failing over to an API endpoint the peer does not have.
 */

package tdnsmp

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// serveDNS answers NOTIFY(CHUNK) over TCP on ln through receiver's
// receive pipeline, the way tdns routes them in production.
func serveDNS(t *testing.T, ctx context.Context, ln net.Listener, receiver *peerEnv) {
	t.Helper()
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = receiver.Bridge.ChunkHandler.RouteViaRouter(ctx, r.Question[0].Name, r, w)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		_ = srv.ShutdownContext(ctx)
	})
}

func TestDNSEndpointURI(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
		want string
	}{
		{"192.0.2.1", 8055, "dns://192.0.2.1:8055/"},
		{"::1", 8055, "dns://[::1]:8055/"},
		{"2001:db8::53", 53, "dns://[2001:db8::53]:53/"},
		{"combiner.example.", 8053, "dns://combiner.example.:8053/"},
	} {
		if got := dnsEndpointURI(tc.host, tc.port); got != tc.want {
			t.Errorf("dnsEndpointURI(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// The query-mode receiver dials the sender at the address GetPeerAddress
// returns; an IPv6 host must come back bracketed.
func TestGetPeerAddress_IPv6(t *testing.T) {
	env := newIntegEnv(t, nil)
	const carol = "carol.agent.example."
	p := transport.NewPeer(carol)
	p.SetDiscoveryAddress(&transport.Address{Host: "2001:db8::53", Port: 8053, Transport: "udp"})
	if err := env.Bob.Bridge.PeerRegistry.Add(p); err != nil {
		t.Fatal(err)
	}
	addr, ok := env.Bob.Bridge.ChunkHandler.GetPeerAddress(carol)
	if !ok || addr != "[2001:db8::53]:8053" {
		t.Fatalf("GetPeerAddress(%s) = %q, %v; want [2001:db8::53]:8053", carol, addr, ok)
	}
}

// `peer ping` from an agent to a combiner configured at [::1]:port goes
// over DNS. Before the fix the DNS dial failed on the unbracketed host and
// the ping fell back to the API, reporting "no API endpoint configured".
func TestPeerPing_IPv6StaticPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, env.Bob)

	bob := dns.Fqdn(env.Bob.Identity)
	address := ln.Addr().String()
	conf := &Config{}
	conf.InternalMp.TransportManager = env.Alice.Bridge.TransportManager
	conf.InternalMp.mpConfig.Store(&MultiProviderConf{Role: "agent", Combiner: &PeerConf{Identity: bob, Address: address}})

	peer := conf.lookupStaticPeer(bob)
	if peer == nil {
		t.Fatalf("no static peer for %s at %s", bob, address)
	}
	if want := "dns://" + address + "/"; peer.DNSEndpoint != want {
		t.Errorf("DNSEndpoint = %q, want %q", peer.DNSEndpoint, want)
	}

	resp := doPeerPing(conf, bob, false)
	if resp.Error {
		t.Fatalf("peer ping to %s at %s: %s", bob, address, resp.ErrorMsg)
	}
	if !strings.Contains(resp.Msg, "(dns transport)") {
		t.Errorf("ping went over the wrong transport: %s", resp.Msg)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Ping, integTestTimeout); !ok {
		t.Fatal("ping did not reach the combiner's MsgQs.Ping")
	}
}

// When DNS cannot deliver a ping and the peer has no API endpoint, the
// error names both mechanisms. Before tdns-transport #20 it carried only
// the API miss, which hid why DNS failed.
func TestPeerPing_BothTransportsFailNamesBoth(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	address := ln.Addr().String()
	ln.Close() // nothing listens: the DNS dial is refused

	env := newIntegEnv(t, nil)
	bob := dns.Fqdn(env.Bob.Identity)
	conf := &Config{}
	conf.InternalMp.TransportManager = env.Alice.Bridge.TransportManager
	conf.InternalMp.mpConfig.Store(&MultiProviderConf{Role: "agent", Combiner: &PeerConf{Identity: bob, Address: address}})

	resp := doPeerPing(conf, bob, false)
	if !resp.Error {
		t.Fatalf("ping to %s with nothing listening succeeded: %s", address, resp.Msg)
	}
	for _, want := range []string{"all transports failed", "DNS", "API", "no API endpoint configured"} {
		if !strings.Contains(resp.ErrorMsg, want) {
			t.Errorf("error lacks %q: %s", want, resp.ErrorMsg)
		}
	}
}
