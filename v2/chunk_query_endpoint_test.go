package tdnsmp

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	transport "github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// endpointConf is an agent's DNS config that publishes 192.0.2.1:5354.
func endpointConf(chunkQueryEndpoint string) *MultiProviderConf {
	mp := &MultiProviderConf{Identity: "endpoint.agent.example."}
	mp.Dns.Addresses.Publish = []string{"192.0.2.1"}
	mp.Dns.Port = 5354
	mp.Dns.ChunkQueryEndpoint = chunkQueryEndpoint
	return mp
}

// The endpoint is known in every chunk mode. Whether every NOTIFY names it
// is the query-mode setting, which query mode still requires.
func TestChunkQueryEndpointsInEveryChunkMode(t *testing.T) {
	const want = "192.0.2.1:5354"
	for _, c := range []struct {
		mode, setting string
		inNotify      bool
		fails         bool
	}{
		{mode: "edns0"},
		{mode: "edns0", setting: "bad"},
		{mode: "query", setting: "include", inNotify: true},
		{mode: "query", setting: "none"},
		{mode: "query", setting: "bad", fails: true},
		{mode: "query", fails: true},
	} {
		got, inNotify, err := chunkQueryEndpoints("auditor", endpointConf(c.setting), c.mode)
		if c.fails {
			if err == nil || !strings.Contains(err.Error(), "auditor.dns.chunk_mode=query") {
				t.Errorf("%s/%q: err %v, want the query mode's complaint", c.mode, c.setting, err)
			}
			continue
		}
		if err != nil || got != want || inNotify != c.inNotify {
			t.Errorf("%s/%q: %q, inNotify %v, err %v; want %q, inNotify %v", c.mode, c.setting, got, inNotify, err, want, c.inNotify)
		}
	}
}

// An agent in the default edns0 mode that sends a payload too large for one
// DNS message sends it by query, and its NOTIFY names where to ask, so that
// the receiver need not look the sender's address up.
func TestAnEdns0AgentNamesItsEndpointWhenAPayloadGoesByQuery(t *testing.T) {
	var mu sync.Mutex
	var inline bool
	var named string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if local, ok := o.(*dns.EDNS0_LOCAL); ok {
					switch local.Code {
					case edns0.EDNS0_CHUNK_OPTION_CODE:
						inline = true
					case edns0.EDNS0_CHUNK_QUERY_ENDPOINT_CODE:
						named = string(local.Data)
					}
				}
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	mp := endpointConf("")
	endpoint, inNotify, err := chunkQueryEndpoints("agent", mp, "edns0")
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role: roleAgent, LocalID: mp.Identity, ControlZone: integControlZone, APITimeout: time.Second, DNSTimeout: 2 * time.Second,
		AgentRegistry: &AgentRegistry{
			S: core.NewStringer[AgentId, *Agent](), LocalAgent: mp,
			ProviderGroupManager: NewProviderGroupManager(mp.Identity), GossipStateTable: NewGossipStateTable(mp.Identity),
		},
		MsgQs: &MsgQs{}, ChunkMode: "edns0", SupportedMechanisms: []string{"dns"},
		ChunkQueryEndpoint: endpoint, ChunkQueryEndpointInNotify: inNotify,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := transport.NewPeer("peer.agent.example.")
	if err := peer.SetDNSCarrierAddress(&transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := bridge.DNSTransport.SendApp(ctx, peer, &transport.AppMessage{
		TypeToken: "status", Payload: bytes.Repeat([]byte("x"), 70000), FireAndForget: true,
	}); err != nil {
		t.Fatalf("SendApp: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if inline {
		t.Error("a 70,000-byte payload rode inline")
	}
	if want := "192.0.2.1:5354"; named != want {
		t.Errorf("the NOTIFY names endpoint %q, want %q", named, want)
	}
}
