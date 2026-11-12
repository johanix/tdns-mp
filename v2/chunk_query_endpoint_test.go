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
	tdns "github.com/johanix/tdns/v2"
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

// Only a published address is the endpoint: that is the operator's word for
// where the agent is. Where it listens says nothing of where another host can
// reach it.
func TestOnlyAPublishedAddressIsTheEndpoint(t *testing.T) {
	for _, c := range []struct {
		publish, listen []string
		want            string
	}{
		{listen: []string{"0.0.0.0:5300"}},
		{listen: []string{"127.0.0.1:5300"}},
		{listen: []string{"10.0.0.1:5300"}},
		{listen: []string{"192.0.2.7"}},
		{publish: []string{" "}, listen: []string{"192.0.2.7"}},
		{publish: []string{"192.0.2.1"}, listen: []string{"192.0.2.7"}, want: "192.0.2.1:5354"},
		{publish: []string{"192.0.2.1:5300"}, want: "192.0.2.1:5300"},
		{publish: []string{"2001:db8::7"}, want: "[2001:db8::7]:5354"},
		{publish: []string{"[2001:db8::7]"}, want: "[2001:db8::7]:5354"},
		{publish: []string{"[2001:db8::7]:5300"}, want: "[2001:db8::7]:5300"},
		{publish: []string{"127.0.0.1"}, want: "127.0.0.1:5354"},
		{publish: []string{"agent.example."}, want: "agent.example.:5354"},
	} {
		mp := endpointConf("include")
		mp.Dns.Addresses.Publish = c.publish
		mp.Dns.Addresses.Listen = c.listen
		for _, mode := range []string{"edns0", "query"} {
			got, _, err := chunkQueryEndpoints("agent", mp, mode)
			if err != nil || got != c.want {
				t.Errorf("%s: publish %q, listen %q: %q, err %v; want %q", mode, c.publish, c.listen, got, err, c.want)
			}
		}
	}
}

// endpointAgent is an agent in edns0 mode, its chunk query endpoint set from
// mp as start-up sets it.
func endpointAgent(t *testing.T, mp *MultiProviderConf) *MPTransportBridge {
	t.Helper()
	endpoint, inNotify, err := chunkQueryEndpoints("agent", mp, "edns0")
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role: roleAgent, LocalID: mp.Identity, ControlZone: mp.Identity, APITimeout: time.Second, DNSTimeout: 2 * time.Second,
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
	return bridge
}

// chunkQueriesAt serves DNS on a loopback port, refuses every query, and
// passes on the names of the CHUNK queries it is asked.
func chunkQueriesAt(t *testing.T) (net.Addr, <-chan string) {
	t.Helper()
	asked := make(chan string, 8)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == core.TypeCHUNK {
			asked <- r.Question[0].Name
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr(), asked
}

// sendTooLarge has sender send receiver, at addr, a payload too large for one
// DNS message, and wants the receiver to ask for it where asked listens.
func sendTooLarge(t *testing.T, sender *MPTransportBridge, senderID, receiver string, addr net.Addr, asked <-chan string) {
	t.Helper()
	peer := transport.NewPeer(receiver)
	setDNSCarrier(t, peer, loopbackCarrier(addr))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = sender.DNSTransport.SendApp(ctx, peer, &transport.AppMessage{
		TypeToken: "status", Payload: bytes.Repeat([]byte("x"), 70000), FireAndForget: true,
	})
	select {
	case qname := <-asked:
		if !strings.Contains(qname, senderID) {
			t.Errorf("the receiver asked for %q, not for a payload from %s", qname, senderID)
		}
	case <-ctx.Done():
		t.Fatal("the receiver never asked at the address it has for the sender")
	}
}

func loopbackCarrier(addr net.Addr) *transport.Address {
	return &transport.Address{Host: "127.0.0.1", Port: uint16(addr.(*net.TCPAddr).Port), Transport: "tcp"}
}

// An agent that publishes nothing names no endpoint, so a receiver fetches an
// oversized payload from the address it has for the agent. Named, the listen
// address would have sent it elsewhere: here to a port where nothing answers.
func TestAReceiverAsksAnAgentThatPublishesNothingAtTheAddressItHasForIt(t *testing.T) {
	const bob = "bob.agent.example."
	for _, listen := range []string{"0.0.0.0:1", "127.0.0.1:1", "10.0.0.1:1"} {
		t.Run(listen, func(t *testing.T) {
			chunks, asked := chunkQueriesAt(t)
			env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0"})
			alice := listenDNS(t, env, env.Alice)
			setDNSCarrier(t, env.Alice.Bridge.PeerRegistry.GetOrCreate(bob), loopbackCarrier(chunks))

			mp := &MultiProviderConf{Identity: bob}
			mp.Dns.Addresses.Listen = []string{listen}
			sendTooLarge(t, endpointAgent(t, mp), bob, env.Alice.Identity, alice, asked)
		})
	}
}

// A signer replaces the bridge's chunk handler at its start. Named no
// endpoint, it asks an agent at the address configured for the agent, and not
// at the NOTIFY's source on port 53.
func TestASignerAsksAnAgentThatNamesNoEndpointAtItsConfiguredAddress(t *testing.T) {
	const bob, signer = "bob.agent.example.", "signer.agent.example."
	chunks, asked := chunkQueriesAt(t)

	// initMPSigner sets the process's store of hand-overs.
	prev := actingHeld.Load()
	t.Cleanup(func() { actingHeld.Store(prev) })

	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = newMPTestKeyDB(t)
	conf.Config.Internal.StopCh = make(chan struct{})
	t.Cleanup(func() { close(conf.Config.Internal.StopCh) })
	mpSigner := &MultiProviderConf{Identity: signer, Agents: []*PeerConf{{Identity: bob, Address: chunks.String()}}}
	if err := conf.initMPSigner(mpSigner); err != nil {
		t.Fatalf("initMPSigner: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveDNS(t, ctx, ln, &peerEnv{Identity: signer, Bridge: conf.InternalMp.MPTransport})

	mp := &MultiProviderConf{Identity: bob}
	mp.Dns.Addresses.Listen = []string{"127.0.0.1:1"}
	sendTooLarge(t, endpointAgent(t, mp), bob, signer, ln.Addr(), asked)
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

	bridge := endpointAgent(t, endpointConf(""))
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
