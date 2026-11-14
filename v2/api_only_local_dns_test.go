/*
 * An agent whose supported_mechanisms leave DNS out still reaches its own
 * signer and combiner over DNS, the only mechanism those two speak. Between
 * agents supported_mechanisms decides: such an agent sends nothing to
 * another agent over DNS, and hears nothing from one.
 */

package tdnsmp

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	localDNSAgentID    = "local-dns.agent.example."
	localDNSSignerID   = "signer.local-dns.example."
	localDNSCombinerID = "combiner.local-dns.example."
	localDNSOtherID    = "bob.agent.example."
)

// localDNSAgent is an agent with the given supported_mechanisms, its signer
// at signerAddr and a combiner, as an agent's config names them. It
// authorizes its signer and combiner, as an agent does, and the other agent
// localDNSOtherID.
func localDNSAgent(t *testing.T, signerAddr string, mechanisms ...string) *peerEnv {
	t.Helper()
	mp := &MultiProviderConf{Identity: localDNSAgentID}
	registry := &AgentRegistry{
		S: core.NewStringer[AgentId, *Agent](), LocalAgent: mp,
		ProviderGroupManager: NewProviderGroupManager(localDNSAgentID), GossipStateTable: NewGossipStateTable(localDNSAgentID),
	}
	msgQs := &MsgQs{
		Msg:               make(chan *AgentMsgPostPlus, 4),
		Hello:             make(chan *AgentMsgReport, 4),
		Beat:              make(chan *AgentMsgReport, 4),
		Ping:              make(chan *AgentMsgReport, 4),
		Confirmation:      make(chan *ConfirmationDetail, 4),
		KeystateInventory: make(chan *KeystateInventoryMsg, 4),
		KeystateSignal:    make(chan *KeystateSignalMsg, 4),
		StatusUpdate:      make(chan *StatusUpdateMsg, 4),
	}
	bridge, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role: roleAgent, LocalID: localDNSAgentID, ControlZone: localDNSAgentID,
		APITimeout: 2 * time.Second, DNSTimeout: 2 * time.Second,
		AgentRegistry: registry, MsgQs: msgQs, ChunkMode: "edns0", SupportedMechanisms: mechanisms,
		CombinerID: localDNSCombinerID, SignerID: localDNSSignerID, SignerAddress: signerAddr,
		AuthorizedPeers: func() []string { return []string{localDNSSignerID, localDNSCombinerID, localDNSOtherID} },
		GetZone:         tdns.Zones.Get, GetZoneNames: tdns.Zones.Keys,
	})
	if err != nil {
		t.Fatalf("NewMPTransportBridge: %v", err)
	}
	registry.MPTransport = bridge
	registry.TransportManager = bridge.TransportManager
	return &peerEnv{Identity: localDNSAgentID, Registry: registry, Bridge: bridge, MsgQs: msgQs}
}

// localDNSSigner is the agent's signer: a signer's bridge that authorizes
// the agent.
func localDNSSigner(t *testing.T) *peerEnv {
	t.Helper()
	return newPeer(t, localDNSSignerID, "edns0", &integEnvConfig{
		Role: roleSigner, ControlZoneIsIdentity: true, AuthorizedPeers: []string{localDNSAgentID}})
}

// serveDNSOn serves handle over UDP and TCP at one loopback port, and
// returns that address.
func serveDNSOn(t *testing.T, handle dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	var started sync.WaitGroup
	started.Add(2)
	servers := []*dns.Server{
		{PacketConn: pc, Handler: handle, NotifyStartedFunc: started.Done},
		{Listener: ln, Net: "tcp", Handler: handle, NotifyStartedFunc: started.Done},
	}
	for _, srv := range servers {
		go func() { _ = srv.ActivateAndServe() }()
	}
	started.Wait()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		for _, srv := range servers {
			_ = srv.ShutdownContext(ctx)
		}
	})
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// An agent without the DNS mechanism has the DNS transport for its own
// signer and combiner, and DNS goes to them and to no one else. With the
// mechanism, DNS goes to any peer.
func TestAnAgentWithoutDNSHasItForItsOwnSignerAndCombinerOnly(t *testing.T) {
	apiOnly := localDNSAgent(t, "127.0.0.1:53", "api")
	if apiOnly.Bridge.DNSTransport == nil {
		t.Fatal("an api-only agent with a signer and a combiner has no DNS transport")
	}
	both := localDNSAgent(t, "127.0.0.1:53", "api", "dns")
	for _, tc := range []struct {
		peer          string
		apiOnly, both bool
	}{
		{localDNSSignerID, true, true},
		{localDNSCombinerID, true, true},
		{"COMBINER.local-dns.example", true, true},
		{localDNSOtherID, false, true},
		{"", false, true},
	} {
		if got := apiOnly.Bridge.dnsWith(tc.peer); got != tc.apiOnly {
			t.Errorf("api-only agent: dnsWith(%q) = %v, want %v", tc.peer, got, tc.apiOnly)
		}
		if got := both.Bridge.dnsWith(tc.peer); got != tc.both {
			t.Errorf("api+dns agent: dnsWith(%q) = %v, want %v", tc.peer, got, tc.both)
		}
	}
	if got := chunkNotifySender("6981284f." + localDNSSignerID); got != localDNSSignerID {
		t.Errorf("chunkNotifySender = %q, want %q", got, localDNSSignerID)
	}
	if got := chunkNotifySender("6981284f."); got != "" {
		t.Errorf("chunkNotifySender of a name with no sender = %q, want none", got)
	}
}

// An agent without the DNS mechanism hands a zone over to its signer: the
// hand-over goes over DNS and reaches the signer as a KEYSTATE "acting".
// Before, the agent had no DNS transport and the hand-over was never sent.
func TestAnAgentWithoutDNSHandsAZoneOverToItsSigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	signer := localDNSSigner(t)
	signer.Bridge.StartIncomingMessageRouter(ctx)
	addr := serveDNSOn(t, func(w dns.ResponseWriter, r *dns.Msg) {
		_ = signer.Bridge.ChunkHandler.RouteViaRouter(ctx, r.Question[0].Name, r, w)
	})
	agent := localDNSAgent(t, addr, "api")

	zone := "handed.local-dns.example."
	handover := &ActingHandover{Zone: zone, Serial: 7, Newest: 7, Digest: "d7", Made: time.Now()}
	if _, err := agent.Bridge.sendActingToSigner(ZoneName(zone), &ZoneUpdate{Acting: handover}, "d1"); err != nil {
		t.Fatalf("the hand-over to the signer: %v", err)
	}
	sig, ok := recvWithin(signer.MsgQs.KeystateSignal, integTestTimeout)
	if !ok {
		t.Fatal("the hand-over did not reach the signer")
	}
	if sig.Signal != "acting" || sig.Zone != zone || sig.SenderID != localDNSAgentID || sig.Acting == nil || sig.Acting.Serial != 7 {
		t.Fatalf("the signer has %+v, want the agent's hand-over of %s at serial 7", sig, zone)
	}
}

// An agent hears its signer over DNS whatever its mechanisms: the signer's
// key inventory reaches it. Another agent's NOTIFY reaches it only with the
// DNS mechanism. Without it the NOTIFY is refused before it is read, though
// the agent authorizes that agent.
func TestAnAgentWithoutDNSHearsItsSignerAndNoOtherAgent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mechanisms []string
		otherHeard bool
	}{
		{"api only", []string{"api"}, false},
		{"api and dns", []string{"api", "dns"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			agent := localDNSAgent(t, "127.0.0.1:53", tc.mechanisms...)
			agent.Bridge.StartIncomingMessageRouter(ctx)
			host, port := parseHostPort(serveDNSOn(t, func(w dns.ResponseWriter, r *dns.Msg) {
				_ = agent.Bridge.chunkNotify(ctx, &tdns.DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: r.Question[0].Name})
			}), 53)
			agentAt := func(t *testing.T) *transport.Peer {
				p := transport.NewPeer(localDNSAgentID)
				setDNSCarrier(t, p, &transport.Address{Host: host, Port: port, Transport: "udp"})
				return p
			}

			signer := localDNSSigner(t)
			zone := "heard.local-dns.example."
			sctx, scancel := context.WithTimeout(ctx, integTestTimeout)
			defer scancel()
			resp, err := signer.Bridge.sendKeystate(sctx, agentAt(t), &PeerKeystateRequest{
				SenderID: localDNSSignerID, Zone: zone, Signal: "inventory", Timestamp: time.Now()})
			if err != nil || !resp.Accepted {
				t.Fatalf("the signer's inventory: resp %+v, err %v", resp, err)
			}
			inv, ok := recvWithin(agent.MsgQs.KeystateInventory, integTestTimeout)
			if !ok {
				t.Fatal("the signer's inventory did not reach the agent")
			}
			if inv.Zone != zone || inv.SenderID != localDNSSignerID {
				t.Fatalf("the agent has %+v, want the signer's inventory of %s", inv, zone)
			}

			other := newPeer(t, localDNSOtherID, "edns0", &integEnvConfig{ControlZoneIsIdentity: true})
			pctx, pcancel := context.WithTimeout(ctx, integTestTimeout)
			defer pcancel()
			_, err = other.Bridge.DNSTransport.Ping(pctx, agentAt(t), &transport.PingRequest{
				SenderID: localDNSOtherID, Nonce: "0123456789abcdef", Timestamp: time.Now()})
			switch {
			case tc.otherHeard && err != nil:
				t.Fatalf("the other agent's ping over DNS: %v", err)
			case !tc.otherHeard && (err == nil || !strings.Contains(err.Error(), "rcode REFUSED")):
				t.Fatalf("the other agent's ping over DNS: err %v, want REFUSED", err)
			}
		})
	}
}

// An agent without the DNS mechanism beats its signer over DNS, as its infra
// beat loop does: the beat is eligible for DNS because the peer is its own
// signer.
func TestAnAgentWithoutDNSBeatsItsSigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	signer := localDNSSigner(t)
	signer.Bridge.StartIncomingMessageRouter(ctx)
	addr := serveDNSOn(t, func(w dns.ResponseWriter, r *dns.Msg) {
		_ = signer.Bridge.ChunkHandler.RouteViaRouter(ctx, r.Question[0].Name, r, w)
	})
	agent := localDNSAgent(t, addr, "api")

	// the signer as an agent registers it (InitializeSignerAsPeer)
	infra := &Agent{Peer: hsync.NewPeer(hsync.PeerID(localDNSSignerID))}
	infra.DnsMethod, infra.IsInfraPeer = true, true
	agent.Registry.S.Set(AgentId(localDNSSignerID), infra)
	host, port := parseHostPort(addr, 53)
	speer := agent.Bridge.PeerRegistry.GetOrCreate(localDNSSignerID)
	setDNSCarrier(t, speer, &transport.Address{Host: host, Port: port, Transport: "udp"})
	speer.SetMechanismState("DNS", transport.PeerStateOperational, "signer infra peer")

	bctx, bcancel := context.WithTimeout(ctx, integTestTimeout)
	defer bcancel()
	resp, err := agent.Bridge.SendBeatWithFallback(bctx, infra, 1)
	if err != nil || resp == nil {
		t.Fatalf("the beat to the signer: resp %+v, err %v", resp, err)
	}
}
