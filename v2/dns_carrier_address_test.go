/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The DNS carrier dials only a DNS address (tdns-transport
 * docs/2026-10-27-dns-carrier-address.md). A peer that offers only the API
 * has no DNS carrier address. The sites that ask whether there is anywhere
 * to send to a peer ask Addressable: they count such a peer while its API
 * is usable, and no longer once its TLSA is withdrawn. The ping operation
 * goes over the transport the operator names, and that one only.
 */
package tdnsmp

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// setDNSCarrier sets the address the DNS carrier dials, which a test passes
// as a DNS address.
func setDNSCarrier(t *testing.T, p *transport.Peer, addr *transport.Address) {
	t.Helper()
	if err := p.SetDNSCarrierAddress(addr); err != nil {
		t.Fatalf("SetDNSCarrierAddress: %v", err)
	}
}

const apiOnlyTLSAOwner = "_8443._tcp.api.api-only.example."

// apiOnly gives p what discovery gives a peer that offers only the API: an
// endpoint, the API's address and, when usable, a TLSA. Without one it is
// the peer after its TLSA was withdrawn: the set is empty, and the API
// mechanism is NEEDED.
func apiOnly(t *testing.T, p *transport.Peer, usable bool) {
	t.Helper()
	p.SetAPIEndpoint("https://api.api-only.example.:8443/api")
	p.SetMechanismAddress("API", &transport.Address{Host: "192.0.2.10", Port: 8443, Transport: "https", Path: "/api"})
	set := transport.TLSASet{Owner: apiOnlyTLSAOwner, Validated: true}
	if usable {
		rr, err := dns.NewRR(apiOnlyTLSAOwner + " 600 IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		if err != nil {
			t.Fatal(err)
		}
		set.Records = []*dns.TLSA{rr.(*dns.TLSA)}
	} else {
		p.SetMechanismState("API", transport.PeerStateNeeded, "TLSA withdrawn")
	}
	p.SetMechanismTLSA("API", set)
	if p.DNSCarrierAddress() != nil || p.APIUsable() != usable || p.Addressable() != usable {
		t.Fatalf("the API-only peer: carrier %v, usable %v, addressable %v; want none, %v, %v",
			p.DNSCarrierAddress(), p.APIUsable(), p.Addressable(), usable, usable)
	}
}

var apiOnlyCases = []struct {
	name   string
	usable bool
}{{"usable API", true}, {"TLSA withdrawn", false}}

// A failed discovery leg does not regress a peer it can still send to. An
// API-only peer counts while its API is usable. Its state is NEEDED here,
// so that only the address clause can keep it.
func TestOnDiscoveryFailedAsksAddressable(t *testing.T) {
	for _, tc := range apiOnlyCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntegEnv(t, nil)
			peer := env.Alice.Bridge.TransportManager.PeerRegistry.GetOrCreate("api-only.example.")
			apiOnly(t, peer, tc.usable)
			env.Alice.Bridge.TransportManager.OnDiscoveryFailed(peer, errors.New("no contact endpoints found"))
			if got := peer.GetState(); (got == transport.PeerStateError) == tc.usable {
				t.Errorf("state %v after a failed discovery; want ERROR only with nothing to send to", got)
			}
		})
	}
}

// A peer in ERROR is re-armed for discovery only when there is nowhere to
// send to it. Its API mechanism is NEEDED in both cases, so that only the
// address clause decides.
func TestRearmFailedDiscoveryAsksAddressable(t *testing.T) {
	for _, tc := range apiOnlyCases {
		t.Run(tc.name, func(t *testing.T) {
			reg := transport.NewPeerRegistry()
			peer := reg.GetOrCreate("api-only.example.")
			apiOnly(t, peer, tc.usable)
			peer.SetMechanismState("API", transport.PeerStateNeeded, "test")
			peer.SetState(transport.PeerStateError, "discovery failed")
			rearmFailedDiscovery(reg, "api-only.example.")
			want := transport.PeerStateNeeded
			if tc.usable {
				want = transport.PeerStateError
			}
			if got := peer.GetState(); got != want {
				t.Errorf("state %v, want %v", got, want)
			}
		})
	}
}

// A message forwarded by another agent starts a discovery of the deliverer
// only when there is nowhere to send to it. Discovery asks for the resolver
// first, which this test watches.
func TestDelivererDiscoveryAsksAddressable(t *testing.T) {
	for _, tc := range apiOnlyCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntegEnv(t, nil)
			const deliverer = "api-only.example."
			apiOnly(t, env.Bob.Bridge.TransportManager.PeerRegistry.GetOrCreate(deliverer), tc.usable)
			discovering := make(chan struct{}, 8)
			env.Bob.Bridge.TransportManager.GetImr = func() *transport.Imr {
				select {
				case discovering <- struct{}{}:
				default:
				}
				return nil
			}

			msg := makeSyncIncomingMessage(t, env.Alice.Identity, env.Bob.Identity, integControlZone, nextDistributionID(),
				map[string][]string{integControlZone: {integControlZone + " 3600 IN NS ns1." + integControlZone}})
			msg.TransportSender = deliverer
			env.Bob.Bridge.routeIncomingMessage(msg)
			if _, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, 5*time.Second); !ok {
				t.Fatal("the transport did not queue the SYNC")
			}

			wait := 2 * time.Second
			if tc.usable {
				wait = 300 * time.Millisecond
			}
			select {
			case <-discovering:
				if tc.usable {
					t.Error("a discovery of a deliverer with a usable API started")
				}
			case <-time.After(wait):
				if !tc.usable {
					t.Error("no discovery of a deliverer with nowhere to send to")
				}
			}
		})
	}
}

// The ping operation goes over the transport the operator names, and that
// one only: DNS when none is named, and a name of neither is refused before
// any ping. Over DNS, an API-only peer has no address to ping, and its
// HTTPS address is not dialled in its place, whatever its API's state.
// Over the API with its TLSA withdrawn, it is not dialled either.
func TestPingGoesOverTheNamedTransportOnly(t *testing.T) {
	for _, tc := range []struct {
		name      string
		usable    bool
		transport string
		want      string
	}{
		{"usable API, --dns", true, "dns", "ping over dns failed"},
		{"TLSA withdrawn, --dns", false, "dns", "ping over dns failed"},
		{"TLSA withdrawn, --api", false, "api", "ping over api failed"},
		{"usable API, no transport named", true, "", "ping over dns failed"},
		{"usable API, a transport of neither kind", true, "udp", `unknown ping_transport "udp" (use dns or api)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newIntegEnv(t, nil)
			conf := &Config{Config: &tdns.Config{}}
			conf.SetMpConfig(&MultiProviderConf{Identity: env.Alice.Identity})
			conf.InternalMp.TransportManager = env.Alice.Bridge.TransportManager
			apiOnly(t, conf.InternalMp.TransportManager.PeerRegistry.GetOrCreate("api-only.example."), tc.usable)

			body, err := json.Marshal(AgentDistribPost{Command: "op", Op: "ping", To: "api-only.example.", PingTransport: tc.transport})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			conf.APIagentDistrib(NewDistributionCache())(w, httptest.NewRequest(http.MethodPost, "/agent/distrib", bytes.NewReader(body)))
			var resp AgentDistribResponse
			if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !resp.Error || !strings.Contains(resp.ErrorMsg, tc.want) {
				t.Errorf("error %v %q, want one with %q", resp.Error, resp.ErrorMsg, tc.want)
			}
			if (tc.transport == "dns" || tc.transport == "") && !strings.Contains(resp.ErrorMsg, "no address available") {
				t.Errorf("the DNS ping found an address to dial: %q", resp.ErrorMsg)
			}
		})
	}
}

// A relocate names an address the DNS carrier will dial. One that names an
// HTTPS address is refused, and the address held stays.
func TestRelocateToAnHTTPSAddressIsRefused(t *testing.T) {
	env, alice, _ := senderRuleEnv(t)
	relocate := func(addr string) {
		routeAs(t, env, alice, []byte(`{"type":"relocate","MyIdentity":"`+alice+`","new_address":`+addr+
			`,"valid_until":`+jsonInt(time.Now().Add(time.Hour).Unix())+`}`))
	}
	relocate(`{"host":"192.0.2.7","port":5353,"transport":"udp"}`)
	relocate(`{"host":"192.0.2.10","port":8443,"transport":"https","path":"/api"}`)
	p, ok := env.Bob.Bridge.PeerRegistry.Get(alice)
	if !ok {
		t.Fatal("the sender is not in the registry")
	}
	if a := p.DNSCarrierAddress(); a == nil || a.Host != "192.0.2.7" || a.Port != 5353 || a.Transport != "udp" {
		t.Errorf("DNSCarrierAddress %+v, want the udp relocate 192.0.2.7:5353 kept", a)
	}
}

// The peer list shows each mechanism's own address: on the API row the
// API's, which a peer that offers both has apart from the DNS carrier's.
func TestPeerListShowsEachMechanismsAddress(t *testing.T) {
	const id = "both.example."
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: "test-agent.example."})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	agent := NewAgent(AgentId(id))
	agent.ApiMethod, agent.DnsMethod = true, true
	ar.S.Set(AgentId(id), agent)
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.TransportManager = &transport.TransportManager{PeerRegistry: transport.NewPeerRegistry()}
	peer := conf.InternalMp.TransportManager.PeerRegistry.GetOrCreate(id)
	peer.SetAPIEndpoint("https://api.both.example.:8443/api")
	peer.SetMechanismAddress("API", &transport.Address{Host: "192.0.2.10", Port: 8443, Transport: "https", Path: "/api"})
	dnsAddr := &transport.Address{Host: "192.0.2.20", Port: 53, Transport: "udp"}
	setDNSCarrier(t, peer, dnsAddr)
	peer.SetMechanismAddress("DNS", dnsAddr)

	rows := map[string]PeerInfo{}
	for _, p := range ListKnownPeers(conf) {
		rows[p.Transport] = p
	}
	for _, want := range []struct {
		transport string
		host      string
		port      uint16
	}{{"API", "192.0.2.10", 8443}, {"DNS", "192.0.2.20", 53}} {
		row, ok := rows[want.transport]
		if !ok {
			t.Errorf("no %s row", want.transport)
			continue
		}
		if row.Port != want.port || len(row.Addresses) != 1 || row.Addresses[0] != want.host {
			t.Errorf("%s row: %v port %d, want %s port %d", want.transport, row.Addresses, row.Port, want.host, want.port)
		}
	}
}
