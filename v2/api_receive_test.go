/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS mechanism end to end (cleanup plan step 5): the transport's
 * own sender posts to the sync API endpoints, the endpoints hand the body
 * to the receive pipeline, and the reply the sender reads back is the
 * pipeline's inline confirmation shaped into the endpoint's response
 * object. What reaches the MP queues is what a NOTIFY(CHUNK) would have
 * delivered, stamped with the mechanism.
 */

package tdnsmp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// postAPIHello routes a hello for zone from sender through the receiver's
// HTTPS pipeline entry and returns the endpoint's response object.
func postAPIHello(t *testing.T, receiver *peerEnv, sender, zone string) *AgentHelloResponse {
	t.Helper()
	body, err := json.Marshal(&transport.HelloPost{
		MessageType: transport.VerbHello, MyIdentity: sender, YourIdentity: receiver.Identity, Zone: zone, Time: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	sink := &apiReplySink{kind: apiEndpointHello, w: rec, local: AgentId(receiver.Identity)}
	if err := receiver.Bridge.ChunkHandler.RouteAPIPayload(context.Background(), body, "127.0.0.1:0", "", sink); err != nil {
		t.Logf("RouteAPIPayload: %v", err)
	}
	var resp AgentHelloResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("hello response %q: %v", rec.Body.String(), err)
	}
	return &resp
}

// apiEndpointsServer serves the receiver's sync API endpoints the way the
// agent router mounts them, under /api/v1. It asks for a client
// certificate and does not require one; the TLSA middleware in front of
// the endpoints is not mounted.
func apiEndpointsServer(t *testing.T, receiver *peerEnv) *httptest.Server {
	t.Helper()
	conf := &Config{}
	conf.InternalMp.MPTransport = receiver.Bridge
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/hello", conf.apiSyncEndpoint(apiEndpointHello))
	mux.HandleFunc("/api/v1/beat", conf.apiSyncEndpoint(apiEndpointBeat))
	mux.HandleFunc("/api/v1/sync/ping", conf.apiSyncEndpoint(apiEndpointPing))
	mux.HandleFunc("/api/v1/msg", conf.apiSyncEndpoint(apiEndpointMsg))
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// apiSender is an HTTPS sender for local that trusts the test receiver,
// and presents the given client certificate, if any.
func apiSender(srv *httptest.Server, local string, certs ...tls.Certificate) *transport.APITransport {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return transport.NewAPITransport(&transport.APITransportConfig{
		LocalID: local, DefaultTimeout: integTestTimeout, TLSConfig: &tls.Config{RootCAs: pool, Certificates: certs}})
}

// clientCert is a self-signed client certificate whose common name is
// identity.
func clientCert(t *testing.T, identity string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAPIReceive_SenderToPipeline(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	const zone = "api-receive.example."
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, bob, alice)
	addHSYNCPARAMServers(t, zd, shortLabel(bob), shortLabel(alice))

	// The production seam: RouteToCallback -> routeIncomingMessage.
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)
	tr := apiSender(srv, alice)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()

	// hello
	hello, err := tr.Hello(ctx, peer, &transport.HelloRequest{SenderID: alice, SharedZones: []string{zone}, Timestamp: time.Now()})
	if err != nil || !hello.Accepted || hello.ResponderID != bob {
		t.Fatalf("Hello: %+v %v", hello, err)
	}
	r, ok := recvWithin(env.Bob.MsgQs.Hello, integTestTimeout)
	if !ok {
		t.Fatal("hello did not reach MsgQs.Hello")
	}
	if r.MessageType != AgentMsgHello || string(r.Identity) != alice || string(r.Zone) != zone || r.Transport != transport.MechanismAPI {
		t.Errorf("hello report: %+v", *r)
	}

	// beat
	beat, err := tr.Beat(ctx, peer, &transport.BeatRequest{SenderID: alice, Zones: []string{zone}, Timestamp: time.Now()})
	if err != nil || !beat.Ack || beat.ResponderID != bob {
		t.Fatalf("Beat: %+v %v", beat, err)
	}
	b, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout)
	if !ok {
		t.Fatal("beat did not reach MsgQs.Beat")
	}
	if b.MessageType != AgentMsgBeat || string(b.Identity) != alice || b.Transport != transport.MechanismAPI || string(b.Zone) != zone {
		t.Errorf("beat report: %+v", *b)
	}
	if p, ok := env.Bob.Bridge.PeerRegistry.Get(alice); !ok || p.GetLastBeatReceived().IsZero() {
		t.Error("the beat must record inbound liveness on the peer")
	}

	// ping: the nonce comes back through the ping confirm
	ping, err := tr.Ping(ctx, peer, &transport.PingRequest{SenderID: alice, Nonce: "n-1", Timestamp: time.Now()})
	if err != nil || !ping.OK || ping.Nonce != "n-1" {
		t.Fatalf("Ping: %+v %v", ping, err)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Ping, integTestTimeout); !ok {
		t.Fatal("ping did not reach MsgQs.Ping")
	}

	// an application message, verbatim on /msg
	payload, _ := json.Marshal(&AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: AgentId(alice), YourIdentity: AgentId(bob),
		Zone: ZoneName(zone), Records: map[string][]string{zone: {zone + " 3600 IN TXT \"api\""}}, Time: time.Now()})
	resp, err := tr.SendApp(ctx, peer, &transport.AppMessage{Scope: zone, TypeToken: "sync", Payload: payload})
	if err != nil || resp.ResponderID != bob {
		t.Fatalf("SendApp: %+v %v", resp, err)
	}
	if resp.Status != transport.ConfirmSuccess && resp.Status != transport.ConfirmPending {
		t.Fatalf("SendApp status %v, want success or pending: %+v", resp.Status, resp)
	}
	m, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("sync did not reach MsgQs.Msg")
	}
	if string(m.OriginatorID) != alice || string(m.Zone) != zone || len(m.Records[zone]) != 1 {
		t.Errorf("sync delivered: %+v", m.AgentMsgPost)
	}
}

// A body the parser cannot read is answered with the endpoint's error
// shape, not an HTTP error, and never reaches a queue.
func TestAPIReceive_BadBody(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)
	res, err := srv.Client().Post(srv.URL+"/api/v1/beat", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var reply AgentBeatResponse
	if err := json.NewDecoder(res.Body).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !reply.Error || string(reply.MyIdentity) != env.Bob.Identity {
		t.Errorf("empty body: status %d reply %+v", res.StatusCode, reply)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Error("an unparseable body must not reach MsgQs.Beat")
	}
}

// Each endpoint takes its own verbs: a beat or a sync posted to /hello (the
// route without the TLSA middleware), or a hello posted to /beat, is refused
// before the pipeline and reaches no queue.
func TestAPIReceive_EndpointTakesOnlyItsVerbs(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	const zone = "api-verbs.example."
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, bob, alice)
	addHSYNCPARAMServers(t, zd, shortLabel(bob), shortLabel(alice))
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)

	beat, _ := json.Marshal(&transport.BeatPost{MessageType: transport.VerbBeat, MyIdentity: alice, YourIdentity: bob, Zones: []string{zone}, Time: time.Now()})
	sync, _ := json.Marshal(&AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: AgentId(alice), YourIdentity: AgentId(bob),
		Zone: ZoneName(zone), Records: map[string][]string{zone: {zone + " 3600 IN TXT \"verbs\""}}, Time: time.Now()})
	hello, _ := json.Marshal(&transport.HelloPost{MessageType: transport.VerbHello, MyIdentity: alice, YourIdentity: bob, Zone: zone, Time: time.Now()})

	for _, c := range []struct {
		path string
		body []byte
	}{{"/api/v1/hello", beat}, {"/api/v1/hello", sync}, {"/api/v1/beat", hello}, {"/api/v1/msg", beat}} {
		res, err := srv.Client().Post(srv.URL+c.path, "application/json", bytes.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		var reply map[string]interface{}
		err = json.NewDecoder(res.Body).Decode(&reply)
		res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if reply["Error"] != true {
			t.Errorf("%s took a body it must refuse: %v", c.path, reply)
		}
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Error("a refused beat reached MsgQs.Beat")
	}
	if _, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, 100*time.Millisecond); ok {
		t.Error("a refused sync reached MsgQs.Msg")
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Hello, 100*time.Millisecond); ok {
		t.Error("a refused hello reached MsgQs.Hello")
	}
}

// A bridge without the DNS mechanism registers no CHUNK NOTIFY handler, and
// still has the receive pipeline for the HTTPS entry.
func TestBridge_WithoutDNSRegistersNoChunkNotifyHandler(t *testing.T) {
	id := "api-only.agent.example."
	mp := &MultiProviderConf{Identity: id}
	registry := &AgentRegistry{
		S: core.NewStringer[AgentId, *Agent](), LocalAgent: mp,
		ProviderGroupManager: NewProviderGroupManager(id), GossipStateTable: NewGossipStateTable(id),
	}
	bridge, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role: roleAgent, LocalID: id, ControlZone: integControlZone, APITimeout: time.Second, DNSTimeout: time.Second,
		AgentRegistry: registry, MsgQs: &MsgQs{}, ChunkMode: "edns0", SupportedMechanisms: []string{"api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bridge.DNSTransport != nil || bridge.ChunkHandler == nil {
		t.Fatalf("DNSTransport=%v ChunkHandler=%v, want no DNS transport and a receive pipeline", bridge.DNSTransport, bridge.ChunkHandler)
	}
	if err := bridge.RegisterChunkNotifyHandler(); err == nil {
		t.Fatal("RegisterChunkNotifyHandler must refuse without a DNS transport")
	}
	if err := bridge.Start(context.Background()); err != nil {
		t.Fatalf("Start without DNS: %v", err)
	}
}

// The answer to an HTTPS beat carries the receiver's gossip, as the answer
// to a DNS beat does (plan decision 26): alice beats bob over HTTPS only,
// and bob's row for the zone's group is in alice's gossip table when the
// beat returns.
// apiGossipEnv is alice and bob sharing zone, each with its own gossip row
// for the zone's group, and bob's sync API endpoints serving.
func apiGossipEnv(t *testing.T, zone string) (env *integEnv, srv *httptest.Server, group string) {
	t.Helper()
	env = newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	for _, p := range []*peerEnv{env.Alice, env.Bob} {
		pgm := p.Registry.ProviderGroupManager
		pgm.RecomputeGroups()
		pg := pgm.GetGroupForZone(ZoneName(zone))
		if pg == nil {
			t.Fatalf("%s has no provider group for the zone", p.Identity)
		}
		group = pg.GroupHash
		// each agent's own row, as the engine writes it before its beats
		p.Registry.GossipStateTable.RefreshLocalStates(p.Registry, pgm)
	}
	env.Bob.Registry.S.Set(AgentId(alice), NewAgent(AgentId(alice)))
	env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	return env, apiEndpointsServer(t, env.Bob), group
}

func TestAPIReceive_BeatAnswerCarriesGossip(t *testing.T) {
	env, srv, group := apiGossipEnv(t, "api-gossip.example.")
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	tr := apiSender(srv, alice)
	env.Alice.Bridge.APITransport = tr
	env.Alice.Bridge.TransportManager.APITransport = tr
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())
	peer.SetMechanismState("API", transport.PeerStateIntroducing, "said hello")
	if err := env.Alice.Bridge.PeerRegistry.Add(peer); err != nil {
		t.Fatalf("the peer: %v", err)
	}
	agent := NewAgent(AgentId(bob))
	agent.ApiMethod = true // and no DNS: the gossip can only come over HTTPS

	ours := env.Alice.Registry.GossipStateTable
	ours.mu.RLock()
	before := ours.States[group][bob]
	ours.mu.RUnlock()
	if before != nil {
		t.Fatal("alice has bob's row before any beat")
	}
	resp, err := env.Alice.Bridge.SendBeatWithFallback(env.ctx, agent, 1)
	if err != nil || resp == nil || !resp.Ack {
		t.Fatalf("the beat: %+v %v", resp, err)
	}
	if len(resp.Gossip) == 0 {
		t.Error("the answer to the HTTPS beat carried no gossip")
	}
	ours.mu.RLock()
	heard := ours.States[group][bob]
	ours.mu.RUnlock()
	if heard == nil || heard.Identity != bob {
		t.Fatalf("alice did not get bob's row with the answer to her HTTPS beat: %+v", heard)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout); !ok {
		t.Error("the beat did not reach bob's MsgQs.Beat")
	}
}

// On /beat and /sync/ping the sender the body names is the identity of the
// client certificate (review M1 of plan decision 26). A peer that presents
// its own certificate and names alice gets no answer, and no gossip built
// for alice; the beat reaches no queue. Alice's own certificate, its name
// in other case and without the trailing dot, is alice.
func TestAPIReceive_SenderIsTheClientCertificate(t *testing.T) {
	const zone = "api-cert.example."
	env, srv, _ := apiGossipEnv(t, zone)
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()

	carol := apiSender(srv, alice, clientCert(t, "carol.agent.example."))
	beat, err := carol.Beat(ctx, peer, &transport.BeatRequest{SenderID: alice, Zones: []string{zone}, Timestamp: time.Now()})
	if err != nil || beat.Ack {
		t.Fatalf("a beat naming alice under carol's certificate was taken: %+v %v", beat, err)
	}
	if len(beat.Gossip) != 0 {
		t.Errorf("carol got the gossip built for alice: %s", beat.Gossip)
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Error("a beat naming alice under carol's certificate reached MsgQs.Beat")
	}
	ping, err := carol.Ping(ctx, peer, &transport.PingRequest{SenderID: alice, Nonce: "n-1", Timestamp: time.Now()})
	if err != nil || ping.OK {
		t.Fatalf("a ping naming alice under carol's certificate was answered: %+v %v", ping, err)
	}
	// Under her own certificate alice names herself in OriginatorID, which
	// the parser reads first, and carol in MyIdentity, which the beat
	// router reads first: refused as a whole, not booked as carol's beat.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{clientCert(t, alice)}}}}
	body := `{"MessageType":"beat","OriginatorID":"` + alice + `","MyIdentity":"carol.agent.example.","Zones":["` + zone + `"]}`
	res, err := client.Post(srv.URL+"/api/v1/beat", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	var reply AgentBeatResponse
	err = json.NewDecoder(res.Body).Decode(&reply)
	res.Body.Close()
	if err != nil || !reply.Error || len(reply.Gossip) != 0 {
		t.Fatalf("a beat naming alice and carol under alice's certificate: %+v %v", reply, err)
	}
	if b, ok := recvWithin(env.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Errorf("a beat naming alice and carol reached MsgQs.Beat as %s's", b.Identity)
	}

	own := apiSender(srv, alice, clientCert(t, "Alice.Agent.Example"))
	beat, err = own.Beat(ctx, peer, &transport.BeatRequest{SenderID: alice, Zones: []string{zone}, Timestamp: time.Now()})
	if err != nil || !beat.Ack {
		t.Fatalf("alice's beat under her own certificate: %+v %v", beat, err)
	}
	if len(beat.Gossip) == 0 {
		t.Error("the answer to alice's beat under her own certificate carried no gossip")
	}
	if _, ok := recvWithin(env.Bob.MsgQs.Beat, integTestTimeout); !ok {
		t.Error("alice's beat did not reach MsgQs.Beat")
	}
}

// A SYNC sent over HTTPS carries its sender's distribution ID, and the
// receiver confirms it under that ID, over DNS: the confirmation finds the
// sender's queue entry (issue #221). Before, the receiver gave the message
// an ID of its own, and the entry stayed in the sender's queue, to be sent
// again for a day.
func TestAPIReceive_ASyncIsConfirmedUnderTheSendersDistributionID(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ControlZoneIsIdentity: true})
	const zone = "confirm.https.example."
	const distID = "d-221"
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, bob, alice)
	addHSYNCPARAMServers(t, zd, shortLabel(bob), shortLabel(alice))

	// alice takes the confirmation over DNS
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alice's listener: %v", err)
	}
	env.Alice.Registry.S.Set(AgentId(bob), NewAgent(AgentId(bob)))
	env.Alice.Bridge.PeerRegistry.GetOrCreate(bob)
	serveDNS(t, env.ctx, ln, env.Alice)
	if err := env.Bob.Bridge.PeerRegistry.Add(peerFromAddress(alice, ln.Addr().String())); err != nil {
		t.Fatalf("alice at bob: %v", err)
	}

	// bob takes the SYNC over HTTPS
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	srv := apiEndpointsServer(t, env.Bob)
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(peer, srv.Certificate())

	// the SYNC in alice's queue, as the reliable queue holds it while it is
	// out (its worker is not running here)
	queue := env.Alice.Bridge.ReliableQueue
	if err := queue.Enqueue(&transport.OutgoingMessage{DistributionID: distID, RecipientID: bob, Zone: zone}); err != nil {
		t.Fatalf("the queue: %v", err)
	}
	state := func() string {
		for _, m := range queue.GetPendingMessages() {
			if m.DistributionID == distID {
				return m.State
			}
		}
		return "gone"
	}
	before := state()

	msg, err := syncAppMessage(&PeerSyncRequest{SenderID: alice, Zone: zone, MessageType: "sync", Timestamp: time.Now(),
		DistributionID: distID, Operations: []core.RROperation{{Operation: "replace", RRtype: "TXT",
			Records: []string{zone + " 3600 IN TXT \"https\""}}}}, bob)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()
	resp, err := apiSender(srv, alice).SendApp(ctx, peer, msg)
	if err != nil || resp.ResponderID != bob {
		t.Fatalf("SendApp: %+v %v", resp, err)
	}
	m, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the SYNC did not reach bob's message queue")
	}
	if m.DistributionID != distID {
		t.Errorf("bob has the SYNC under %q, want the sender's %q", m.DistributionID, distID)
	}
	for deadline := time.Now().Add(integTestTimeout); state() == before; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("bob's confirmation did not reach alice's queue entry: it is still %s", before)
		}
	}
	if got := state(); got != transport.MessageAwaitingConfirm.String() {
		t.Errorf("after bob's PENDING alice's entry is %s, want it awaiting the final confirmation", got)
	}

	// bob's final confirmation, as its data engine sends it once the
	// update is through, under the ID the SYNC came with: it closes the entry
	env.Bob.Bridge.sendRemoteConfirmation(&RemoteConfirmationDetail{OriginatingDistID: m.DistributionID,
		OriginatingSender: alice, Zone: zone, Status: "SUCCESS"})
	for deadline := time.Now().Add(integTestTimeout); state() != "gone"; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("bob's final confirmation did not close alice's queue entry: it is %s", state())
		}
	}
}
