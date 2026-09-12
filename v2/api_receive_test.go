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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
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
	if err := receiver.Bridge.ChunkHandler.RouteAPIPayload(context.Background(), body, "127.0.0.1:0", sink); err != nil {
		t.Logf("RouteAPIPayload: %v", err)
	}
	var resp AgentHelloResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("hello response %q: %v", rec.Body.String(), err)
	}
	return &resp
}

// apiEndpointsServer serves the receiver's sync API endpoints the way the
// agent router mounts them, under /api/v1.
func apiEndpointsServer(t *testing.T, receiver *peerEnv) *httptest.Server {
	t.Helper()
	conf := &Config{}
	conf.InternalMp.MPTransport = receiver.Bridge
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/hello", conf.apiSyncEndpoint(apiEndpointHello))
	mux.HandleFunc("/api/v1/beat", conf.apiSyncEndpoint(apiEndpointBeat))
	mux.HandleFunc("/api/v1/sync/ping", conf.apiSyncEndpoint(apiEndpointPing))
	mux.HandleFunc("/api/v1/msg", conf.apiSyncEndpoint(apiEndpointMsg))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
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
	tr := transport.NewAPITransport(&transport.APITransportConfig{LocalID: alice, DefaultTimeout: integTestTimeout})
	peer := transport.NewPeer(bob)
	peer.APIEndpoint = srv.URL + "/api/v1"
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
	if p, ok := env.Bob.Bridge.PeerRegistry.Get(alice); !ok || p.LastBeatReceived.IsZero() {
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
	res, err := http.Post(srv.URL+"/api/v1/beat", "application/json", nil)
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
