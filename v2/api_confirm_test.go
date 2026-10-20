/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Confirmations over the HTTPS mechanism. The receiver of a SYNC sends its
 * PENDING and its final confirmation over HTTPS when the originator offers
 * it, the originator's /msg takes them and they settle its reliable-queue
 * entry. A confirmation the HTTPS receiver refuses goes over DNS, and a
 * confirmation over HTTPS speaks for the client certificate's identity
 * only.
 */

package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// confirmWait bounds the wait for a confirmation that a goroutine sends.
const confirmWait = 5 * time.Second

// queueState is the state of the message with id in q, "gone" when the
// queue no longer holds it.
func queueState(q *transport.ReliableMessageQueue, id string) string {
	for _, m := range q.GetPendingMessages() {
		if m.DistributionID == id {
			return m.State
		}
	}
	return "gone"
}

// queueSync puts a SYNC for zone to bob in alice's reliable queue, as her
// send of it leaves it: waiting for bob's confirmations.
func queueSync(t *testing.T, env *integEnv, zone string) string {
	t.Helper()
	id := nextDistributionID()
	if err := env.Alice.Bridge.ReliableQueue.Enqueue(&transport.OutgoingMessage{
		DistributionID: id, RecipientID: dns.Fqdn(env.Bob.Identity), Zone: zone}); err != nil {
		t.Fatal(err)
	}
	return id
}

// bobConfirmsOverHTTPS gives bob an HTTPS sender that trusts srv and
// presents bob's certificate, and alice as a peer at srv.
func bobConfirmsOverHTTPS(t *testing.T, env *integEnv, srv *httptest.Server) *transport.Peer {
	t.Helper()
	bob := dns.Fqdn(env.Bob.Identity)
	env.Bob.Bridge.APITransport = apiSender(srv, bob, clientCert(t, bob))
	peer := transport.NewPeer(dns.Fqdn(env.Alice.Identity))
	peer.APIEndpoint = srv.URL + "/api/v1"
	if err := env.Bob.Bridge.PeerRegistry.Add(peer); err != nil {
		t.Fatalf("alice at bob: %v", err)
	}
	return peer
}

// A SYNC from alice reaches bob, and both of bob's confirmations go back
// over HTTPS: the PENDING keeps alice's queue entry waiting, the final
// SUCCESS closes it. Alice has no DNS address at bob, so HTTPS is the only
// way they can reach her.
//
// The SYNC enters bob as a NOTIFY delivers it, with alice's distribution
// ID. Over HTTPS the receiver makes the message an ID of its own until
// the sender puts its own in the payload (plan decision 41, PR #224).
func TestAPIConfirm_SyncConfirmationsOverHTTPS(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	const zone = "api-confirm.example."
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	bobConfirmsOverHTTPS(t, env, apiEndpointsServer(t, env.Alice))

	id := queueSync(t, env, zone)
	records := map[string][]string{zone: {zone + " 3600 IN TXT \"confirm over https\""}}
	env.Bob.Bridge.routeIncomingMessage(makeSyncIncomingMessage(t, alice, bob, zone, id, records))
	if _, ok := recvMsgWithin(t, env.Bob.MsgQs.Msg, integTestTimeout); !ok {
		t.Fatal("the sync did not reach bob's MsgQs.Msg")
	}

	pending, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, confirmWait)
	if !ok {
		t.Fatal("bob's PENDING did not reach alice")
	}
	if pending.DistributionID != id || pending.Source != bob || pending.Status != transport.ConfirmPending.String() {
		t.Fatalf("the PENDING alice got: %+v", pending)
	}
	if got := queueState(env.Alice.Bridge.ReliableQueue, id); got != transport.MessageAwaitingConfirm.String() {
		t.Fatalf("after the PENDING alice's entry is %s, want it awaiting the final confirmation", got)
	}

	// Bob's combiner has applied the records: the final word goes back.
	env.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: alice, Zone: ZoneName(zone), Status: "SUCCESS",
		AppliedRecords: records[zone]})
	final, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, confirmWait)
	if !ok {
		t.Fatal("bob's final confirmation did not reach alice")
	}
	if final.DistributionID != id || final.Source != bob || final.Status != transport.ConfirmSuccess.String() ||
		len(final.AppliedRecords) != 1 {
		t.Fatalf("the final confirmation alice got: %+v", final)
	}
	if got := queueState(env.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
}

// Alice's HTTPS receiver is from before confirmations went over HTTPS: its
// /msg refuses them. Bob's final confirmation goes over DNS instead and
// closes alice's queue entry.
func TestAPIConfirm_RefusedOverHTTPSGoesOverDNS(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	const zone = "api-confirm-fallback.example."
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))

	// What /msg answered a confirmation with before this change.
	var posts atomic.Int32
	old := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		sink := &apiReplySink{kind: apiEndpointMsg, w: w, local: AgentId(alice)}
		_ = sink.fail(fmt.Sprintf("message type %q is not accepted on %s", transport.VerbConfirm, r.URL.Path))
	}))
	t.Cleanup(old.Close)
	peer := bobConfirmsOverHTTPS(t, env, old)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDNS(t, env.ctx, ln, env.Alice)
	addr := &transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	peer.SetDiscoveryAddress(addr)
	peer.SetMechanismAddress("DNS", addr)

	id := queueSync(t, env, zone)
	env.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: alice, Zone: ZoneName(zone), Status: "SUCCESS"})
	final, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, confirmWait)
	if !ok {
		t.Fatal("bob's final confirmation did not reach alice")
	}
	if final.DistributionID != id || final.Source != bob || final.Status != transport.ConfirmSuccess.String() {
		t.Fatalf("the final confirmation alice got: %+v", final)
	}
	if got := queueState(env.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if n := posts.Load(); n != 1 {
		t.Errorf("the HTTPS receiver got %d POSTs, want the one it refused", n)
	}
}

// A confirmation over HTTPS is the word of the client certificate's
// identity. Carol, a peer alice talks to, presents her own certificate and
// names bob: refused, and alice's entry for bob stays. Bob's own
// certificate, his name in other case and without the trailing dot, closes
// it.
func TestAPIConfirm_SenderIsTheClientCertificate(t *testing.T) {
	const carol = "carol.agent.example."
	alice := dns.Fqdn("alice.agent.example.")
	bob := dns.Fqdn("bob.agent.example.")
	env := newIntegEnv(t, &integEnvConfig{AuthorizedPeers: []string{alice, bob, carol}})
	const zone = "api-confirm-cert.example."
	zd := seedZoneWithHSYNC3(t, zone, alice, bob, carol)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob), shortLabel(carol))
	srv := apiEndpointsServer(t, env.Alice)
	peer := transport.NewPeer(alice)
	peer.APIEndpoint = srv.URL + "/api/v1"
	ctx, cancel := context.WithTimeout(context.Background(), confirmWait)
	defer cancel()

	id := queueSync(t, env, zone)
	confirm := &transport.ConfirmRequest{SenderID: bob, Zone: zone, DistributionID: id, Status: transport.ConfirmSuccess, Timestamp: time.Now()}

	err := apiSender(srv, carol, clientCert(t, carol)).Confirm(ctx, peer, confirm)
	if err == nil {
		t.Fatal("a confirmation naming bob under carol's certificate was taken")
	}
	if got, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, 100*time.Millisecond); ok {
		t.Errorf("a confirmation naming bob under carol's certificate reached alice: %+v", got)
	}
	if got := queueState(env.Alice.Bridge.ReliableQueue, id); got == "gone" {
		t.Fatal("a confirmation naming bob under carol's certificate closed alice's entry for bob")
	}

	if err := apiSender(srv, bob, clientCert(t, "Bob.Agent.Example")).Confirm(ctx, peer, confirm); err != nil {
		t.Fatalf("bob's confirmation under his own certificate: %v", err)
	}
	if _, ok := recvConfirmWithin(t, env.Alice.MsgQs.Confirmation, confirmWait); !ok {
		t.Fatal("bob's confirmation under his own certificate did not reach alice")
	}
	if got := queueState(env.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after bob's confirmation alice's entry is %s, want it closed", got)
	}
}

// The body a confirmation posts to /msg, byte-locked like the other HTTPS
// bodies (golden_api_test.go): the confirm payload the DNS mechanism
// carries, which the receiver's parser reads as the verb "confirm" from
// its sender.
func TestGoldenAPIConfirmRequest(t *testing.T) {
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(&AgentMsgResponse{Status: "ok", AgentId: "b.example.", Msg: "received"})
	}))
	t.Cleanup(srv.Close)
	peer := transport.NewPeer("b.example.")
	peer.APIEndpoint = srv.URL + "/api/v1"
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	err := apiSender(srv, "a.example.").Confirm(context.Background(), peer, &transport.ConfirmRequest{
		SenderID: "a.example.", Zone: "z.example.", DistributionID: "d-1", Nonce: "n-1", Status: transport.ConfirmSuccess,
		Message: "applied", AppliedRecords: []string{"z.example. 3600 IN NS ns1.a.example."}, Timestamp: at})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	want, err := os.ReadFile("testdata/golden-api/msg-confirm-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("msg-confirm-request changed:\n got  %s\n want %s", body, want)
	}
	im, err := parseAppPayload("", body, "127.0.0.1:0")
	if err != nil || im.Token() != transport.VerbConfirm || im.SenderID != "a.example." || im.Zone != "z.example." {
		t.Errorf("the receiver's parser reads %+v, %v", im, err)
	}
}
