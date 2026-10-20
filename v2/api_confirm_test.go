/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A SYNC's confirmations go back on the mechanism the SYNC arrived on: a
 * SYNC over DNS is confirmed by NOTIFY, a SYNC over HTTPS over HTTPS,
 * whatever else the originator offers. A confirmation that fails is not
 * sent on the other mechanism. A confirmation over HTTPS speaks for the
 * client certificate's identity only.
 */

package tdnsmp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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

// mechanismEnv is alice and bob sharing zone, alice reachable at bob over
// both mechanisms: her sync API endpoints over HTTPS and her receive
// pipeline over DNS, each counting what reaches it. Bob reaches alice's
// HTTPS with his own certificate. With refuseHTTPS alice's /msg refuses
// every message.
type mechanismEnv struct {
	*integEnv
	zone       string
	alice      string
	bob        string
	posts      atomic.Int32 // POSTs to alice's /msg
	notifies   atomic.Int32 // NOTIFYs to alice
	aliceAtBob *transport.Peer
}

func newMechanismEnv(t *testing.T, zone string, refuseHTTPS bool) *mechanismEnv {
	t.Helper()
	me := &mechanismEnv{
		integEnv: newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true}),
		zone:     zone,
	}
	me.alice, me.bob = dns.Fqdn(me.Alice.Identity), dns.Fqdn(me.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, me.alice, me.bob)
	addHSYNCPARAMServers(t, zd, shortLabel(me.alice), shortLabel(me.bob))

	conf := &Config{}
	conf.InternalMp.MPTransport = me.Alice.Bridge
	msg := conf.apiSyncEndpoint(apiEndpointMsg)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		me.posts.Add(1)
		if refuseHTTPS {
			sink := &apiReplySink{kind: apiEndpointMsg, w: w, local: AgentId(me.alice)}
			_ = sink.fail("refused")
			return
		}
		msg(w, r)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsSrv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			me.notifies.Add(1)
		}
		_ = me.Alice.Bridge.ChunkHandler.RouteViaRouter(me.ctx, r.Question[0].Name, r, w)
	})}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		_ = dnsSrv.ShutdownContext(ctx)
	})

	me.Bob.Bridge.APITransport = apiSender(srv, me.bob, clientCert(t, me.bob))
	me.aliceAtBob = transport.NewPeer(me.alice)
	me.aliceAtBob.APIEndpoint = srv.URL + "/api/v1"
	addr := &transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	me.aliceAtBob.SetDiscoveryAddress(addr)
	me.aliceAtBob.SetMechanismAddress("DNS", addr)
	if err := me.Bob.Bridge.PeerRegistry.Add(me.aliceAtBob); err != nil {
		t.Fatalf("alice at bob: %v", err)
	}
	return me
}

// finalFrom is bob's final confirmation of the SYNC m, as his engine hands
// it over once his combiner has applied the records.
func (me *mechanismEnv) finalFrom(m *AgentMsgPostPlus) {
	me.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: m.DistributionID, OriginatingSender: string(m.OriginatorID), OriginatingMechanism: m.Mechanism,
		Zone: m.Zone, Status: "SUCCESS", AppliedRecords: m.Records[string(m.Zone)]})
}

// confirmed waits for alice to book one of bob's confirmations of id with
// status.
func (me *mechanismEnv) confirmed(t *testing.T, id string, status transport.ConfirmStatus) {
	t.Helper()
	c, ok := recvConfirmWithin(t, me.Alice.MsgQs.Confirmation, confirmWait)
	if !ok {
		t.Fatalf("bob's %s did not reach alice", status)
	}
	if c.DistributionID != id || c.Source != me.bob || c.Status != status.String() {
		t.Fatalf("alice booked %+v, want %s for %s from bob", c, status, id)
	}
}

// A SYNC that comes over DNS is confirmed by NOTIFY, both the PENDING and
// the final word, though alice offers HTTPS too: nothing is posted to her.
// The SYNC goes over the wire from alice's own sender.
func TestConfirm_DNSSyncIsConfirmedByDNS(t *testing.T) {
	me := newMechanismEnv(t, "confirm-dns.example.", false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	me.Bob.Bridge.StartIncomingMessageRouter(me.ctx)
	serveDNS(t, me.ctx, ln, me.Bob)
	bobAtAlice := transport.NewPeer(me.bob)
	addr := &transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	bobAtAlice.SetDiscoveryAddress(addr)
	bobAtAlice.SetMechanismAddress("DNS", addr)

	id := queueSync(t, me.integEnv, me.zone)
	records := map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"sync over dns\""}}
	ctx, cancel := context.WithTimeout(context.Background(), confirmWait)
	defer cancel()
	if _, err := me.Alice.Bridge.SendSyncWithFallback(ctx, bobAtAlice, &PeerSyncRequest{
		SenderID: me.alice, Zone: me.zone, MessageType: "sync", DistributionID: id, Records: records, Timestamp: time.Now()}); err != nil {
		t.Fatalf("the SYNC over DNS: %v", err)
	}
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	if m.Mechanism != transport.MechanismDNS || m.DistributionID != id {
		t.Fatalf("bob has the sync as %q over %q, want %q over DNS", m.DistributionID, m.Mechanism, id)
	}

	me.confirmed(t, id, transport.ConfirmPending)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != transport.MessageAwaitingConfirm.String() {
		t.Fatalf("after the PENDING alice's entry is %s, want it awaiting the final confirmation", got)
	}
	me.finalFrom(m)
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if n := me.notifies.Load(); n != 2 {
		t.Errorf("alice got %d NOTIFYs, want the PENDING and the final word", n)
	}
	if n := me.posts.Load(); n != 0 {
		t.Errorf("a SYNC over DNS was confirmed over HTTPS: %d POSTs to alice", n)
	}
}

// A SYNC that comes over HTTPS is confirmed over HTTPS, though alice has a
// DNS address too: no NOTIFY reaches her.
//
// The SYNC enters bob as the HTTPS pipeline delivers it once the sender
// puts its distribution ID in the payload (plan decision 41, PR #224);
// before that, bob would confirm under an ID of his own.
func TestConfirm_HTTPSSyncIsConfirmedOverHTTPS(t *testing.T) {
	me := newMechanismEnv(t, "confirm-https.example.", false)
	id := queueSync(t, me.integEnv, me.zone)
	in := makeSyncIncomingMessage(t, me.alice, me.bob, me.zone, id,
		map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"sync over https\""}})
	in.Mechanism = transport.MechanismAPI
	me.Bob.Bridge.routeIncomingMessage(in)
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok || m.Mechanism != transport.MechanismAPI {
		t.Fatalf("bob has the sync over %q, want API", m.Mechanism)
	}

	me.confirmed(t, id, transport.ConfirmPending)
	me.finalFrom(m)
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if n := me.posts.Load(); n != 2 {
		t.Errorf("alice got %d POSTs, want the PENDING and the final word", n)
	}
	if n := me.notifies.Load(); n != 0 {
		t.Errorf("a SYNC over HTTPS was confirmed by NOTIFY: %d NOTIFYs to alice", n)
	}
}

// A confirmation that fails over HTTPS is not sent over DNS: alice's /msg
// refuses both of bob's, no NOTIFY follows, and alice's entry stays for her
// queue to send the SYNC again.
func TestConfirm_FailedHTTPSConfirmIsNotSentOverDNS(t *testing.T) {
	me := newMechanismEnv(t, "confirm-no-fallback.example.", true)
	id := queueSync(t, me.integEnv, me.zone)
	in := makeSyncIncomingMessage(t, me.alice, me.bob, me.zone, id,
		map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"refused\""}})
	in.Mechanism = transport.MechanismAPI
	me.Bob.Bridge.routeIncomingMessage(in)
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	me.finalFrom(m)

	deadline := time.Now().Add(confirmWait)
	for me.posts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := me.posts.Load(); n != 2 {
		t.Fatalf("alice's /msg got %d POSTs, want the PENDING and the final word", n)
	}
	time.Sleep(300 * time.Millisecond) // time for a NOTIFY that must not come
	if n := me.notifies.Load(); n != 0 {
		t.Errorf("a refused HTTPS confirmation was sent over DNS: %d NOTIFYs", n)
	}
	if c, ok := recvConfirmWithin(t, me.Alice.MsgQs.Confirmation, 10*time.Millisecond); ok {
		t.Errorf("alice booked a confirmation she refused: %+v", c)
	}
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got == "gone" {
		t.Error("a refused confirmation closed alice's entry")
	}
}

// A confirmation whose SYNC's mechanism is not known goes nowhere: it is
// not guessed.
func TestConfirm_UnknownMechanismSendsNothing(t *testing.T) {
	me := newMechanismEnv(t, "confirm-unknown.example.", false)
	id := queueSync(t, me.integEnv, me.zone)
	me.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: me.alice, Zone: ZoneName(me.zone), Status: "SUCCESS"})
	time.Sleep(300 * time.Millisecond) // time for a confirmation that must not come
	if p, n := me.posts.Load(), me.notifies.Load(); p != 0 || n != 0 {
		t.Errorf("a confirmation with no mechanism went out: %d POSTs, %d NOTIFYs", p, n)
	}
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got == "gone" {
		t.Error("alice's entry closed")
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
