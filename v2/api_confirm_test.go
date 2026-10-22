/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A SYNC's confirmations go first on the mechanism the SYNC arrived on: a
 * SYNC over DNS is confirmed by NOTIFY, a SYNC over HTTPS over HTTPS,
 * whatever else the originator offers. A confirmation that fails there goes
 * on the other mechanism. A confirmation over HTTPS speaks for the client
 * certificate's identity only.
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
	"github.com/johanix/tdns/v2/core"
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

// alice's /msg: it serves, refuses every message, or hangs.
type httpsMode int

const (
	httpsServes httpsMode = iota
	httpsRefuses
	httpsHangs
)

// mechanismEnv is alice and bob sharing zone, alice reachable at bob over
// both mechanisms: her sync API endpoints over HTTPS and her receive
// pipeline over DNS, each counting what reaches it. Bob reaches alice's
// HTTPS with his own certificate, and checks hers against the TLSA he
// holds for her; mode says what her /msg does.
type mechanismEnv struct {
	*integEnv
	zone       string
	alice      string
	bob        string
	posts      atomic.Int32 // POSTs to alice's /msg
	notifies   atomic.Int32 // NOTIFYs to alice
	aliceAtBob *transport.Peer
}

func newMechanismEnv(t *testing.T, zone string, mode httpsMode) *mechanismEnv {
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
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		me.posts.Add(1)
		switch mode {
		case httpsRefuses:
			sink := &apiReplySink{kind: apiEndpointMsg, w: w, local: AgentId(me.alice)}
			_ = sink.fail("refused")
		case httpsHangs:
			// The body read, the server sees the client go.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-release:
			}
		default:
			msg(w, r)
		}
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first

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
	if mode == httpsHangs {
		// as an agent's: longer than the time a confirmation has
		me.Bob.Bridge.APITransport.HTTPClient.Timeout = 10 * time.Second
	}
	me.aliceAtBob = transport.NewPeer(me.alice)
	me.aliceAtBob.APIEndpoint = srv.URL + "/api/v1"
	setTLSA(me.aliceAtBob, srv.Certificate())
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
		OriginatingDistID: m.DistributionID, OriginatingSender: string(m.OriginatorID), Mechanism: m.Mechanism,
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
	me := newMechanismEnv(t, "confirm-dns.example.", httpsServes)
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
	me := newMechanismEnv(t, "confirm-https.example.", httpsServes)
	id := queueSync(t, me.integEnv, me.zone)
	in := makeSyncIncomingMessage(t, me.alice, me.bob, me.zone, id,
		map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"sync over https\""}})
	in.Mechanism = transport.MechanismAPI
	me.Bob.Bridge.routeIncomingMessage(in)
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	if m.Mechanism != transport.MechanismAPI {
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

// A confirmation that fails over HTTPS goes over DNS: alice's /msg, from
// before confirmations went over HTTPS, refuses both of bob's, and both
// reach her by NOTIFY and close her entry.
func TestConfirm_RefusedHTTPSConfirmGoesOverDNS(t *testing.T) {
	me := newMechanismEnv(t, "confirm-refused.example.", httpsRefuses)
	id := queueSync(t, me.integEnv, me.zone)
	in := makeSyncIncomingMessage(t, me.alice, me.bob, me.zone, id,
		map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"refused\""}})
	in.Mechanism = transport.MechanismAPI
	me.Bob.Bridge.routeIncomingMessage(in)
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	me.confirmed(t, id, transport.ConfirmPending)
	me.finalFrom(m)
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 2 || n != 2 {
		t.Errorf("%d POSTs and %d NOTIFYs, want each confirmation refused over HTTPS and sent by NOTIFY", p, n)
	}
}

// A peer that hangs on HTTPS leaves DNS time: the HTTPS try gets half of
// the confirmation's time, though its own timeout is longer, and the
// NOTIFY carries the confirmation.
func TestConfirm_HangingHTTPSLeavesDNSTime(t *testing.T) {
	me := newMechanismEnv(t, "confirm-hang.example.", httpsHangs)
	id := queueSync(t, me.integEnv, me.zone)
	me.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: me.alice, Mechanism: transport.MechanismAPI,
		Zone: ZoneName(me.zone), Status: "SUCCESS"})
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("alice's entry is %s, want it closed", got)
	}
	if n := me.notifies.Load(); n != 1 {
		t.Errorf("%d NOTIFYs, want the confirmation's", n)
	}
}

// A confirmation that fails over DNS goes over HTTPS: alice's DNS address
// at bob answers nothing, and both of bob's confirmations of a SYNC that
// came over DNS reach her over HTTPS and close her entry.
func TestConfirm_FailedDNSConfirmGoesOverHTTPS(t *testing.T) {
	me := newMechanismEnv(t, "confirm-dns-fails.example.", httpsServes)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	ln.Close() // nothing listens there: every NOTIFY is refused
	me.aliceAtBob.SetDiscoveryAddress(dead)
	me.aliceAtBob.SetMechanismAddress("DNS", dead)

	id := queueSync(t, me.integEnv, me.zone)
	in := makeSyncIncomingMessage(t, me.alice, me.bob, me.zone, id,
		map[string][]string{me.zone: {me.zone + " 3600 IN TXT \"dns fails\""}})
	in.Mechanism = transport.MechanismDNS
	me.Bob.Bridge.routeIncomingMessage(in)
	m, ok := recvMsgWithin(t, me.Bob.MsgQs.Msg, integTestTimeout)
	if !ok {
		t.Fatal("the sync did not reach bob")
	}
	me.confirmed(t, id, transport.ConfirmPending)
	me.finalFrom(m)
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("after the final confirmation alice's entry is %s, want it closed", got)
	}
	if n := me.posts.Load(); n != 2 {
		t.Errorf("alice got %d POSTs, want both confirmations over HTTPS", n)
	}
}

// A confirmation that fails over DNS falls back to HTTPS only when the
// peer's API is usable: an endpoint alone, with no TLSA to check its
// certificate against, is no fallback, and the NOTIFY keeps all the time.
func TestConfirm_NoHTTPSFallbackWithoutATLSA(t *testing.T) {
	me := newMechanismEnv(t, "confirm-no-tlsa.example.", httpsServes)
	b := me.Bob.Bridge
	if got := b.otherConfirmTransport(b.DNSTransport, me.aliceAtBob); got != b.APITransport {
		t.Fatalf("alice with an endpoint and a TLSA: the fallback from DNS is %v, want HTTPS", got)
	}
	me.aliceAtBob.SetMechanismTLSA("API", transport.TLSASet{})
	if got := b.otherConfirmTransport(b.DNSTransport, me.aliceAtBob); got != nil {
		t.Errorf("alice with an endpoint and no TLSA: the fallback from DNS is %s, want none", got.Name())
	}
}

// A confirmation that goes on the other mechanism is logged loudly the
// first time for a peer and mechanism, and then not before an hour has
// passed: a pair that works one way only shows, without a line per
// confirmation.
func TestConfirmFallbackIsLoggedOnceAnHour(t *testing.T) {
	env := newIntegEnv(t, nil)
	b := env.Bob.Bridge
	if !b.noteConfirmFallback("alice.", "API", "DNS", nil) {
		t.Error("the first fallback to a peer was not logged loudly")
	}
	if b.noteConfirmFallback("alice.", "API", "DNS", nil) {
		t.Error("a second fallback within the hour was logged loudly")
	}
	if !b.noteConfirmFallback("alice.", "DNS", "API", nil) || !b.noteConfirmFallback("carol.", "API", "DNS", nil) {
		t.Error("the first fallback on another mechanism, or to another peer, was not logged loudly")
	}
	b.confirmFallbackMu.Lock()
	b.confirmFallbackLogged["alice.|API"] = time.Now().Add(-61 * time.Minute)
	b.confirmFallbackMu.Unlock()
	if !b.noteConfirmFallback("alice.", "API", "DNS", nil) {
		t.Error("a fallback an hour later was not logged loudly")
	}
}

// A confirmation whose SYNC's mechanism is not known still goes: by what
// the peer offers, HTTPS first when she has an endpoint. Not sent, it would
// leave alice sending her SYNC again.
func TestConfirm_UnknownMechanismGoesByThePeersOffer(t *testing.T) {
	me := newMechanismEnv(t, "confirm-unknown.example.", httpsServes)
	id := queueSync(t, me.integEnv, me.zone)
	me.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: me.alice, Zone: ZoneName(me.zone), Status: "SUCCESS"})
	me.confirmed(t, id, transport.ConfirmSuccess)
	if got := queueState(me.Alice.Bridge.ReliableQueue, id); got != "gone" {
		t.Errorf("alice's entry is %s, want it closed", got)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 1 || n != 0 {
		t.Errorf("%d POSTs and %d NOTIFYs, want the confirmation over HTTPS, which alice offers", p, n)
	}
}

// The engine carries the mechanism a remote update arrived on to its final
// confirmation: when this agent's combiner confirms the forward, the
// confirmation to the originator names the mechanism to go back on.
func TestTheEngineCarriesTheSyncsMechanismToTheFinalConfirmation(t *testing.T) {
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	const zone = ZoneName("carry.example.")
	zdr.Tracking[zone] = map[AgentId]map[uint16]*TrackedRRset{}
	zdr.PendingRemoteConfirms = map[string]*PendingRemoteConfirmation{
		"to-combiner": {OriginatingDistID: "from-alice", OriginatingSender: "alice.agent.example.", Mechanism: transport.MechanismAPI, Zone: zone},
	}
	var got []*RemoteConfirmationDetail
	msgQs := &MsgQs{OnRemoteConfirmationReady: func(d *RemoteConfirmationDetail) { got = append(got, d) }}
	zdr.ProcessConfirmation(&ConfirmationDetail{DistributionID: "to-combiner", Zone: zone, Source: "combiner.example.",
		Status: "SUCCESS", AppliedRecords: []string{"carry.example.\t3600\tIN\tTXT\t\"x\""}}, msgQs)
	if len(got) != 1 {
		t.Fatalf("%d confirmations to the originator, want 1", len(got))
	}
	if got[0].OriginatingDistID != "from-alice" || got[0].Mechanism != transport.MechanismAPI {
		t.Errorf("the confirmation to the originator: %+v, want from-alice over API", got[0])
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
	setTLSA(peer, srv.Certificate())
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
	setTLSA(peer, srv.Certificate())
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

// A remote update that changes nothing is confirmed at once (decision 42).
// That confirmation, too, goes back on the mechanism the update arrived on.
func TestTheNoOpConfirmationGoesBackOnTheArrivalMechanism(t *testing.T) {
	r := newEngineRig(t, "noop.mechanism.example.")
	done := make(chan *AgentMsgResponse, 1)
	r.msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: r.zone, AgentId: roleB, UpdateType: "remote", DeliveredBy: roleB,
		OriginatingDistID: "d1", OriginatingTime: time.Now(), Mechanism: transport.MechanismAPI,
		Update: &ZoneUpdate{Zone: r.zone, AgentId: roleB,
			Operations: []core.RROperation{{Operation: "replace", RRtype: "CDS", Records: []string{}}}},
		Response: done}
	if _, ok := recvWithin(done, 5*time.Second); !ok {
		t.Fatal("the engine did not answer")
	}
	d, ok := recvWithin(r.confs, time.Second)
	if !ok || d.OriginatingDistID != "d1" || d.Status != "ok" || d.Mechanism != transport.MechanismAPI {
		t.Errorf("the confirmation of an update that changes nothing: confirmed=%v %+v, want d1 ok back over API", ok, d)
	}
}
