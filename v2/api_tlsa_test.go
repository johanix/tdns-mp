/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * HTTPS between agents as they run it (tdns-mp#234): each bridge loads its
 * certificate from files and checks the receiver's certificate against the
 * receiver's TLSA, with no CA (InsecureSkipVerify); each receiver serves
 * the agent sync router, whose middleware checks the client's certificate
 * against the client's TLSA.
 */

package tdnsmp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// writeAgentCert writes a self-signed certificate for identity and its key
// as PEM files, as an agent's api cert_file and key_file, and returns their
// paths and the certificate.
func writeAgentCert(t *testing.T, identity string) (certFile, keyFile string, cert tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: identity},
		DNSNames:     []string{"api." + strings.TrimSuffix(identity, ".")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, cert
}

// leaf is cert's own certificate, parsed.
func leaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// setTLSA gives peer a validated TLSA set for its API, one 3 1 1 record per
// certificate, as discovery stores it.
func setTLSA(peer *transport.Peer, certs ...*x509.Certificate) {
	set := transport.TLSASet{Owner: "_443._tcp.api." + peer.ID, Validated: true}
	for _, c := range certs {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		set.Records = append(set.Records, &dns.TLSA{
			Hdr:   dns.RR_Header{Name: set.Owner, Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
			Usage: 3, Selector: 1, MatchingType: 1, Certificate: hex.EncodeToString(sum[:])})
	}
	peer.SetMechanismTLSA("API", set)
}

// tlsaEnv is alice and bob sharing zone, each with a certificate from
// files, each serving the agent sync router under that certificate as the
// agent does, and each knowing the other at its server with a TLSA set that
// names the other's certificate second, after a record for another key.
type tlsaEnv struct {
	*integEnv
	zone   string
	srv    map[string]*httptest.Server // by identity
	opened map[string]*atomic.Int32    // connections each server accepted
}

func newTLSAEnv(t *testing.T, zone string) *tlsaEnv {
	t.Helper()
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, Certificates: true})
	alice := dns.Fqdn(env.Alice.Identity)
	bob := dns.Fqdn(env.Bob.Identity)
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	te := &tlsaEnv{integEnv: env, zone: zone, srv: map[string]*httptest.Server{}, opened: map[string]*atomic.Int32{}}
	for _, p := range []*peerEnv{env.Alice, env.Bob} {
		pgm := p.Registry.ProviderGroupManager
		pgm.RecomputeGroups()
		p.Registry.GossipStateTable.RefreshLocalStates(p.Registry, pgm)
		p.Bridge.StartIncomingMessageRouter(env.ctx)
		te.srv[p.Identity], te.opened[p.Identity] = serveAgentRouter(t, p)
	}
	for _, pair := range [][2]*peerEnv{{env.Alice, env.Bob}, {env.Bob, env.Alice}} {
		local, remote := pair[0], pair[1]
		local.Registry.S.Set(AgentId(remote.Identity), NewAgent(AgentId(remote.Identity)))
		peer := local.Bridge.PeerRegistry.GetOrCreate(remote.Identity)
		peer.SetAPIEndpoint(te.srv[remote.Identity].URL + "/api/v1")
		setTLSA(peer, leaf(t, otherAgentCert(t)), leaf(t, remote.Cert))
	}
	return te
}

// otherAgentCert is a certificate with a key no TLSA here names.
func otherAgentCert(t *testing.T) tls.Certificate {
	t.Helper()
	_, _, cert := writeAgentCert(t, "mallory.agent.example.")
	return cert
}

// serveAgentRouter serves p's agent sync router, TLSA middleware included,
// under p's certificate, asking for a client certificate as the agent's
// dispatcher does, and counts the connections it accepts.
func serveAgentRouter(t *testing.T, p *peerEnv) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	conf := &Config{}
	conf.InternalMp.MPTransport = p.Bridge
	conf.InternalMp.AgentRegistry = p.Registry
	rtr, err := conf.SetupAgentSyncRouter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(rtr)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.Cert}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	opened := &atomic.Int32{}
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, opened
}

// beat sends a beat for the env's zone from one peer to the other over the
// sender's own HTTPS client.
func (te *tlsaEnv) beat(t *testing.T, from, to *peerEnv) (*transport.BeatResponse, error) {
	t.Helper()
	peer, ok := from.Bridge.PeerRegistry.Get(to.Identity)
	if !ok {
		t.Fatalf("%s does not know %s", from.Identity, to.Identity)
	}
	ctx, cancel := context.WithTimeout(te.ctx, integTestTimeout)
	defer cancel()
	return from.Bridge.APITransport.Beat(ctx, peer, &transport.BeatRequest{SenderID: from.Identity, Zones: []string{te.zone}, Timestamp: time.Now()})
}

// A beat goes both ways, each end checking the other's certificate against
// the other's TLSA set, whose second record names it.
func TestTLSA_BeatBothWays(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-both.example.")
	if te.Alice.Bridge.PeerRegistry.OnRemove == nil {
		t.Error("the bridge does not drop a peer's HTTPS client with the peer")
	}
	for _, pair := range [][2]*peerEnv{{te.Alice, te.Bob}, {te.Bob, te.Alice}} {
		from, to := pair[0], pair[1]
		resp, err := te.beat(t, from, to)
		if err != nil || !resp.Ack {
			t.Fatalf("%s's beat to %s: %+v %v", from.Identity, to.Identity, resp, err)
		}
		if _, ok := recvWithin(to.MsgQs.Beat, integTestTimeout); !ok {
			t.Errorf("%s's beat did not reach %s's MsgQs.Beat", from.Identity, to.Identity)
		}
	}
}

// A receiver whose certificate its TLSA does not name is refused before any
// request: the beat fails with ErrTLSAMismatch and reaches no queue.
func TestTLSA_ImpostorReceiverGetsNoRequest(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-impostor.example.")
	peer, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	setTLSA(peer, leaf(t, otherAgentCert(t)))
	if _, err := te.beat(t, te.Alice, te.Bob); !errors.Is(err, transport.ErrTLSAMismatch) {
		t.Fatalf("a beat to a server the TLSA does not name: %v, want ErrTLSAMismatch", err)
	}
	if b, ok := recvWithin(te.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Errorf("the beat reached the receiver as %s's", b.Identity)
	}
}

// A receiver with no TLSA is not dialed, and the bridge picks DNS for it.
func TestTLSA_NoTLSANoDial(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-none.example.")
	peer, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	peer.SetMechanismTLSA("API", transport.TLSASet{Owner: "_443._tcp.api." + peer.ID, Validated: true})
	peer.SetDiscoveryAddress(&transport.Address{Host: "127.0.0.1", Port: 53, Transport: "udp"})
	before := te.opened[te.Bob.Identity].Load()
	if _, err := te.beat(t, te.Alice, te.Bob); !errors.Is(err, transport.ErrNoTLSA) {
		t.Fatalf("a beat to a peer with no TLSA: %v, want ErrNoTLSA", err)
	}
	if n := te.opened[te.Bob.Identity].Load() - before; n != 0 {
		t.Errorf("%d connections to a peer with no TLSA, want none", n)
	}
	if got := te.Alice.Bridge.TransportManager.SelectTransport(peer); got != transport.Transport(te.Alice.Bridge.DNSTransport) {
		t.Errorf("SelectTransport picked %v for a peer with no TLSA, want DNS", got)
	}
}

// A client whose certificate its TLSA does not name is refused by the
// receiver's middleware, and its beat reaches no queue.
func TestTLSA_ImpostorClientRefused(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-client.example.")
	alice, _ := te.Bob.Bridge.PeerRegistry.Get(te.Alice.Identity)
	setTLSA(alice, leaf(t, otherAgentCert(t)))
	if _, err := te.beat(t, te.Alice, te.Bob); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a beat under a certificate the client's TLSA does not name: %v, want a 401", err)
	}
	if b, ok := recvWithin(te.Bob.MsgQs.Beat, 100*time.Millisecond); ok {
		t.Errorf("the beat reached the receiver as %s's", b.Identity)
	}
}

// peer ping --api goes through the API transport: the receiver is checked
// against its TLSA, and the agent presents its client certificate, which
// the receiver's middleware checks.
func TestTLSA_PeerPingOverAPI(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-ping.example.")
	conf := &Config{}
	conf.InternalMp.TransportManager = te.Alice.Bridge.TransportManager
	resp := doPeerPing(conf, te.Bob.Identity, true)
	if resp.Error || !strings.Contains(resp.Msg, "(api transport)") {
		t.Fatalf("peer ping --api: %+v", resp)
	}

	peer, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	setTLSA(peer, leaf(t, otherAgentCert(t)))
	if resp := doPeerPing(conf, te.Bob.Identity, true); !resp.Error || !strings.Contains(resp.ErrorMsg, "TLSA") {
		t.Errorf("peer ping --api to a server the TLSA does not name: %+v", resp)
	}
}

// A client certificate the bridge cannot load stops it: an agent that
// cannot present its certificate is refused by every peer.
func TestTLSA_UnloadableClientCertificateIsFatal(t *testing.T) {
	_, err := NewMPTransportBridge(&MPTransportBridgeConfig{
		Role: roleAgent, LocalID: "alice.agent.example.", SupportedMechanisms: []string{"api"},
		ClientCertFile: filepath.Join(t.TempDir(), "missing.pem"), ClientKeyFile: filepath.Join(t.TempDir(), "missing.key"),
	})
	if err == nil {
		t.Error("a bridge whose client certificate cannot be loaded was made")
	}
}

// A passed check holds for a while, for that peer and that certificate.
func TestTLSAVerdictsHoldForAWhile(t *testing.T) {
	now := time.Now()
	v := &tlsaVerdicts{hold: time.Minute, now: func() time.Time { return now }}
	a := leaf(t, otherAgentCert(t))
	b := leaf(t, otherAgentCert(t))
	if v.holds("a.example.", a) {
		t.Fatal("a verdict holds before any check")
	}
	v.pass("a.example.", a)
	if !v.holds("a.example.", a) {
		t.Error("a passed check does not hold")
	}
	if v.holds("b.example.", a) || v.holds("a.example.", b) {
		t.Error("a verdict holds for another peer or another certificate")
	}
	now = now.Add(time.Minute)
	if v.holds("a.example.", a) {
		t.Error("a verdict holds past its time")
	}
}

// The middleware keeps no refusal, and a pass it keeps ends when the
// client's TLSA set is gone: a client refused under one TLSA passes under
// the next at once, and is refused at once when its set is emptied.
func TestTLSA_ARefusalIsNotKeptAndAWithdrawalEndsAPass(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-verdict.example.")
	alice, _ := te.Bob.Bridge.PeerRegistry.Get(te.Alice.Identity)
	setTLSA(alice, leaf(t, otherAgentCert(t)))
	if _, err := te.beat(t, te.Alice, te.Bob); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("under a TLSA that does not name the client: %v, want a 401", err)
	}
	setTLSA(alice, leaf(t, te.Alice.Cert))
	if resp, err := te.beat(t, te.Alice, te.Bob); err != nil || !resp.Ack {
		t.Fatalf("under a TLSA that names the client, after a refusal: %+v %v", resp, err)
	}
	alice.SetMechanismTLSA("API", transport.TLSASet{Owner: "_443._tcp.api." + alice.ID, Validated: true})
	if _, err := te.beat(t, te.Alice, te.Bob); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("after the client's TLSA went, within the pass's minute: %v, want a 401", err)
	}
}

// A client certificate whose name leaves out the trailing dot names the
// same agent: the middleware reads it as the receive pipeline does.
func TestTLSA_ClientNameWithoutTheTrailingDot(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-nodot.example.")
	_, _, cert := writeAgentCert(t, strings.TrimSuffix(te.Alice.Identity, "."))
	alice, _ := te.Bob.Bridge.PeerRegistry.Get(te.Alice.Identity)
	setTLSA(alice, leaf(t, cert))
	tr := transport.NewAPITransport(&transport.APITransportConfig{LocalID: te.Alice.Identity, DefaultTimeout: integTestTimeout,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}}) //nolint:gosec
	bob, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	ctx, cancel := context.WithTimeout(te.ctx, integTestTimeout)
	defer cancel()
	resp, err := tr.Beat(ctx, bob, &transport.BeatRequest{SenderID: te.Alice.Identity, Zones: []string{te.zone}, Timestamp: time.Now()})
	if err != nil || !resp.Ack {
		t.Fatalf("a beat under a certificate named without the trailing dot: %+v %v", resp, err)
	}
}

// A beat to a peer with no TLSA is not tried over HTTPS: the API mechanism
// is not eligible, whatever its state.
func TestTLSA_NoTLSANoHTTPSBeat(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-nobeat.example.")
	peer, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	peer.SetMechanismTLSA("API", transport.TLSASet{Owner: "_443._tcp.api." + peer.ID, Validated: true})
	peer.SetMechanismState("API", transport.PeerStateOperational, "test")
	agent := NewAgent(AgentId(te.Bob.Identity))
	agent.ApiMethod = true
	ctx, cancel := context.WithTimeout(te.ctx, integTestTimeout)
	defer cancel()
	_, err := te.Alice.Bridge.SendBeatWithFallback(ctx, agent, 1)
	if err == nil || strings.Contains(err.Error(), "TLSA") {
		t.Errorf("a beat to a peer with no TLSA: %v, want it not tried over HTTPS", err)
	}
}

// The reliable queue counts API as ready only with a TLSA: a hello on the
// unauthenticated /hello introduces API without one.
func TestTLSA_RecipientReadyOverAPINeedsATLSA(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-ready.example.")
	peer, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	peer.SetMechanismState("API", transport.PeerStateOperational, "test")
	ready := func() bool {
		return recipientTransportReady(te.Alice.Registry, te.Alice.Bridge.PeerRegistry, te.Bob.Identity)
	}
	if !ready() {
		t.Fatal("a peer OPERATIONAL over API with a TLSA is not ready")
	}
	peer.SetMechanismTLSA("API", transport.TLSASet{Owner: "_443._tcp.api." + peer.ID, Validated: true})
	if ready() {
		t.Error("a peer OPERATIONAL over API with no TLSA is ready")
	}
}

// A pass held for a client ends when its TLSA set is replaced by another,
// not only when it is emptied: the old certificate is refused at once.
func TestTLSA_AReplacedSetEndsAPass(t *testing.T) {
	te := newTLSAEnv(t, "tlsa-replaced.example.")
	if resp, err := te.beat(t, te.Alice, te.Bob); err != nil || !resp.Ack {
		t.Fatalf("a beat under alice's certificate: %+v %v", resp, err)
	}
	alice, _ := te.Bob.Bridge.PeerRegistry.Get(te.Alice.Identity)
	setTLSA(alice, leaf(t, otherAgentCert(t))) // alice's key rotated away
	if _, err := te.beat(t, te.Alice, te.Bob); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("the old certificate after its TLSA set was replaced, within the pass's minute: %v, want a 401", err)
	}
}

// A pass is remembered only for the TLSA set the certificate was checked
// against: a set replaced while the check ran leaves no pass behind, and
// the next request is checked afresh.
func TestTLSAVerdictsRememberOnlyTheSetChecked(t *testing.T) {
	now := time.Now()
	v := &tlsaVerdicts{hold: time.Minute, now: func() time.Time { return now }}
	cert := leaf(t, otherAgentCert(t))
	peer := transport.NewPeer("alice.agent.example.")
	setTLSA(peer, cert)
	checks := 0
	replacedMidCheck := func() error {
		checks++
		setTLSA(peer, cert, leaf(t, otherAgentCert(t))) // another set, stored while the check ran
		return nil
	}
	if err := v.checkClient(peer, cert, replacedMidCheck); err != nil {
		t.Fatal(err)
	}
	if v.holds(tlsaVerdictPeer(peer), cert) {
		t.Error("a pass is remembered for a set the certificate was not checked against")
	}
	steady := func() error { checks++; return nil }
	for i := 0; i < 2; i++ {
		if err := v.checkClient(peer, cert, steady); err != nil {
			t.Fatal(err)
		}
	}
	if checks != 2 {
		t.Errorf("%d checks, want 2: the replaced set's, and one for the set now held, remembered after", checks)
	}
}
