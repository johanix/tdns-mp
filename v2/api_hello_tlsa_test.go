/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * /hello takes a client certificate the TLSA middleware has checked, as
 * every other sync API endpoint does (#56): a hello under a certificate its
 * sender's TLSA names is taken; one with no certificate, or a certificate
 * the TLSA does not name, is refused; one that comes before the receiver
 * has the sender's TLSA is refused retryably, and a known sender is looked
 * up so that a later hello passes. The body names the certificate's agent.
 */

package tdnsmp

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

// hello sends a hello for the env's zone to bob, naming from as its sender,
// over tr.
func (te *tlsaEnv) hello(t *testing.T, tr *transport.APITransport, from string) (*transport.HelloResponse, error) {
	t.Helper()
	bob, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	ctx, cancel := context.WithTimeout(te.ctx, integTestTimeout)
	defer cancel()
	return tr.Hello(ctx, bob, &transport.HelloRequest{SenderID: from, SharedZones: []string{te.zone}, Timestamp: time.Now()})
}

// agentClient is an HTTPS client as agents run it (no CA) for local,
// presenting cert, if any.
func agentClient(local string, certs ...tls.Certificate) *transport.APITransport {
	return transport.NewAPITransport(&transport.APITransportConfig{LocalID: local, DefaultTimeout: integTestTimeout,
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, Certificates: certs}}) //nolint:gosec
}

// noHello fails t if a hello reached bob's pipeline.
func (te *tlsaEnv) noHello(t *testing.T, what string) {
	t.Helper()
	if r, ok := recvWithin(te.Bob.MsgQs.Hello, 100*time.Millisecond); ok {
		t.Errorf("%s reached the pipeline as %s's hello", what, r.Identity)
	}
}

// A hello under a certificate its sender's TLSA names is taken.
func TestHello_TakenUnderACheckedCertificate(t *testing.T) {
	te := newTLSAEnv(t, "hello-ok.example.")
	resp, err := te.hello(t, te.Alice.Bridge.APITransport, te.Alice.Identity)
	if err != nil || !resp.Accepted {
		t.Fatalf("a hello under alice's own certificate: %+v %v", resp, err)
	}
	if _, ok := recvWithin(te.Bob.MsgQs.Hello, integTestTimeout); !ok {
		t.Error("the hello did not reach bob's pipeline")
	}
}

// A hello with no client certificate, or under one the sender's TLSA does
// not name, is refused before it reaches the pipeline.
func TestHello_RefusedWithoutACheckedCertificate(t *testing.T) {
	te := newTLSAEnv(t, "hello-refused.example.")
	if _, err := te.hello(t, agentClient(te.Alice.Identity), te.Alice.Identity); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a hello with no client certificate: %v, want a 401", err)
	}
	te.noHello(t, "a hello with no client certificate")

	_, _, claimsAlice := writeAgentCert(t, te.Alice.Identity) // alice's name, another key
	impostor := agentClient(te.Alice.Identity, claimsAlice)
	if _, err := te.hello(t, impostor, te.Alice.Identity); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a hello under a certificate alice's TLSA does not name: %v, want a 401", err)
	}
	te.noHello(t, "a hello under an impostor's certificate")
}

// A hello under alice's certificate that names another agent is refused,
// though that agent shares the zone: a hello introduces only the agent that
// sent it.
func TestHello_BodyMustNameTheCertificatesAgent(t *testing.T) {
	te := newTLSAEnv(t, "hello-other.example.")
	const carol, zone = "carol.agent.example.", "hello-three.example."
	zd := seedZoneWithHSYNC3(t, zone, te.Alice.Identity, te.Bob.Identity, carol)
	addHSYNCPARAMServers(t, zd, shortLabel(te.Alice.Identity), shortLabel(te.Bob.Identity), shortLabel(carol))
	te.Bob.Registry.ProviderGroupManager.RecomputeGroups()
	bob, _ := te.Alice.Bridge.PeerRegistry.Get(te.Bob.Identity)
	ctx, cancel := context.WithTimeout(te.ctx, integTestTimeout)
	defer cancel()
	resp, err := te.Alice.Bridge.APITransport.Hello(ctx, bob, &transport.HelloRequest{SenderID: carol, SharedZones: []string{zone}, Timestamp: time.Now()})
	if err == nil && resp.Accepted {
		t.Fatalf("a hello naming carol under alice's certificate was taken: %+v", resp)
	}
	te.noHello(t, "a hello naming carol under alice's certificate")
}

// A hello that comes before the receiver has the sender's TLSA is refused
// retryably (503). A sender the receiver knows is looked up, so a later
// hello passes; one it does not know is not.
func TestHello_RefusedRetryablyUntilTheTLSAIsKnown(t *testing.T) {
	te := newTLSAEnv(t, "hello-early.example.")
	const carol, dave = "carol.agent.example.", "dave.agent.example."
	te.Bob.Registry.S.Set(AgentId(carol), NewAgent(AgentId(carol)))
	_, _, carolCert := writeAgentCert(t, carol)
	_, _, daveCert := writeAgentCert(t, dave)

	for _, c := range []struct {
		id   string
		cert tls.Certificate
	}{{carol, carolCert}, {dave, daveCert}} {
		_, err := te.hello(t, agentClient(c.id, c.cert), c.id)
		if err == nil || !strings.Contains(err.Error(), "503") {
			t.Errorf("%s's hello before bob has its TLSA: %v, want a 503", c.id, err)
		}
		var te2 *transport.TransportError
		if err != nil && (!errors.As(err, &te2) || !te2.Retryable) {
			t.Errorf("%s's refused hello is not retryable: %v", c.id, err)
		}
	}
	te.noHello(t, "a hello before the TLSA is known")

	deadline := time.Now().Add(integTestTimeout)
	for {
		if _, ok := te.Bob.Bridge.PeerRegistry.Get(carol); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bob did not look up carol, an agent it knows, after her early hello")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := te.Bob.Bridge.PeerRegistry.Get(dave); ok {
		t.Error("bob looked up dave, an agent it does not know, on his hello")
	}

	// Once bob has carol's TLSA, her hello passes the middleware.
	peer, _ := te.Bob.Bridge.PeerRegistry.Get(carol)
	setTLSA(peer, leaf(t, carolCert))
	// The pipeline may still turn her down (she shares no zone); the
	// middleware must not.
	if _, err := te.hello(t, agentClient(carol, carolCert), carol); err != nil &&
		(strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "401")) {
		t.Errorf("carol's hello after bob has her TLSA was refused by the middleware: %v", err)
	}
}

// Of callers racing to look one sender up, one wins until the minute is
// over: the check and the note are one step.
func TestHello_OneLookUpPerSenderAMinute(t *testing.T) {
	now := time.Now()
	v := &tlsaVerdicts{hold: time.Minute, now: func() time.Time { return now }}
	const callers = 64
	start := make(chan struct{})
	won := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			won <- v.takeKey("carol.agent.example.")
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < callers; i++ {
		if <-won {
			winners++
		}
	}
	if winners != 1 {
		t.Errorf("%d of %d racing callers won the look-up, want 1", winners, callers)
	}
	now = now.Add(time.Minute)
	if !v.takeKey("carol.agent.example.") {
		t.Error("no look-up after the minute is over")
	}
}
