/*
 * A peer that is found without an address, and whose hello arrives before
 * the address does (tdns-mp #84).
 *
 * The scenarios run two harness peers with payload crypto, their engines,
 * and a resolver each over records the test publishes
 * (discovery_harness_test.go).
 * "Alice" looks "Bob" up while his SVCB record is missing: the URI and the
 * key are found, the address is not, and the mechanism stays NEEDED with
 * contact info "partial".
 */

package tdnsmp

import (
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// noAddressScenario is two peers that listen, with Bob published without
// his address and Alice having looked him up.
type noAddressScenario struct {
	env        *integEnv
	zone       *discoveryZone
	alice, bob *peerEnv
	// bobAddress is the record that is missing: publishing it completes
	// what Alice can find about Bob.
	bobAddress dns.RR
}

// newNoAddressScenario builds the scenario and starts Alice's engine with
// cfg. It returns once her discovery of Bob has found him without an address.
func newNoAddressScenario(t *testing.T, cfg hsync.Config) *noAddressScenario {
	t.Helper()
	zone := newDiscoveryZone(t)
	keys := map[string]*harnessKey{
		"alice.agent.example.": newHarnessKey(t),
		"bob.agent.example.":   newHarnessKey(t),
	}
	env := newIntegEnv(t, &integEnvConfig{
		AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true,
		Discovery: zone, Keys: keys,
	})
	s := &noAddressScenario{env: env, zone: zone, alice: env.Alice, bob: env.Bob}

	zone.set(dnsDiscoveryRecords(s.alice.Identity, listenDNS(t, env, s.alice), keys[s.alice.Identity])...)
	for _, rr := range dnsDiscoveryRecords(s.bob.Identity, listenDNS(t, env, s.bob), keys[s.bob.Identity]) {
		if rr.Header().Rrtype == dns.TypeSVCB {
			s.bobAddress = rr
			continue
		}
		zone.set(rr)
	}

	startHarnessEngine(t, env, s.alice, cfg).MarkNeeded(hsync.PeerID(s.bob.Identity), "", nil)
	deadline := time.Now().Add(integTestTimeout)
	for {
		if p, ok := s.alice.Bridge.PeerRegistry.Get(s.bob.Identity); ok && p.MechanismContactInfo(transport.MechanismDNS) == "partial" {
			if p.HasMechanism(transport.MechanismDNS) {
				t.Fatal("precondition: Alice found an address for Bob, whose SVCB record is not published")
			}
			return s
		}
		if time.Now().After(deadline) {
			t.Fatal("precondition: Alice's discovery of Bob did not register his URI")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// bobIntroducesHimself starts Bob's engine: he looks Alice up, sends his
// hello, and beats her. It returns when his side of the link is OPERATIONAL,
// which is after Alice's hello route has taken his hello and she has
// answered it.
func (s *noAddressScenario) bobIntroducesHimself(t *testing.T) {
	t.Helper()
	startHarnessEngine(t, s.env, s.bob, harnessIntervals()).MarkNeeded(hsync.PeerID(s.alice.Identity), "", nil)
	waitForDNSState(t, s.bob, s.alice.Identity, transport.PeerStateOperational, 5*time.Second)
}

// The case from a running fleet: the peer's hello arrives while its address
// is not known. The hello must not introduce the mechanism: nothing discovers
// an introduced mechanism, and every send to the peer then failed for want of
// an address until the daemon was restarted. The mechanism stays NEEDED, and
// when the address can be found, the discovery retry finds it and the link
// comes up.
func TestAHelloDoesNotIntroduceAMechanismWithNoAddress(t *testing.T) {
	s := newNoAddressScenario(t, harnessIntervals())
	s.bobIntroducesHimself(t)

	// Alice has accepted Bob's hello and answers his beats. She has no
	// address for him, also after the discovery his hello started and a few
	// rounds of her retry.
	time.Sleep(4 * harnessIntervals().RetryInterval)
	p, _ := s.alice.Bridge.PeerRegistry.Get(s.bob.Identity)
	if p.HasMechanism(transport.MechanismDNS) {
		t.Fatal("Alice has an address for Bob, whose SVCB record is not published")
	}
	if st := dnsState(s.alice, s.bob.Identity); st != transport.PeerStateNeeded {
		t.Fatalf("after Bob's hello Alice holds his DNS mechanism, which has no address, at %v, want NEEDED", st)
	}

	s.zone.set(s.bobAddress)
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 5*time.Second)
	if !p.HasMechanism(transport.MechanismDNS) {
		t.Error("Alice reads Bob's DNS mechanism as OPERATIONAL without an address")
	}
}

// The hello starts a discovery of a sender that has no address, as it does
// for a sender that is not in the registry, and when that discovery finds
// the address the hello introduces the mechanism after all. Alice's own
// retry is an hour away here: only the hello can bring the link up.
func TestAHelloStartsTheDiscoveryOfASenderWithNoAddress(t *testing.T) {
	cfg := harnessIntervals()
	cfg.RetryInterval = time.Hour
	s := newNoAddressScenario(t, cfg)

	s.zone.set(s.bobAddress)
	time.Sleep(100 * time.Millisecond)
	if st := dnsState(s.alice, s.bob.Identity); st != transport.PeerStateNeeded {
		t.Fatalf("precondition: Alice holds Bob's DNS mechanism at %v before his hello, want NEEDED", st)
	}

	s.bobIntroducesHimself(t)
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 5*time.Second)
}

// A mechanism that is past NEEDED and has no address is discovered again by
// the engine's retry, whatever its state. Nothing leaves a mechanism like
// that any more; the test puts it there, as an inbound hello did before, on a
// peer whose discovery the engine has marked as failed.
func TestAnIntroducedMechanismWithNoAddressIsDiscoveredAgain(t *testing.T) {
	s := newNoAddressScenario(t, harnessIntervals())
	p, _ := s.alice.Bridge.PeerRegistry.Get(s.bob.Identity)
	deadline := time.Now().Add(integTestTimeout)
	for p.GetState() != transport.PeerStateError {
		if time.Now().After(deadline) {
			t.Fatalf("precondition: Alice's failed discovery left Bob at %v, want ERROR", p.GetState())
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.SetMechanismState(transport.MechanismDNS, transport.PeerStateIntroducing, "DNS hello accepted and authorized")

	time.Sleep(4 * harnessIntervals().RetryInterval)
	if p.HasMechanism(transport.MechanismDNS) {
		t.Fatal("Alice has an address for Bob, whose SVCB record is not published")
	}
	s.zone.set(s.bobAddress)
	deadline = time.Now().Add(5 * time.Second)
	for !p.HasMechanism(transport.MechanismDNS) {
		if time.Now().After(deadline) {
			t.Fatal("Alice's discovery retry did not look up a peer whose introduced mechanism has no address")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// With the address the mechanism is one the rounds can beat: Bob, who
	// runs no engine here, looks Alice up when her first beat arrives.
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 10*time.Second)
}

// The same rule for the HTTPS mechanism, through its receive entry: a hello
// from a sender whose API endpoint is not known does not introduce the API
// mechanism; one from a sender with an endpoint does.
func TestAnAPIHelloIntroducesOnlyAMechanismWithAnEndpoint(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	apiState := func(pe *peerEnv, peer string) transport.PeerState {
		p, _ := pe.Bridge.PeerRegistry.Get(peer)
		st, _ := p.MechanismRawState(transport.MechanismAPI)
		return st
	}

	// Bob has no endpoint for Alice.
	env.Bob.Bridge.StartIncomingMessageRouter(env.ctx)
	if resp := postAPIHello(t, env.Bob, env.Alice.Identity, "any.example."); resp.Error {
		t.Fatalf("hello refused: %+v", resp)
	}
	if st := apiState(env.Bob, env.Alice.Identity); st != transport.PeerStateNeeded {
		t.Errorf("a hello from a sender with no API endpoint left the API mechanism at %v, want NEEDED", st)
	}

	// Alice has one for Bob.
	env.Alice.Bridge.StartIncomingMessageRouter(env.ctx)
	env.Alice.Bridge.PeerRegistry.GetOrCreate(env.Bob.Identity).APIEndpoint = "https://api.bob.agent.example.:8443/api/v1"
	if resp := postAPIHello(t, env.Alice, env.Bob.Identity, "any.example."); resp.Error {
		t.Fatalf("hello refused: %+v", resp)
	}
	if st := apiState(env.Alice, env.Bob.Identity); st != transport.PeerStateIntroducing {
		t.Errorf("a hello from a sender with an API endpoint left the API mechanism at %v, want INTRODUCING", st)
	}
}
