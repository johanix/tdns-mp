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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
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
	// discoveries is held by each discovery of Alice's engine
	// (serialDiscovery), and by a test while the lookups it counts run.
	discoveries sync.Mutex
}

// serialDiscovery is an engine's transport with the engine's discoveries
// made one at a time, under mu. The engine's retry starts one every
// RetryInterval (50 ms in the harness), also while one is running. A lookup
// that runs while the peer's records are not in the cache, flushed for a
// lookup past it or not yet cached by the first one, asks the server too,
// and a test that counts the lookups at the server holds mu while those it
// counts run (#290).
type serialDiscovery struct {
	hsync.TransportBridge
	mu *sync.Mutex
}

func (d serialDiscovery) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.TransportBridge.DiscoverPeer(ctx, identity)
}

// newNoAddressScenario builds the scenario and starts Alice's engine with
// cfg. It returns once her discovery of Bob has found him without an address.
// The answer that his address is not there is not cached.
func newNoAddressScenario(t *testing.T, cfg hsync.Config) *noAddressScenario {
	t.Helper()
	return newNoAddressScenarioCached(t, cfg, 0)
}

// newNoAddressScenarioCached is newNoAddressScenario with the answer that
// Bob's address is not there cached by Alice's resolver for denialTTL
// seconds.
func newNoAddressScenarioCached(t *testing.T, cfg hsync.Config, denialTTL uint32) *noAddressScenario {
	t.Helper()
	zone := newDiscoveryZone(t)
	zone.cacheDenials(denialTTL)
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

	startHarnessEngine(t, env, s.alice, cfg, func(d *hsync.Deps) {
		d.Transport = serialDiscovery{TransportBridge: d.Transport, mu: &s.discoveries}
	}).MarkNeeded(hsync.PeerID(s.bob.Identity), "", nil)
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

// sayHello has from, which runs no engine here, send one hello to its peer
// over the wire, as an agent that has just started does: it looks the peer up
// if it has not, its side of the link is at KNOWN, and it is put back there
// afterwards, so that the next call is a hello again. The peer must accept.
func sayHello(t *testing.T, from, to *peerEnv) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()
	p, ok := from.Bridge.PeerRegistry.Get(to.Identity)
	if !ok || !p.HasMechanism(transport.MechanismDNS) {
		if err := from.Bridge.DiscoverAndRegisterAgent(ctx, to.Identity); err != nil {
			t.Fatalf("%s cannot look %s up: %v", from.Identity, to.Identity, err)
		}
		p, _ = from.Bridge.PeerRegistry.Get(to.Identity)
	}
	agent, ok := from.Registry.S.Get(AgentId(to.Identity))
	if !ok {
		t.Fatalf("%s has no view of %s after looking it up", from.Identity, to.Identity)
	}
	p.SetMechanismState(transport.MechanismDNS, transport.PeerStateKnown, "just started")
	resp, err := from.Bridge.SendHelloWithFallback(ctx, agent, nil)
	if err != nil || resp == nil || !resp.Accepted {
		t.Fatalf("hello from %s to %s: response %+v, err %v, want it accepted", from.Identity, to.Identity, resp, err)
	}
	p.SetMechanismState(transport.MechanismDNS, transport.PeerStateKnown, "just started")
}

// waitForLookups waits until count reports n.
func waitForLookups(t *testing.T, what string, count func() int, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for count() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%s was asked for %d times, want %d", what, count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// What the answer says is in the resolver's cache a moment later.
	time.Sleep(50 * time.Millisecond)
}

// bobAddressLookups is how many times Bob's SVCB record has been asked for
// at the authoritative server: the lookups Alice's resolver did not answer
// from its cache. Bob's own resolver never asks for it.
func (s *noAddressScenario) bobAddressLookups() int {
	return s.zone.asked("dns."+s.bob.Identity, dns.TypeSVCB)
}

// A resolver caches the answer that a record is not there. A peer that was
// looked up before its address could be found stays without one for as long
// as that answer is cached, whatever the discovery retry asks: it is answered
// from the cache. The peer's hello says that its records can be found now, so
// the discovery it starts looks the peer up past the cache, and the link comes
// up without waiting for the cached answer to expire.
func TestAHelloLooksUpASenderWithNoAddressPastTheCache(t *testing.T) {
	s := newNoAddressScenarioCached(t, harnessIntervals(), 60)
	p, _ := s.alice.Bridge.PeerRegistry.Get(s.bob.Identity)

	// The answer that Bob has no address is in Alice's cache: her retry goes
	// on, and none of its lookups reaches the server, also not when the
	// address has been published.
	time.Sleep(4 * harnessIntervals().RetryInterval)
	s.zone.set(s.bobAddress)
	time.Sleep(4 * harnessIntervals().RetryInterval)
	if got := s.bobAddressLookups(); got != 1 {
		t.Fatalf("precondition: Bob's SVCB record was asked for %d times, want once: Alice's resolver does not hold the answer that it is not there", got)
	}
	if p.HasMechanism(transport.MechanismDNS) {
		t.Fatal("precondition: Alice found Bob's address through a cache that says there is none")
	}

	s.bobIntroducesHimself(t)
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 5*time.Second)
	if got := s.bobAddressLookups(); got < 2 {
		t.Errorf("Bob's SVCB record was asked for %d times, want one more after his hello", got)
	}
}

// Hellos cannot drive flushes: a sender with no address is looked up past
// the cache once, and for the rest of the interval the discovery its hellos
// start goes through the cache, as before. Bob's address is never published
// here, so every one of his hellos finds him without one.
func TestHellosWithinTheIntervalStartOneLookupPastTheCache(t *testing.T) {
	// Alice's own retry is an hour away: only the hellos look Bob up.
	cfg := harnessIntervals()
	cfg.RetryInterval = time.Hour
	s := newNoAddressScenarioCached(t, cfg, 60)

	sayHello(t, s.bob, s.alice)
	waitForLookups(t, "Bob's SVCB record", s.bobAddressLookups, 2)
	for i := 0; i < 4; i++ {
		sayHello(t, s.bob, s.alice)
	}
	time.Sleep(200 * time.Millisecond)
	if got := s.bobAddressLookups(); got != 2 {
		t.Errorf("Bob's SVCB record was asked for %d times after five hellos, want 2: when Alice discovered him, and once past the cache", got)
	}
	if st := dnsState(s.alice, s.bob.Identity); st != transport.PeerStateNeeded {
		t.Errorf("Alice holds Bob's DNS mechanism, which has no address, at %v, want NEEDED", st)
	}
}

// When the interval has passed, the next hello from a sender that still has
// no address is looked up past the cache again. Here the address is
// published after the first such lookup, whose answer is cached, and found by
// the second.
func TestAHelloAfterTheIntervalIsLookedUpPastTheCacheAgain(t *testing.T) {
	const interval = 300 * time.Millisecond
	cfg := harnessIntervals()
	cfg.RetryInterval = time.Hour
	s := newNoAddressScenarioCached(t, cfg, 60)
	s.alice.Bridge.rediscoveryInterval = interval

	sayHello(t, s.bob, s.alice)
	waitForLookups(t, "Bob's SVCB record", s.bobAddressLookups, 2)
	s.zone.set(s.bobAddress)
	time.Sleep(interval)

	sayHello(t, s.bob, s.alice)
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 5*time.Second)
	if got := s.bobAddressLookups(); got != 3 {
		t.Errorf("Bob's SVCB record was asked for %d times, want 3", got)
	}
}

// The interval is one per peer for every lookup past the cache: a peer that
// was looked up for its hello is not looked up again for refusing ours while
// the interval lasts. Bob's hello finds him without an address; when his
// address is found, by Alice's retry once the cached answer has expired, he
// refuses her hellos, holding nobody authorized.
func TestALookupPastTheCacheForAHelloCountsForRefusedHellosToo(t *testing.T) {
	// The answer that Bob's address is not there is cached for a second.
	// His JWK record is cached for a minute, so every lookup of it at the
	// server is one past the cache.
	s := newNoAddressScenarioCached(t, harnessIntervals(), 1)
	s.bob.Bridge.authorizedPeers = func() []string { return nil }
	jwkLookups := func() int { return s.zone.asked("dns."+s.bob.Identity, core.TypeJWK) }
	// Alice's retries wait, and the one running ends, while the lookups
	// up to the one for Bob's hello are counted.
	func() {
		s.discoveries.Lock()
		defer s.discoveries.Unlock()
		if got := jwkLookups(); got != 1 {
			t.Fatalf("precondition: Bob's JWK record was asked for %d times, want once: when Alice discovered him", got)
		}
		sayHello(t, s.bob, s.alice)
		waitForLookups(t, "Bob's JWK record", jwkLookups, 2)
	}()
	// Bob holds no peer: his hello gave him a view of Alice, and a peer he
	// holds is admitted whatever its state (#178 step 7).
	s.bob.Registry.S.Remove(AgentId(s.alice.Identity))

	s.zone.set(s.bobAddress)
	waitForRefusals(t, s.alice, s.bob.Identity, helloRefusalsBeforeRediscovery+3)
	if got := jwkLookups(); got != 2 {
		t.Errorf("Bob's JWK record was asked for %d times while he refused %d hellos, want 2: when Alice discovered him, and once past the cache for his hello",
			got, refusedInARow(s.alice, s.bob.Identity))
	}
}

// A sender that is not in the registry at all has no address either, and is
// looked up past the cache in the same way. It needs it more: the engine does
// not know the peer, so no retry of its own would ever find it. Here an
// earlier lookup of Bob failed before any of his records were published, and
// left nothing in the registry and its answers in the cache. The peers run
// without payload crypto: with it, a hello from a sender whose key is not
// held does not get this far.
func TestAHelloFromAnUnknownSenderIsLookedUpPastTheCache(t *testing.T) {
	zone := newDiscoveryZone(t)
	zone.cacheDenials(60)
	env := newIntegEnv(t, &integEnvConfig{
		AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true,
		Discovery: zone,
	})
	alice, bob := env.Alice, env.Bob
	zone.set(dnsDiscoveryRecords(alice.Identity, listenDNS(t, env, alice), newHarnessKey(t))...)
	bobRecords := dnsDiscoveryRecords(bob.Identity, listenDNS(t, env, bob), newHarnessKey(t))
	cfg := harnessIntervals()
	cfg.RetryInterval = time.Hour
	startHarnessEngine(t, env, alice, cfg)

	lookUp := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		return alice.Bridge.DiscoverAndRegisterAgent(ctx, bob.Identity)
	}
	if err := lookUp(); err == nil {
		t.Fatal("precondition: Alice found Bob, who has published nothing")
	}
	zone.set(bobRecords...)
	if err := lookUp(); err == nil {
		t.Fatal("precondition: Alice found Bob through a cache that says he has published nothing")
	}
	if _, known := alice.Registry.S.Get(AgentId(bob.Identity)); known {
		t.Fatal("precondition: Bob is in Alice's registry after two lookups that found nothing")
	}

	sayHello(t, bob, alice)
	waitForDNSState(t, alice, bob.Identity, transport.PeerStateOperational, 5*time.Second)
}
