/*
 * A peer that refuses our hello because the key we hold for it is not the
 * one it uses (tdns-mp #145).
 *
 * The scenarios run two harness peers with payload crypto, their engines,
 * and a resolver each over records the test publishes
 * (discovery_harness_test.go). "Alice" looks "Bob" up while the JWK record
 * published for him is an older one, as a secondary that started from a
 * stored copy of his identity zone serves it until his first publish reaches
 * it. Bob has the right key for Alice.
 */

package tdnsmp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/johanix/tdns/v2/core"
)

// refusedHelloScenario is two peers that listen, with their engines started
// and their first hellos held back, as an agent's are until its identity is
// published.
type refusedHelloScenario struct {
	env        *integEnv
	zone       *discoveryZone
	alice, bob *peerEnv
	// bobKey is the key Bob runs with.
	bobKey     *harnessKey
	bobListens net.Addr
	engines    map[*peerEnv]*hsync.Engine
	// release lets the hellos go.
	release func()
}

// newRefusedHelloScenario builds the scenario with the harness intervals.
// Alice's records are published; Bob's are the test's to publish
// (publishBob). With authorize unset neither peer holds the other authorized.
func newRefusedHelloScenario(t *testing.T, authorize bool) *refusedHelloScenario {
	t.Helper()
	return newRefusedHelloScenarioWith(t, authorize, harnessIntervals())
}

// newRefusedHelloScenarioWith is newRefusedHelloScenario with the engines'
// intervals given.
func newRefusedHelloScenarioWith(t *testing.T, authorize bool, cfg hsync.Config) *refusedHelloScenario {
	t.Helper()
	zone := newDiscoveryZone(t)
	keys := map[string]*harnessKey{
		"alice.agent.example.": newHarnessKey(t),
		"bob.agent.example.":   newHarnessKey(t),
	}
	env := newIntegEnv(t, &integEnvConfig{
		AuthorizeAllPeers: authorize, ChunkMode: "edns0", ControlZoneIsIdentity: true,
		Discovery: zone, Keys: keys,
	})
	s := &refusedHelloScenario{
		env: env, zone: zone, alice: env.Alice, bob: env.Bob,
		bobKey:  keys[env.Bob.Identity],
		engines: map[*peerEnv]*hsync.Engine{},
	}
	zone.set(dnsDiscoveryRecords(s.alice.Identity, listenDNS(t, env, s.alice), keys[s.alice.Identity])...)
	s.bobListens = listenDNS(t, env, s.bob)

	gate := make(chan struct{})
	s.release = func() { close(gate) }
	held := func(deps *hsync.Deps) {
		deps.HelloReady = func(ctx context.Context) bool {
			select {
			case <-gate:
				return true
			case <-ctx.Done():
				return false
			}
		}
	}
	// Each engine makes its discoveries one at a time: the harness retry
	// starts one every 50 ms while a peer is NEEDED, also while the one
	// MarkNeeded started is still running, and two discoveries through a
	// cache that holds nothing yet both ask the server (#304).
	for _, pe := range []*peerEnv{s.alice, s.bob} {
		serial := func(deps *hsync.Deps) {
			deps.Transport = serialDiscovery{TransportBridge: deps.Transport, mu: &sync.Mutex{}}
		}
		s.engines[pe] = startHarnessEngine(t, env, pe, cfg, held, serial)
	}
	return s
}

// publishBob publishes Bob's records with key as his long-term key.
func (s *refusedHelloScenario) publishBob(key *harnessKey) {
	s.zone.set(dnsDiscoveryRecords(s.bob.Identity, s.bobListens, key)...)
}

// discovers has pe look peer up and waits until it holds peer's mechanism at
// KNOWN, with its hello to come.
func (s *refusedHelloScenario) discovers(t *testing.T, pe, peer *peerEnv) {
	t.Helper()
	s.engines[pe].MarkNeeded(hsync.PeerID(peer.Identity), "", nil)
	waitForDNSState(t, pe, peer.Identity, transport.PeerStateKnown, integTestTimeout)
}

// bobJWKLookups is how many times Bob's JWK record has been asked for at the
// authoritative server: the lookups Alice's resolver did not answer from its
// cache. Bob's own resolver never asks for it.
func (s *refusedHelloScenario) bobJWKLookups() int {
	return s.zone.asked("dns."+s.bob.Identity, core.TypeJWK)
}

// heldJWK is the JWK that pe holds for peer.
func heldJWK(pe *peerEnv, peer string) string {
	p, ok := pe.Bridge.PeerRegistry.Get(peer)
	if !ok {
		return ""
	}
	jwk, _ := p.MechanismJWK(transport.MechanismDNS)
	return jwk
}

// refusedInARow is how many hellos and beats in a row peer has refused pe.
func refusedInARow(pe *peerEnv, peer string) int {
	tm := pe.Bridge
	tm.refusedHellosMu.Lock()
	defer tm.refusedHellosMu.Unlock()
	if r := tm.refusedHellos[peer]; r != nil {
		return r.inARow
	}
	return 0
}

// lookedUpAt is when pe last booked a lookup of peer past the cache.
func lookedUpAt(pe *peerEnv, peer string) time.Time {
	tm := pe.Bridge
	tm.refusedHellosMu.Lock()
	defer tm.refusedHellosMu.Unlock()
	if r := tm.refusedHellos[peer]; r != nil {
		return r.rediscovered
	}
	return time.Time{}
}

// waitForRefusals waits until peer has refused n of pe's hellos in a row.
func waitForRefusals(t *testing.T, pe *peerEnv, peer string, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for refusedInARow(pe, peer) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s refused %d of %s's hellos in a row, want %d", peer, refusedInARow(pe, peer), pe.Identity, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The case from a running fleet: Alice discovered Bob while an older JWK was
// served for him, and holds that key. Every hello between the two is refused:
// what Alice encrypts to the old key Bob cannot decrypt, and what Bob signs
// does not verify with it. After a few refusals Alice flushes what her
// resolver has cached for Bob and looks him up again, the record now says
// his current key, and the link comes up without a restart of either.
func TestAPeerWhoseKeyWeHoldWrongIsLookedUpAgain(t *testing.T) {
	s := newRefusedHelloScenario(t, true)
	old := newHarnessKey(t)
	s.publishBob(old)
	s.discovers(t, s.alice, s.bob)
	s.discovers(t, s.bob, s.alice)
	if got := heldJWK(s.alice, s.bob.Identity); got != old.jwk {
		t.Fatalf("precondition: Alice holds the key %q for Bob, want the older one that was published", got)
	}

	// Bob's first publish reaches the server: the record is his current key.
	// Alice's resolver has the older record cached.
	s.publishBob(s.bobKey)
	s.release()

	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 10*time.Second)
	waitForDNSState(t, s.bob, s.alice.Identity, transport.PeerStateOperational, 10*time.Second)
	if got := heldJWK(s.alice, s.bob.Identity); got != s.bobKey.jwk {
		t.Errorf("Alice holds the key %q for Bob, want his current one", got)
	}
	if got := s.bobJWKLookups(); got != 2 {
		t.Errorf("Bob's JWK record was looked up %d times, want 2: when Alice discovered him, and once more after his refusals", got)
	}
}

// A peer that goes on refusing is looked up again once, and then not before
// the interval has passed, however many hellos it refuses in between. That
// holds when the older key is still what the lookup returns, and when the
// refusal has nothing to do with a key: a peer that does not hold us
// authorized answers REFUSED too.
func TestAPeerThatKeepsRefusingIsLookedUpOncePerInterval(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) *refusedHelloScenario
	}{
		{"TheOlderKeyIsStillServed", func(t *testing.T) *refusedHelloScenario {
			s := newRefusedHelloScenario(t, true)
			s.publishBob(newHarnessKey(t))
			s.discovers(t, s.alice, s.bob)
			s.discovers(t, s.bob, s.alice)
			return s
		}},
		{"ThePeerDoesNotHoldUsAuthorized", func(t *testing.T) *refusedHelloScenario {
			s := newRefusedHelloScenario(t, false)
			s.publishBob(s.bobKey)
			s.discovers(t, s.alice, s.bob)
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.setup(t)
			s.release()

			// Well past the refusals that start the lookup.
			waitForRefusals(t, s.alice, s.bob.Identity, helloRefusalsBeforeRediscovery+8)
			if got := s.bobJWKLookups(); got != 2 {
				t.Errorf("Bob's JWK record was looked up %d times while he refused %d hellos, want 2: when Alice discovered him, and once more",
					got, refusedInARow(s.alice, s.bob.Identity))
			}
			if st := dnsState(s.alice, s.bob.Identity); st != transport.PeerStateKnown {
				t.Errorf("Alice holds Bob's DNS mechanism at %v, want KNOWN: he refuses her hello", st)
			}
		})
	}
}

// A refusal or two is common while a peer starts: it has not loaded the zone
// that authorizes us yet. That starts no lookup, and when the peer then
// accepts, the count starts over.
func TestAFewRefusedHellosStartNoLookup(t *testing.T) {
	// Hellos far enough apart that the zone below is in place between the
	// second and the third.
	cfg := harnessIntervals()
	cfg.HelloFastSpacing, cfg.HelloRetryInterval = 400*time.Millisecond, 400*time.Millisecond
	s := newRefusedHelloScenarioWith(t, false, cfg)
	s.publishBob(s.bobKey)
	s.discovers(t, s.alice, s.bob)
	s.discovers(t, s.bob, s.alice)
	// Bob holds no peer: a peer he holds is admitted whatever its state
	// until the hold time is over (#178 step 7). Her key stays with him.
	s.engines[s.bob].RemovePeer(hsync.PeerID(s.alice.Identity))
	s.release()

	waitForRefusals(t, s.alice, s.bob.Identity, helloRefusalsBeforeRediscovery-1)
	// Bob loads a zone that lists them both.
	zd := seedZoneWithHSYNC3(t, "refused-hello.example.", s.alice.Identity, s.bob.Identity)
	addHSYNCPARAMServers(t, zd, shortLabel(s.alice.Identity), shortLabel(s.bob.Identity))

	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 10*time.Second)
	if got := s.bobJWKLookups(); got != 1 {
		t.Errorf("Bob's JWK record was looked up %d times, want once: %d refused hellos start no lookup",
			got, helloRefusalsBeforeRediscovery-1)
	}
	if got := refusedInARow(s.alice, s.bob.Identity); got != 0 {
		t.Errorf("%d refusals in a row on the books after Bob accepted a hello, want none", got)
	}
}

// When the interval has passed and the peer still refuses, it is looked up
// again. Here Bob's JWK record still holds the older key at its second
// lookup, the first after his refusals, and his current key from the third
// on: the one made once the interval has passed.
func TestAPeerThatStillRefusesIsLookedUpAgainAfterTheInterval(t *testing.T) {
	const interval = 500 * time.Millisecond
	s := newRefusedHelloScenario(t, true)
	s.alice.Bridge.rediscoveryInterval = interval
	s.publishBob(newHarnessKey(t))
	// The first lookup after the refusals, the second of Bob's JWK record,
	// returns the older key again; the zone serves his current key from the
	// next one on. As it answers that lookup it notes when Alice booked it:
	// the interval runs from there, and the booking is before the server
	// counts the lookup. The zone does both, not this goroutine, which a
	// loaded machine may hold until after the next lookup (#304).
	booked := make(chan time.Time, 1)
	s.zone.setAfter("dns."+s.bob.Identity, core.TypeJWK, 2, dnsDiscoveryRecords(s.bob.Identity, s.bobListens, s.bobKey),
		func() { booked <- lookedUpAt(s.alice, s.bob.Identity) })
	s.discovers(t, s.alice, s.bob)
	s.discovers(t, s.bob, s.alice)
	s.release()

	var first time.Time
	select {
	case first = <-booked:
	case <-time.After(5 * time.Second):
		t.Fatal("Alice did not look Bob up again after his refusals")
	}
	if first.IsZero() {
		t.Fatal("Alice looked Bob up again with no lookup on her books")
	}

	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 10*time.Second)
	if waited := time.Since(first); waited < interval*9/10 {
		t.Errorf("Alice looked Bob up again %v after the lookup before, want no sooner than %v", waited, interval)
	}
	if got := s.bobJWKLookups(); got != 3 {
		t.Errorf("Bob's JWK record was looked up %d times, want 3", got)
	}
	if got := heldJWK(s.alice, s.bob.Identity); got != s.bobKey.jwk {
		t.Errorf("Alice holds the key %q for Bob, want his current one", got)
	}
}

// Only a refusal counts. A peer that does not answer at all is not looked up
// again for it: its key is not what stands in the way.
func TestAHelloThatGetsNoAnswerStartsNoLookup(t *testing.T) {
	s := newRefusedHelloScenario(t, true)
	// Bob's records name a port where nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.bobListens = ln.Addr()
	ln.Close()
	s.publishBob(s.bobKey)
	s.discovers(t, s.alice, s.bob)
	s.release()

	time.Sleep(15 * harnessIntervals().HelloRetryInterval)
	if got := refusedInARow(s.alice, s.bob.Identity); got != 0 {
		t.Errorf("%d refusals counted for a peer that does not answer", got)
	}
	if got := s.bobJWKLookups(); got != 1 {
		t.Errorf("Bob's JWK record was looked up %d times, want once: when Alice discovered him", got)
	}
}

// A peer that is given a new key while this agent runs. The agent holds the
// peer's mechanism past the hello: it sends beats, and a peer whose beats
// fail is still sent beats, never a hello. So the peer refuses beats and no
// hello, and the count behind the fresh lookup has to see those too. Here
// Alice holds an older key for Bob and holds him as OPERATIONAL, as she would
// had he changed his key since their last beat.
func TestAPeerThatRefusesOurBeatsIsLookedUpAgain(t *testing.T) {
	s := newRefusedHelloScenario(t, true)
	old := newHarnessKey(t)
	s.publishBob(old)
	s.discovers(t, s.alice, s.bob)
	s.discovers(t, s.bob, s.alice)
	if got := heldJWK(s.alice, s.bob.Identity); got != old.jwk {
		t.Fatalf("precondition: Alice holds the key %q for Bob, want the older one that was published", got)
	}
	p, ok := s.alice.Bridge.PeerRegistry.Get(s.bob.Identity)
	if !ok {
		t.Fatal("precondition: Alice has no peer entry for Bob")
	}
	p.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test: as after a completed handshake")

	// The record is Bob's current key; Alice's resolver has the older one
	// cached.
	s.publishBob(s.bobKey)
	s.release()

	deadline := time.Now().Add(15 * time.Second)
	for heldJWK(s.alice, s.bob.Identity) != s.bobKey.jwk {
		if time.Now().After(deadline) {
			t.Fatalf("Alice still holds the older key for Bob after %d of her messages were refused in a row; his JWK record was looked up %d time(s)",
				refusedInARow(s.alice, s.bob.Identity), s.bobJWKLookups())
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitForDNSState(t, s.alice, s.bob.Identity, transport.PeerStateOperational, 10*time.Second)
	waitForDNSState(t, s.bob, s.alice.Identity, transport.PeerStateOperational, 10*time.Second)
	if got := s.bobJWKLookups(); got != 2 {
		t.Errorf("Bob's JWK record was looked up %d times, want 2: when Alice discovered him, and once more after his refusals", got)
	}
}
