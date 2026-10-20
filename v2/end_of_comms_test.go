/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// namingZones is a zone lookup with one multi-provider zone, whose
// participants are the identities given.
type namingZones struct{ participants []hsync.PeerID }

type namingZone struct{ participants []hsync.PeerID }

func (z namingZone) ZoneName() string                    { return "named.endofcomms.example." }
func (z namingZone) HSYNC3() []dns.RR                    { return nil }
func (z namingZone) IsMultiProvider() bool               { return true }
func (z namingZone) Participants() []hsync.PeerID        { return z.participants }
func (n *namingZones) Get(string) (hsync.ZoneView, bool) { return namingZone{n.participants}, true }
func (n *namingZones) Items() map[string]hsync.ZoneView {
	return map[string]hsync.ZoneView{"named.endofcomms.example.": namingZone{n.participants}}
}

// endOfCommsEngine wires an engine into bob's registry as the agent does:
// the engine's registry is the agent's, and its hooks make and drop the
// views. The zone names bob and the identities given.
func endOfCommsEngine(t *testing.T, env *integEnv, named ...string) (*hsync.Engine, *namingZones) {
	t.Helper()
	ar := env.Bob.Registry
	zones := &namingZones{participants: []hsync.PeerID{hsync.PeerID(env.Bob.Identity)}}
	for _, id := range named {
		zones.participants = append(zones.participants, hsync.PeerID(id))
	}
	engine := hsync.NewEngine(hsync.Deps{
		LocalID: hsync.PeerID(env.Bob.Identity),
		Zones:   zones,
		PeerHooks: hsync.PeerHooks{
			OnPeerStored:  func(peer *hsync.Peer) { ar.materializeAgentView(peer) },
			OnPeerRemoved: func(peer *hsync.Peer) { ar.removePeerView(peer) },
		},
	}, hsync.DefaultConfig())
	ar.HsyncEngine = engine
	ar.Registry = engine.Registry()
	return engine, zones
}

// A peer this agent holds that shares no zone is admitted, and once it is
// removed it is not.
func TestARemovedPeerIsNoLongerAdmitted(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	engine, _ := endOfCommsEngine(t, env)
	engine.MarkNeeded(hsync.PeerID(alice), "", nil)
	p := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	p.SetMechanismState("DNS", transport.PeerStateOperational, "test seed")
	p.SetMechanismLastBeatSent("DNS", time.Now())
	if st := env.Bob.Registry.effectiveAgentState(AgentId(alice)); st != AgentStateLegacy {
		t.Fatalf("precondition: alice reads %v at bob, want LEGACY", st)
	}
	if ok, why := env.Bob.Bridge.IsPeerAuthorized(alice, ""); !ok {
		t.Fatalf("a held peer that shares no zone was refused: %s", why)
	}

	engine.RemovePeer(hsync.PeerID(alice))
	if ok, why := env.Bob.Bridge.IsPeerAuthorized(alice, ""); ok {
		t.Fatalf("a removed peer was admitted: %s", why)
	}
}

// A held peer that shares no zone is admitted whatever its state: one whose
// beats have failed for a while reads DEGRADED, and its hello after a restart
// is taken.
func TestAKeptPeerIsAdmittedWhateverItsState(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	engine, _ := endOfCommsEngine(t, env)
	engine.MarkNeeded(hsync.PeerID(alice), "", nil)
	p := env.Bob.Bridge.PeerRegistry.GetOrCreate(alice)
	p.SetMechanismState("DNS", transport.PeerStateDegraded, "test seed")
	if st := env.Bob.Registry.effectiveAgentState(AgentId(alice)); st == AgentStateLegacy {
		t.Fatalf("precondition: alice reads %v, want a state other than LEGACY", st)
	}
	if ok, why := env.Bob.Bridge.IsPeerAuthorized(alice, ""); !ok {
		t.Fatalf("a DEGRADED held peer that shares no zone was refused: %s", why)
	}
	if env.Bob.Bridge.admittedForKeyOnly(alice, "any.endofcomms.example.") {
		t.Error("admittedForKeyOnly does not count the held peer as admitted in full")
	}
}

// A beat or a hello on its way when the engine removed the peer sends
// nothing, and neither the engine's registry nor the agent's holds the
// identity afterwards.
func TestABeatOnItsWayDoesNotRecreateARemovedPeersView(t *testing.T) {
	const id = AgentId("agent.removed.endofcomms.example.")
	ar := newE1bRegistry()
	peer := enginePeer(ar, id)
	ar.materializeAgentView(peer)
	ar.Registry.S.Remove(peer.ID)
	ar.removePeerView(peer)

	b := &mpHsyncBridge{ar: ar, tm: &MPTransportBridge{}}
	if _, _, err := b.SendBeat(context.Background(), peer, 1); err != errPeerNotHeld {
		t.Errorf("a beat through the removed peer: err = %v, want %v", err, errPeerNotHeld)
	}
	if err := b.SendHello(context.Background(), peer, nil); err != errPeerNotHeld {
		t.Errorf("a hello through the removed peer: err = %v, want %v", err, errPeerNotHeld)
	}
	ar.materializeAgentView(peer) // the engine's store hook after the beat
	if _, ok := ar.S.Get(id); ok {
		t.Error("the agent's registry holds the removed peer again")
	}
	if _, ok := ar.Registry.S.Get(peer.ID); ok {
		t.Error("the engine's registry holds the removed peer again")
	}
}

// A discovery that completes for an identity that no zone names puts nothing
// in the registry.
func TestADiscoveryForAnIdentityNoZoneNamesIsDropped(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	const carol = "carol.endofcomms.example."
	endOfCommsEngine(t, env)
	env.Bob.Bridge.TransportManager.OnPeerDiscovered(transport.NewPeer(carol))
	if _, ok := env.Bob.Registry.S.Get(carol); ok {
		t.Error("the agent's registry holds an identity no zone names")
	}
	if _, ok := env.Bob.Registry.Registry.S.Get(carol); ok {
		t.Error("the engine's registry holds an identity no zone names")
	}
}

// A discovery on its way when the peer was removed does not put it back: no
// zone names it any more. One that a zone names is registered.
func TestADiscoveryOnItsWayDoesNotPutARemovedPeerBack(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	engine, zones := endOfCommsEngine(t, env, alice)
	engine.MarkNeeded(hsync.PeerID(alice), "named.endofcomms.example.", nil)
	if _, ok := env.Bob.Registry.S.Get(AgentId(alice)); !ok {
		t.Fatal("setup: alice has no view at bob")
	}
	zones.participants = zones.participants[:1] // alice is named no more
	engine.RemovePeer(hsync.PeerID(alice))

	env.Bob.Bridge.TransportManager.OnPeerDiscovered(transport.NewPeer(alice))
	if _, ok := env.Bob.Registry.S.Get(AgentId(alice)); ok {
		t.Error("the discovery put the removed peer's view back")
	}
	if _, ok := env.Bob.Registry.Registry.S.Get(hsync.PeerID(alice)); ok {
		t.Error("the discovery put the removed peer back in the engine's registry")
	}

	zones.participants = append(zones.participants, hsync.PeerID(alice))
	env.Bob.Bridge.TransportManager.OnPeerDiscovered(transport.NewPeer(alice))
	if _, ok := env.Bob.Registry.S.Get(AgentId(alice)); !ok {
		t.Error("a discovery of an identity a zone names again was dropped")
	}
}

// The auditor's engine takes the agent's gate: in a zone without the
// auditor's record it registers no provider, from a diff or from a pass.
func TestAnAuditorsHsyncDiffRegistersNothingInAZoneWithoutItsRecord(t *testing.T) {
	const zone = "noauditor.endofcomms.example."
	const auditor = "auditor.endofcomms.example."
	zd := providerZone(t, zone, arrivalA, arrivalB)
	conf := roleConf(t, AppTypeMPAuditor, "auditor", auditor, zd)
	engine := newAuditorHsyncEngine(conf)
	mpzd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("setup: the zone is not there")
	}
	_ = engine.ApplyHsyncDiff(zone, hsync.HsyncDiff{Adds: mpZoneView{mpzd}.HSYNC3()})
	if added, _, _ := engine.ReconcileZone(zone); added != 0 {
		t.Errorf("a pass added %d provider(s) in a zone without the auditor's record", added)
	}
	for _, id := range []string{arrivalA, arrivalB} {
		if _, ok := engine.Registry().S.Get(hsync.PeerID(id)); ok {
			t.Errorf("the auditor registered %s in a zone without its record", id)
		}
	}
}

// A peer that keeps refusing our beats is not looked up again once no zone
// names it: at the end of comms the side that removes it last sees that.
func TestARefusingPeerNoZoneNamesIsNotLookedUp(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	endOfCommsEngine(t, env)
	for i := 0; i < helloRefusalsBeforeRediscovery; i++ {
		if env.Bob.Bridge.noteRefused(alice, "beats") {
			t.Fatalf("refusal %d had a peer no zone names looked up again", i+1)
		}
	}
}

// Admission is not trust. A peer this agent holds with no zone, as the
// operator's discover leaves one before its discovery, passes check 2, the
// gate before the crypto. Its signed SYNC still gets nowhere: without its
// key the payload does not verify, and the message is dropped before any
// handler runs. Once its key is known, the same SYNC reaches the handler and
// is refused there: it shares no zone. So check 2 is no way in.
func TestAHeldPeerThatWasNeverDiscoveredGetsNoSyncIn(t *testing.T) {
	zone := newDiscoveryZone(t)
	keys := map[string]*harnessKey{
		"alice.agent.example.": newHarnessKey(t),
		"bob.agent.example.":   newHarnessKey(t),
	}
	env := newIntegEnv(t, &integEnvConfig{
		ChunkMode: "edns0", ControlZoneIsIdentity: true, Discovery: zone, Keys: keys,
	})
	alice, bob := env.Alice, env.Bob
	zone.set(dnsDiscoveryRecords(bob.Identity, listenDNS(t, env, bob), keys[bob.Identity])...)
	aliceAt := listenDNS(t, env, alice) // her records are not published yet

	// Bob holds Alice, with no zone, and has never looked her up.
	bobEngine, _ := endOfCommsEngine(t, env)
	bobEngine.MarkNeeded(hsync.PeerID(alice.Identity), "", nil)
	if ok, why := bob.Bridge.IsPeerAuthorized(alice.Identity, ""); !ok {
		t.Fatalf("precondition: check 2 does not admit the held peer: %s", why)
	}

	ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
	defer cancel()
	if err := alice.Bridge.DiscoverAndRegisterAgent(ctx, bob.Identity); err != nil {
		t.Fatalf("Alice cannot look Bob up: %v", err)
	}
	toBob, _ := alice.Bridge.PeerRegistry.Get(bob.Identity)
	const syncZone = "admission.endofcomms.example."
	send := func() (*PeerSyncResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
		defer cancel()
		return alice.Bridge.SendSyncWithFallback(ctx, toBob, &PeerSyncRequest{
			SenderID: alice.Identity, Zone: syncZone, MessageType: "sync", SyncType: PeerSyncTypeNS,
			DistributionID: nextDistributionID(),
			Records:        map[string][]string{syncZone: {syncZone + " 3600 IN NS ns.alice.example."}},
		})
	}
	// What Bob's router saw from Alice: its stats count a message once it
	// has been read, past the crypto.
	routed := func() uint64 {
		p, ok := bob.Bridge.PeerRegistry.Get(alice.Identity)
		if !ok {
			return 0
		}
		_, _, n := p.Stats.GetStats()
		return uint64(n)
	}
	nothingForBob := func(when string) {
		t.Helper()
		select {
		case m := <-bob.MsgQs.Msg:
			t.Errorf("%s: a SYNC reached Bob's queue: %+v", when, m)
		case <-time.After(200 * time.Millisecond):
		}
	}

	if resp, err := send(); err == nil {
		t.Errorf("without her key: Bob answered Alice's SYNC: %+v", resp)
	}
	if n := routed(); n != 0 {
		t.Errorf("without her key: Bob's router read %d message(s) from Alice, want none", n)
	}
	nothingForBob("without her key")

	// Bob gets her key: the SYNC is read, and the handler refuses it.
	zone.set(dnsDiscoveryRecords(alice.Identity, aliceAt, keys[alice.Identity])...)
	bob.Bridge.flushAndDiscover(alice.Identity) // past his cached miss
	resp, err := send()
	if err == nil && resp != nil && resp.Status == transport.ConfirmSuccess {
		t.Errorf("with her key: Bob took a SYNC from a peer that shares no zone: %+v", resp)
	}
	if n := routed(); n == 0 {
		t.Error("with her key: Bob's router read nothing from Alice, want the SYNC read and refused")
	}
	nothingForBob("with her key")
}

// The agent's combiner is named by its config, not by a zone: one that keeps
// refusing our beats, after a change of its key, is looked up again
// (PR #193), though no zone names it.
func TestTheCombinerIsLookedUpAgainThoughNoZoneNamesIt(t *testing.T) {
	const combiner = "combiner.endofcomms.example."
	env := newIntegEnv(t, &integEnvConfig{CombinerID: combiner})
	endOfCommsEngine(t, env)
	looked := false
	for i := 0; i < helloRefusalsBeforeRediscovery; i++ {
		looked = env.Bob.Bridge.noteRefused(combiner, "beats")
	}
	if !looked {
		t.Fatal("a combiner that keeps refusing our beats was not looked up again")
	}
}

// Refusals from a peer that no zone names book no look-up: once a zone names
// it, its next run of refusals has it looked up at once.
func TestARefusalNoZoneNamesBooksNoLookup(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	_, zones := endOfCommsEngine(t, env)
	for i := 0; i < helloRefusalsBeforeRediscovery; i++ {
		env.Bob.Bridge.noteRefused(alice, "beats")
	}
	zones.participants = append(zones.participants, hsync.PeerID(alice))
	if !env.Bob.Bridge.noteRefused(alice, "beats") {
		t.Fatal("a peer named again was not looked up: the refusals before booked a look-up that was not made")
	}
}

// A discovery that completes for a peer the engine holds, found by the
// operator and named by no zone, completes as any other: the peer's
// mechanisms are what it offers, and one that is usable is KNOWN.
func TestADiscoveryOfAPeerTheEngineHoldsCompletes(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	const carol = "carol.endofcomms.example."
	engine, _ := endOfCommsEngine(t, env)
	engine.MarkNeeded(hsync.PeerID(carol), "", nil)
	p := env.Bob.Bridge.PeerRegistry.GetOrCreate(carol)
	p.SetMechanismContactInfo("DNS", "complete")
	env.Bob.Bridge.TransportManager.OnPeerDiscovered(p)
	if st, _ := p.MechanismRawState("DNS"); st != transport.PeerStateKnown {
		t.Errorf("the DNS mechanism of a held peer reads %v after its discovery, want KNOWN", st)
	}
	if v, ok := env.Bob.Registry.S.Get(carol); !ok || !v.DnsMethod || v.ApiMethod {
		t.Errorf("the held peer's view after its discovery: %+v, want DNS only", v)
	}
}

// An agent whose identity is configured without its trailing dot, or in
// another case, still has its standing in a zone that lists it.
func TestStandingIsReadOnTheCanonicalName(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{})
	alice := env.Alice.Identity
	zones := &namingZones{participants: []hsync.PeerID{hsync.PeerID(env.Bob.Identity), hsync.PeerID(alice)}}
	for _, local := range []string{strings.TrimSuffix(env.Bob.Identity, "."), strings.ToUpper(env.Bob.Identity)} {
		engine := hsync.NewEngine(hsync.Deps{LocalID: hsync.PeerID(local), Zones: zones}, hsync.DefaultConfig())
		if !engine.ZoneNamesPeer(hsync.PeerID(alice)) {
			t.Errorf("local identity %q: the zone that lists it names no peer", local)
		}
		if engine.ZoneNamesPeer(hsync.PeerID(strings.ToUpper(env.Bob.Identity))) {
			t.Errorf("local identity %q: the agent is named as its own peer", local)
		}
	}
}
