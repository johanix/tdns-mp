/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
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
