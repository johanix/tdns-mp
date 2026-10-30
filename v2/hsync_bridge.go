/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"errors"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// mpHsyncBridge implements hsync.TransportBridge for AgentRegistry + MPTransport.
type mpHsyncBridge struct {
	ar *AgentRegistry
	tm *MPTransportBridge
}

func (b *mpHsyncBridge) DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error) {
	if b.tm == nil || b.tm.TransportManager == nil {
		return nil, context.Canceled
	}
	rearmFailedDiscovery(b.tm.TransportManager.PeerRegistry, identity)
	return b.tm.TransportManager.DiscoverPeer(ctx, identity)
}

// rearmFailedDiscovery puts a peer whose last discovery failed back to
// NEEDED so that the transport discovers it again.
//
// OnDiscoveryFailed (the bridge's own seam in NewMPTransportBridge) marks
// such a peer ERROR at the top level. The transport's DiscoverPeer takes any
// top-level state at or above KNOWN for "already discovered" and returns the
// peer untouched; ERROR is the highest state value, so a failed peer was
// never resolved again by the engine's periodic discovery retry: every
// attempt returned at once, without a query, and only a kick from the
// peer's own traffic (an inbound message with no verification key) ever
// rediscovered it. On a cold start, where a peer's identity is not yet
// published when it is first looked up, that made discovery wait for the
// peer to call first.
//
// Only a peer that really is unresolved is re-armed: one that is not
// Addressable (no DNS carrier address, no usable API) and has no mechanism
// past NEEDED. OnDiscoveryFailed writes ERROR again if the
// retry fails too.
//
// A mechanism past NEEDED that has no address does not count: it is not
// resolved, whatever its state says, and the engine's retry asks for it to
// be discovered (tdns-mp #84).
func rearmFailedDiscovery(reg *transport.PeerRegistry, identity string) {
	if reg == nil {
		return
	}
	p, ok := reg.Get(identity)
	if !ok || p == nil || p.GetState() != transport.PeerStateError || p.Addressable() {
		return
	}
	for _, mech := range []string{"API", "DNS"} {
		if !p.HasMechanism(mech) {
			continue
		}
		switch st, _ := p.MechanismRawState(mech); st {
		case transport.PeerStateKnown, transport.PeerStateIntroducing, transport.PeerStateOperational,
			transport.PeerStateDegraded, transport.PeerStateInterrupted:
			return
		}
	}
	p.SetState(transport.PeerStateNeeded, "discovery retry after a failed discovery")
}

// errPeerNotHeld is a send to a peer object the engine no longer holds: the
// peer was removed while the send was on its way, and nothing is sent (#132).
var errPeerNotHeld = errors.New("peer is no longer held by the engine")

// agentViewForPeer returns the persistent ar.S view for the peer (materializing
// it if needed), or a transient unstored view when no AgentRegistry is wired
// (test harnesses). E1.b: the view shares the peer pointer, so there is no
// post-send copy-back — persistAgentAndPeer is gone.
func agentViewForPeer(ar *AgentRegistry, peer *hsync.Peer) *Agent {
	if peer == nil {
		return nil
	}
	if ar != nil {
		return ar.materializeAgentView(peer)
	}
	return newAgentView(peer)
}

func (b *mpHsyncBridge) SendHello(ctx context.Context, peer *hsync.Peer, sharedZones []string) error {
	if b.tm == nil {
		return nil
	}
	agent := agentViewForPeer(b.ar, peer)
	if agent == nil {
		return errPeerNotHeld
	}
	_, err := b.tm.SendHelloWithFallback(ctx, agent, sharedZones)
	return err
}

func (b *mpHsyncBridge) SendBeat(ctx context.Context, peer *hsync.Peer, sequence uint64) (bool, string, error) {
	if b.tm == nil {
		return false, "", nil
	}
	agent := agentViewForPeer(b.ar, peer)
	if agent == nil {
		return false, "", errPeerNotHeld
	}
	tp := b.tm.GetOrCreatePeer(agent)
	beforeAPI := tp.MechanismBeatSequence("API")
	beforeDNS := tp.MechanismBeatSequence("DNS")

	resp, err := b.tm.SendBeatWithFallback(ctx, agent, sequence)
	used := beatTransportUsed(agent, tp, beforeAPI, beforeDNS)
	if err != nil || resp == nil {
		return false, used, err
	}
	return resp.Ack, used, nil
}

func beatTransportUsed(agent *Agent, tp *transport.Peer, beforeAPI, beforeDNS uint64) string {
	agent.Mu.RLock()
	apiMethod, dnsMethod := agent.ApiMethod, agent.DnsMethod
	agent.Mu.RUnlock()
	apiSent := apiMethod && tp.MechanismBeatSequence("API") > beforeAPI
	dnsSent := dnsMethod && tp.MechanismBeatSequence("DNS") > beforeDNS
	switch {
	case dnsSent && !apiSent:
		return hsync.TransportDNS
	case apiSent && !dnsSent:
		return hsync.TransportAPI
	case dnsSent:
		return hsync.TransportDNS
	case apiSent:
		return hsync.TransportAPI
	default:
		return ""
	}
}

func (b *mpHsyncBridge) MechanismSupported(name string) bool {
	if b.tm == nil {
		return true
	}
	return b.tm.isTransportSupported(name)
}

func (b *mpHsyncBridge) FireDiscoveryFailed(peerID hsync.PeerID, err error) {
	if b.ar != nil {
		if agent, ok := b.ar.S.Get(AgentId(peerID)); ok {
			b.ar.fireOnDiscoveryFailed(agent, err)
		}
	}
}

func (b *mpHsyncBridge) AfterDiscoverPeer(peer *hsync.Peer) {
	if b.ar == nil || peer == nil {
		return
	}
	// E1.b: the view shares the peer pointer — there is no copy to re-sync.
	// Just make sure the view exists for a peer whose discovery completed
	// before anything materialized it.
	b.ar.materializeAgentView(peer)
}

func (b *mpHsyncBridge) SyncPeerZones(peer *hsync.Peer) {
	agent := b.ar.materializeAgentView(peer)
	if agent == nil {
		return
	}
	b.ar.RecomputeSharedZonesAndSyncState(agent)
}

func (b *mpHsyncBridge) PeerRegistry() *transport.PeerRegistry {
	if b.tm == nil || b.tm.TransportManager == nil {
		return transport.NewPeerRegistry()
	}
	return b.tm.TransportManager.PeerRegistry
}

type mpZoneLookup struct{}

func (mpZoneLookup) Get(zone string) (hsync.ZoneView, bool) {
	mpzd, ok := Zones.Get(zone)
	if !ok {
		return nil, false
	}
	return mpZoneView{mpzd}, true
}

func (mpZoneLookup) Items() map[string]hsync.ZoneView {
	out := make(map[string]hsync.ZoneView)
	for name, mpzd := range Zones.Items() {
		if mpzd != nil {
			out[name] = mpZoneView{mpzd}
		}
	}
	return out
}

type mpZoneView struct {
	*MPZoneData
}

func (v mpZoneView) ZoneName() string { return v.MPZoneData.ZoneName }
func (v mpZoneView) IsMultiProvider() bool {
	return v.MPZoneData.Options[tdns.OptMultiProvider]
}
func (v mpZoneView) Participants() []hsync.PeerID {
	members, _, _ := zoneParticipants(v.MPZoneData.ZoneName, instructionsFor(ZoneName(v.MPZoneData.ZoneName)))
	out := make([]hsync.PeerID, 0, len(members))
	for _, id := range members {
		out = append(out, hsync.PeerID(id))
	}
	return out
}

type pgmHsyncLookup struct {
	pgm *ProviderGroupManager
}

func (p pgmHsyncLookup) Groups() []hsync.ProviderGroupInfo {
	if p.pgm == nil {
		return nil
	}
	p.pgm.mu.RLock()
	defer p.pgm.mu.RUnlock()
	var out []hsync.ProviderGroupInfo
	for hash, pg := range p.pgm.Groups {
		zones := make([]hsync.ZoneName, len(pg.Zones))
		for i, z := range pg.Zones {
			zones[i] = hsync.ZoneName(z)
		}
		out = append(out, hsync.ProviderGroupInfo{
			GroupHash:     hash,
			Members:       pg.Members,
			VotingMembers: pg.VotingMembers,
			Zones:         zones,
		})
	}
	return out
}

func (p pgmHsyncLookup) GetGroup(groupHash string) *hsync.ProviderGroupInfo {
	if p.pgm == nil {
		return nil
	}
	pg := p.pgm.GetGroup(groupHash)
	if pg == nil {
		return nil
	}
	zones := make([]hsync.ZoneName, len(pg.Zones))
	for i, z := range pg.Zones {
		zones[i] = hsync.ZoneName(z)
	}
	info := &hsync.ProviderGroupInfo{
		GroupHash:     pg.GroupHash,
		Members:       pg.Members,
		VotingMembers: pg.VotingMembers,
		Zones:         zones,
	}
	return info
}

func wireAgentGossipCallbacks(conf *Config, ar *AgentRegistry) {
	if ar == nil || ar.GossipStateTable == nil {
		return
	}
	ar.GossipStateTable.SetOnGroupOperational(func(groupHash string) {
		lem := conf.InternalMp.LeaderElectionManager
		pgm := ar.ProviderGroupManager
		if lem == nil || pgm == nil {
			return
		}
		pg := pgm.GetGroup(groupHash)
		if pg == nil {
			// A heartbeat round that checked a copy of the groups taken
			// before the group went must not leave it marked OPERATIONAL:
			// a group that comes back would then call no election.
			ar.GossipStateTable.forgetGroup(groupHash)
			return
		}
		if len(pg.VotingMembers) == 0 {
			return
		}
		// The members come from zone data and carry the trailing dot; a
		// configured identity need not (isAmong). A leaving member excused
		// and not heard is no voter (plan S7).
		voters := withoutExcused(pg.VotingMembers, conf.gateExcused(groupHash))
		if len(voters) == 0 || !isAmong(voters, lem.localID) {
			return
		}
		initiator := voters[0]
		for _, m := range voters[1:] {
			if m < initiator {
				initiator = m
			}
		}
		if dns.Fqdn(string(lem.localID)) != dns.Fqdn(initiator) {
			return
		}
		// A leader whose lease runs is held already when this agent
		// restarted inside it: a beat merges the peers' gossip, and with it
		// the group's term and leader (ApplyGossipElection), before the
		// matrix is checked. An election now would end that lease early.
		// A group that degraded had its leader cleared
		// (InvalidateGroupLeader), and a new group has none: those elect.
		// The operator's election is started elsewhere, and still is.
		if leader, ok := lem.GetGroupLeader(groupHash); ok {
			lgElect.Info("group operational with a leader whose lease runs, no election",
				"group", shortHash(groupHash), "leader", leader)
			return
		}
		lem.StartGroupElection(groupHash, voters, pg.Zones)
	})
	// The gate of a group leaves out a leaving voting member that is
	// excused and not heard (design 3.2, plan S7); its election does too
	// (setUpLeaderElection).
	ar.GossipStateTable.SetGateExcused(conf.gateExcused)
	ar.GossipStateTable.SetOnGroupDegraded(func(groupHash string) {
		if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
			lem.InvalidateGroupLeader(groupHash)
			// what the leader began for the parent stops with its lead
			// (design 3.2): tdns's UPDATE retries outlived it by 75 s
			if pg := ar.ProviderGroupManager.GetGroup(groupHash); pg != nil {
				conf.cancelGroupParentWork(pg.Zones)
			}
		}
	})
	ar.GossipStateTable.SetOnElectionUpdate(func(groupHash string, state GroupElectionState) {
		if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
			lem.ApplyGossipElection(groupHash, state)
		}
	})
	// A group whose last zone has left it is gone for both: the election
	// manager drops its election, and the gossip table what it remembers of
	// it, so that a group that comes back elects as a new group does.
	if pgm := ar.ProviderGroupManager; pgm != nil {
		pgm.SetOnGroupGone(func(groupHash string) {
			ar.GossipStateTable.forgetGroup(groupHash)
			if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
				lem.groupGone(groupHash)
			}
		})
	}
}

func newAgentHsyncEngine(conf *Config) *hsync.Engine {
	ar := conf.InternalMp.AgentRegistry
	wireAgentGossipCallbacks(conf, ar)
	deps, cfg := buildHsyncEngineDeps(conf)
	// Agent-only: gate the diff on the local agent's standing, and run the
	// removal teardown. The zone's election is checked after the diff, by
	// zoneChanged (step 8).
	deps.GateOnLocalPresence = true
	deps.Host.OnLocalRemoved = func(zone hsync.ZoneName) {
		ar.localRemovedFromZone(ZoneName(zone))
	}
	return hsync.NewEngine(deps, cfg)
}

func newAuditorHsyncEngine(conf *Config) *hsync.Engine {
	deps, cfg := buildHsyncEngineDeps(conf)
	// The auditor has an ON record and auditors= in every zone it audits
	// (guide/auditor.md). In a zone without them it expects no peers, as
	// ReconcileZone has it, and an HSYNC3 add there marks no provider as
	// needed: its hellos would be refused.
	deps.GateOnLocalPresence = true
	return hsync.NewEngine(deps, cfg)
}

// hsyncConfigFromMp builds the hsync engine's timer config from the parsed
// multi-provider: block: hsync.DefaultConfig() with every
// syncengine.intervals key that is set (> 0) applied, in seconds. The beat
// interval is read from Remote.BeatInterval, which the config parser has
// already reconciled with syncengine.intervals.beatinterval
// (normalizeSyncengineIntervals), so the engine's beat ticker, the gossiped
// LocalBeatInterval and the transport bridge all run on the same value.
func hsyncConfigFromMp(mp *MultiProviderConf) hsync.Config {
	cfg := hsync.DefaultConfig()
	if mp == nil {
		return cfg
	}
	secs := func(dst *time.Duration, v int) {
		if v > 0 {
			*dst = time.Duration(v) * time.Second
		}
	}
	iv := mp.Syncengine.Intervals
	secs(&cfg.BeatInterval, int(mp.Remote.BeatInterval))
	secs(&cfg.BeatIntervalMin, iv.BeatFastInterval)
	secs(&cfg.HelloRetryInterval, iv.HelloRetry)
	secs(&cfg.RetryInterval, iv.DiscoveryRetry)
	secs(&cfg.ReconcileInterval, iv.Reconcile)
	secs(&cfg.HelloFastSpacing, iv.HelloFastInterval)
	secs(&cfg.PeerHold, iv.PeerHold)
	if iv.HelloFastAttempts > 0 {
		cfg.HelloFastAttempts = iv.HelloFastAttempts
	}
	return cfg
}

func buildHsyncEngineDeps(conf *Config) (hsync.Deps, hsync.Config) {
	ar := conf.InternalMp.AgentRegistry
	mp := conf.MpConfig()
	cfg := hsyncConfigFromMp(mp)
	lgEngine.Info("hsync engine intervals",
		"beat", cfg.BeatInterval,
		"beat_fast", cfg.BeatIntervalMin,
		"helloretry", cfg.HelloRetryInterval,
		"hello_fast_attempts", cfg.HelloFastAttempts,
		"hello_fast_interval", cfg.HelloFastSpacing,
		"discoveryretry", cfg.RetryInterval,
		"reconcile", cfg.ReconcileInterval,
		"catchup_outage", catchUpOutageFor(mp),
		"peer_hold", cfg.PeerHold)
	deps := hsync.Deps{
		LocalID:           hsync.PeerID(mp.Identity),
		LocalBeatInterval: mp.Remote.BeatInterval,
		Zones:             mpZoneLookup{},
		Transport:         &mpHsyncBridge{ar: ar, tm: conf.InternalMp.MPTransport},
		HelloReady:        conf.InternalMp.IdentityReady.Wait,
		Gossip:            newAgentGossipPort(ar),
		ProviderGroups:    pgmHsyncLookup{pgm: ar.ProviderGroupManager},
		PeerHooks: hsync.PeerHooks{
			// E1.b: pure view-materialization — the view shares the stored
			// peer's pointer, so there is nothing to copy or sync.
			OnPeerStored: func(peer *hsync.Peer) { ar.materializeAgentView(peer) },
			// Phase 3c: prunes are events — drop the MP view + transport
			// peer promptly when the engine removes a peer object.
			OnPeerRemoved: func(peer *hsync.Peer) {
				peer.Mu.RLock()
				since := peer.Unshared
				peer.Mu.RUnlock()
				if !since.IsZero() {
					lgEngine.Info("peer removed: no zone shared for the hold time",
						"peer", peer.ID, "since", since)
				}
				ar.removePeerView(peer)
				// The catch-up's requests and sender are kept by identity:
				// a new peer stored under it since the removal keeps them.
				if !ar.engineHoldsSuccessor(peer) {
					conf.InternalMp.CatchUp.Forget(AgentId(peer.ID))
				}
			},
			// A discovery that outlived the peer's removal: drop the
			// transport peer it made again, as the removal did.
			OnRemovedPeerDiscovered: func(peer *hsync.Peer) { ar.removePeerView(peer) },
			// The end of comms (design 3.1): the reconcile loop keeps a peer
			// that no zone names for the hold time, then removes it.
			OnPeerUnshared: func(peer *hsync.Peer, unshared bool) {
				if unshared {
					lgEngine.Info("peer shares no zone with this agent any more, kept for the hold time",
						"peer", peer.ID, "hold", cfg.PeerHold)
					return
				}
				lgEngine.Info("peer is named by a zone again, kept", "peer", peer.ID)
			},
		},
		Host: hsync.HostCallbacks{
			OnHsync3Changed: func(zone hsync.ZoneName) {
				if ar.ProviderGroupManager != nil {
					ar.ProviderGroupManager.RecomputeGroups()
				}
			},
			BeforeHeartbeats: func() {
				if ar.GossipStateTable == nil || ar.ProviderGroupManager == nil {
					return
				}
				ar.GossipStateTable.RefreshLocalStates(ar, ar.ProviderGroupManager)
				// every zone's thaw is asked at every beat round (plan S7),
				// before the gate: an excusal comes with time
				conf.thawRound()
				// The groups are copied out, and checked with the manager's
				// lock free. A group that has just become OPERATIONAL has its
				// election called from in there, by a callback that reads the
				// manager. With the read lock held across the call, a
				// recompute that asked for the write lock in between waited
				// for this round, the callback's read waited for the
				// recompute, and the agent beat no more (tdns-mp #180).
				for _, pg := range ar.ProviderGroupManager.GetGroups() {
					ar.GossipStateTable.CheckGroupState(pg.GroupHash, pg.VotingMembers)
				}
			},
		},
	}
	return deps, cfg
}
