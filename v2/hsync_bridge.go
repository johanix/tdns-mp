/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
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
	return b.tm.TransportManager.DiscoverPeer(ctx, identity)
}

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
	_, err := b.tm.SendHelloWithFallback(ctx, agent, sharedZones)
	return err
}

func (b *mpHsyncBridge) SendBeat(ctx context.Context, peer *hsync.Peer, sequence uint64) (bool, string, error) {
	if b.tm == nil {
		return false, "", nil
	}
	agent := agentViewForPeer(b.ar, peer)
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
func (v mpZoneView) HSYNC3() []dns.RR {
	apex, err := v.MPZoneData.GetOwner(v.MPZoneData.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	rrset, ok := apex.RRtypes.Get(core.TypeHSYNC3)
	if !ok {
		return nil
	}
	return rrset.RRs
}

func (v mpZoneView) Participants() []hsync.PeerID {
	apex, err := v.MPZoneData.GetOwner(v.MPZoneData.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	participants, _ := zoneParticipants(apex)
	out := make([]hsync.PeerID, 0, len(participants))
	for _, id := range participants {
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
			GroupHash: hash,
			Members:   pg.Members,
			Zones:     zones,
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
		GroupHash: pg.GroupHash,
		Members:   pg.Members,
		Zones:     zones,
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
		if pg == nil || len(pg.VotingMembers) == 0 {
			return
		}
		localID := string(lem.localID)
		weVote := false
		for _, m := range pg.VotingMembers {
			if m == localID {
				weVote = true
				break
			}
		}
		if !weVote {
			return
		}
		initiator := pg.VotingMembers[0]
		for _, m := range pg.VotingMembers[1:] {
			if m < initiator {
				initiator = m
			}
		}
		if localID == initiator {
			lem.StartGroupElection(groupHash, pg.VotingMembers, pg.Zones)
		}
	})
	ar.GossipStateTable.SetOnGroupDegraded(func(groupHash string) {
		if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
			lem.InvalidateGroupLeader(groupHash)
		}
	})
	ar.GossipStateTable.SetOnElectionUpdate(func(groupHash string, state GroupElectionState) {
		if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
			lem.ApplyGossipElection(groupHash, state)
		}
	})
}

func newAgentHsyncEngine(conf *Config) *hsync.Engine {
	ar := conf.InternalMp.AgentRegistry
	wireAgentGossipCallbacks(conf, ar)
	deps, cfg := buildHsyncEngineDeps(conf)
	// Agent-only: gate the diff on local HSYNC3 presence (weAreInHSYNC) and
	// re-home the removal teardown + RFI/election side effects of UpdateAgents.
	deps.GateOnLocalPresence = true
	deps.Host.OnLocalRemoved = func(zone hsync.ZoneName) {
		ar.CleanupZoneRelationships(ZoneName(zone))
	}
	deps.Host.OnHsyncMembersAdded = func(zone hsync.ZoneName, added []hsync.PeerID, localAdded bool) {
		ar.reattachHsyncMemberAdds(conf, ZoneName(zone), added, localAdded)
	}
	return hsync.NewEngine(deps, cfg)
}

func newAuditorHsyncEngine(conf *Config) *hsync.Engine {
	deps, cfg := buildHsyncEngineDeps(conf)
	return hsync.NewEngine(deps, cfg)
}

func buildHsyncEngineDeps(conf *Config) (hsync.Deps, hsync.Config) {
	ar := conf.InternalMp.AgentRegistry
	mp := conf.MpConfig()
	cfg := hsync.DefaultConfig()
	if bi := mp.Remote.BeatInterval; bi > 0 {
		cfg.BeatInterval = time.Duration(bi) * time.Second
	}
	deps := hsync.Deps{
		LocalID:           hsync.PeerID(mp.Identity),
		LocalBeatInterval: mp.Remote.BeatInterval,
		Zones:             mpZoneLookup{},
		Transport:         &mpHsyncBridge{ar: ar, tm: conf.InternalMp.MPTransport},
		Gossip:            newAgentGossipPort(ar),
		ProviderGroups:    pgmHsyncLookup{pgm: ar.ProviderGroupManager},
		PeerHooks: hsync.PeerHooks{
			// E1.b: pure view-materialization — the view shares the stored
			// peer's pointer, so there is nothing to copy or sync.
			OnPeerStored: func(peer *hsync.Peer) { ar.materializeAgentView(peer) },
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
				ar.ProviderGroupManager.mu.RLock()
				for _, pg := range ar.ProviderGroupManager.Groups {
					ar.GossipStateTable.CheckGroupState(pg.GroupHash, pg.Members)
				}
				ar.ProviderGroupManager.mu.RUnlock()
			},
		},
	}
	return deps, cfg
}
