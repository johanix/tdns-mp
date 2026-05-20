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

func (b *mpHsyncBridge) RegisterDiscovered(peer *hsync.Peer, result *hsync.DiscoveryResult) error {
	if b.tm == nil {
		return nil
	}
	agent := hsyncPeerToAgent(peer)
	b.ar.S.Set(agent.Identity, agent)
	return b.tm.RegisterDiscoveredAgent(&AgentDiscoveryResult{
		Identity: string(peer.ID),
		APIUri:   result.APIUri,
		DNSUri:   result.DNSUri,
	})
}

func (b *mpHsyncBridge) SendHello(ctx context.Context, peer *hsync.Peer, sharedZones []string) error {
	if b.tm == nil {
		return nil
	}
	agent := agentForTransport(b.ar, peer)
	_, err := b.tm.SendHelloWithFallback(ctx, agent, sharedZones)
	persistAgentAndPeer(b.ar, peer, agent)
	return err
}

func (b *mpHsyncBridge) SendBeat(ctx context.Context, peer *hsync.Peer, sequence uint64) (bool, string, error) {
	if b.tm == nil {
		return false, "", nil
	}
	agent := agentForTransport(b.ar, peer)
	var beforeAPI, beforeDNS uint32
	agent.Mu.RLock()
	if agent.ApiDetails != nil {
		beforeAPI = agent.ApiDetails.SentBeats
	}
	if agent.DnsDetails != nil {
		beforeDNS = agent.DnsDetails.SentBeats
	}
	agent.Mu.RUnlock()

	resp, err := b.tm.SendBeatWithFallback(ctx, agent, sequence)
	persistAgentAndPeer(b.ar, peer, agent)
	used := beatTransportUsed(agent, beforeAPI, beforeDNS)
	if err != nil || resp == nil {
		return false, used, err
	}
	return resp.Ack, used, nil
}

func beatTransportUsed(agent *Agent, beforeAPI, beforeDNS uint32) string {
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	apiSent := agent.ApiMethod && agent.ApiDetails != nil && agent.ApiDetails.SentBeats > beforeAPI
	dnsSent := agent.DnsMethod && agent.DnsDetails != nil && agent.DnsDetails.SentBeats > beforeDNS
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
	if agent, ok := b.ar.S.Get(AgentId(peer.ID)); ok {
		persistAgentAndPeer(b.ar, peer, agent)
	}
}

func (b *mpHsyncBridge) SyncPeerZones(peer *hsync.Peer) {
	agent := hsyncPeerToAgent(peer)
	b.ar.S.Set(agent.Identity, agent)
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
	return newAuditorHsyncEngine(conf)
}

func newAuditorHsyncEngine(conf *Config) *hsync.Engine {
	ar := conf.InternalMp.AgentRegistry
	cfg := hsync.DefaultConfig()
	if bi := conf.Config.MultiProvider.Remote.BeatInterval; bi > 0 {
		cfg.BeatInterval = time.Duration(bi) * time.Second
	}
	deps := hsync.Deps{
		LocalID:           hsync.PeerID(conf.Config.MultiProvider.Identity),
		LocalBeatInterval: conf.Config.MultiProvider.Remote.BeatInterval,
		Zones:             mpZoneLookup{},
		Transport:         &mpHsyncBridge{ar: ar, tm: conf.InternalMp.MPTransport},
		ProviderGroups:    pgmHsyncLookup{pgm: ar.ProviderGroupManager},
		PeerHooks: hsync.PeerHooks{
			OnPeerStored: func(peer *hsync.Peer) { syncHsyncPeerToAgent(ar, peer) },
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
	return hsync.NewEngine(deps, cfg)
}
