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
	agent := hsyncPeerToAgent(peer)
	_, err := b.tm.SendHelloWithFallback(ctx, agent, sharedZones)
	syncAgentFromHsyncPeer(b.ar, peer, agent)
	return err
}

func (b *mpHsyncBridge) SendBeat(ctx context.Context, peer *hsync.Peer, sequence uint64) (bool, error) {
	if b.tm == nil {
		return false, nil
	}
	agent := hsyncPeerToAgent(peer)
	resp, err := b.tm.SendBeatWithFallback(ctx, agent, sequence)
	syncAgentFromHsyncPeer(b.ar, peer, agent)
	if err != nil || resp == nil {
		return false, err
	}
	return resp.Ack, nil
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
		updated := agentToHsyncPeer(agent)
		peer.Mu.Lock()
		peer.ApiDetails = updated.ApiDetails
		peer.DnsDetails = updated.DnsDetails
		peer.ApiMethod = updated.ApiMethod
		peer.DnsMethod = updated.DnsMethod
		peer.State = updated.State
		peer.Mu.Unlock()
		syncHsyncPeerToAgent(b.ar, peer)
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

func hsyncPeerToAgent(peer *hsync.Peer) *Agent {
	if peer == nil {
		return nil
	}
	peer.Mu.RLock()
	defer peer.Mu.RUnlock()
	agent := &Agent{
		Identity:    AgentId(peer.ID),
		PeerID:      peer.TransportID,
		ApiDetails:  hsyncDetailsToAgent(peer.ApiDetails),
		DnsDetails:  hsyncDetailsToAgent(peer.DnsDetails),
		ApiMethod:   peer.ApiMethod,
		DnsMethod:   peer.DnsMethod,
		IsInfraPeer: peer.IsInfraPeer,
		Zones:       make(map[ZoneName]bool),
		State:       AgentState(peer.State),
		LastState:   peer.LastState,
	}
	for z := range peer.Zones {
		agent.Zones[ZoneName(z)] = true
	}
	for _, t := range peer.Deferred {
		agent.DeferredTasks = append(agent.DeferredTasks, DeferredAgentTask{
			Precondition: t.Precondition,
			Action:       t.Action,
			Desc:         t.Desc,
		})
	}
	return agent
}

func syncAgentFromHsyncPeer(ar *AgentRegistry, peer *hsync.Peer, agent *Agent) {
	if ar == nil || peer == nil || agent == nil {
		return
	}
	peer.Mu.RLock()
	agent.ApiDetails = hsyncDetailsToAgent(peer.ApiDetails)
	agent.DnsDetails = hsyncDetailsToAgent(peer.DnsDetails)
	agent.State = AgentState(peer.State)
	agent.ApiMethod = peer.ApiMethod
	agent.DnsMethod = peer.DnsMethod
	peer.Mu.RUnlock()
	ar.S.Set(agent.Identity, agent)
}

func agentToHsyncPeer(agent *Agent) *hsync.Peer {
	if agent == nil {
		return nil
	}
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	peer := hsync.NewPeer(hsync.PeerID(agent.Identity))
	peer.TransportID = agent.PeerID
	peer.ApiDetails = agentDetailsToHsync(agent.ApiDetails)
	peer.DnsDetails = agentDetailsToHsync(agent.DnsDetails)
	peer.ApiMethod = agent.ApiMethod
	peer.DnsMethod = agent.DnsMethod
	peer.IsInfraPeer = agent.IsInfraPeer
	peer.State = hsync.PeerState(agent.State)
	peer.LastState = agent.LastState
	for z := range agent.Zones {
		peer.Zones[hsync.ZoneName(z)] = true
	}
	return peer
}

func hsyncDetailsToAgent(d *hsync.PeerDetails) *AgentDetails {
	if d == nil {
		return &AgentDetails{State: AgentStateNeeded}
	}
	return &AgentDetails{
		State:             AgentState(d.State),
		LatestError:       d.LatestError,
		LatestErrorTime:   d.LatestErrorTime,
		DiscoveryFailures: d.DiscoveryFailures,
		HelloTime:         d.HelloTime,
		LastContactTime:   d.LastContactTime,
		BeatInterval:      d.BeatInterval,
		SentBeats:         d.SentBeats,
		ReceivedBeats:     d.ReceivedBeats,
		LatestSBeat:       d.LatestSBeat,
		LatestRBeat:       d.LatestRBeat,
	}
}

func agentDetailsToHsync(d *AgentDetails) *hsync.PeerDetails {
	if d == nil {
		return &hsync.PeerDetails{State: hsync.PeerStateNeeded}
	}
	return &hsync.PeerDetails{
		State:             hsync.PeerState(d.State),
		LatestError:       d.LatestError,
		LatestErrorTime:   d.LatestErrorTime,
		DiscoveryFailures: d.DiscoveryFailures,
		HelloTime:         d.HelloTime,
		LastContactTime:   d.LastContactTime,
		BeatInterval:      d.BeatInterval,
		SentBeats:         d.SentBeats,
		ReceivedBeats:     d.ReceivedBeats,
		LatestSBeat:       d.LatestSBeat,
		LatestRBeat:       d.LatestRBeat,
	}
}

func syncHsyncPeerToAgent(ar *AgentRegistry, peer *hsync.Peer) {
	if ar == nil || peer == nil {
		return
	}
	agent := hsyncPeerToAgent(peer)
	ar.S.Set(agent.Identity, agent)
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
