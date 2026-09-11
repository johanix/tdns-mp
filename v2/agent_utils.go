/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (ar *AgentRegistry) AddZoneToAgent(identity AgentId, zone ZoneName) {
	agent, exists := ar.S.Get(identity)
	if !exists {
		return
	}

	agent.Mu.Lock()
	if agent.Zones == nil {
		agent.Zones = make(map[ZoneName]bool)
	}
	agent.Zones[zone] = true
	agent.Mu.Unlock()

	ar.S.Set(identity, agent)
}

func (ar *AgentRegistry) GetAgentsForZone(zone ZoneName) []*Agent {
	members := participantFQDNSetForApex(zoneApex(zone))
	var agents []*Agent
	for _, agent := range ar.S.Items() {
		if members[dns.Fqdn(string(agent.ID))] {
			agents = append(agents, agent)
		}
	}
	return agents
}

// RecomputeSharedZonesAndSyncState is the hook fired after HSYNC changes.
// Since C7 there is nothing to sync into transport; the derived shared-zone
// set is computed on demand.
//
// END.0: the former LEGACY↔OPERATIONAL top-level agent.State flip is RETIRED.
// LEGACY is now a pure derived display overlay (effectiveAgentState): an
// established peer with zero derived participations. There is no top-level
// State to flip here — the canonical connection state lives per-mechanism on
// transport.Peer, and the LEGACY overlay is recomputed on every read.
func (ar *AgentRegistry) RecomputeSharedZonesAndSyncState(agent *Agent) {
	// C7: transport.Peer holds no zone knowledge any more. The derived set is
	// read at the points that need it (beat construction, the sync LEGACY
	// gate, the LEGACY display overlay) via sharedParticipantZones.
	shared := ar.sharedParticipantZones(agent.ID)
	lgAgent.Debug("recomputed shared zones", "zones", len(shared), "peer", agent.ID)
}

func (conf *Config) NewAgentRegistry() *AgentRegistry {
	mp := conf.MpConfig()
	if mp == nil {
		lgAgent.Error("NewAgentRegistry: multi-provider config is nil")
		return nil
	}
	if mp.Identity == "" {
		lgAgent.Error("identity is empty")
		return nil
	}

	li := viper.GetInt("agent.remote.locateinterval")
	if li <= 10 {
		li = 10
	}
	if li > 300 {
		li = 300
	}

	return &AgentRegistry{
		// S:              cmap.New[*Agent](),
		S:                    core.NewStringer[AgentId, *Agent](),
		LocalAgent:           mp,
		LocateInterval:       li,
		ProviderGroupManager: NewProviderGroupManager(mp.Identity),
		GossipStateTable:     NewGossipStateTable(mp.Identity),
	}
}

// MarkAgentAsNeeded marks a remote agent as NEEDED by delegating to the hsync
// engine's NG discovery path (HsyncEngine.MarkNeeded), which drives discovery
// and hello. No-op if no HsyncEngine is wired (the legacy in-process discovery
// fallback was retired with A3d's legacy-path retirement).
func (ar *AgentRegistry) MarkAgentAsNeeded(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	if ar.HsyncEngine != nil {
		var task *hsync.DeferredTask
		if deferredTask != nil {
			task = &hsync.DeferredTask{
				Precondition: deferredTask.Precondition,
				Action:       deferredTask.Action,
				Desc:         deferredTask.Desc,
			}
		}
		ar.HsyncEngine.MarkNeeded(hsync.PeerID(remoteid), hsync.ZoneName(zonename), task)
		return
	}
}

// RediscoverAgent forces a fresh discovery pass for an already-known agent via
// the NG engine (the `peer reset` path). Unlike MarkAgentAsNeeded, it re-drives
// discovery even when the peer already exists. No-op if no HsyncEngine.
func (ar *AgentRegistry) RediscoverAgent(id AgentId) {
	if ar.HsyncEngine == nil {
		lgAgent.Warn("RediscoverAgent called with no HsyncEngine; discovery not triggered", "agent", id)
		return
	}
	ar.HsyncEngine.Rediscover(hsync.PeerID(id))
}

// fireOnDiscoveryFailed invokes the TransportManager's
// OnDiscoveryFailed seam if registered. Resolves the peer via
// PeerRegistry.GetOrCreate (the peer typically does not exist yet
// when discovery is failing) and passes a non-nil *Peer plus the
// terminating error for this round. The discovery loop continues
// to retry on the next tick — the callback is per-round, not
// terminal. See Bite D in
// tdns-mp/docs/2026-04-30-transport-refactor-semi-easy-bites.md.
func (ar *AgentRegistry) fireOnDiscoveryFailed(agent *Agent, err error) {
	if ar.TransportManager == nil || ar.TransportManager.OnDiscoveryFailed == nil {
		return
	}
	peer := ar.TransportManager.PeerRegistry.GetOrCreate(string(agent.ID))
	ar.TransportManager.OnDiscoveryFailed(peer, err)
}

// DiscoverAgentAsync marks an agent as NEEDED for discovery by DiscoveryRetrierNG.
//
// DEPRECATED: This function is now a thin wrapper around MarkAgentAsNeeded() for backward compatibility.
func (ar *AgentRegistry) DiscoverAgentAsync(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	lgAgent.Debug("deprecated wrapper, marking agent as NEEDED", "agent", remoteid)

	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(remoteid) == ar.LocalAgent.Identity {
		lgAgent.Debug("skipping self-identification", "agent", remoteid)
		return
	}

	// Delegate to new unified discovery path
	ar.MarkAgentAsNeeded(remoteid, zonename, deferredTask)
}

// Create a new synchronous function for code that needs immediate results
func (ar *AgentRegistry) GetAgentInfo(identity AgentId) (*Agent, error) {
	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(identity) == ar.LocalAgent.Identity {
		return nil, fmt.Errorf("cannot get info for self as remote agent")
	}

	// Check if we already know this agent
	agent, exists := ar.S.Get(identity)
	if !exists {
		return nil, fmt.Errorf("agent %s not found", identity)
	}

	return agent, nil
}

func AgentToString(a *Agent) string {
	if a == nil {
		return "<nil>"
	}
	return string(a.ID)
}

// GetZoneAgentData returns the zone's member agents, derived from the HSYNC3
// RRset and HSYNCPARAM roles. It does not check whether the agents are
// operational, or try to fetch missing information.
func (ar *AgentRegistry) GetZoneAgentData(zonename ZoneName) (*ZoneAgentData, error) {
	var zad = &ZoneAgentData{
		ZoneName: zonename,
	}

	agents := []*Agent{}

	lgAgent.Debug("getting zone agent data", "zone", zonename)

	zd, exists := Zones.Get(string(zonename))
	if !exists {
		lgAgent.Warn("zone is unknown", "zone", zonename)
		return nil, fmt.Errorf("zone %q is unknown", zonename)
	}

	apex, err := zd.GetOwner(string(zonename))
	if err != nil {
		lgAgent.Error("error getting apex", "zone", zonename, "err", err)
		return nil, fmt.Errorf("error getting apex for zone %q: %v", zonename, err)
	}

	hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
	if len(hsyncRRset.RRs) == 0 {
		lgAgent.Warn("zone has no HSYNC3 RRset", "zone", zonename)
		return nil, fmt.Errorf("zone %q has no HSYNC3 RRset", zonename)
	}

	// Convert the RRs to strings for transmission
	hsyncStrs := make([]string, len(hsyncRRset.RRs))
	for i, rr := range hsyncRRset.RRs {
		hsyncStrs[i] = rr.String()
	}

	// Build label->Identity map so we can resolve Upstream labels to FQDNs.
	// Kept complete (all HSYNC3 records) so Upstream resolution still works.
	labelToIdentity := map[string]string{}
	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				labelToIdentity[h3.Label] = h3.Identity
			}
		}
	}

	// Membership is HSYNCPARAM-derived: only identities with a HSYNCPARAM
	// role are zone members / distribution recipients. An identity present
	// in HSYNC3 but granted no role is not included.
	participantList, _ := zoneParticipants(apex)
	participantSet := make(map[string]struct{}, len(participantList))
	for _, id := range participantList {
		participantSet[id] = struct{}{}
	}

	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				// Skip if this is our own identity
				if hsync3.Identity == ar.LocalAgent.Identity {
					zad.MyUpstream = AgentId(labelToIdentity[hsync3.Upstream])
					continue // don't add ourselves to the list of agents
				} else if labelToIdentity[hsync3.Upstream] == ar.LocalAgent.Identity {
					zad.MyDownstreams = append(zad.MyDownstreams, AgentId(hsync3.Identity))
				}
				// Skip identities with no HSYNCPARAM role — they have an
				// HSYNC3 mapping but are not members of this zone.
				if _, isParticipant := participantSet[hsync3.Identity]; !isParticipant {
					continue
				}
				// Found an HSYNC3 record, try to locate the agent
				agent, err := ar.GetAgentInfo(AgentId(hsync3.Identity))
				if err != nil {
					// Transient DTO placeholder — never stored in ar.S, so the
					// throwaway hsync.Peer allocation is fine (E1.b).
					agent = &Agent{
						Peer:     hsync.NewPeer(AgentId(hsync3.Identity)),
						State:    AgentStateError,
						ErrorMsg: fmt.Sprintf("error getting agent info: %v", err),
					}
					agent.LastState = time.Now()
				} else {
					// E1.b: the marshaled State shadow used to be refreshed by
					// the bridge's per-hello/beat wrapper-replace (from the NG
					// store, itself stale post-D2.5). Stamp it from the
					// canonical transport.Peer store at DTO-build time instead
					// — the same source `peer list` and `gossip state` read.
					st := ar.effectiveAgentState(agent.ID)
					agent.Mu.Lock()
					agent.State = st
					agent.Mu.Unlock()
				}
				agents = append(agents, agent)
			}
		}
	}

	zad.Agents = agents
	return zad, nil
}

// CleanupZoneRelationships is the OnLocalRemoved hook: it fires when the
// local agent stops participating in a zone's management. By design it is
// a no-op beyond logging.
//
// Since A2, zone membership is DERIVED, not stored: ParticipantsForZone
// (provider_groups.go) recomputes the participant set from HSYNCPARAM on
// every read. So when local participation in `zonename` ends, there is no
// stored per-zone relationship to tear down — it simply stops being
// derived on the next read, and provider groups recompute via
// OnHsync3Changed. There is nothing to manually clean up here.
//
// Revisit only if the testbed shows orphaned per-zone state surviving a
// local removal; that would mean some state is still stored rather than
// derived, and should be moved to derivation rather than scrubbed here.
func (ar *AgentRegistry) CleanupZoneRelationships(zonename ZoneName) {
	lgAgent.Info("local removal from zone; membership is derived, no teardown needed", "zone", zonename)
}

// reattachHsyncMemberAdds re-homes the per-add CONFIG RFI deferred tasks and the
// membership-change election kick that used to live in UpdateAgents. It is driven
// by the member-add set ApplyHsyncDiff already computed (HSYNCPARAM-gated), so a
// role-less identity neither triggers an RFI nor kicks an election. The plain
// "remote agent, no relationship" discovery is already handled by ApplyHsyncDiff's
// MarkNeeded; this only attaches the upstream/downstream RFI tasks.
func (ar *AgentRegistry) reattachHsyncMemberAdds(conf *Config, zonename ZoneName, added []hsync.PeerID, localAdded bool) {
	if len(added) == 0 && !localAdded {
		return
	}
	ourId := AgentId(ar.LocalAgent.Identity)

	var synchedDataUpdateQ chan *SynchedDataUpdate
	var msgQs *MsgQs
	if conf.InternalMp.MsgQs != nil {
		synchedDataUpdateQ = conf.InternalMp.MsgQs.SynchedDataUpdate
		msgQs = conf.InternalMp.MsgQs
	}

	// Build label->Identity and Identity->record from the zone's full current
	// HSYNC3 RRset (the delta alone would miss unchanged upstream records).
	labelToIdentity := map[string]string{}
	recByIdentity := map[AgentId]*core.HSYNC3{}
	if zd, exists := Zones.Get(string(zonename)); exists {
		if apex, err := zd.GetOwner(zd.ZoneName); err == nil && apex != nil {
			if hsync3RRset, ok := apex.RRtypes.Get(core.TypeHSYNC3); ok {
				for _, rr := range hsync3RRset.RRs {
					if prr, ok := rr.(*dns.PrivateRR); ok {
						if h3, ok := prr.Data.(*core.HSYNC3); ok {
							labelToIdentity[h3.Label] = h3.Identity
							recByIdentity[AgentId(h3.Identity)] = h3
						}
					}
				}
			}
		}
	}

	// If our own record was (re)added and we have an upstream, request its config.
	if localAdded {
		if h3 := recByIdentity[ourId]; h3 != nil && h3.Upstream != "." {
			upstreamIdentity := AgentId(labelToIdentity[h3.Upstream])
			if upstreamIdentity == "" {
				lgAgent.Warn("cannot resolve upstream label to identity, skipping", "zone", zonename, "upstream", h3.Upstream)
			} else {
				upstreamLabel := h3.Upstream
				ar.MarkAgentAsNeeded(upstreamIdentity, zonename, &DeferredAgentTask{
					Precondition: func() bool {
						// Operational gate reads the canonical transport.Peer
						// store (END.0); was agent.ApiDetails.State.
						return ar.isAgentOperational(upstreamIdentity)
					},
					Action: func() (bool, error) {
						lgAgent.Info("executing deferred RFI for upstream data", "upstream", upstreamLabel, "zone", zonename)
						amp := AgentMgmtPost{
							MessageType: AgentMsgRfi,
							RfiType:     "CONFIG",
							RfiSubtype:  "upstream",
							Zone:        zonename,
							Upstream:    upstreamIdentity,
						}
						ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ, msgQs)
						return true, nil
					},
					Desc: fmt.Sprintf("RFI for upstream data from %q", upstreamLabel),
				})
			}
		}
	}

	// For each member add whose upstream is us, request its config (downstream).
	for _, pid := range added {
		id := AgentId(pid)
		h3 := recByIdentity[id]
		if h3 == nil {
			continue
		}
		if AgentId(labelToIdentity[h3.Upstream]) != ourId {
			continue
		}
		downstreamId := id
		ar.MarkAgentAsNeeded(downstreamId, zonename, &DeferredAgentTask{
			Precondition: func() bool {
				// Operational gate reads the canonical transport.Peer store
				// (END.0); was agent.State.
				return ar.isAgentOperational(downstreamId)
			},
			Action: func() (bool, error) {
				lgAgent.Info("executing deferred RFI for downstream data", "downstream", downstreamId, "zone", zonename)
				amp := AgentMgmtPost{
					MessageType: AgentMsgRfi,
					RfiType:     "CONFIG",
					RfiSubtype:  "downstream",
					Zone:        zonename,
					Downstream:  downstreamId,
				}
				ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ, msgQs)
				return true, nil
			},
			Desc: fmt.Sprintf("RFI for downstream data from %q", downstreamId),
		})
	}

	// Membership changed (HSYNC3 identity add) — kick a leader election.
	if ar.LeaderElectionManager != nil {
		lem := ar.LeaderElectionManager
		if lem.configuredPeers(zonename) == 0 {
			lem.StartElection(zonename, 0)
		} else if ar.ProviderGroupManager != nil {
			if pg := ar.ProviderGroupManager.GetGroupForZone(zonename); pg != nil {
				lem.DeferGroupElection(pg.GroupHash)
			}
		}
	}
}

func (agent *Agent) AddDeferredAgentTask(task *DeferredAgentTask) {
	agent.Mu.Lock()
	agent.Deferred = append(agent.Deferred, *task)
	agent.Mu.Unlock()
}

func (agent *Agent) MarshalJSON() ([]byte, error) {
	// Create a temporary struct without non-JSON-friendly fields
	type AgentJSON struct {
		Identity    AgentId
		InitialZone ZoneName
		ApiMethod   bool
		DnsMethod   bool
		Zones       map[ZoneName]bool
		State       AgentState
		LastState   time.Time
		ErrorMsg    string
	}

	agent.Mu.RLock()
	zones := make(map[ZoneName]bool, len(agent.Zones))
	for k, v := range agent.Zones {
		zones[k] = v
	}
	aj := AgentJSON{
		Identity:    agent.ID,
		InitialZone: agent.InitialZone,
		ApiMethod:   agent.ApiMethod,
		DnsMethod:   agent.DnsMethod,
		Zones:       zones,
		State:       agent.State,
		LastState:   agent.LastState,
		ErrorMsg:    agent.ErrorMsg,
	}
	agent.Mu.RUnlock()

	lgAgent.Debug("using local agent MarshalJSON", "agent", agent.ID)
	return json.Marshal(aj)
}
