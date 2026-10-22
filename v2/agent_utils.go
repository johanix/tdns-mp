/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"fmt"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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

	return &AgentRegistry{
		// S:              cmap.New[*Agent](),
		S:                    core.NewStringer[AgentId, *Agent](),
		LocalAgent:           mp,
		ProviderGroupManager: NewProviderGroupManager(mp.Identity),
		GossipStateTable:     NewGossipStateTable(mp.Identity),
	}
}

// MarkAgentAsNeeded hands a remote agent to the hsync engine
// (HsyncEngine.MarkNeeded), which drives its discovery and hello. Without an
// engine there is nothing to hand it to.
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
	// ON records only: an OFF record is nobody's upstream or downstream.
	labelToIdentity := map[string]string{}
	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok && h3.State != 0 {
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
				on := hsync3.State != 0
				// Skip if this is our own identity
				if isAmong([]string{hsync3.Identity}, AgentId(ar.LocalAgent.Identity)) {
					if on {
						zad.MyUpstream = AgentId(labelToIdentity[hsync3.Upstream])
					}
					continue // don't add ourselves to the list of agents
				} else if on && isAmong([]string{labelToIdentity[hsync3.Upstream]}, AgentId(ar.LocalAgent.Identity)) {
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
					// A placeholder for an agent the registry does not have;
					// never stored in ar.S, so the throwaway hsync.Peer
					// allocation is fine (E1.b). agentInfo reports it as ERROR.
					agent = &Agent{
						Peer:     hsync.NewPeer(AgentId(hsync3.Identity)),
						ErrorMsg: fmt.Sprintf("error getting agent info: %v", err),
					}
					agent.LastState = time.Now()
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
// derived on the next read. The provider groups are recomputed on that path
// by ApplyHsyncDiff (OnHsync3Changed). There is nothing to manually clean up
// here.
//
// Revisit only if the testbed shows orphaned per-zone state surviving a
// local removal; that would mean some state is still stored rather than
// derived, and should be moved to derivation rather than scrubbed here.
func (ar *AgentRegistry) CleanupZoneRelationships(zonename ZoneName) {
	lgAgent.Info("local removal from zone; membership is derived, no teardown needed", "zone", zonename)
}

// localRemovedFromZone is the OnLocalRemoved hook. The groups are recomputed
// right after it on the same path (ApplyHsyncDiff calls OnHsync3Changed
// there too, tdns-mp #183), under the recompute's own lock. Without the
// recompute the zone stayed in the group this agent was in, and a give-back
// in the same refresh found this agent still leading the zone and ran the
// leader's setup here.
func (ar *AgentRegistry) localRemovedFromZone(zone ZoneName) {
	ar.CleanupZoneRelationships(zone)
}

// reattachHsyncMemberAdds re-homes the membership-change election kick that used
// to live in UpdateAgents. It is driven by the member-add set ApplyHsyncDiff
// already computed (HSYNCPARAM-gated), so a role-less identity does not kick an
// election. Discovery of the added members is ApplyHsyncDiff's MarkNeeded, with
// the periodic ReconcileZone behind it.
//
// UpdateAgents also queued a CONFIG upstream/downstream RFI here for a new
// upstream or downstream. Nothing ever consumed the answer, and since
// CommandHandler switches on Command the request was dropped unsent, so those
// tasks are gone. The debug CLI's send-rfi still asks for CONFIG on demand.
func (ar *AgentRegistry) reattachHsyncMemberAdds(zonename ZoneName, added []hsync.PeerID, localAdded bool) {
	if len(added) == 0 && !localAdded {
		return
	}

	// Membership changed (HSYNC3 identity add): a zone without peers elects
	// its one agent here. A zone in a provider group starts nothing here:
	// its election is the group's (leaveElectionToGroup).
	if ar.LeaderElectionManager != nil {
		lem := ar.LeaderElectionManager
		if lem.configuredPeers(zonename) == 0 {
			lem.StartElection(zonename, 0)
		} else if ar.ProviderGroupManager != nil {
			if pg := ar.ProviderGroupManager.GetGroupForZone(zonename); pg != nil {
				lem.leaveElectionToGroup(pg.GroupHash)
			}
		}
	}
}

func (agent *Agent) AddDeferredAgentTask(task *DeferredAgentTask) {
	agent.Mu.Lock()
	agent.Deferred = append(agent.Deferred, *task)
	agent.Mu.Unlock()
}

// agentInfo builds the management API's report of an agent: the view's
// fields and the state the transport's per-mechanism store derives now. An
// agent the registry does not hold (a placeholder from GetZoneAgentData)
// is reported as ERROR with the reason it carries.
func (ar *AgentRegistry) agentInfo(agent *Agent) *AgentInfo {
	state := ar.effectiveAgentState(agent.ID)
	if _, held := ar.S.Get(agent.ID); !held && agent.ErrorMsg != "" {
		state = AgentStateError
	}
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	zones := make(map[ZoneName]bool, len(agent.Zones))
	for k, v := range agent.Zones {
		zones[k] = v
	}
	return &AgentInfo{
		Identity:    agent.ID,
		InitialZone: agent.InitialZone,
		ApiMethod:   agent.ApiMethod,
		DnsMethod:   agent.DnsMethod,
		Zones:       zones,
		State:       state,
		LastState:   agent.LastState,
		ErrorMsg:    agent.ErrorMsg,
	}
}

// zoneAgentInfo is the report of a zone's agents.
func (ar *AgentRegistry) zoneAgentInfo(zad *ZoneAgentData) *ZoneAgentInfo {
	info := &ZoneAgentInfo{ZoneName: zad.ZoneName, MyUpstream: zad.MyUpstream, MyDownstreams: zad.MyDownstreams}
	for _, agent := range zad.Agents {
		info.Agents = append(info.Agents, ar.agentInfo(agent))
	}
	return info
}
