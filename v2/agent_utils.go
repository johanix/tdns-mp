/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"errors"
	"fmt"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

func (ar *AgentRegistry) GetAgentsForZone(zone ZoneName) []*Agent {
	members := participantFQDNSet(string(zone), instructionsFor(zone))
	var agents []*Agent
	for _, agent := range ar.S.Items() {
		if members.has(string(agent.ID)) {
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

// GetZoneAgentData returns the zone's member agents (zoneParticipants), each
// with its standing: every ON record, with a role or without (plan S15), and
// a provider whose removal is under way. It does not check whether the
// agents are operational, or try to fetch missing information.
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

	// A zone not loaded yet that its agent stored serials of was placed in
	// its group at the start (plan S9): its members are the stored
	// reading's, which is what the readers act by anyway (activeOr).
	apex, err := zd.GetOwner(string(zonename))
	switch {
	case errors.Is(err, tdns.ErrZoneNotReady) && instrStore.Load().reading(zd.ZoneName) != nil:
		apex = nil
	case err != nil:
		lgAgent.Error("error getting apex", "zone", zonename, "err", err)
		return nil, fmt.Errorf("error getting apex for zone %q: %v", zonename, err)
	}

	in := activeOr(zd.ZoneName, apex)
	if !hasHSYNC3(in) {
		lgAgent.Warn("zone has no HSYNC3 RRset", "zone", zonename)
		return nil, fmt.Errorf("zone %q has no HSYNC3 RRset", zonename)
	}

	// Every member is a recipient, with a role or without; the callers that
	// mean a vote filter by standing. Upstreams resolve through the ON
	// records: an OFF record is nobody's upstream or downstream. The members
	// come in the records' order, then the providers whose removal is under
	// way with no record.
	members, voting, auditors := zoneParticipants(zd.ZoneName, in)
	self := AgentId(ar.LocalAgent.Identity)
	ids := make([]string, 0, len(members))
	for _, r := range in.Records {
		if isAmong([]string{r.Identity}, self) {
			zad.MyUpstream = AgentId(in.identityOf(r.Upstream))
		} else if isAmong([]string{in.identityOf(r.Upstream)}, self) {
			zad.MyDownstreams = append(zad.MyDownstreams, AgentId(r.Identity))
		}
		ids = append(ids, r.Identity)
	}
	for _, id := range members {
		if !isAmong(ids, AgentId(id)) {
			ids = append(ids, id)
		}
	}
	zad.Standing = map[AgentId]string{}
	for _, id := range ids {
		if isAmong([]string{id}, self) {
			continue // don't add ourselves to the list of agents
		}
		zad.Standing[AgentId(id)] = standingName(in, members, voting, auditors, id)
		agent, err := ar.GetAgentInfo(AgentId(id))
		if err != nil {
			// A placeholder for an agent the registry does not have;
			// never stored in ar.S, so the throwaway hsync.Peer
			// allocation is fine (E1.b). agentInfo reports it as ERROR.
			agent = &Agent{
				Peer:     hsync.NewPeer(AgentId(id)),
				ErrorMsg: fmt.Sprintf("error getting agent info: %v", err),
			}
			agent.LastState = time.Now()
		}
		agents = append(agents, agent)
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
	info := &ZoneAgentInfo{ZoneName: zad.ZoneName, MyUpstream: zad.MyUpstream, MyDownstreams: zad.MyDownstreams, Standing: zad.Standing}
	for _, agent := range zad.Agents {
		info.Agents = append(info.Agents, ar.agentInfo(agent))
	}
	return info
}
