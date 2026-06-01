/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// discoveryFailureFlushThreshold is the number of consecutive discovery
// failures before flushing the IMR cache for the agent's domain.
const discoveryFailureFlushThreshold = 3

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
		if members[dns.Fqdn(string(agent.Identity))] {
			agents = append(agents, agent)
		}
	}
	return agents
}

// RecomputeSharedZonesAndSyncState updates an agent's shared zones and transitions between
// OPERATIONAL and LEGACY states based on zone count.
// This should be called after HSYNC changes to keep agent state synchronized with zone membership.
func (ar *AgentRegistry) RecomputeSharedZonesAndSyncState(agent *Agent) {
	// Derive the shared-zone set (zones where both we and this agent are
	// participants) without holding agent.Mu — zone-data access must not nest
	// under the agent lock. LEGACY is now defined as derived participations == 0.
	shared := ar.sharedParticipantZones(agent.Identity)
	zoneCount := len(shared)
	identity := agent.Identity

	// State transition under the peer mutex only — released before any transport
	// call (lock order: AgentRegistry.mu -> peer mutex -> transport.PeerRegistry
	// -> transport.Peer; never hold the peer mutex across a transport call).
	agent.Mu.Lock()
	oldState := agent.State
	if zoneCount == 0 && (oldState == AgentStateOperational || oldState == AgentStateIntroduced) {
		// Transition to LEGACY when zones go to zero
		agent.State = AgentStateLegacy
		agent.LastState = time.Now()
		lgAgent.Info("agent transitioned to LEGACY (no shared zones)",
			"agent", identity, "from", AgentStateToString[oldState])
	} else if zoneCount > 0 && oldState == AgentStateLegacy {
		// Transition back to OPERATIONAL when zones are re-added
		agent.State = AgentStateOperational
		agent.LastState = time.Now()
		lgAgent.Info("agent transitioned LEGACY to OPERATIONAL",
			"agent", identity, "zones", zoneCount)
	}
	agent.Mu.Unlock()

	// Sync the derived shared zones to the transport peer (atomic replace under
	// the transport.Peer lock; no peer mutex held here).
	if ar.TransportManager != nil {
		peer := ar.TransportManager.PeerRegistry.GetOrCreate(string(identity))
		zoneStrs := make([]string, len(shared))
		for i, zone := range shared {
			zoneStrs[i] = string(zone)
		}
		peer.ReplaceSharedZones(zoneStrs)
		lgAgent.Debug("synced zones to peer", "zones", zoneCount, "peer", identity)
	}
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

func FetchSVCB(baseurl string, resolvers []string, timeout time.Duration,
	retries int) (*dns.SVCB, []string, uint16, string, error) {
	parsedUri, err := url.Parse(baseurl)
	if err != nil {
		lgAgent.Error("failed to parse URI target", "url", baseurl, "err", err)
		return nil, nil, 0, "", err
	}

	targetName, _, err := net.SplitHostPort(parsedUri.Host)
	if err != nil {
		targetName = parsedUri.Host
	}

	rrset, err := tdns.RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeSVCB, timeout, retries, resolvers)
	if err != nil {
		lgAgent.Error("SVCB query failed", "err", err)
		return nil, nil, 0, "", err
	}

	// Process SVCB response
	if rrset == nil {
		lgAgent.Warn("SVCB response contained zero RRs", "target", targetName)
		return nil, nil, 0, "", fmt.Errorf("response to %s SVCB contained zero RRs", targetName)
	}

	var addrs []string
	var port uint16
	var svcbrr *dns.SVCB

	if len(rrset.RRs) == 0 {
		return nil, nil, 0, "", fmt.Errorf("response to %s SVCB contained zero RRs", targetName)
	}

	for _, rr := range rrset.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok {
			lgAgent.Debug("SVCB record found", "target", targetName, "record", svcb.String())
			svcbrr = svcb
			// Process SVCB record (addresses and port)
			for _, kv := range svcb.Value {
				switch kv.Key() {
				case dns.SVCB_IPV4HINT:
					ipv4Hints := kv.(*dns.SVCBIPv4Hint)
					for _, ip := range ipv4Hints.Hint {
						addrs = append(addrs, ip.String())
					}
				case dns.SVCB_IPV6HINT:
					ipv6Hints := kv.(*dns.SVCBIPv6Hint)
					for _, ip := range ipv6Hints.Hint {
						addrs = append(addrs, ip.String())
					}
				case dns.SVCB_PORT:
					tmpPort := kv.(*dns.SVCBPort)
					port = uint16(tmpPort.Port)
				}
			}
		}
	}
	return svcbrr, addrs, port, targetName, nil
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
	peer := ar.TransportManager.PeerRegistry.GetOrCreate(agent.PeerID)
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
	return string(a.Identity)
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
					agent = &Agent{
						Identity:  AgentId(hsync3.Identity),
						PeerID:    hsync3.Identity,
						State:     AgentStateError,
						ErrorMsg:  fmt.Sprintf("error getting agent info: %v", err),
						LastState: time.Now(),
					}
				}
				agents = append(agents, agent)
			}
		}
	}

	zad.Agents = agents
	return zad, nil
}

// CleanupZoneRelationships handles the complex cleanup when we're no longer involved in a zone's management
func (ar *AgentRegistry) CleanupZoneRelationships(zonename ZoneName) {
	lgAgent.Warn("TODO: cleanup not yet implemented", "zone", zonename)
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
						if agent, exists := ar.S.Get(upstreamIdentity); exists {
							return agent.ApiDetails.State == AgentStateOperational
						}
						return false
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
				if agent, exists := ar.S.Get(downstreamId); exists {
					return agent.State == AgentStateOperational
				}
				return false
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
	agent.DeferredTasks = append(agent.DeferredTasks, *task)
	agent.Mu.Unlock()
}

func (agent *Agent) CreateOperationalAgentTask(action func() (bool, error), desc string) *DeferredAgentTask {
	return &DeferredAgentTask{
		Precondition: func() bool {
			return agent.State == AgentStateOperational
		},
		Action: action,
		Desc:   desc,
	}
}

func (agent *Agent) CreateAgentUpstreamRFI() *DeferredAgentTask {
	return &DeferredAgentTask{
		Desc: "Create Upstream RFI",
		Precondition: func() bool {
			return agent.State == AgentStateOperational
		},
		Action: func() (bool, error) {
			lgAgent.Info("sending RFI to upstream agent (NYI)", "agent", agent.Identity)
			return true, nil
		},
	}
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
		Identity:    agent.Identity,
		InitialZone: agent.InitialZone,
		ApiMethod:   agent.ApiMethod,
		DnsMethod:   agent.DnsMethod,
		Zones:       zones,
		State:       agent.State,
		LastState:   agent.LastState,
		ErrorMsg:    agent.ErrorMsg,
	}
	agent.Mu.RUnlock()

	lgAgent.Debug("using local agent MarshalJSON", "agent", agent.Identity)
	return json.Marshal(aj)
}
