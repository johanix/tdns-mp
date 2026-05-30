package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (ar *AgentRegistry) HeartbeatHandler(report *AgentMsgReport) {
	switch report.MessageType {
	case AgentMsgBeat:
		lgAgent.Debug("received BEAT", "from", report.Identity)
		if agent, exists := ar.S.Get(report.Identity); exists {
			agent.Mu.Lock()
			now := time.Now()
			if report.Transport == "DNS" && agent.DnsDetails != nil {
				agent.DnsDetails.LatestRBeat = now
				agent.DnsDetails.ReceivedBeats++
				agent.DnsDetails.BeatInterval = report.BeatInterval
			} else if agent.ApiDetails != nil {
				agent.ApiDetails.LatestRBeat = now
				agent.ApiDetails.ReceivedBeats++
				agent.ApiDetails.BeatInterval = report.BeatInterval
			}
			agent.Mu.Unlock()
		}

		// Process gossip from API beat (DNS beats process gossip in routeBeatMessage)
		if report.Transport == "API" && ar.GossipStateTable != nil {
			if abp, ok := report.Msg.(*AgentBeatPost); ok && len(abp.Gossip) > 0 {
				for i := range abp.Gossip {
					ar.GossipStateTable.MergeGossip(&abp.Gossip[i])
				}
				lgAgent.Debug("merged gossip from incoming API beat", "sender", report.Identity, "groups", len(abp.Gossip))

				if ar.ProviderGroupManager != nil {
					if len(ar.ProviderGroupManager.Groups) == 0 {
						ar.ProviderGroupManager.RecomputeGroups()
					}
					for i := range abp.Gossip {
						pg := ar.ProviderGroupManager.GetGroup(abp.Gossip[i].GroupHash)
						if pg != nil {
							ar.GossipStateTable.CheckGroupState(pg.GroupHash, pg.Members)
						}
					}
				}
			}
		}

	default:
		lgAgent.Warn("unknown message type in HeartbeatHandler", "type", AgentMsgToString[report.MessageType])
	}
}

func (agent *Agent) CheckState(ourBeatInterval uint32) {
	// Use best-of-both transports: if either transport has recent beats, agent is healthy.
	latestRBeat := agent.ApiDetails.LatestRBeat
	if agent.DnsDetails.LatestRBeat.After(latestRBeat) {
		latestRBeat = agent.DnsDetails.LatestRBeat
	}
	latestSBeat := agent.ApiDetails.LatestSBeat
	if agent.DnsDetails.LatestSBeat.After(latestSBeat) {
		latestSBeat = agent.DnsDetails.LatestSBeat
	}

	remoteBeatInterval := time.Duration(agent.ApiDetails.BeatInterval) * time.Second
	if dnsInterval := time.Duration(agent.DnsDetails.BeatInterval) * time.Second; dnsInterval > remoteBeatInterval {
		remoteBeatInterval = dnsInterval
	}
	if remoteBeatInterval == 0 {
		remoteBeatInterval = 30 * time.Second
	}
	localBeatInterval := time.Duration(ourBeatInterval) * time.Second
	if localBeatInterval == 0 {
		localBeatInterval = 30 * time.Second
	}

	// Check if either transport is in a state that warrants beat health checking.
	apiActive := false
	dnsActive := false
	switch agent.ApiDetails.State {
	case AgentStateOperational, AgentStateLegacy, AgentStateDegraded, AgentStateInterrupted:
		apiActive = true
	}
	switch agent.DnsDetails.State {
	case AgentStateOperational, AgentStateLegacy, AgentStateDegraded, AgentStateInterrupted:
		dnsActive = true
	}
	if !apiActive && !dnsActive {
		return
	}

	timeSinceLastReceivedBeat := time.Since(latestRBeat)
	timeSinceLastSentBeat := time.Since(latestSBeat)

	// Check beat health and set DEGRADED/INTERRUPTED when beats are failing
	// NOTE: OPERATIONAL vs LEGACY is determined by zone count (see RecomputeSharedZonesAndSyncState)
	// This function only handles beat health degradation, not zone-based state transitions
	if timeSinceLastReceivedBeat > 10*remoteBeatInterval || timeSinceLastSentBeat > 10*localBeatInterval {
		agent.ApiDetails.State = AgentStateInterrupted
		agent.DnsDetails.State = AgentStateInterrupted
	} else if timeSinceLastReceivedBeat > 2*remoteBeatInterval || timeSinceLastSentBeat > 2*localBeatInterval {
		agent.ApiDetails.State = AgentStateDegraded
		agent.DnsDetails.State = AgentStateDegraded
	} else {
		// Beats healthy — promote top-level state if transports are ahead.
		// Never drag transport states back down to a lower top-level state.
		if agent.State == AgentStateNeeded || agent.State == AgentStateKnown || agent.State == AgentStateIntroduced {
			agent.State = AgentStateOperational
		}
	}
}

func (agent *Agent) SendApiBeat(msg *AgentBeatPost) (*AgentBeatResponse, error) {
	if agent == nil {
		return nil, fmt.Errorf("agent is nil")
	}
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	// Create a context with a 2-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use the context with the RequestNG function
	status, resp, err := agent.Api.ApiClient.RequestNGWithContext(ctx, "POST", "/beat", msg, false)
	if err != nil {
		return nil, fmt.Errorf("HTTPS beat failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTPS beat returned status %d (%s)", status, http.StatusText(status))
	}

	var abr AgentBeatResponse
	err = json.Unmarshal(resp, &abr)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling BEAT response: %v", err)
	}

	return &abr, nil
}
