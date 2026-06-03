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
