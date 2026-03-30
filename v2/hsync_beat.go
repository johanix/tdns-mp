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

func (ar *AgentRegistry) SendHeartbeats() {
	// Refresh local gossip state before sending beats
	if ar.GossipStateTable != nil && ar.ProviderGroupManager != nil {
		ar.GossipStateTable.RefreshLocalStates(ar, ar.ProviderGroupManager)
	}

	// log.Printf("HsyncEngine: Sending heartbeats to INTRODUCED or OPERATIONAL agents")
	for _, a := range ar.S.Items() {
		// Infra peers (combiner, signer) are handled by StartInfraBeatLoop at lower frequency.
		if a.IsInfraPeer {
			continue
		}
		// DNS-55: Check EITHER transport state (API or DNS)
		// Send heartbeat if ANY transport is INTRODUCED or better (including LEGACY)
		a.Mu.RLock()
		apiState := a.ApiDetails.State
		dnsState := a.DnsDetails.State
		a.Mu.RUnlock()

		apiReady := apiState == AgentStateIntroduced || apiState == AgentStateOperational ||
			apiState == AgentStateLegacy || apiState == AgentStateDegraded || apiState == AgentStateInterrupted
		dnsReady := dnsState == AgentStateIntroduced || dnsState == AgentStateOperational ||
			dnsState == AgentStateLegacy || dnsState == AgentStateDegraded || dnsState == AgentStateInterrupted

		if !apiReady && !dnsReady {
			lgAgent.Debug("not sending heartbeat, both transports below INTRODUCED",
				"agent", a.Identity, "apiState", AgentStateToString[apiState], "dnsState", AgentStateToString[dnsState])
			continue
		}

		lgAgent.Debug("sending heartbeat",
			"agent", a.Identity, "apiState", AgentStateToString[apiState], "dnsState", AgentStateToString[dnsState])

		go func(a *Agent) {
			agent := a
			var err error
			var beatAck bool
			var beatMsg string

			if ar.MPTransport != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				sequence := uint64(0)
				agent.Mu.RLock()
				if agent.ApiDetails.SentBeats > 0 {
					sequence = uint64(agent.ApiDetails.SentBeats)
				}
				agent.Mu.RUnlock()
				beatResp, beatErr := ar.MPTransport.SendBeatWithFallback(ctx, agent, sequence)
				err = beatErr
				if beatResp != nil {
					beatAck = beatResp.Ack
					beatMsg = beatResp.State
				}
			} else {
				abr, apiErr := agent.SendApiBeat(&AgentBeatPost{
					MessageType:    AgentMsgBeat,
					MyIdentity:     AgentId(ar.LocalAgent.Identity),
					YourIdentity:   agent.Identity,
					MyBeatInterval: ar.LocalAgent.Remote.BeatInterval,
				})
				err = apiErr
				if abr != nil {
					beatAck = !abr.Error
					beatMsg = abr.Msg
				}
			}

			agent.Mu.Lock()
			switch {
			case err != nil:
				lgAgent.Warn("error sending heartbeat", "agent", agent.Identity, "err", err)
				if agent.ApiDetails.LatestError == "" {
					agent.ApiDetails.LatestError = err.Error()
					agent.ApiDetails.LatestErrorTime = time.Now()
				}

			case !beatAck:
				agent.ApiDetails.LatestError = beatMsg
				agent.ApiDetails.LatestErrorTime = time.Now()

			default:
				now := time.Now()
				agent.ApiDetails.State = AgentStateOperational
				agent.ApiDetails.LatestSBeat = now
				agent.ApiDetails.LatestError = ""
				agent.ApiDetails.SentBeats++
				agent.DnsDetails.State = AgentStateOperational
				agent.DnsDetails.LatestSBeat = now
				agent.DnsDetails.LatestError = ""
				agent.DnsDetails.SentBeats++
				if len(agent.DeferredTasks) > 0 {
					lgAgent.Info("agent has deferred tasks, executing", "agent", agent.Identity, "count", len(agent.DeferredTasks))
					var remainingTasks []DeferredAgentTask
					for _, task := range agent.DeferredTasks {
						if task.Precondition() {
							ok, err := task.Action()
							if err != nil {
								lgAgent.Error("deferred task failed", "task", task.Desc, "err", err)
								remainingTasks = append(remainingTasks, task)
							} else if ok {
								lgAgent.Info("deferred task executed successfully", "task", task.Desc)
							} else {
								remainingTasks = append(remainingTasks, task)
							}
						} else {
							remainingTasks = append(remainingTasks, task)
						}
					}
					agent.DeferredTasks = remainingTasks
				}
			}
			agent.CheckState(ar.LocalAgent.Remote.BeatInterval)
			ar.S.Set(agent.Identity, agent)
			agent.Mu.Unlock()
		}(a)
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

	switch agent.ApiDetails.State {
	case AgentStateOperational, AgentStateLegacy, AgentStateDegraded, AgentStateInterrupted:
		// proceed with beat health checking
	default:
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
		// Beats healthy - sync transport state to top-level state
		// Top-level agent.State is managed by RecomputeSharedZonesAndSyncState() based on zone count
		agent.ApiDetails.State = agent.State
		agent.DnsDetails.State = agent.State
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
