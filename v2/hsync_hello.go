package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/miekg/dns"
)

func (ar *AgentRegistry) HelloHandler(report *AgentMsgReport) {
	// log.Printf("HelloHandler: Received HELLO from %s", report.Identity)

	switch report.MessageType {
	case AgentMsgHello:
		lgAgent.Debug("received initial HELLO", "from", report.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		lgAgent.Warn("unknown message type in HelloHandler", "type", AgentMsgToString[report.MessageType])
	}
}

func (ar *AgentRegistry) EvaluateHello(ahp *AgentHelloPost) (bool, string, error) {
	lgAgent.Debug("evaluating HELLO", "agent", ahp.MyIdentity, "zone", ahp.Zone)

	// Now let's check if we need to know this agent
	if ahp.Zone == "" {
		lgAgent.Warn("no zone specified in HELLO message")
		return false, "Error: No zone specified in HELLO message", nil
	}

	// Check if we have this zone
	if _, exists := Zones.Get(string(ahp.Zone)); !exists {
		lgAgent.Warn("unknown zone in HELLO, may be a timing issue", "zone", ahp.Zone)
		return false, fmt.Sprintf("Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone), nil
	}

	// Both our identity and the remote agent must be participants (HSYNCPARAM
	// role-holders) in the zone — not merely co-present in HSYNC3. A role-less/
	// OFF identity is rejected here, the HELLO admission boundary.
	members := participantFQDNSetForApex(zoneApex(ahp.Zone))
	if len(members) == 0 {
		lgAgent.Warn("zone has no HSYNC participants", "zone", ahp.Zone)
		return false, fmt.Sprintf("Error: Zone %q has no HSYNC participants", ahp.Zone), nil
	}
	foundMe := members[dns.Fqdn(string(ar.LocalAgent.Identity))]
	foundYou := members[dns.Fqdn(string(ahp.MyIdentity))]
	if !foundMe || !foundYou {
		lgAgent.Warn("zone participants do not include both identities",
			"zone", ahp.Zone, "yourIdentity", ahp.MyIdentity, "myIdentity", ar.LocalAgent.Identity)
		return false, fmt.Sprintf("Error: Zone %q participants do not include both our identities", ahp.Zone), nil
	}

	return true, "", nil
}

func (agent *Agent) SendApiHello(msg *AgentHelloPost) (*AgentHelloResponse, error) {
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/hello", msg, false)
	if err != nil {
		return nil, fmt.Errorf("API hello failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("API hello returned status %d (%s)", status, http.StatusText(status))
	}

	var ahr AgentHelloResponse
	err = json.Unmarshal(resp, &ahr)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling HELLO response: %v", err)
	}

	return &ahr, nil
}
