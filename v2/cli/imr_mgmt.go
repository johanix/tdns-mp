/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"

	tdnscli "github.com/johanix/tdns/v2/cli"
)

// SendImrMgmtCmd POSTs an AgentMgmtPost to the daemon's /imr endpoint.
// role selects the ApiClient -- presently always "agent" in tdns-mpcli
// since tdns-mpagent is the only tdns-mp app that hosts an IMR, but
// kept as an argument so the helper stays symmetric with the tdns
// library's SendImrMgmtCmd and accepts new roles trivially if more
// MP apps ever embed an IMR.
func SendImrMgmtCmd(role string, req *AgentMgmtPost) (*AgentMgmtResponse, error) {
	api, err := tdnscli.GetApiClient(role, true)
	if err != nil {
		log.Fatalf("Error getting API client for role %q: %v", role, err)
	}

	_, buf, err := api.RequestNG("POST", "/imr", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	return &amr, nil
}
