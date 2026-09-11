/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// SendImrMgmtCmd POSTs an AgentMgmtPost to the /imr endpoint of the
// instance cmd's tree targets. Presently only tdns-mpagent hosts an IMR.
func SendImrMgmtCmd(cmd *cobra.Command, req *AgentMgmtPost) (*AgentMgmtResponse, error) {
	api, err := GetApiClientForCmd(cmd, true)
	if err != nil {
		log.Fatalf("Error getting API client for %q: %v", RoleForCmd(cmd), err)
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
