/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mpcli combiner config — runtime introspection of the
 * combiner's effective multi-provider config. Mirrors
 * "tdns-mpcli agent config" but for the combiner role.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

var combinerConfigVerbose bool

var combinerConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Runtime introspection of the combiner's multi-provider config",
}

var combinerConfigStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the running combiner's effective multi-provider config",
	Long: `Show the running combiner's effective multi-provider config.

Use -v to include the agent-identity list, protected namespaces,
sync-api listen addresses, and provider zones.

Sensitive paths (private key locations, JOSE pubkey paths) are
intentionally not exposed via this endpoint.`,
	Run: func(cmd *cobra.Command, args []string) {
		api, err := tdnscli.GetApiClient("combiner", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		req := CombinerConfigPost{
			Command: "status",
			Verbose: combinerConfigVerbose,
		}

		_, buf, err := api.RequestNG("POST", "/combiner/config", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}

		var resp CombinerConfigResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}

		renderCombinerConfig(&resp, combinerConfigVerbose)
	},
}

func renderCombinerConfig(r *CombinerConfigResponse, verbose bool) {
	fmt.Printf("Combiner: %s\n", r.Identity)
	fmt.Printf("  Role:           %s\n", r.Role)
	fmt.Printf("  Active:         %t\n", r.Active)
	if len(r.CombinerOptions) > 0 {
		fmt.Printf("  Combiner opts:  %s\n", strings.Join(r.CombinerOptions, ", "))
	} else {
		fmt.Printf("  Combiner opts:  (none)\n")
	}
	if r.ChunkMode != "" {
		fmt.Printf("  Chunk mode:     %s\n", r.ChunkMode)
	}
	if r.ChunkMaxSize > 0 {
		fmt.Printf("  Chunk max:      %d bytes\n", r.ChunkMaxSize)
	}
	fmt.Printf("  Agents:         %d\n", r.AgentCount)

	if !verbose {
		return
	}

	if len(r.AgentIdentities) > 0 {
		fmt.Println("  Agent identities:")
		for _, a := range r.AgentIdentities {
			fmt.Printf("    - %s\n", a)
		}
	}
	if len(r.ProtectedNamespaces) > 0 {
		fmt.Println("  Protected namespaces:")
		for _, ns := range r.ProtectedNamespaces {
			fmt.Printf("    - %s\n", ns)
		}
	}
	if len(r.SyncApiListen) > 0 {
		fmt.Println("  SyncAPI listen:")
		for _, addr := range r.SyncApiListen {
			fmt.Printf("    - %s\n", addr)
		}
	}
	if len(r.ProviderZones) > 0 {
		fmt.Println("  Provider zones:")
		for _, z := range r.ProviderZones {
			fmt.Printf("    - %s\n", z)
		}
	}
}

func init() {
	combinerConfigStatusCmd.Flags().BoolVarP(&combinerConfigVerbose, "verbose", "v", false,
		"include agent identities, protected namespaces, listen addresses, provider zones")
	combinerConfigCmd.AddCommand(combinerConfigStatusCmd)
	CombinerCmd.AddCommand(combinerConfigCmd)
}
