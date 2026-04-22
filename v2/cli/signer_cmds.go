/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"log"

	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

// SignerCmd is the parent command for all signer operations.
var SignerCmd = &cobra.Command{
	Use:   "signer",
	Short: "Interact with the MP signer via API",
}

// SignerZoneMPListCmd is the signer-specific "mplist" subcommand. It's
// attached to the signer's zone tree by mpcli/shared_cmds.go via
// tdnscli.NewZoneCmd("signer", SignerZoneMPListCmd).
var SignerZoneMPListCmd = &cobra.Command{
	Use:   "mplist",
	Short: "List multi-provider zones with HSYNCPARAM details",
	Run: func(cmd *cobra.Command, args []string) {
		api, err := tdnscli.GetApiClient("signer", true)
		if err != nil {
			log.Fatalf("Error getting API client: %v", err)
		}

		resp, err := SendMPListCommand(api)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		ListMPZones(resp)
	},
}
