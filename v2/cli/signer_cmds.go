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

// signerZoneMPListCmd adds "mplist" to the signer's zone command tree.
// The signer uses the standard tdnscli.ZoneCmd (shared with tdns-auth),
// so we attach via init() rather than defining a custom signerZoneCmd.
var signerZoneMPListCmd = &cobra.Command{
	Use:   "mplist",
	Short: "List multi-provider zones with HSYNCPARAM details",
	Run: func(cmd *cobra.Command, args []string) {
		// signerZoneMPListCmd is only added to ZoneCmd by tdns-mp's init();
		// tdns-mp's mpcli attaches ZoneCmd under SignerCmd → role "signer".
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

func init() {
	tdnscli.ZoneCmd.AddCommand(signerZoneMPListCmd)
}
