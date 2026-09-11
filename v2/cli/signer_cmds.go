/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"log"

	"github.com/spf13/cobra"
)

// newSignerZoneMPListCmd is the signer-specific "mplist" subcommand,
// handed to tdnscli.NewZoneCmd as an extra by NewSignerTree.
func newSignerZoneMPListCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "mplist",
		Short: "List multi-provider zones with HSYNCPARAM details",
		Run: func(cmd *cobra.Command, args []string) {
			api, err := GetApiClientForCmd(cmd, true)
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
	return c
}
