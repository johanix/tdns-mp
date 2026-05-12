/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor-side cobra leaves for the observation commands under
 * `tdns-mpcli auditor peer ...`: list and zones. Both reuse the
 * existing role-parameterised runners (ListDistribPeers,
 * listPeerZones) that the agent uses; the auditor's API endpoint
 * /auditor/distrib serves the same command set via the shared
 * handleSharedDistribCommand helper.
 */
package cli

import (
	"github.com/spf13/cobra"
)

// NewAuditorPeerListCmd returns a `list` cobra command bound to
// the auditor role.
func NewAuditorPeerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all known peer agents",
		Long: `Show all peer agents that this auditor has discovered and
established communication with. Displays both API and DNS transports
independently with their current state, plus leader-election status
for every provider group the auditor observes.`,
		Run: func(cmd *cobra.Command, args []string) {
			ListDistribPeers(cmd, "auditor")
		},
	}
}

// NewAuditorPeerZonesCmd returns a `zones` cobra command bound to
// the auditor role.
func NewAuditorPeerZonesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "zones",
		Short: "List shared zones for each peer agent",
		Long: `Show which zones are shared with each peer agent.
Displays agent identity and their shared zones in a compact format.`,
		Run: func(cmd *cobra.Command, args []string) {
			listPeerZones(cmd, "auditor")
		},
	}
}
