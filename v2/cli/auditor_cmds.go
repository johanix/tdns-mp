/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor CLI commands. Phase A scope: just the parent AuditorCmd
 * so mpcli has a "auditor" prefix. Phase C adds eventlog / zones /
 * observations subcommands.
 */
package cli

import "github.com/spf13/cobra"

// AuditorCmd is the parent command for all auditor operations.
var AuditorCmd = &cobra.Command{
	Use:   "auditor",
	Short: "Interact with the MP auditor via API",
}
