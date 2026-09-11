/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Command registration for tdns-mpcli.
 * All role-specific commands are behind a prefix:
 *   signer   → mpsigner API
 *   combiner → mpcombiner API
 *   agent    → agent API
 *   auditor  → mpauditor API
 *
 * Each prefix is one tree built by a factory in tdns-mp/v2/cli/trees.go.
 * The same factories build the per-instance trees that wireInstances()
 * (root.go) adds for apiservers entries carrying a role:, so
 * `tdns-mpcli agent ...` and `tdns-mpcli p2-agent ...` offer the same
 * commands by construction.
 */
package main

import (
	mpcli "github.com/johanix/tdns-mp/v2/cli"
	mpconfigure "github.com/johanix/tdns-mp/v2/cli/configure"
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// Global commands (not role-specific)
	rootCmd.AddCommand(cli.VersionCmd)
	rootCmd.AddCommand(mpconfigure.Cmd)

	// Signer. The canonical tree also carries four package-level commands
	// that an instance tree cannot (a *cobra.Command has one parent): tdns's
	// ReportCmd and AuthCmd, and this package's RootKeysCmd and JwtCmd. Kept
	// here so nothing an operator could type before is gone.
	signer := mpcli.NewSignerTree("signer", "signer")
	signer.AddCommand(cli.ReportCmd, cli.AuthCmd, mpcli.RootKeysCmd, mpcli.JwtCmd)
	rootCmd.AddCommand(signer)

	rootCmd.AddCommand(mpcli.NewCombinerTree("combiner", "combiner"))
	rootCmd.AddCommand(mpcli.NewAgentTree("agent", "agent"))
	rootCmd.AddCommand(mpcli.NewAuditorTree("auditor", "auditor"))
}
