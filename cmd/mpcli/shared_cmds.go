/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Command registration for tdns-mpcli.
 * All role-specific commands are behind a prefix:
 *   signer   → mpsigner API
 *   combiner → mpcombiner API
 *   agent    → agent API
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
	mpcli "github.com/johanix/tdns-mp/v2/cli"
)

func init() {
	// Global commands (not role-specific)
	rootCmd.AddCommand(cli.VersionCmd)

	// Signer commands (from tdns/v2/cli, under "signer" prefix)
	rootCmd.AddCommand(mpcli.SignerCmd)
	mpcli.SignerCmd.AddCommand(cli.PingCmd)
	mpcli.SignerCmd.AddCommand(cli.StopCmd)
	mpcli.SignerCmd.AddCommand(cli.DaemonCmd)
	mpcli.SignerCmd.AddCommand(cli.DebugCmd)
	mpcli.SignerCmd.AddCommand(cli.ConfigCmd)
	mpcli.SignerCmd.AddCommand(cli.ZoneCmd)
	mpcli.SignerCmd.AddCommand(cli.KeystoreCmd)
	mpcli.SignerCmd.AddCommand(cli.TruststoreCmd)
	mpcli.SignerCmd.AddCommand(cli.ReportCmd)
	mpcli.SignerCmd.AddCommand(cli.AuthCmd)
	mpcli.SignerCmd.AddCommand(cli.RootKeysCmd)
	mpcli.SignerCmd.AddCommand(cli.JwtCmd)

	// Combiner commands (from tdns-mp/v2/cli)
	// Note: combiner has its own zone management (combiner_edits_cmds.go)
	// so we don't add cli.ZoneCmd here to avoid duplicate "zone" commands.
	rootCmd.AddCommand(mpcli.CombinerCmd)
	mpcli.CombinerCmd.AddCommand(cli.PingCmd)
	mpcli.CombinerCmd.AddCommand(cli.StopCmd)
	mpcli.CombinerCmd.AddCommand(cli.DaemonCmd)
	mpcli.CombinerCmd.AddCommand(cli.DebugCmd)
	mpcli.CombinerCmd.AddCommand(cli.ConfigCmd)
	mpcli.CombinerCmd.AddCommand(cli.KeysCmd)
	mpcli.CombinerCmd.AddCommand(cli.CombinerDistribCmd)
	mpcli.CombinerCmd.AddCommand(cli.CombinerTransactionCmd)

	// Agent commands (from tdns-mp/v2/cli)
	rootCmd.AddCommand(mpcli.AgentCmd)
	mpcli.AgentCmd.AddCommand(cli.PingCmd)
	mpcli.AgentCmd.AddCommand(cli.StopCmd)
	mpcli.AgentCmd.AddCommand(cli.DaemonCmd)
	mpcli.AgentCmd.AddCommand(cli.DebugCmd)
	mpcli.AgentCmd.AddCommand(cli.ConfigCmd)
	mpcli.AgentCmd.AddCommand(cli.KeystoreCmd)
	mpcli.AgentCmd.AddCommand(cli.TruststoreCmd)
	mpcli.AgentCmd.AddCommand(cli.KeysCmd)
	mpcli.AgentCmd.AddCommand(cli.AgentDistribCmd)
	mpcli.AgentCmd.AddCommand(cli.AgentTransactionCmd)
	// Standard zone commands from tdns (list, reload, etc.)
	// MP-specific zone subcommands (mplist, addrr, delrr, edits)
	// are added to cli.AgentZoneCmd via tdns-mp/v2/cli init()
	mpcli.AgentCmd.AddCommand(cli.AgentZoneCmd)
}
