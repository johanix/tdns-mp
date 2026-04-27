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
	mpcli "github.com/johanix/tdns-mp/v2/cli"
	mpconfigure "github.com/johanix/tdns-mp/v2/cli/configure"
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// Global commands (not role-specific)
	rootCmd.AddCommand(cli.VersionCmd)
	rootCmd.AddCommand(mpconfigure.Cmd)

	// Signer commands (from tdns/v2/cli, under "signer" prefix)
	rootCmd.AddCommand(mpcli.SignerCmd)
	mpcli.SignerCmd.AddCommand(cli.NewPingCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewStopCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewDaemonCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewDebugCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewConfigCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewZoneCmd("signer", mpcli.SignerZoneMPListCmd))
	mpcli.SignerCmd.AddCommand(cli.NewKeystoreCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.NewTruststoreCmd("signer"))
	mpcli.SignerCmd.AddCommand(cli.ReportCmd)
	mpcli.SignerCmd.AddCommand(cli.AuthCmd)
	mpcli.SignerCmd.AddCommand(cli.RootKeysCmd)
	mpcli.SignerCmd.AddCommand(cli.JwtCmd)

	// Combiner commands (from tdns-mp/v2/cli)
	// Note: combiner has its own zone management (combiner_edits_cmds.go)
	// so we don't add cli.ZoneCmd here to avoid duplicate "zone" commands.
	rootCmd.AddCommand(mpcli.CombinerCmd)
	mpcli.CombinerCmd.AddCommand(cli.NewPingCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(cli.NewStopCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(cli.NewDaemonCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(cli.NewDebugCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(cli.NewConfigCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(cli.NewKeysCmd("combiner"))
	mpcli.CombinerCmd.AddCommand(mpcli.CombinerDistribCmd)
	mpcli.CombinerCmd.AddCommand(mpcli.CombinerTransactionCmd)

	// Agent commands (from tdns-mp/v2/cli)
	rootCmd.AddCommand(mpcli.AgentCmd)
	mpcli.AgentCmd.AddCommand(cli.NewPingCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewStopCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewDaemonCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewDebugCmd("agent", mpcli.DebugAgentCmd))
	mpcli.AgentCmd.AddCommand(cli.NewConfigCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewKeystoreCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewTruststoreCmd("agent"))
	mpcli.AgentCmd.AddCommand(cli.NewKeysCmd("agent"))
	mpcli.AgentCmd.AddCommand(mpcli.AgentDistribCmd)
	mpcli.AgentCmd.AddCommand(mpcli.AgentTransactionCmd)
	// Standard zone commands from tdns (list, reload, etc.)
	// MP-specific zone subcommands (mplist, addrr, delrr, edits)
	// are added to cli.AgentZoneCmd via tdns-mp/v2/cli init()
	mpcli.AgentCmd.AddCommand(cli.AgentZoneCmd)

	// Auditor commands (from tdns-mp/v2/cli). Phase A: just the
	// parent prefix and the standard daemon commands; auditor-
	// specific subcommands (eventlog, zones, observations) land
	// in Phase C.
	rootCmd.AddCommand(mpcli.AuditorCmd)
	mpcli.AuditorCmd.AddCommand(cli.NewPingCmd("auditor"))
	mpcli.AuditorCmd.AddCommand(cli.NewStopCmd("auditor"))
	mpcli.AuditorCmd.AddCommand(cli.NewDaemonCmd("auditor"))
	mpcli.AuditorCmd.AddCommand(cli.NewDebugCmd("auditor"))
	mpcli.AuditorCmd.AddCommand(cli.NewConfigCmd("auditor"))
}
