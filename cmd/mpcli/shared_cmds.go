/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Command registration for tdns-mpcli.
 * Imports commands from tdns/v2/cli (base DNS commands)
 * and will import from tdns-mp/v2/cli (MP commands) when
 * those are created.
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
)

func init() {
	// Base commands (from tdns/v2/cli)
	rootCmd.AddCommand(cli.PingCmd)
	rootCmd.AddCommand(cli.StopCmd)
	rootCmd.AddCommand(cli.DaemonCmd)
	rootCmd.AddCommand(cli.VersionCmd)
	rootCmd.AddCommand(cli.DebugCmd)
	rootCmd.AddCommand(cli.ConfigCmd)
	rootCmd.AddCommand(cli.ZoneCmd)
	rootCmd.AddCommand(cli.KeystoreCmd)
	rootCmd.AddCommand(cli.TruststoreCmd)
	rootCmd.AddCommand(cli.ReportCmd)

	// Auth/signer commands (from tdns/v2/cli)
	rootCmd.AddCommand(cli.AuthCmd)

	// Keys (from tdns/v2/cli)
	rootCmd.AddCommand(cli.RootKeysCmd)
	rootCmd.AddCommand(cli.JwtCmd)

	// Agent + Combiner parent commands (from tdns/v2/cli)
	// These contain MP-specific subcommands
	rootCmd.AddCommand(cli.AgentCmd)
	rootCmd.AddCommand(cli.CombinerCmd)

	// Agent subcommands
	cli.AgentCmd.AddCommand(cli.DaemonCmd)
	cli.AgentCmd.AddCommand(cli.DebugCmd)
	cli.AgentCmd.AddCommand(cli.ConfigCmd)
	cli.AgentCmd.AddCommand(cli.KeystoreCmd)
	cli.AgentCmd.AddCommand(cli.TruststoreCmd)
	cli.AgentCmd.AddCommand(cli.KeysCmd)
	cli.AgentCmd.AddCommand(cli.AgentDistribCmd)
	cli.AgentCmd.AddCommand(cli.AgentTransactionCmd)

	// Combiner subcommands
	cli.CombinerCmd.AddCommand(cli.DaemonCmd)
	cli.CombinerCmd.AddCommand(cli.DebugCmd)
	cli.CombinerCmd.AddCommand(cli.ConfigCmd)
	cli.CombinerCmd.AddCommand(cli.ZoneCmd)
	cli.CombinerCmd.AddCommand(cli.KeysCmd)
	cli.CombinerCmd.AddCommand(cli.CombinerDistribCmd)
	cli.CombinerCmd.AddCommand(cli.CombinerTransactionCmd)

	// TODO: When tdns-mp/v2/cli/ exists, import MP-specific
	// commands here:
	// mpcli "github.com/johanix/tdns-mp/v2/cli"
	// rootCmd.AddCommand(mpcli.SomeCommand)
}
