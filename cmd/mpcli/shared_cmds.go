/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Command registration for tdns-mpcli.
 * Base DNS commands from tdns/v2/cli.
 * Combiner commands from tdns-mp/v2/cli.
 */
package main

import (
	cli "github.com/johanix/tdns/v2/cli"
	mpcli "github.com/johanix/tdns-mp/v2/cli"
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

	// Agent commands (from tdns/v2/cli)
	rootCmd.AddCommand(cli.AgentCmd)
	cli.AgentCmd.AddCommand(cli.DaemonCmd)
	cli.AgentCmd.AddCommand(cli.DebugCmd)
	cli.AgentCmd.AddCommand(cli.ConfigCmd)
	cli.AgentCmd.AddCommand(cli.KeystoreCmd)
	cli.AgentCmd.AddCommand(cli.TruststoreCmd)
	cli.AgentCmd.AddCommand(cli.KeysCmd)
	cli.AgentCmd.AddCommand(cli.AgentDistribCmd)
	cli.AgentCmd.AddCommand(cli.AgentTransactionCmd)

	// Combiner commands (from tdns-mp/v2/cli)
	rootCmd.AddCommand(mpcli.CombinerCmd)
	mpcli.CombinerCmd.AddCommand(cli.PingCmd)
	mpcli.CombinerCmd.AddCommand(cli.StopCmd)
	mpcli.CombinerCmd.AddCommand(cli.DaemonCmd)
	mpcli.CombinerCmd.AddCommand(cli.DebugCmd)
	mpcli.CombinerCmd.AddCommand(cli.ConfigCmd)
	mpcli.CombinerCmd.AddCommand(cli.ZoneCmd)
	mpcli.CombinerCmd.AddCommand(cli.KeysCmd)
	mpcli.CombinerCmd.AddCommand(cli.CombinerDistribCmd)
	mpcli.CombinerCmd.AddCommand(cli.CombinerTransactionCmd)
}
