/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * tdns-cli agent keys / tdns-cli combiner keys: generate JOSE keypair or show public key.
 * Uses server config file (agent or combiner) for long_term_jose_priv_key path.
 */

package cli

import (
	"fmt"
	"log"
	"os"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

var keysServerConfig string

// NewKeysCmd returns a fresh "keys" command tree for a daemon of the given
// kind. kind must be "agent" or "combiner" — the tree is only meaningful for
// those two (their configs point to the long_term_jose_priv_key). The target
// instance is read from the tree.
func NewKeysCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "keys",
		Short: "JOSE keypair for secure CHUNK (generate, show)",
		Long:  `Generate a JOSE keypair or display the public key. Uses the server config file (agent or combiner) to get long_term_jose_priv_key path, or --server-config.`,
	}
	c.PersistentFlags().StringVar(&keysServerConfig, "server-config", "",
		"path to agent/combiner config file (overrides apiservers.*.config_file)")

	generate := &cobra.Command{
		Use:   "generate",
		Short: "Generate JOSE keypair and write to config path or -output",
		Run: func(cmd *cobra.Command, args []string) {
			runKeysCommand(kind, cmd, "generate", args)
		},
	}
	generate.Flags().StringP("output", "o", "", "path for generated private key (overrides config)")

	show := &cobra.Command{
		Use:   "show",
		Short: "Print public key (JWK) from configured long_term_jose_priv_key",
		Run: func(cmd *cobra.Command, args []string) {
			runKeysCommand(kind, cmd, "show", args)
		},
	}

	c.AddCommand(generate, show)
	return c
}

func runKeysCommand(kind string, cmd *cobra.Command, subcommand string, args []string) {
	if kind != "agent" && kind != "combiner" {
		log.Fatalf("keys must be run under agent or combiner (e.g. tdns-cli agent keys %s)", subcommand)
	}

	serverConfigPath := keysServerConfig
	if serverConfigPath == "" {
		clientKey := tdnscli.GetClientKeyFromParent(RoleForCmd(cmd))
		if ad := tdnscli.GetApiDetailsByClientKey(clientKey); ad != nil && ad.ConfigFile != "" {
			serverConfigPath = ad.ConfigFile
		}
	}
	if serverConfigPath == "" {
		log.Fatalf("No server config: set apiservers.*.config_file in tdns-cli config for %s, or use --server-config",
			tdnscli.GetClientKeyFromParent(RoleForCmd(cmd)))
	}

	mp, err := tdnsmp.LoadMpConfigForKeys(serverConfigPath)
	if err != nil {
		log.Fatalf("Load multi-provider section of %s: %v", serverConfigPath, err)
	}

	runArgs := []string{subcommand}
	if subcommand == "generate" {
		output, _ := cmd.Flags().GetString("output")
		if output != "" {
			runArgs = append(runArgs, "-output", output)
		}
	}

	if err := tdnsmp.RunKeysCmd(mp, runArgs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
