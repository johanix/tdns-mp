/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	mpcli "github.com/johanix/tdns-mp/v2/cli"
	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
	_ "github.com/johanix/tdns/v2/core"
)

var cfgFile, cfgFileUsed string
var LocalConfig string

var rootCmd = &cobra.Command{
	Use:   "tdns-mpcli",
	Short: "tdns-mpcli is the CLI tool for tdns multi-provider applications",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		tdns.SetupCliLogging()
		if isRootKeysCommand(cmd) || isConfigureCommand(cmd) {
			return
		}
		initConfig()
		initApi()
	},
}

// wireInstances adds one command tree per extra daemon instance named in the
// CLI config, and reports any entry it declined to wire.
//
// This runs from Execute rather than from an init() because it needs the
// config, and it runs BEFORE rootCmd.Execute because an instance name is a
// command WORD: cobra resolves the command path in Find(), which happens
// before PersistentPreRun, where the config is normally loaded. A tree that
// does not exist by then cannot be routed to.
//
// The read is deliberately best-effort (see mpcli.EarlyApiServers): commands
// that need no config at all -- keys generate, configure -- must keep working
// with no config file present, and at this point we do not yet know which
// command was typed. The authoritative config load, with real error
// reporting, still happens in PersistentPreRun.
func wireInstances() {
	// cobra adds "help" and "completion" lazily, during Execute -- i.e. after
	// this runs. Force them in first so the collision check can see them: an
	// instance named "help" would otherwise be accepted here and then fight
	// cobra's own command. Both initialisers are idempotent.
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()

	cfgPath := mpcli.ConfigPathFromArgs(os.Args[1:])
	for _, w := range mpcli.WireInstanceTrees(rootCmd, mpcli.EarlyApiServers(cfgPath)) {
		fmt.Fprintf(os.Stderr, "tdns-mpcli: %s\n", w)
	}
}

func Execute() {
	wireInstances()
	cobra.CheckErr(rootCmd.Execute())
}

func ExecuteContext(ctx context.Context) {
	wireInstances()
	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

func isRootKeysCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "keys" {
			p := c.Parent()
			return p != nil && p.Name() == "tdns-mpcli"
		}
	}
	return false
}

func isConfigureCommand(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "configure" {
			p := c.Parent()
			return p != nil && p.Name() == "tdns-mpcli"
		}
	}
	return false
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is $%s, then %s)", mpcli.ConfigEnvVar, mpcli.DefaultConfigFile))
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
	rootCmd.PersistentFlags().StringVarP(&tdns.Globals.ParentZone, "pzone", "Z", "", "parent zone name")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Debug, "debug", "d", false, "debug output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&tdns.Globals.ShowHeaders, "headers", "H", false, "show headers")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(mpcli.ConfigPathFromArgs(nil)) // $TDNS_MPCLI_CONFIG or the default
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if tdns.Globals.Verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
	}

	// Expand any top-level "include:" directives (single-level; see
	// mpcli.MergeIncludes, which the early apiservers read uses too so that
	// an instance entry living in an include: file becomes a command word).
	if err := mpcli.MergeIncludes(viper.GetViper(), cfgFileUsed); err != nil {
		log.Fatalf("%v", err)
	}

	LocalConfig = viper.GetString("cli.localconfig")
	if LocalConfig != "" {
		_, err := os.Stat(LocalConfig)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Fatalf("Error stat(%s): %v", LocalConfig, err)
			}
		} else {
			viper.SetConfigFile(LocalConfig)
			if err := viper.MergeInConfig(); err != nil {
				log.Fatalf("Error merging in local config from '%s'", LocalConfig)
			} else {
				if tdns.Globals.Verbose {
					fmt.Printf("Merging in local config from '%s'\n", LocalConfig)
				}
			}
		}
	}

	cli.ValidateConfig(nil, cfgFileUsed)
	if err := viper.Unmarshal(&cconf); err != nil {
		log.Fatalf("FATAL: viper.Unmarshal failed: %v", err)
	}
}

var cconf cli.CliConf

func initApi() {
	if err := cli.InitApiClients(&cconf); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
}
