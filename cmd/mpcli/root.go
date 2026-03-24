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

	tdns "github.com/johanix/tdns/v2"
	cli "github.com/johanix/tdns/v2/cli"
	_ "github.com/johanix/tdns/v2/core"
)

var cfgFile, cfgFileUsed string
var LocalConfig string

const defaultMpcliCfgFile = "/etc/tdns/tdns-mpcli.yaml"

var rootCmd = &cobra.Command{
	Use:   "tdns-mpcli",
	Short: "tdns-mpcli is the CLI tool for tdns multi-provider applications",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		tdns.SetupCliLogging()
		if isRootKeysCommand(cmd) {
			return
		}
		initConfig()
		initApi()
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func ExecuteContext(ctx context.Context) {
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

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		fmt.Sprintf("config file (default is %s)", defaultMpcliCfgFile))
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
		viper.SetConfigFile(defaultMpcliCfgFile)
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
	err := viper.Unmarshal(&cconf)
	if err != nil {
		log.Fatalf("FATAL: viper.Unmarshal failed: %v", err)
	}
}

var cconf CliConf

type CliConf struct {
	ApiServers []ApiDetails
	Keys       tdns.KeyConf
}

type ApiDetails struct {
	Name       string `validate:"required" yaml:"name"`
	BaseURL    string `validate:"required" yaml:"baseurl"`
	ApiKey     string `validate:"required" yaml:"apikey"`
	AuthMethod string `validate:"required" yaml:"authmethod"`
	RootCA     string `yaml:"rootca"`
	Command    string `yaml:"command,omitempty"`
	ConfigFile string `yaml:"config_file,omitempty"`
}

func initApi() {
	if tdns.Globals.Debug {
		fmt.Printf("initApi: setting up API clients for:")
	}
	for _, val := range cconf.ApiServers {
		rootCA := val.RootCA
		if rootCA == "" {
			rootCA = "insecure"
		}
		tmp := tdns.NewClient(val.Name, val.BaseURL, val.ApiKey, val.AuthMethod, rootCA)
		if tmp == nil {
			log.Fatalf("initApi: Failed to setup API client for %q", val.Name)
		}
		tdns.Globals.ApiClients[val.Name] = tmp
		if tdns.Globals.Debug {
			fmt.Printf(" %s ", val.Name)
		}
	}
	if tdns.Globals.Debug {
		fmt.Printf("\n")
	}

	authClient, exists := tdns.Globals.ApiClients["tdns-auth"]
	if !exists || authClient == nil {
		log.Fatalf("FATAL: No API server named 'tdns-auth' found in config")
	}
	tdns.Globals.Api = authClient

	numtsigs, _ := tdns.ParseTsigKeys(&cconf.Keys)
	if tdns.Globals.Debug {
		fmt.Printf("Parsed %d TSIG keys\n", numtsigs)
	}
}
