/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Discovering extra daemon instances from the CLI config, early enough for
 * cobra to route to them.
 *
 * A copy of tdns v2/cli/instances.go (tdns commit d9071e65, 2026-09-07)
 * adapted to tdns-mp, which pins a tdns/v2/cli that predates it: the
 * apiservers entries are read into a local struct because the pinned
 * ApiDetails has no Role field, and the include: shim is this package's own
 * because the pinned library has no MergeViperIncludes. When tdns-mp re-pins,
 * delete this file and import the tdns one. The four tree factories stay.
 *
 * The config shape, identical to tdns-ncli's:
 *
 *   apiservers:
 *      - name:       tdns-mpagent        # canonical: name = registered clientKey
 *        baseurl:    https://127.0.0.1:7054/api/v1
 *        ...
 *      - name:       p2-agent            # instance: name = command word = clientKey
 *        role:       agent               # which tree to build for it
 *        baseurl:    https://127.0.0.1:7254/api/v1
 *        ...
 *
 *   tdns-mpcli agent    zone mplist      # the canonical tdns-mpagent
 *   tdns-mpcli p2-agent zone mplist      # the instance
 */
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdnscli "github.com/johanix/tdns/v2/cli"
)

// DefaultConfigFile is where tdns-mpcli looks for its config when neither
// --config nor TDNS_MPCLI_CONFIG says otherwise.
const DefaultConfigFile = "/etc/tdns/tdns-mpcli.yaml"

// ConfigEnvVar names the environment variable that overrides the default
// config path. --config still wins over it. It exists so that a session
// working against a non-default config (a test rig, a second fleet) sets it
// once instead of repeating --config on every command.
const ConfigEnvVar = "TDNS_MPCLI_CONFIG"

// knownInstanceRoles are the roles an apiservers entry may ask to be wired
// as, each mapped to the factory that builds that daemon kind's tree for
// one instance.
var knownInstanceRoles = map[string]func(use, role string) *cobra.Command{
	"agent":    NewAgentTree,
	"combiner": NewCombinerTree,
	"signer":   NewSignerTree,
	"auditor":  NewAuditorTree,
}

// instanceEntry is the part of an apiservers entry the early read needs.
// The full entry is decoded later, by the pinned tdns cli's InitApiClients,
// which ignores the role: key it does not know.
type instanceEntry struct {
	Name string `yaml:"name" mapstructure:"name"`
	Role string `yaml:"role" mapstructure:"role"`
}

// ConfigPathFromArgs finds the config file the user asked for, WITHOUT
// running cobra's flag parsing.
//
// It has to work this early because instance names are command words: cobra
// resolves the command path in Find(), which runs before PersistentPreRun --
// where the config is normally read. A tree that does not exist by then
// cannot be routed to, so the apiservers list has to be read ahead of
// Execute().
//
// Precedence: --config, then $TDNS_MPCLI_CONFIG, then the default.
// Deliberately forgiving: an argument shape it does not understand just
// falls back; the authoritative parse still happens later in the normal
// config load, which reports errors properly.
func ConfigPathFromArgs(args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
	}
	if p := os.Getenv(ConfigEnvVar); p != "" {
		return p
	}
	return DefaultConfigFile
}

// MergeIncludes expands a top-level "include:" list in the config v has
// loaded, merging each listed file in turn. viper has no native include
// support. Single-level (non-recursive): an included file's own include:
// is not processed. Relative paths resolve against cfgFile's directory. A
// missing included file is skipped (an optional overlay); a present but
// unreadable one is an error.
//
// Shared by the early read here and the full load in cmd/mpcli/root.go so
// that an apiservers: block living in an include: file is found by both.
func MergeIncludes(v *viper.Viper, cfgFile string) error {
	for _, inc := range v.GetStringSlice("include") {
		incPath := inc
		if !filepath.IsAbs(incPath) {
			incPath = filepath.Join(filepath.Dir(cfgFile), incPath)
		}
		if _, err := os.Stat(incPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat(%s): %v", incPath, err)
		}
		v.SetConfigFile(incPath)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("could not merge included config %s: %v", incPath, err)
		}
	}
	return nil
}

// EarlyApiServers reads just the apiservers: block from the CLI config.
//
// Best-effort by design: every failure returns nil rather than terminating.
// Commands that need no config at all (keys generate, configure) must keep
// working with no config file present, and this runs before we know which
// command was typed. Real config errors are still reported, by the full
// load in PersistentPreRun.
func EarlyApiServers(cfgFile string) []instanceEntry {
	v := viper.New()
	v.SetConfigFile(cfgFile)
	if err := v.ReadInConfig(); err != nil {
		return nil
	}
	if err := MergeIncludes(v, cfgFile); err != nil {
		return nil
	}
	// cli.localconfig, merged the same way the full load does. Skipping it
	// here would mean an apiservers entry that lives ONLY in the local
	// config never becomes a command word.
	if local := v.GetString("cli.localconfig"); local != "" {
		if _, err := os.Stat(local); err == nil {
			v.SetConfigFile(local)
			_ = v.MergeInConfig()
		}
	}
	var entries []instanceEntry
	if err := v.UnmarshalKey("apiservers", &entries); err != nil {
		return nil
	}
	return entries
}

// WireInstanceTrees adds one command tree per apiservers entry carrying a
// role:, and registers each entry's name as its own clientKey.
//
// Returns the problems it declined to act on, for the caller to print. They
// are warnings rather than fatal errors on purpose: a typo in one apiservers
// entry should cost that entry's subcommand, not the whole CLI.
func WireInstanceTrees(root *cobra.Command, entries []instanceEntry) []string {
	var warnings []string
	// Instance names wired by THIS call, so a duplicate can be reported as
	// the duplicate it is rather than as a built-in-role collision.
	wired := map[string]bool{}

	for _, e := range entries {
		if e.Role == "" {
			continue // canonical entry; reached through its built-in tree
		}
		newTree, known := knownInstanceRoles[e.Role]
		if !known {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: role %q has no command tree (known: %s) -- entry ignored",
				e.Name, e.Role, knownRoleList()))
			continue
		}
		if e.Name == "" {
			warnings = append(warnings, "apiservers entry with role but no name -- entry ignored")
			continue
		}
		// A name that shadows a built-in role would silently retarget the
		// canonical tree, which is the exact failure this feature exists to
		// prevent. Refuse it. GetClientKeyFromParent is the pinned tdns
		// cli's only window into its role registry.
		if tdnscli.GetClientKeyFromParent(e.Name) != "" {
			what := "a built-in role"
			if wired[e.Name] {
				what = "an earlier apiservers entry with the same name"
			}
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: name collides with %s -- entry ignored (choose another name)",
				e.Name, what))
			continue
		}
		if existing := findChild(root, e.Name); existing != nil {
			warnings = append(warnings, fmt.Sprintf(
				"apiservers entry %q: name collides with the existing %q command -- entry ignored (choose another name)",
				e.Name, existing.Name()))
			continue
		}

		// The instance is addressed by its own name at both levels: the
		// command word IS the role IS the clientKey. One name for the
		// operator to know.
		tdnscli.RegisterRole(e.Name, e.Name)
		wired[e.Name] = true
		root.AddCommand(newTree(e.Name, e.Name))
	}

	return warnings
}

// findChild reports whether root already has a subcommand answering to
// name, as its name or as one of its aliases. The caller must have forced
// cobra's lazily added "help" and "completion" in first (InitDefaultHelpCmd,
// InitDefaultCompletionCmd) so they are visible here.
func findChild(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name || c.HasAlias(name) {
			return c
		}
	}
	return nil
}

func knownRoleList() string {
	names := make([]string, 0, len(knownInstanceRoles))
	for r := range knownInstanceRoles {
		names = append(names, r)
	}
	return strings.Join(names, ", ")
}
