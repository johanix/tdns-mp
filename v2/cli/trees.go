/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * The four tdns-mpcli command trees, one factory per daemon kind.
 *
 * Each factory builds the WHOLE tree for one instance of one daemon kind:
 * `use` is the word typed on the command line, `role` is the key
 * GetApiClient resolves to an ApiClient (see role_target.go for role vs
 * kind). The canonical trees are `NewAgentTree("agent", "agent")` and so
 * on; an instance from the config is `NewAgentTree("p2-agent", "p2-agent")`.
 * Same code path for both, so the canonical tree and an instance tree cannot
 * drift apart -- there is nothing to drift.
 *
 * Nothing here is a copy of a command: every subcommand comes from a
 * factory, either tdns's (NewPingCmd, NewZoneCmd, NewKeystoreCmd, ...) or
 * this package's. A *cobra.Command has exactly one parent, so a second tree
 * has to be a second instantiation -- but it is not a second DEFINITION.
 *
 * Keystore and truststore are added last, by the rule tdns follows: their
 * --help text embeds the supported-algorithm list at construction time, so
 * they must not be built before the binary's init() has registered its
 * algorithms. Callers build trees from Execute()/init() of package main,
 * which is after every library init() has run.
 */
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	tdnscli "github.com/johanix/tdns/v2/cli"
)

// treeRoot makes a tagged tree root. An instance tree (use != kind) gets a
// Long that says what it is; Short is set by each factory via shortFor.
func treeRoot(use, role, kind, daemon string) *cobra.Command {
	c := &cobra.Command{Use: use}
	if use != kind {
		c.Long = fmt.Sprintf(`Interact with the %q %s instance via its management API.

This is the same command set as %q, targeting a different daemon. The
target is the apiservers entry named %q in the tdns-mpcli config.`, role, daemon, kind, role)
	}
	return TagRole(c, role)
}

// NewAgentTree builds a tdns-mpagent command tree targeting one instance.
func NewAgentTree(use, role string) *cobra.Command {
	const kind = "agent"
	c := treeRoot(use, role, kind, "tdns-mpagent")
	c.Short = shortFor(use, kind, "TDNS Agent commands")

	c.AddCommand(
		tdnscli.NewPingCmd(role),
		tdnscli.NewStopCmd(role),
		tdnscli.NewDaemonCmd(role),
		tdnscli.NewDebugCmd(role, debugAgentLeaves(kind)...),
		tdnscli.NewConfigCmd(role),
		NewKeysCmd(kind),
		newAgentDistribCmd(kind),
		newAgentTransactionCmd(kind),
		NewAgentZoneCmd(role, kind),
		newAgentLocalCmd(kind),
		newAgentDiscoverCmd(kind),
		newAgentPeerCmd(kind),
		newAgentImrCmd(kind),
		newHsyncCmd(kind),
		newRouterCmd(kind),
		NewGossipCmd(kind),
	)
	c.AddCommand(
		tdnscli.NewKeystoreCmd(role),
		tdnscli.NewTruststoreCmd(role),
	)
	return c
}

// NewCombinerTree builds a tdns-mpcombiner command tree targeting one
// instance.
func NewCombinerTree(use, role string) *cobra.Command {
	const kind = "combiner"
	c := treeRoot(use, role, kind, "tdns-mpcombiner")
	c.Short = shortFor(use, kind, "TDNS Combiner commands")

	c.AddCommand(
		tdnscli.NewPingCmd(role),
		tdnscli.NewStopCmd(role),
		tdnscli.NewDaemonCmd(role),
		tdnscli.NewDebugCmd(role),
		combinerConfigCmd(role, kind),
		NewKeysCmd(kind),
		newCombinerDistribCmd(kind),
		newCombinerTransactionCmd(kind),
		newCombinerAddDataCmd(kind),
		newCombinerRemoveDataCmd(kind),
		newCombinerListDataCmd(kind),
		newCombinerZoneCmd(kind),
		newCombinerShowDataCmd(kind),
		newCombinerPeerCmd(kind),
		newRouterCmd(kind),
		NewGossipCmd(kind),
	)
	return c
}

// combinerConfigCmd is tdns's "config" subtree (reload, reload-zones, status)
// with its "status" leaf replaced by the combiner's own, which shows the
// running combiner's effective multi-provider config. Until 2026-09 the two
// "config" commands sat side by side under the combiner root and the second
// (tdns's) was unreachable; now reload and reload-zones are reachable and
// status keeps the behaviour it had.
func combinerConfigCmd(role, kind string) *cobra.Command {
	c := tdnscli.NewConfigCmd(role)
	c.Short = "Runtime introspection of the combiner's multi-provider config; config and zone reload"
	for _, sub := range c.Commands() {
		if sub.Name() == "status" {
			c.RemoveCommand(sub)
		}
	}
	c.AddCommand(newCombinerConfigStatusCmd(kind))
	return c
}

// NewSignerTree builds a tdns-mpsigner command tree targeting one instance.
//
// The canonical signer tree additionally carries tdns's static AuthCmd and
// ReportCmd and this package's RootKeysCmd and JwtCmd (see
// cmd/mpcli/shared_cmds.go). They are package-level vars, so they can hang
// off one tree only, and they are offline tools or (auth) target a
// tdns-auth this CLI has no client for; an instance tree does without them.
func NewSignerTree(use, role string) *cobra.Command {
	const kind = "signer"
	c := treeRoot(use, role, kind, "tdns-mpsigner")
	c.Short = shortFor(use, kind, "Interact with the MP signer via API")

	c.AddCommand(
		tdnscli.NewPingCmd(role),
		tdnscli.NewStopCmd(role),
		tdnscli.NewDaemonCmd(role),
		tdnscli.NewDebugCmd(role),
		tdnscli.NewConfigCmd(role),
		tdnscli.NewZoneCmd(role, newSignerZoneMPListCmd(kind)),
		NewPeerCmd(kind),
		newRouterCmd(kind),
		NewGossipCmd(kind),
	)
	c.AddCommand(
		signerKeystoreCmd(role),
		tdnscli.NewTruststoreCmd(role),
	)
	return c
}

// signerKeystoreCmd is tdns's keystore subtree minus the four "dnssec"
// leaves that call tdns-auth's KSK-rollover automation endpoints
// (/rollover/*, /config/paths), which the mp signer does not serve. In the
// pinned tdns cli those leaves also hardcode the auth role, so against an
// mp signer they could only ever fail; better that --help does not offer
// them. One line to undo if the signer ever gains those endpoints.
func signerKeystoreCmd(role string) *cobra.Command {
	c := tdnscli.NewKeystoreCmd(role)
	for _, sub := range c.Commands() {
		if sub.Name() != "dnssec" {
			continue
		}
		for _, leaf := range sub.Commands() {
			switch leaf.Name() {
			case "policy", "ds-push", "query-parent", "auto-rollover":
				sub.RemoveCommand(leaf)
			}
		}
	}
	return c
}

// NewAuditorTree builds a tdns-mpauditor command tree targeting one
// instance. The auditor gets gossip and peer subtrees because it
// participates in the HSYNC3 protocol the same way agents do.
func NewAuditorTree(use, role string) *cobra.Command {
	const kind = "auditor"
	c := treeRoot(use, role, kind, "tdns-mpauditor")
	c.Short = shortFor(use, kind, "Interact with the MP auditor via API")

	peer := NewPeerCmd(kind)
	peer.AddCommand(NewAuditorPeerListCmd(), NewAuditorPeerZonesCmd())

	c.AddCommand(
		tdnscli.NewPingCmd(role),
		tdnscli.NewStopCmd(role),
		tdnscli.NewDaemonCmd(role),
		tdnscli.NewDebugCmd(role),
		tdnscli.NewConfigCmd(role),
		NewGossipCmd(kind),
		peer,
		tdnscli.NewZoneCmd(role, newAuditorZoneMPListCmd(kind)),
		newAuditorDistribCmd(kind),
		newAuditorEventlogCmd(kind),
		newAuditorZonesCmd(kind),
		newAuditorObservationsCmd(kind),
		newAuditorWebCmd(kind),
	)
	c.AddCommand(
		tdnscli.NewKeystoreCmd(role),
		tdnscli.NewTruststoreCmd(role),
	)
	return c
}

// shortFor keeps the canonical trees' one-line descriptions exactly as they
// were, and gives instance trees one that names the instance.
func shortFor(use, kind, canonical string) string {
	if use == kind {
		return canonical
	}
	return fmt.Sprintf("%s (instance %q)", canonical, use)
}
