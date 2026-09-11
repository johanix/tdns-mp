/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Which daemon instance a command targets.
 *
 * A command tree carries its target as an annotation on the tree's ROOT, and
 * every command below it inherits that by walking up. This exists so a Run
 * closure can ask "which instance am I acting on?" without the answer having
 * been threaded down to it through every constructor in between.
 *
 * That matters because threading is exactly what had been getting forgotten.
 * 29 call sites in this package hardcoded GetApiClient("agent") and friends.
 * With one instance of each daemon that is invisible. With two, it silently
 * drives the WRONG daemon: no error, no crash, an edit applied to the other
 * provider's agent. All 29 now resolve off the command tree instead.
 *
 * A closure gets its *cobra.Command for free, so GetApiClientForCmd cannot be
 * forgotten in the way a threaded parameter can. Prefer it in new code.
 *
 * This file is a copy of tdns v2/cli/role_target.go (tdns commit d9071e65,
 * 2026-09-07) adapted to tdns-mp, which pins a tdns/v2/cli that predates it.
 * When tdns-mp re-pins, delete this file and import the tdns one: same names,
 * same behaviour. See docs/2026-09-10-mpcli-multi-instance-assessment.md.
 *
 * Two words are kept apart throughout this package:
 *
 *   role  -- the TARGET: the key GetApiClient resolves to an ApiClient. For a
 *            canonical tree that is "agent", "combiner", "signer" or
 *            "auditor"; for an instance tree it is the instance name
 *            ("p2-agent"). It is what TagRole stores.
 *   kind  -- the DAEMON TYPE: which of the four mp daemons this tree talks
 *            to, for URL paths ("/agent/distrib") and behaviour gates
 *            ("only agents and auditors gossip"). Constant per tree and
 *            passed to factories as a literal.
 *
 * With one instance per daemon the two are equal, which is how 29 sites got
 * away with using one string for both.
 */
package cli

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
)

// roleAnnotation is the cobra Annotations key holding a subtree's target role.
const roleAnnotation = "tdns.role"

// TagRole marks cmd -- and thus everything below it -- as targeting role.
// Returns cmd so it can be used inline in an AddCommand argument list.
func TagRole(cmd *cobra.Command, role string) *cobra.Command {
	if cmd == nil {
		return nil
	}
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[roleAnnotation] = role
	return cmd
}

// RoleForCmd returns the role cmd's tree targets, or "" if the tree is
// untagged. The walk is upward from cmd, so a subtree may override its
// parent's tag -- which is what lets a single tree host a command that
// deliberately talks to a different daemon.
func RoleForCmd(cmd *cobra.Command) string {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations == nil {
			continue
		}
		if role, ok := c.Annotations[roleAnnotation]; ok && role != "" {
			return role
		}
	}
	return ""
}

// GetApiClientForCmd resolves the ApiClient for whichever instance cmd's tree
// targets.
//
// An untagged tree is a wiring bug, not a user error: every tree root is
// tagged where it is built. Say so plainly rather than falling back to a
// default role, because the failure a default would produce is the silent
// wrong-target one this whole mechanism exists to prevent.
func GetApiClientForCmd(cmd *cobra.Command, dieOnError bool) (*tdns.ApiClient, error) {
	role := RoleForCmd(cmd)
	if role == "" {
		name := "<nil>"
		if cmd != nil {
			name = cmd.CommandPath()
		}
		err := fmt.Errorf("command %q is in an untagged command tree: no target instance (this is a wiring bug -- see TagRole)", name)
		if dieOnError {
			log.Fatalf("%v", err)
		}
		return nil, err
	}
	return tdnscli.GetApiClient(role, dieOnError)
}
