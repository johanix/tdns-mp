/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: interview flow.
 *
 * Six prompts total:
 *   global:  keys dir, certs dir, public IP
 *   roles:   identity per agent/signer/combiner
 *
 * Port assignment is deterministic (see constants below) and
 * shown as a table. The user accepts or proceeds and edits
 * afterwards — there is no per-port prompt loop.
 */
package configure

import (
	"fmt"
	"io"

	cfg "github.com/johanix/tdns/v2/cli/configure"
)

// Defaults used when a prompt has no seed value (first run).
const (
	defaultKeysDir  = "/etc/tdns/keys"
	defaultCertsDir = "/etc/tdns/certs"
	defaultPublicIP = "127.0.0.1"
)

// Built-in port layout (same box, all three roles).
const (
	signerDnsPort   = 8053
	signerDns53Port = 53
	signerApiPort   = 7053

	combinerDnsPort = 8055
	combinerApiPort = 7055

	agentDnsPort = 8054
	agentApiPort = 7054
)

// runInterview walks the minimum prompt set. `current` seeds
// defaults; on first run pass a zero CoordinatedValues.
func runInterview(p *cfg.Prompter, current CoordinatedValues) CoordinatedValues {
	out := current

	fmt.Fprintln(p.Out, "\n=== Global ===")
	out.Global.KeysDir = p.Ask("keys directory", cfg.OrDefault(current.Global.KeysDir, defaultKeysDir), cfg.AbsDir)
	out.Global.CertsDir = p.Ask("certs directory", cfg.OrDefault(current.Global.CertsDir, defaultCertsDir), cfg.AbsDir)
	out.Global.PublicIP = p.Ask("public IP (shared by all three roles)", cfg.OrDefault(current.Global.PublicIP, defaultPublicIP), cfg.NonEmpty("public IP"))

	fmt.Fprintln(p.Out, "\n=== Identities ===")
	out.Agent.Identity = p.AskIdentity("agent identity", current.Agent.Identity)
	out.Signer.Identity = p.AskIdentity("signer identity", current.Signer.Identity)
	out.Combiner.Identity = p.AskIdentity("combiner identity", current.Combiner.Identity)

	showPortTable(p.Out)
	if !p.AskYesNo("\nAccept these defaults?", true) {
		fmt.Fprintln(p.Out, "OK — these defaults will be used now; edit the generated configs afterwards to change them.")
	}
	return out
}

// showPortTable prints the fixed port layout so the user knows
// what is about to be baked in.
func showPortTable(w io.Writer) {
	fmt.Fprintln(w, "\nPort layout (same-box defaults):")
	fmt.Fprintf(w, "   %-17s %-12s %s\n", "role", "DNS", "mgmt API")
	fmt.Fprintf(w, "   %-17s %-12s %d\n", "tdns-mpsigner", fmt.Sprintf("%d, %d", signerDnsPort, signerDns53Port), signerApiPort)
	fmt.Fprintf(w, "   %-17s %-12d %d\n", "tdns-mpcombiner", combinerDnsPort, combinerApiPort)
	fmt.Fprintf(w, "   %-17s %-12d %d\n", "tdns-mpagent", agentDnsPort, agentApiPort)
}
