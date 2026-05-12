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
	"net"
	"strings"

	cfg "github.com/johanix/tdns/v2/cli/configure"
	"github.com/miekg/dns"
)

// Defaults used when a prompt has no seed value (first run).
const (
	defaultKeysDir    = "/etc/tdns/keys"
	defaultCertsDir   = "/etc/tdns/certs"
	defaultPublicIP   = "127.0.0.1"
	defaultInternalIP = "127.0.0.1"
)

// Built-in port layout (same box, all four roles).
const (
	signerDnsPort   = 8053
	signerDns53Port = 53
	signerApiPort   = 7053

	combinerDnsPort = 8055
	combinerApiPort = 7055

	agentDnsPort = 8054
	agentApiPort = 7054

	auditorDnsPort = 8056
	auditorApiPort = 7056
)

// runInterview walks the minimum prompt set. `current` seeds
// defaults; on first run pass a zero CoordinatedValues.
func runInterview(p *cfg.Prompter, current CoordinatedValues) CoordinatedValues {
	out := current

	fmt.Fprintln(p.Out, "\n=== Global ===")
	out.Global.KeysDir = p.Ask("keys directory", cfg.OrDefault(current.Global.KeysDir, defaultKeysDir), cfg.AbsDir)
	out.Global.CertsDir = p.Ask("certs directory", cfg.OrDefault(current.Global.CertsDir, defaultCertsDir), cfg.AbsDir)
	out.Global.PublicIP = p.Ask("public IP (advertised in certs, mpcli base URLs, example zone notify/primary)", cfg.OrDefault(current.Global.PublicIP, defaultPublicIP), ipLiteral)

	// InternalIP is what each role binds and what the roles dial each other on.
	// On a same-host deployment 127.0.0.1 is correct; on AWS EC2 / multi-host
	// setups the operator must supply a private IP that is actually on the
	// local interface (the public IP often is not).
	internalSeed := cfg.OrDefault(current.Global.InternalIP, defaultInternalIP)
	out.Global.InternalIP = p.Ask("internal IP (bind address + inter-role dial target; 127.0.0.1 for single-host)", internalSeed, ipLiteral)

	fmt.Fprintln(p.Out, "\n=== Identities ===")
	out.Agent.Identity = p.AskIdentity("agent identity", current.Agent.Identity)
	out.Signer.Identity = p.AskIdentity("signer identity", current.Signer.Identity)
	out.Combiner.Identity = p.AskIdentity("combiner identity", current.Combiner.Identity)

	// Optional auditor role. The auditor is a read-only MP
	// participant — it joins gossip and observes signaling but
	// never contributes zone data. Default to yes on re-runs where
	// an auditor identity is already on disk; default to no on
	// first run so the common three-role setup stays minimal.
	auditorDefault := current.Auditor.Identity != ""
	if p.AskYesNo("\nAlso generate a tdns-mpauditor config?", auditorDefault) {
		out.Auditor.Identity = p.AskIdentity("auditor identity", current.Auditor.Identity)
	} else {
		out.Auditor.Identity = ""
	}

	// The agent has an auto-created zone (the agent identity itself, e.g.
	// agent.hare.mp.axfr.net.). The two prompts below configure that
	// zone's published NS RDATA and the downstream secondaries it
	// NOTIFYs. Both are optional and can be edited later in the YAML.
	fmt.Fprintln(p.Out, "\n=== Agent auto-zone ===")
	nsSeed := strings.Join(current.Agent.LocalNameservers, " ")
	nsAns := p.Ask("nameservers for agent zone (FQDNs published as NS records; whitespace-separated, blank ok)", nsSeed, fqdnList)
	out.Agent.LocalNameservers = parseFqdnList(nsAns)
	notifySeed := strings.Join(current.Agent.LocalNotify, " ")
	notifyAns := p.Ask("notify addresses for agent zone (host:port of downstream secondaries; whitespace-separated, blank ok)", notifySeed, hostPortList)
	out.Agent.LocalNotify = parseHostPortList(notifyAns)

	showPortTable(p.Out, out.Auditor.Identity != "")
	if !p.AskYesNo("\nAccept these defaults?", true) {
		fmt.Fprintln(p.Out, "OK — these defaults will be used now; edit the generated configs afterwards to change them.")
	}
	return out
}

// fqdnList accepts whitespace-separated FQDN-like tokens. Empty is
// allowed. Each token must look like a domain name; a trailing dot
// is added automatically by parseFqdnList.
func fqdnList(s string) error {
	for _, tok := range strings.Fields(s) {
		// dns.IsDomainName accepts both fqdn and partial; we
		// only need a coarse check that it is not garbage.
		if _, ok := dns.IsDomainName(tok); !ok {
			return fmt.Errorf("%q is not a valid domain name", tok)
		}
	}
	return nil
}

// parseFqdnList splits whitespace-separated input into FQDNs (with
// trailing dots added if missing).
func parseFqdnList(s string) []string {
	tokens := strings.Fields(s)
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, dns.Fqdn(t))
	}
	return out
}

// hostPortList accepts whitespace-separated host:port tokens. Empty
// is allowed. Each token must split via net.SplitHostPort.
func hostPortList(s string) error {
	for _, tok := range strings.Fields(s) {
		if _, _, err := net.SplitHostPort(tok); err != nil {
			return fmt.Errorf("%q is not a valid host:port: %v", tok, err)
		}
	}
	return nil
}

// parseHostPortList splits whitespace-separated input into host:port
// strings, returning them as-is (already validated by hostPortList).
func parseHostPortList(s string) []string {
	return strings.Fields(s)
}

// ipLiteral rejects non-IP input. Used by both the PublicIP and
// InternalIP prompts; accepting hostnames here would silently
// produce invalid entries in fields that expect IPs (cert SANs,
// listen addresses for binds). Users who want a hostname can edit
// the generated configs afterwards.
func ipLiteral(s string) error {
	if err := cfg.NonEmpty("IP address")(s); err != nil {
		return err
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("%q is not an IP literal (hostnames not accepted here)", s)
	}
	return nil
}

// showPortTable prints the fixed port layout so the user knows
// what is about to be baked in. The auditor row is included only
// when the auditor role was opted into in the interview.
func showPortTable(w io.Writer, withAuditor bool) {
	fmt.Fprintln(w, "\nPort layout (same-box defaults):")
	fmt.Fprintf(w, "   %-17s %-12s %s\n", "role", "DNS", "mgmt API")
	fmt.Fprintf(w, "   %-17s %-12s %d\n", "tdns-mpsigner", fmt.Sprintf("%d, %d", signerDnsPort, signerDns53Port), signerApiPort)
	fmt.Fprintf(w, "   %-17s %-12d %d\n", "tdns-mpcombiner", combinerDnsPort, combinerApiPort)
	fmt.Fprintf(w, "   %-17s %-12d %d\n", "tdns-mpagent", agentDnsPort, agentApiPort)
	if withAuditor {
		fmt.Fprintf(w, "   %-17s %-12d %d\n", "tdns-mpauditor", auditorDnsPort, auditorApiPort)
	}
}
