/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: interview engine.
 *
 * Six prompts total:
 *
 *   global:   keys dir, certs dir, public IP
 *   each role (agent, signer, combiner):  identity
 *
 * Port assignment is deterministic and shown as a table before
 * the final confirmation. The user can accept the defaults or
 * proceed and edit them in the generated YAML afterwards —
 * there is no "tweak each port" loop.
 *
 * Identities are accepted as-is, canonicalised via dns.Fqdn()
 * and echoed back so the user sees the final value.
 */
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
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

// --- Prompt primitives ---

type validator func(string) error

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter() *prompter {
	return &prompter{
		in:  bufio.NewReader(os.Stdin),
		out: os.Stdout,
	}
}

func (p *prompter) ask(label, dflt string, v validator) string {
	for {
		if dflt != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", label, dflt)
		} else {
			fmt.Fprintf(p.out, "%s: ", label)
		}
		line, err := p.in.ReadString('\n')
		if err != nil && line == "" {
			return ""
		}
		val := strings.TrimSpace(line)
		if val == "" {
			val = dflt
		}
		if v != nil {
			if vErr := v(val); vErr != nil {
				fmt.Fprintf(p.out, "  invalid: %v\n", vErr)
				continue
			}
		}
		return val
	}
}

// askIdentity accepts a bare name, canonicalises it with
// dns.Fqdn(), echoes the canonical form back, and returns it.
func (p *prompter) askIdentity(label, dflt string) string {
	raw := p.ask(label, dflt, nonEmpty("identity"))
	fq := dns.Fqdn(strings.TrimSpace(raw))
	if fq != raw {
		fmt.Fprintf(p.out, "  using %s\n", fq)
	}
	return fq
}

// askYesNo prompts for yes/no. Empty input returns `defaultYes`.
// Any non-"n"-starting answer counts as yes.
func (p *prompter) askYesNo(label string, defaultYes bool) bool {
	tag := "[Y/n]"
	if !defaultYes {
		tag = "[y/N]"
	}
	fmt.Fprintf(p.out, "%s %s: ", label, tag)
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return defaultYes
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	if ans == "" {
		return defaultYes
	}
	return ans[0] != 'n'
}

// --- Validators ---

func nonEmpty(field string) validator {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

func absDir(s string) error {
	if err := nonEmpty("directory")(s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "/") {
		return fmt.Errorf("must be an absolute path")
	}
	return nil
}

// --- Interview orchestrator ---

// runInterview walks the minimum prompt set. `current` seeds
// defaults; on first run pass a zero CoordinatedValues and
// built-in defaults are used.
func runInterview(current CoordinatedValues) CoordinatedValues {
	p := newPrompter()
	out := current

	fmt.Fprintln(p.out, "\n=== Global ===")
	out.Global.KeysDir = p.ask("keys directory", orDefault(current.Global.KeysDir, defaultKeysDir), absDir)
	out.Global.CertsDir = p.ask("certs directory", orDefault(current.Global.CertsDir, defaultCertsDir), absDir)
	out.Global.PublicIP = p.ask("public IP (shared by all three roles)", orDefault(current.Global.PublicIP, defaultPublicIP), nonEmpty("public IP"))

	fmt.Fprintln(p.out, "\n=== Identities ===")
	out.Agent.Identity = p.askIdentity("agent identity", current.Agent.Identity)
	out.Signer.Identity = p.askIdentity("signer identity", current.Signer.Identity)
	out.Combiner.Identity = p.askIdentity("combiner identity", current.Combiner.Identity)

	showPortTable(p.out)
	if !p.askYesNo("\nAccept these defaults?", true) {
		fmt.Fprintln(p.out, "OK — these defaults will be used now; edit the generated configs afterwards to change them.")
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

func orDefault(cur, dflt string) string {
	if cur == "" {
		return dflt
	}
	return cur
}
