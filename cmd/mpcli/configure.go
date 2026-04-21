/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: cobra command.
 *
 * `tdns-mpcli configure` is a bootstrap tool that interviews
 * the user and emits coordinated configs for mpagent, mpsigner,
 * mpcombiner and mpcli. It runs *before* any config exists (first
 * run) and may be re-run safely later (re-run seeds prompts with
 * current values).
 *
 * Safeguards (see tdns-mp/docs/2026-04-21-mpcli-configure-plan.md):
 *   - Unconditional timestamped backup of any replaced file.
 *   - Diff preview with single top-level confirmation.
 *   - Atomic write + YAML re-parse.
 *   - Live-server gate (typed confirmation per live server).
 *
 * This command intentionally does NOT go through the normal
 * PersistentPreRun config/API bootstrap; it must work when no
 * mpcli.yaml exists yet.
 */
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Interactive bootstrap for tdns-mp config files",
	Long: `Interview the user and emit coordinated configs for
tdns-mpagent, tdns-mpsigner, tdns-mpcombiner and tdns-mpcli
under /etc/tdns/.

Safe to re-run: existing values become the prompt defaults.
Live servers must be explicitly confirmed before their
config is replaced.`,
	RunE: runConfigure,
}

func init() {
	rootCmd.AddCommand(configureCmd)
}

func runConfigure(cmd *cobra.Command, args []string) error {
	fmt.Println("Reading any existing configuration…")
	existing := make(map[string]string, 4)
	for _, p := range allConfigPaths() {
		content, err := readFileIfExists(p)
		if err != nil {
			return err
		}
		existing[p] = content
		if content == "" {
			fmt.Printf("  %s: (not present)\n", p)
		} else {
			fmt.Printf("  %s: %d bytes\n", p, len(content))
		}
	}

	current, err := readExistingCoordinated()
	if err != nil {
		return fmt.Errorf("parse existing configs: %w", err)
	}

	next := runInterview(current)

	// API keys are substituted into the rendered YAML, so they
	// must exist before rendering. Generation is in-memory only
	// at this stage — nothing lands on disk until after the user
	// confirms the diff.
	if next.Agent.ApiKey, err = ensureApiKey(next.Agent.ApiKey); err != nil {
		return err
	}
	if next.Signer.ApiKey, err = ensureApiKey(next.Signer.ApiKey); err != nil {
		return err
	}
	if next.Combiner.ApiKey, err = ensureApiKey(next.Combiner.ApiKey); err != nil {
		return err
	}

	rendered, err := renderAll(next)
	if err != nil {
		return fmt.Errorf("render templates: %w", err)
	}

	changes := make([]fileChange, 0, len(rendered))
	for _, p := range allConfigPaths() {
		changes = append(changes, fileChange{
			path:   p,
			oldTxt: existing[p],
			newTxt: rendered[p],
		})
	}

	in := stdinReader()
	if !confirmApply(os.Stdout, in, changes) {
		fmt.Println("\nAborted. No files changed.")
		return nil
	}

	// Live-server gate: any still-running daemon whose config
	// is about to change must be confirmed explicitly, using
	// the current (pre-change) apikey to probe.
	if err := gateLiveServers(os.Stdout, in, current, existing, changes); err != nil {
		fmt.Println("\n" + err.Error())
		return nil
	}

	// Generate missing key/cert material now — only after the
	// user has committed to the write. Existing files are
	// preserved (no rotation).
	if err := generateMissingMaterial(next); err != nil {
		return fmt.Errorf("generate material: %w", err)
	}

	if _, err := applyChanges(os.Stdout, changes); err != nil {
		return fmt.Errorf("apply changes: %w", err)
	}
	fmt.Println("\nDone.")
	return nil
}

// generateMissingMaterial walks the derived per-role paths and
// generates any missing JOSE keypairs and TLS certs. Existing
// files are left untouched (reuse-not-rotate).
func generateMissingMaterial(cv CoordinatedValues) error {
	paths := makeRolePaths(cv.Global.KeysDir, cv.Global.CertsDir)

	roles := []struct {
		label    string
		privKey  string
		certFile string
		keyFile  string
		identity string
	}{
		{"agent", paths.AgentJosePriv, paths.AgentCert, paths.AgentKey, cv.Agent.Identity},
		{"signer", paths.SignerJosePriv, paths.SignerCert, paths.SignerKey, cv.Signer.Identity},
		{"combiner", paths.CombinerJosePriv, paths.CombinerCert, paths.CombinerKey, cv.Combiner.Identity},
	}

	for _, role := range roles {
		pub, keyID, gen, err := ensureJoseKeypair(role.privKey)
		if err != nil {
			return fmt.Errorf("%s jose: %w", role.label, err)
		}
		if gen {
			fmt.Printf("  generated %s JOSE keypair (KeyID %s)\n    priv: %s\n    pub:  %s\n",
				role.label, keyID, role.privKey, pub)
		}

		// Cert SANs include the shared public IP so the cert
		// validates for traffic coming in on that address.
		certGen, err := ensureTLSCert(role.certFile, role.keyFile, role.identity, cv.Global.PublicIP+":0")
		if err != nil {
			return fmt.Errorf("%s tls: %w", role.label, err)
		}
		if certGen {
			fmt.Printf("  generated %s TLS cert/key\n    cert: %s\n    key:  %s\n",
				role.label, role.certFile, role.keyFile)
		}
	}
	return nil
}
