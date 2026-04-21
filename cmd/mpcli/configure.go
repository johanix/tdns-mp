/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * `tdns-mpcli configure` — mpcli-specific wiring of the generic
 * bootstrap-configurator library (tdns/v2/cli/configure).
 *
 * The library owns prompt/diff/atomic-write/live-ping/generate
 * plumbing. This file provides:
 *
 *   - ordered list of the four mp configs
 *   - ReadExisting: parse existing YAMLs into CoordinatedValues
 *   - RunInterview: prompt the six coordinated knobs
 *   - RenderAll: template rendering
 *   - LiveTargets: per-role API probe inputs
 *   - GenerateMaterial: JOSE keys + TLS certs per role
 */
package main

import (
	"fmt"

	"github.com/johanix/tdns/v2/cli/configure"
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
	return configure.Run(configure.Spec{
		Paths: allConfigPaths(),

		ReadExisting: func() (any, error) {
			return readExistingCoordinated()
		},

		RunInterview: func(p *configure.Prompter, seed any) (any, error) {
			cv := seed.(CoordinatedValues)
			return runInterview(p, cv), nil
		},

		RenderAll: func(state any) (map[string]string, error) {
			cv, err := materialiseApiKeys(state.(CoordinatedValues))
			if err != nil {
				return nil, err
			}
			return renderAll(cv)
		},

		LiveTargets: func(state any) []configure.LiveTarget {
			cv := state.(CoordinatedValues)
			return liveTargetsFor(cv)
		},

		GenerateMaterial: func(state any) error {
			return generateMissingMaterial(state.(CoordinatedValues))
		},
	})
}

// materialiseApiKeys fills in any missing API keys on the state
// so the template render has something to interpolate.
func materialiseApiKeys(cv CoordinatedValues) (CoordinatedValues, error) {
	var err error
	if cv.Agent.ApiKey, err = configure.EnsureApiKey(cv.Agent.ApiKey); err != nil {
		return cv, err
	}
	if cv.Signer.ApiKey, err = configure.EnsureApiKey(cv.Signer.ApiKey); err != nil {
		return cv, err
	}
	if cv.Combiner.ApiKey, err = configure.EnsureApiKey(cv.Combiner.ApiKey); err != nil {
		return cv, err
	}
	return cv, nil
}

// liveTargetsFor builds the LiveTarget list for the three
// running-daemon roles. mpcli itself is not a server.
func liveTargetsFor(cv CoordinatedValues) []configure.LiveTarget {
	ip := cv.Global.PublicIP
	mk := func(role, path string, port int, apiKey string) configure.LiveTarget {
		url := ""
		if ip != "" {
			url = fmt.Sprintf("https://%s:%d/api/v1", ip, port)
		}
		return configure.LiveTarget{
			Role:      role,
			Path:      path,
			BaseURL:   url,
			APIKey:    apiKey,
			HasConfig: apiKey != "",
		}
	}
	return []configure.LiveTarget{
		mk("mpagent", pathMpagent, agentApiPort, cv.Agent.ApiKey),
		mk("mpsigner", pathMpsigner, signerApiPort, cv.Signer.ApiKey),
		mk("mpcombiner", pathMpcombiner, combinerApiPort, cv.Combiner.ApiKey),
	}
}

// generateMissingMaterial walks the derived per-role paths and
// generates any missing JOSE keypairs and TLS certs using the
// library helpers. Existing files are left untouched.
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
		pub, keyID, gen, err := configure.EnsureJoseKeypair(role.privKey)
		if err != nil {
			return fmt.Errorf("%s jose: %w", role.label, err)
		}
		if gen {
			fmt.Printf("  generated %s JOSE keypair (KeyID %s)\n    priv: %s\n    pub:  %s\n",
				role.label, keyID, role.privKey, pub)
		}

		certGen, err := configure.EnsureTLSCert(role.certFile, role.keyFile, role.identity, cv.Global.PublicIP+":0")
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
