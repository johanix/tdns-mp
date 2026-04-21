/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: cobra command + wiring.
 *
 * Cmd is exported for registration from cmd/mpcli/shared_cmds.go.
 * All role-specific logic (types, YAML parsers, interview flow,
 * templates) lives here; generic plumbing (prompts, diff, atomic
 * write, live-ping, generation of JOSE/TLS/apikey) comes from
 * tdns/v2/cli/configure.
 */
package configure

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"

	cfg "github.com/johanix/tdns/v2/cli/configure"
)

// Cmd is the `tdns-mpcli configure` cobra command.
var Cmd = &cobra.Command{
	Use:   "configure",
	Short: "Interactive bootstrap for tdns-mp config files",
	Long: `Interview the user and emit coordinated configs for
tdns-mpagent, tdns-mpsigner, tdns-mpcombiner and tdns-mpcli
under /etc/tdns/.

Safe to re-run: existing values become the prompt defaults.
Live servers must be explicitly confirmed before their
config is replaced.`,
	RunE: run,
}

func run(cmd *cobra.Command, args []string) error {
	return cfg.Run(cfg.Spec{
		Paths: allConfigPaths(),

		ReadExisting: func() (any, error) {
			return readExistingCoordinated()
		},

		RunInterview: func(p *cfg.Prompter, seed any) (any, error) {
			return runInterview(p, seed.(CoordinatedValues)), nil
		},

		RenderAll: func(state any) (map[string]string, error) {
			cv, err := materialiseApiKeys(state.(CoordinatedValues))
			if err != nil {
				return nil, err
			}
			return renderAll(cv)
		},

		LiveTargets: func(state any) []cfg.LiveTarget {
			return liveTargetsFor(state.(CoordinatedValues))
		},

		GenerateMaterial: func(state any) error {
			return generateMissingMaterial(state.(CoordinatedValues))
		},
	})
}

// materialiseApiKeys fills in any missing API keys so the
// template render has something to interpolate.
func materialiseApiKeys(cv CoordinatedValues) (CoordinatedValues, error) {
	var err error
	if cv.Agent.ApiKey, err = cfg.EnsureApiKey(cv.Agent.ApiKey); err != nil {
		return cv, err
	}
	if cv.Signer.ApiKey, err = cfg.EnsureApiKey(cv.Signer.ApiKey); err != nil {
		return cv, err
	}
	if cv.Combiner.ApiKey, err = cfg.EnsureApiKey(cv.Combiner.ApiKey); err != nil {
		return cv, err
	}
	return cv, nil
}

// liveTargetsFor builds the LiveTarget list for the three
// running-daemon roles. mpcli itself is not a server.
func liveTargetsFor(cv CoordinatedValues) []cfg.LiveTarget {
	ip := cv.Global.PublicIP
	mk := func(role, path string, port int, apiKey string) cfg.LiveTarget {
		url := ""
		if ip != "" {
			url = "https://" + net.JoinHostPort(ip, strconv.Itoa(port)) + "/api/v1"
		}
		return cfg.LiveTarget{
			Role:      role,
			Path:      path,
			BaseURL:   url,
			APIKey:    apiKey,
			HasConfig: apiKey != "",
		}
	}
	return []cfg.LiveTarget{
		mk("mpagent", pathMpagent, agentApiPort, cv.Agent.ApiKey),
		mk("mpsigner", pathMpsigner, signerApiPort, cv.Signer.ApiKey),
		mk("mpcombiner", pathMpcombiner, combinerApiPort, cv.Combiner.ApiKey),
	}
}

// generateMissingMaterial generates any missing JOSE keypairs and
// TLS certs. Existing files are left untouched.
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
		pub, keyID, gen, err := cfg.EnsureJoseKeypair(role.privKey)
		if err != nil {
			return fmt.Errorf("%s jose: %w", role.label, err)
		}
		if gen {
			fmt.Printf("  generated %s JOSE keypair (KeyID %s)\n    priv: %s\n    pub:  %s\n",
				role.label, keyID, role.privKey, pub)
		}
		certGen, err := cfg.EnsureTLSCert(role.certFile, role.keyFile, role.identity, net.JoinHostPort(cv.Global.PublicIP, "0"))
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
