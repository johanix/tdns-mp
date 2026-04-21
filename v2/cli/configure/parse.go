/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: targeted YAML parsers.
 *
 * On re-run, we parse each existing config file into a tiny
 * typed shape that captures only the coordinated knobs. Unknown
 * keys in the YAML are silently ignored — this is by design,
 * the configurator does not claim authority over the full config
 * surface.
 *
 * Directories for keys/certs and the public IP are back-derived
 * from the agent's existing paths/addresses if present.
 */
package configure

import (
	"fmt"
	"net"
	"path/filepath"

	cfg "github.com/johanix/tdns/v2/cli/configure"
	"gopkg.in/yaml.v3"
)

// --- YAML shapes matching the coordinated subset ---

type mpagentYAML struct {
	MultiProvider struct {
		Identity            string `yaml:"identity"`
		LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
		API                 struct {
			CertFile string `yaml:"certfile"`
		} `yaml:"api"`
	} `yaml:"multi-provider"`
	APIServer struct {
		Addresses []string `yaml:"addresses"`
		APIKey    string   `yaml:"apikey"`
	} `yaml:"apiserver"`
}

type mpsignerYAML struct {
	MultiProvider struct {
		Identity            string `yaml:"identity"`
		LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	} `yaml:"multi-provider"`
	APIServer struct {
		Addresses []string `yaml:"addresses"`
		APIKey    string   `yaml:"apikey"`
	} `yaml:"apiserver"`
}

type mpcombinerYAML struct {
	MultiProvider struct {
		Identity            string `yaml:"identity"`
		LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	} `yaml:"multi-provider"`
	APIServer struct {
		Addresses []string `yaml:"addresses"`
		APIKey    string   `yaml:"apikey"`
	} `yaml:"apiserver"`
}

// readExistingCoordinated populates CoordinatedValues from any
// existing YAML files on disk. Missing files contribute zero
// values. Returns an error only for I/O problems or malformed
// YAML — not for missing files.
func readExistingCoordinated() (CoordinatedValues, error) {
	var cv CoordinatedValues

	var agentJosePriv, agentCertFile, agentApiAddr string
	if err := parseAgentFile(pathMpagent, &cv.Agent, &agentJosePriv, &agentCertFile, &agentApiAddr); err != nil {
		return cv, err
	}
	if err := parseSignerFile(pathMpsigner, &cv.Signer); err != nil {
		return cv, err
	}
	if err := parseCombinerFile(pathMpcombiner, &cv.Combiner); err != nil {
		return cv, err
	}

	if agentJosePriv != "" {
		cv.Global.KeysDir = filepath.Dir(agentJosePriv)
	}
	if agentCertFile != "" {
		cv.Global.CertsDir = filepath.Dir(agentCertFile)
	}
	if agentApiAddr != "" {
		cv.Global.PublicIP = hostOnly(agentApiAddr)
	}
	return cv, nil
}

// hostOnly returns just the host portion of a host:port string.
// Uses net.SplitHostPort so bracketed IPv6 ("[::1]:8053") is
// handled correctly and yields the unbracketed host literal
// ("::1"). Bare hosts with no port are returned as-is.
func hostOnly(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

func parseAgentFile(path string, out *AgentValues, jose, cert, apiAddr *string) error {
	content, err := cfg.ReadFileIfExists(path)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	var y mpagentYAML
	if err := yaml.Unmarshal([]byte(content), &y); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out.Identity = y.MultiProvider.Identity
	out.ApiKey = y.APIServer.APIKey
	*jose = y.MultiProvider.LongTermJosePrivKey
	*cert = y.MultiProvider.API.CertFile
	if len(y.APIServer.Addresses) > 0 {
		*apiAddr = y.APIServer.Addresses[0]
	}
	return nil
}

func parseSignerFile(path string, out *SignerValues) error {
	content, err := cfg.ReadFileIfExists(path)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	var y mpsignerYAML
	if err := yaml.Unmarshal([]byte(content), &y); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out.Identity = y.MultiProvider.Identity
	out.ApiKey = y.APIServer.APIKey
	return nil
}

func parseCombinerFile(path string, out *CombinerValues) error {
	content, err := cfg.ReadFileIfExists(path)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	var y mpcombinerYAML
	if err := yaml.Unmarshal([]byte(content), &y); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out.Identity = y.MultiProvider.Identity
	out.ApiKey = y.APIServer.APIKey
	return nil
}
