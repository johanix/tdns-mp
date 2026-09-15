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
 * Directories for keys/certs and the public and internal IPs are
 * back-derived from the agent's existing paths/addresses if present.
 */
package configure

import (
	"fmt"
	"net"
	"path/filepath"

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
		Dns struct {
			Addresses struct {
				Publish []string `yaml:"publish"`
			} `yaml:"addresses"`
		} `yaml:"dns"`
		Local struct {
			Nameservers []string `yaml:"nameservers"`
			Notify      []string `yaml:"notify"`
		} `yaml:"local"`
	} `yaml:"multi-provider"`
	APIServer struct {
		Addresses []string `yaml:"addresses"`
		APIKey    string   `yaml:"apikey"`
		CertFile  string   `yaml:"certfile"`
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

type mpauditorYAML struct {
	MultiProvider struct {
		Identity            string `yaml:"identity"`
		LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	} `yaml:"multi-provider"`
	APIServer struct {
		Addresses []string `yaml:"addresses"`
		APIKey    string   `yaml:"apikey"`
	} `yaml:"apiserver"`
}

// agentSeeds are the global values back-derived from the agent config.
type agentSeeds struct {
	josePriv string
	certFile string
	apiAddr  string
	publicIP string
}

// readExistingCoordinated populates CoordinatedValues from any
// existing YAML files on disk. Missing files contribute zero
// values. Returns an error only for I/O problems or malformed
// YAML — not for missing files.
func readExistingCoordinated() (CoordinatedValues, error) {
	var cv CoordinatedValues

	var seeds agentSeeds
	if err := parseAgentFile(pathMpagent, &cv.Agent, &seeds); err != nil {
		return cv, err
	}
	if err := parseSignerFile(pathMpsigner, &cv.Signer); err != nil {
		return cv, err
	}
	if err := parseCombinerFile(pathMpcombiner, &cv.Combiner); err != nil {
		return cv, err
	}
	if err := parseAuditorFile(pathMpauditor, &cv.Auditor); err != nil {
		return cv, err
	}

	if seeds.josePriv != "" {
		cv.Global.KeysDir = filepath.Dir(seeds.josePriv)
	}
	if seeds.certFile != "" {
		cv.Global.CertsDir = filepath.Dir(seeds.certFile)
	}
	if seeds.apiAddr != "" {
		// The agent's apiserver address is a bind target → InternalIP.
		cv.Global.InternalIP = hostOnly(seeds.apiAddr)
	}
	if net.ParseIP(seeds.publicIP) != nil {
		// The address the agent publishes to peers → PublicIP.
		cv.Global.PublicIP = seeds.publicIP
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

func parseAgentFile(path string, out *AgentValues, seeds *agentSeeds) error {
	content, err := ReadFileIfExists(path)
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
	out.LocalNameservers = y.MultiProvider.Local.Nameservers
	out.LocalNotify = y.MultiProvider.Local.Notify
	seeds.josePriv = y.MultiProvider.LongTermJosePrivKey
	seeds.certFile = y.APIServer.CertFile
	if seeds.certFile == "" {
		seeds.certFile = y.MultiProvider.API.CertFile
	}
	if len(y.APIServer.Addresses) > 0 {
		seeds.apiAddr = y.APIServer.Addresses[0]
	}
	if len(y.MultiProvider.Dns.Addresses.Publish) > 0 {
		seeds.publicIP = y.MultiProvider.Dns.Addresses.Publish[0]
	}
	return nil
}

func parseSignerFile(path string, out *SignerValues) error {
	content, err := ReadFileIfExists(path)
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
	content, err := ReadFileIfExists(path)
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

func parseAuditorFile(path string, out *AuditorValues) error {
	content, err := ReadFileIfExists(path)
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}
	var y mpauditorYAML
	if err := yaml.Unmarshal([]byte(content), &y); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	out.Identity = y.MultiProvider.Identity
	out.ApiKey = y.APIServer.APIKey
	return nil
}
