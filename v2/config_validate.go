/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP-specific config validators, moved from tdns/v2/config_validate.go.
 * Registered via PostValidateConfigHook from MainInit.
 */
package tdnsmp

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"

	tdns "github.com/johanix/tdns/v2"
)

// ValidateMPConfig runs all MP-specific config validators.
// Registered as PostValidateConfigHook from MainInit so these
// run during tdns's ValidateConfig alongside the built-in ones.
func ValidateMPConfig(conf *tdns.Config) error {
	if err := ValidateAgentNameservers(conf); err != nil {
		return err
	}
	if err := ValidateAgentSupportedMechanisms(conf); err != nil {
		return err
	}
	if err := ValidateCryptoFiles(conf); err != nil {
		return err
	}
	if err := ValidateMultiProviderBlock(conf); err != nil {
		return err
	}
	return nil
}

// ValidateAgentNameservers ensures agent.local.nameservers are
// non-empty and outside the agent autozone (no glue). Each entry
// is normalized to FQDN in place.
func ValidateAgentNameservers(conf *tdns.Config) error {
	if conf.MultiProvider == nil || conf.MultiProvider.Role != "agent" || len(conf.MultiProvider.Local.Nameservers) == 0 {
		return nil
	}
	zoneFqdn := dns.Fqdn(conf.MultiProvider.Identity)
	for i, ns := range conf.MultiProvider.Local.Nameservers {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		nsFqdn := dns.Fqdn(ns)
		if nsFqdn == "." {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		if dns.IsSubDomain(zoneFqdn, nsFqdn) {
			return fmt.Errorf("agent.local.nameservers: %q is inside the agent autozone %q (glue not supported)", nsFqdn, conf.MultiProvider.Identity)
		}
		conf.MultiProvider.Local.Nameservers[i] = nsFqdn
	}
	return nil
}

// ValidateAgentSupportedMechanisms validates
// agent.supported_mechanisms configuration.
func ValidateAgentSupportedMechanisms(conf *tdns.Config) error {
	if conf.MultiProvider == nil || conf.MultiProvider.Role != "agent" {
		return nil
	}

	mechanisms := conf.MultiProvider.SupportedMechanisms
	if len(mechanisms) == 0 {
		return fmt.Errorf("agent.supported_mechanisms cannot be empty - agent requires at least one transport mechanism (valid: \"api\", \"dns\")")
	}

	validMechanisms := map[string]bool{"api": true, "dns": true}
	seen := make(map[string]bool)

	for i, m := range mechanisms {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" {
			return fmt.Errorf("agent.supported_mechanisms: empty entry at index %d", i)
		}
		if !validMechanisms[m] {
			return fmt.Errorf("agent.supported_mechanisms: invalid value %q at index %d (valid: \"api\", \"dns\")", mechanisms[i], i)
		}
		if seen[m] {
			return fmt.Errorf("agent.supported_mechanisms: duplicate value %q", m)
		}
		seen[m] = true
		conf.MultiProvider.SupportedMechanisms[i] = m
	}

	return nil
}

// ValidateCryptoFiles validates that configured crypto key files
// exist and are readable.
func ValidateCryptoFiles(conf *tdns.Config) error {
	if conf.MultiProvider != nil && conf.MultiProvider.Role == "agent" && strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey) != "" {
		if err := validateFileExists(conf.MultiProvider.LongTermJosePrivKey, "agent private key"); err != nil {
			return err
		}
		if conf.MultiProvider.Combiner != nil && strings.TrimSpace(conf.MultiProvider.Combiner.LongTermJosePubKey) != "" {
			if err := validateFileExists(conf.MultiProvider.Combiner.LongTermJosePubKey, "combiner public key (multi-provider.combiner)"); err != nil {
				return err
			}
		}
		if conf.MultiProvider.Peers != nil {
			for peerID, peerConf := range conf.MultiProvider.Peers {
				if strings.TrimSpace(peerConf.LongTermJosePubKey) != "" {
					if err := validateFileExists(peerConf.LongTermJosePubKey, fmt.Sprintf("peer agent %s public key", peerID)); err != nil {
						return err
					}
				}
			}
		}
	}

	if conf.MultiProvider != nil && conf.MultiProvider.Role == "combiner" && strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey) != "" {
		if err := validateFileExists(conf.MultiProvider.LongTermJosePrivKey, "combiner private key"); err != nil {
			return err
		}
		for _, agent := range conf.MultiProvider.Agents {
			if strings.TrimSpace(agent.LongTermJosePubKey) != "" {
				label := fmt.Sprintf("agent public key (multi-provider.agents[%s])", agent.Identity)
				if err := validateFileExists(agent.LongTermJosePubKey, label); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// ValidateMultiProviderBlock validates essential fields in the
// multi-provider: config block. At minimum, role and identity
// must be present when the block is active.
func ValidateMultiProviderBlock(conf *tdns.Config) error {
	mp := conf.MultiProvider
	if mp == nil {
		return nil
	}
	if !mp.Active {
		return nil
	}
	if mp.Role == "" {
		return fmt.Errorf("multi-provider.role is required when multi-provider is active")
	}
	validRoles := map[string]bool{"agent": true, "signer": true, "combiner": true}
	if !validRoles[mp.Role] {
		return fmt.Errorf("multi-provider.role: invalid value %q (valid: agent, signer, combiner)", mp.Role)
	}
	if mp.Identity == "" {
		return fmt.Errorf("multi-provider.identity is required when multi-provider is active")
	}
	return nil
}

func validateFileExists(path, description string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%s path is empty", description)
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s file does not exist: %q", description, path)
		}
		return fmt.Errorf("cannot access %s file %q: %w", description, path, err)
	}
	return nil
}
