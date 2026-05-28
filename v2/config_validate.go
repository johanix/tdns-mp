/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * MP-specific config validators. Operate on the tdnsmp-local
 * MultiProviderConf and are invoked from RegisterMpConfigParser's
 * PostParseConfigHook right after parseMultiProvider succeeds.
 *
 * Previously these took *tdns.Config and ran from
 * conf.Config.Internal.PostValidateConfigHook (which fires during
 * tdns.ValidateConfig, BEFORE the MP-config parser hook). That
 * relied on tdns also parsing multi-provider: itself, which goes
 * away in bite 9b. Now they validate the tdns-mp parse directly.
 */
package tdnsmp

import (
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// ValidateMPConfig runs all MP-specific config validators against
// the supplied MultiProviderConf. Called from RegisterMpConfigParser's
// hook after parseMultiProvider returns a non-nil mp. Returns nil
// when mp is nil (no multi-provider: block) so non-MP daemons
// proceed unchanged.
func ValidateMPConfig(mp *MultiProviderConf) error {
	if mp == nil {
		return nil
	}
	if err := ValidateAgentNameservers(mp); err != nil {
		return err
	}
	if err := ValidateAgentSupportedMechanisms(mp); err != nil {
		return err
	}
	if err := ValidateCryptoFiles(mp); err != nil {
		return err
	}
	if err := ValidateMultiProviderBlock(mp); err != nil {
		return err
	}
	return nil
}

// ValidateAgentNameservers ensures agent.local.nameservers are
// non-empty and outside the agent autozone (no glue). Each entry
// is normalized to FQDN in place.
func ValidateAgentNameservers(mp *MultiProviderConf) error {
	if mp.Role != "agent" || len(mp.Local.Nameservers) == 0 {
		return nil
	}
	zoneFqdn := dns.Fqdn(mp.Identity)
	for i, ns := range mp.Local.Nameservers {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		nsFqdn := dns.Fqdn(ns)
		if nsFqdn == "." {
			return fmt.Errorf("agent.local.nameservers: empty entry")
		}
		if dns.IsSubDomain(zoneFqdn, nsFqdn) {
			return fmt.Errorf("agent.local.nameservers: %q is inside the agent autozone %q (glue not supported)", nsFqdn, mp.Identity)
		}
		mp.Local.Nameservers[i] = nsFqdn
	}
	return nil
}

// ValidateAgentSupportedMechanisms validates
// agent.supported_mechanisms configuration.
func ValidateAgentSupportedMechanisms(mp *MultiProviderConf) error {
	if mp.Role != "agent" {
		return nil
	}

	mechanisms := mp.SupportedMechanisms
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
		mp.SupportedMechanisms[i] = m
	}

	return nil
}

// ValidateCryptoFiles validates that configured crypto key files
// exist and are readable.
func ValidateCryptoFiles(mp *MultiProviderConf) error {
	if mp.Role == "agent" && strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		if err := validateFileExists(mp.LongTermJosePrivKey, "agent private key"); err != nil {
			return err
		}
		if mp.Combiner != nil && strings.TrimSpace(mp.Combiner.LongTermJosePubKey) != "" {
			if err := validateFileExists(mp.Combiner.LongTermJosePubKey, "combiner public key (multi-provider.combiner)"); err != nil {
				return err
			}
		}
		if mp.Peers != nil {
			for peerID, peerConf := range mp.Peers {
				if strings.TrimSpace(peerConf.LongTermJosePubKey) != "" {
					if err := validateFileExists(peerConf.LongTermJosePubKey, fmt.Sprintf("peer agent %s public key", peerID)); err != nil {
						return err
					}
				}
			}
		}
	}

	if mp.Role == "combiner" && strings.TrimSpace(mp.LongTermJosePrivKey) != "" {
		if err := validateFileExists(mp.LongTermJosePrivKey, "combiner private key"); err != nil {
			return err
		}
		for _, agent := range mp.Agents {
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
func ValidateMultiProviderBlock(mp *MultiProviderConf) error {
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
