/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp's parser for the multi-provider: config block.
 *
 * Registered as a PostParseConfigHook on the underlying tdns.Config
 * so it runs during tdns.ParseConfig. The result is stashed on
 * conf.SetMpConfig (read back via conf.MpConfig()) and is the runtime source of truth for
 * MP config in tdns-mp (via conf.MpConfig() / WiredMpConfig()).
 *
 * Decodes into tdnsmp.MultiProviderConf (defined in
 * multi_provider_conf.go). The tdns side still has a parallel
 * MultiProviderConf type and parse until Bite 9b of the cutover
 * removes them.
 *
 * Historical context: this file started life as a "shadow" parser
 * that ran alongside tdns's own MP parse for verification. Bites
 * 2-7 of the MP config cutover migrated runtime accessors over to
 * read this parse; bite 8 deleted the verification machinery and
 * dropped the "shadow" naming; bite 9a moved the type definitions
 * into tdns-mp so the parser no longer borrows the tdns type.
 */
package tdnsmp

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"

	tdns "github.com/johanix/tdns/v2"
)

// RegisterMpConfigParser installs the PostParseConfigHook that
// parses the multi-provider: block and installs the result with
// conf.SetMpConfig. Call from tdnsmp.MainInit before
// delegating to tdns.MainInit so the hook is in place when
// tdns.ParseConfig runs.
//
// SetMpConfig also assigns the wiredMpConfig package-level mirror so
// EnsureMP and external WiredMpConfig() callers can read the parse
// without a *tdnsmp.Config in hand.
//
// With SetupLogging now running before ParseConfig, the hook can
// return parse errors directly — they propagate up through
// tdns.ParseConfig and land in the logfile.
func (conf *Config) RegisterMpConfigParser() {
	conf.Config.Internal.PostParseConfigHook = func(c *tdns.Config, configMap map[string]interface{}) error {
		mp, err := parseMultiProvider(configMap)
		if err != nil {
			return fmt.Errorf("multi-provider config parse: %w", err)
		}
		conf.SetMpConfig(mp)
		return nil
	}
}

// parseMultiProvider decodes the multi-provider: subtree of the
// configMap into a fresh MultiProviderConf, runs FQDN normalization
// and option-string parsing. Returns nil, nil if no multi-provider:
// section is present (legitimate for non-MP daemons, though tdns-mp
// daemons normally require one).
func parseMultiProvider(configMap map[string]interface{}) (*MultiProviderConf, error) {
	raw, ok := configMap["multi-provider"]
	if !ok || raw == nil {
		return nil, nil
	}

	var mp MultiProviderConf
	decoderConfig := &mapstructure.DecoderConfig{
		TagName: "yaml",
		Result:  &mp,
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, fmt.Errorf("decoder: %w", err)
	}
	if err := decoder.Decode(raw); err != nil {
		return nil, fmt.Errorf("decode multi-provider: %w", err)
	}

	normalizeMultiProviderIdentities(&mp)
	parseMultiProviderOptions(&mp)
	return &mp, nil
}

// normalizeMultiProviderIdentities FQDN-normalizes every identity
// field in the multi-provider block.
func normalizeMultiProviderIdentities(mp *MultiProviderConf) {
	if mp.Identity != "" {
		mp.Identity = dns.Fqdn(mp.Identity)
	}
	if mp.Dns.ControlZone != "" {
		mp.Dns.ControlZone = dns.Fqdn(mp.Dns.ControlZone)
	}
	if mp.Combiner != nil && mp.Combiner.Identity != "" {
		mp.Combiner.Identity = dns.Fqdn(mp.Combiner.Identity)
	}
	if mp.Signer != nil && mp.Signer.Identity != "" {
		mp.Signer.Identity = dns.Fqdn(mp.Signer.Identity)
	}
	for i, p := range mp.AuthorizedPeers {
		if strings.TrimSpace(p) == "" {
			continue
		}
		mp.AuthorizedPeers[i] = dns.Fqdn(p)
	}
	for _, peer := range mp.Peers {
		if peer != nil && peer.Identity != "" {
			peer.Identity = dns.Fqdn(peer.Identity)
		}
	}
	for _, agent := range mp.Agents {
		if agent != nil && agent.Identity != "" {
			agent.Identity = dns.Fqdn(agent.Identity)
		}
	}
	if mp.Role == "combiner" {
		for i, ns := range mp.ProtectedNamespaces {
			if strings.TrimSpace(ns) == "" {
				continue
			}
			mp.ProtectedNamespaces[i] = dns.Fqdn(ns)
		}
	}
}

// parseMultiProviderOptions decodes the string-list option fields
// (combiner_options, signer_options, agent_options) into typed
// option-set maps on the MultiProviderConf.
func parseMultiProviderOptions(mp *MultiProviderConf) {
	mp.CombinerOptions = map[CombinerOption]bool{}
	for _, raw := range mp.CombinerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if co, ok := StringToCombinerOption[opt]; ok {
			mp.CombinerOptions[co] = true
		}
	}
	if mp.AddSignature && !mp.CombinerOptions[CombinerOptAddSignature] {
		mp.CombinerOptions[CombinerOptAddSignature] = true
	}

	mp.SignerOptions = map[SignerOption]bool{}
	for _, raw := range mp.SignerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if so, ok := StringToSignerOption[opt]; ok {
			mp.SignerOptions[so] = true
		}
	}

	mp.AgentOptions = map[AgentOption]bool{}
	for _, raw := range mp.AgentOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if ao, ok := StringToAgentOption[opt]; ok {
			mp.AgentOptions[ao] = true
		}
	}
}
