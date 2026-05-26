/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Shadow parser for the multi-provider: config block.
 *
 * The long-term goal is to move MultiProviderConf out of tdns/v2 and
 * into tdns-mp/v2. As a first verification step, this file re-parses
 * the same configMap that tdns.ParseConfig just decoded, runs the
 * same FQDN normalization + option-string parsing, and deep-compares
 * against tdns's parsed copy. Any divergence is logged but does not
 * fail startup.
 *
 * Once the shadow has been observed identical across operator configs,
 * the next step is to flip runtime accessors from conf.Config.MultiProvider
 * to the shadow, then delete the originals from tdns.
 *
 * This file owns nothing the rest of tdns-mp reads. It only writes
 * conf.InternalMp.MpConfigShadow for verification purposes.
 */
package tdnsmp

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"github.com/mitchellh/mapstructure"

	tdns "github.com/johanix/tdns/v2"
)

// RegisterShadowMpConfigParser installs the PostParseConfigHook that
// runs the shadow parser. Call from tdnsmp.MainInit before delegating
// to tdns.MainInit.
//
// The hook runs *during* tdns.ParseConfig, which is before
// SetupLogging wires the file handler — any lg.Info/Warn issued from
// the hook would be lost (NetBSD daemons typically discard stderr at
// this stage). So the hook only parses and stashes the result on
// conf; the actual comparison + log line is emitted later by
// EmitShadowMpComparison, called from MainInit after SetupLogging.
func (conf *Config) RegisterShadowMpConfigParser() {
	conf.Config.Internal.PostParseConfigHook = func(c *tdns.Config, configMap map[string]interface{}) error {
		shadow, err := parseShadowMultiProvider(configMap)
		if err != nil {
			conf.InternalMp.MpConfigShadowErr = err
			return nil
		}
		conf.InternalMp.MpConfigShadow = shadow
		return nil
	}
}

// EmitShadowMpComparison emits the result of the shadow MP-config
// parse. Call after tdns.MainInit returns — at that point SetupLogging
// has wired the file handler so the log lines actually land in the
// daemon's logfile.
func (conf *Config) EmitShadowMpComparison() {
	if err := conf.InternalMp.MpConfigShadowErr; err != nil {
		lg.Warn("shadow MP parser: parse error, skipping comparison", "err", err)
		return
	}
	compareShadowMultiProvider(conf.InternalMp.MpConfigShadow, conf.Config.MultiProvider)
}

// parseShadowMultiProvider decodes the multi-provider: subtree of the
// configMap into a fresh MultiProviderConf, runs the same FQDN
// normalization and option-string parsing that tdns currently does
// inline. Returns nil if no multi-provider: section is present.
func parseShadowMultiProvider(configMap map[string]interface{}) (*tdns.MultiProviderConf, error) {
	raw, ok := configMap["multi-provider"]
	if !ok || raw == nil {
		return nil, nil
	}

	var mp tdns.MultiProviderConf
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

	normalizeShadowMultiProviderIdentities(&mp)
	parseShadowMultiProviderOptions(&mp)
	return &mp, nil
}

// normalizeShadowMultiProviderIdentities mirrors the MP-related branch
// of tdns/v2/parseconfig.go normalizeConfigIdentities().
func normalizeShadowMultiProviderIdentities(mp *tdns.MultiProviderConf) {
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
			mp.ProtectedNamespaces[i] = dns.Fqdn(ns)
		}
	}
}

// parseShadowMultiProviderOptions mirrors tdns's parseMultiProviderOptions.
func parseShadowMultiProviderOptions(mp *tdns.MultiProviderConf) {
	mp.CombinerOptions = map[tdns.CombinerOption]bool{}
	for _, raw := range mp.CombinerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if co, ok := tdns.StringToCombinerOption[opt]; ok {
			mp.CombinerOptions[co] = true
		}
		// unknown options: tdns logs a warning; shadow stays silent
		// since tdns has already reported them.
	}
	if mp.AddSignature && !mp.CombinerOptions[tdns.CombinerOptAddSignature] {
		mp.CombinerOptions[tdns.CombinerOptAddSignature] = true
	}

	mp.SignerOptions = map[tdns.SignerOption]bool{}
	for _, raw := range mp.SignerOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if so, ok := tdns.StringToSignerOption[opt]; ok {
			mp.SignerOptions[so] = true
		}
	}

	mp.AgentOptions = map[tdns.AgentOption]bool{}
	for _, raw := range mp.AgentOptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(raw))
		if opt == "" {
			continue
		}
		if ao, ok := tdns.StringToAgentOption[opt]; ok {
			mp.AgentOptions[ao] = true
		}
	}
}

// compareShadowMultiProvider deep-compares the shadow against the
// tdns-parsed reference. Logs identical or detailed diff. Never errors.
func compareShadowMultiProvider(shadow, ref *tdns.MultiProviderConf) {
	if shadow == nil && ref == nil {
		lg.Info("shadow MP parser: both nil (no multi-provider: section)")
		return
	}
	if shadow == nil || ref == nil {
		lg.Warn("shadow MP parser: one side nil",
			"shadow_nil", shadow == nil,
			"ref_nil", ref == nil)
		return
	}
	if reflect.DeepEqual(shadow, ref) {
		lg.Info("shadow MP parser: identical to tdns-side parse")
		return
	}
	diff := cmp.Diff(ref, shadow)
	lg.Warn("shadow MP parser: differs from tdns-side parse",
		"diff", diff)
}
