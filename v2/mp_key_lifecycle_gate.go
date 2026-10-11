/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The rollout gate of key lifecycle ownership (design S4a): a signer runs
 * only when every multi-provider zone it signs is in key-lifecycle-zones,
 * the list of zones tdns-mp's own key machine takes. tdns-mp registers no
 * key lifecycle hook with tdns any more, so a multi-provider zone left off
 * the list would get tdns's single-signer key machine, which knows nothing
 * of the peers. The per-zone list stays: ownership is rolled out zone by
 * zone, not switched on by default.
 */
package tdnsmp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// unlistedMultiProviderZones is the set difference the gate is about: the
// multi-provider zones in served that listed does not name, sorted. Names
// are compared as FQDNs, case-insensitively, as the keystore keys them.
func unlistedMultiProviderZones(served, listed []string) []string {
	have := map[string]bool{}
	for _, z := range listed {
		have[strings.ToLower(dns.Fqdn(z))] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, z := range served {
		name := strings.ToLower(dns.Fqdn(z))
		if have[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// signedMultiProviderZones is the set the gate is over: the multi-provider
// zones this signer signs, the ones whose zone config binds a DNSSEC
// policy. A multi-provider zone the signer only serves, as a non-signing
// provider does (the signed zone comes from another provider's signer),
// has no keys here and no key lifecycle for anyone to own. Multi-provider
// is what ParseZones collected (InternalMp.MPZoneNames: the zones whose
// option was accepted); the policy is the zone config's, bound or not yet
// (a secondary binds it after its first transfer, which is later than the
// signer's start).
func (conf *Config) signedMultiProviderZones() []string {
	mp := map[string]bool{}
	for _, z := range conf.InternalMp.MPZoneNames {
		mp[strings.ToLower(dns.Fqdn(z))] = true
	}
	if len(mp) == 0 || conf.Config == nil {
		return nil
	}
	var out []string
	for _, zc := range conf.Config.Zones {
		name := strings.ToLower(dns.Fqdn(zc.Name))
		if mp[name] && zc.DnssecPolicy != "" {
			out = append(out, name)
		}
	}
	return out
}

// keyLifecycleRolloutGate is the signer's start-time check that every
// multi-provider zone it signs is named in key-lifecycle-zones
// (signedMultiProviderZones), so the gate runs after tdns's MainInit. A
// zone left off the list is a configuration error and the signer refuses
// to start; with key-lifecycle-zones-incomplete the zones are named in a
// warning instead and the signer starts, for the rollout period. Nothing
// to say for a signer that signs no multi-provider zone.
func (conf *Config) keyLifecycleRolloutGate() error {
	served := conf.signedMultiProviderZones()
	if len(served) == 0 {
		return nil
	}
	var listed []string
	incomplete := false
	if mp := conf.MpConfig(); mp != nil {
		listed = mp.KeyLifecycleZones
		incomplete = mp.KeyLifecycleZonesIncomplete
	}
	missing := unlistedMultiProviderZones(served, listed)
	if len(missing) == 0 {
		return nil
	}
	if incomplete {
		lgSigner.Warn("key lifecycle: multi-provider zones this signer signs but key-lifecycle-zones does not name get tdns's single-signer key machine; the signer starts because key-lifecycle-zones-incomplete is set",
			"zones", missing, "count", len(missing))
		return nil
	}
	lgSigner.Error("key lifecycle: every multi-provider zone the signer signs must be in key-lifecycle-zones; the signer refuses to start (set key-lifecycle-zones-incomplete during a rollout)",
		"zones", missing, "count", len(missing))
	return fmt.Errorf("key lifecycle: %d multi-provider zone(s) not in key-lifecycle-zones: %s", len(missing), strings.Join(missing, ", "))
}
