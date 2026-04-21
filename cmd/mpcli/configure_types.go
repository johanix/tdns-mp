/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: coordinated-values types.
 *
 * CoordinatedValues is the minimal set of configuration knobs
 * that must stay consistent across mpagent, mpsigner, mpcombiner
 * and mpcli. Each role's full config is a static template plus
 * substitutions drawn from this struct.
 *
 * Unknown keys in the existing YAML files are ignored on parse;
 * we only care about the coordinated subset. Template emission
 * regenerates the full file from a baked-in template.
 */
package main

// CoordinatedValues holds everything the configurator interviews
// the user for. The goal is the smallest prompt set that gets a
// new user up and running — non-prompted fields are baked into
// the templates as literal defaults.
//
// Global.KeysDir and CertsDir are single directories used for
// all three roles. Per-role filenames are derived:
//
//   {KeysDir}/{role}.jose.priv.json
//   {KeysDir}/{role}.jose.pub.json
//   {CertsDir}/{role}.crt
//   {CertsDir}/{role}.key
//
// If a user wants to reorganise later, they can edit the
// generated YAMLs by hand. The configurator does not try to
// be a general-purpose config editor.
type CoordinatedValues struct {
	Global   GlobalValues
	Agent    AgentValues
	Signer   SignerValues
	Combiner CombinerValues
}

// GlobalValues are cross-role settings prompted only once.
//
// PublicIP is the address all three roles bind their DNS engine
// and management API on (same-box deployment). It is also used
// as the peer address in zone notify/primary and in the mpcli
// baseurls.
type GlobalValues struct {
	KeysDir  string // /etc/tdns/keys
	CertsDir string // /etc/tdns/certs
	PublicIP string // e.g. 192.0.2.10 or 127.0.0.1 for local test
}

// AgentValues is the coordinated config for tdns-mpagent.
// Listen addresses are derived from PublicIP + built-in ports at
// render time — not stored here.
type AgentValues struct {
	Identity string // FQDN with trailing dot, canonicalised via dns.Fqdn
	ApiKey   string
}

// SignerValues is the coordinated config for tdns-mpsigner.
type SignerValues struct {
	Identity string
	ApiKey   string
}

// CombinerValues is the coordinated config for tdns-mpcombiner.
type CombinerValues struct {
	Identity string
	ApiKey   string
}
