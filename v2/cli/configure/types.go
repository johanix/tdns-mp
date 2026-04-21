/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: coordinated-values types.
 *
 * See docs/2026-04-21-mpcli-configure-plan.md for context.
 *
 * Keys/certs directories are single locations used for all three
 * roles. Per-role filenames are derived deterministically:
 *
 *   {KeysDir}/{role}.jose.priv.json
 *   {KeysDir}/{role}.jose.pub.json
 *   {CertsDir}/{role}.crt
 *   {CertsDir}/{role}.key
 */
package configure

// CoordinatedValues holds everything the configurator interviews
// the user for.
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
	KeysDir  string
	CertsDir string
	PublicIP string
}

// AgentValues is the coordinated config for tdns-mpagent.
type AgentValues struct {
	Identity string
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
