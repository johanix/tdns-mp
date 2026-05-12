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
	Auditor  AuditorValues
}

// GlobalValues are cross-role settings prompted only once.
//
// PublicIP is the externally-reachable address the operator
// advertises for this provider. Used for cert SANs, mpcli base
// URLs, and zone notify/primary in the example template.
//
// InternalIP is what each role binds to and what the three roles
// dial each other on. On a single-host deployment this is
// 127.0.0.1. On a multi-host or NAT'd setup (e.g. AWS EC2 where
// PublicIP is not on any local interface) it must be a private
// IP that is actually on the host.
type GlobalValues struct {
	KeysDir    string
	CertsDir   string
	PublicIP   string
	InternalIP string
}

// AgentValues is the coordinated config for tdns-mpagent.
//
// LocalNameservers and LocalNotify configure the auto-created agent
// zone (e.g. agent.hare.mp.axfr.net.). LocalNameservers becomes the
// NS RDATA published in that zone. LocalNotify is the set of
// downstream secondaries that should receive NOTIFY when the agent
// zone changes. Both are optional — empty is fine and means the
// operator will fill them in later.
type AgentValues struct {
	Identity         string
	ApiKey           string
	LocalNameservers []string
	LocalNotify      []string
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

// AuditorValues is the coordinated config for tdns-mpauditor.
//
// The auditor is optional. When Identity is empty no auditor
// config is generated and no keys/certs are produced. Setting
// Identity (via the interactive y/N prompt) enables auditor
// generation alongside the three core roles.
type AuditorValues struct {
	Identity string
	ApiKey   string
}
