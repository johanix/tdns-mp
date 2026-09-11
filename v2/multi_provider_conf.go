/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Multi-provider configuration types.
 *
 * Owned by tdns-mp since Bite 9a of the MP config cutover (the
 * struct moved here from tdns/v2). Bite 9b completed the migration
 * by deleting the parallel definition + parse from tdns. Runtime
 * source of truth: the parse RegisterMpConfigParser's
 * PostParseConfigHook (on conf.Config, the underlying *tdns.Config)
 * installs with conf.SetMpConfig. Accessors: conf.MpConfig() and
 * WiredMpConfig().
 */
package tdnsmp

// MultiProviderConf holds config for multi-provider DNSSEC (RFC 8901).
// Used by all three MP roles: agent, combiner, and signer.
// The Role field determines which role-specific fields are relevant.
// YAML key: "multi-provider:"
type MultiProviderConf struct {
	// === Shared fields (all roles) ===

	// Role: "agent", "combiner", or "signer". Determines which fields are active.
	Role string `yaml:"role"`
	// Active: master switch for multi-provider mode.
	// Must be true AND zone must have options: [multi-provider] for MP behavior.
	Active bool `yaml:"active"`
	// Identity: this node's identity (FQDN) for transport protocol.
	Identity string `yaml:"identity"`
	// LongTermJosePrivKey: path to JOSE private key for secure CHUNK.
	LongTermJosePrivKey string `yaml:"long_term_jose_priv_key"`
	// ChunkMode: "edns0" | "query" for outbound NOTIFY(CHUNK).
	ChunkMode string `yaml:"chunk_mode" mapstructure:"chunk_mode"`
	// ChunkMaxSize: maximum size (bytes) of each data chunk when fragmenting payloads.
	// 0 = default (60000). Useful for testing fragmentation with small values.
	ChunkMaxSize int `yaml:"chunk_max_size" mapstructure:"chunk_max_size"`
	// Agents: the agent peers (address, JOSE public key, optional API URL).
	// Used by signer and combiner roles.
	Agents []*PeerConf `yaml:"agents"`
	// SyncApi: sync API server config for inbound HELLO/BEAT/PING over HTTPS.
	// Used by signer and combiner roles.
	SyncApi struct {
		Addresses struct {
			Listen []string
		}
		CertFile string `yaml:"certfile" mapstructure:"certfile"`
		KeyFile  string `yaml:"keyfile" mapstructure:"keyfile"`
	} `yaml:"syncapi" mapstructure:"syncapi"`

	// === Combiner-specific fields ===

	// CombinerOptions: list of combiner-specific option strings parsed at startup.
	// Known options: "add-signature".
	CombinerOptionsStrs []string                `yaml:"combiner-options" mapstructure:"combiner-options"`
	CombinerOptions     map[CombinerOption]bool `yaml:"-" mapstructure:"-"`

	// ChunkQueryEndpoint: "include" | "none"; required when chunk_mode=query (combiner role).
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"`
	// Signature: template string for a TXT record injected into combined zones (demo feature).
	// Supports {identity} and {zone} placeholders.
	Signature    string `yaml:"signature"`
	AddSignature bool   `yaml:"add-signature" mapstructure:"add-signature"` // DEPRECATED: use combiner-options: [add-signature]
	// ProtectedNamespaces: list of domain suffixes that belong to this provider.
	// NS records from remote agents whose targets fall within any of these namespaces
	// are rejected (prevents namespace intrusion).
	ProtectedNamespaces []string `yaml:"protected-namespaces" mapstructure:"protected-namespaces"`
	// ProviderZones: zones owned by the provider where agents may make targeted edits
	// (e.g. _signal KEY records). Unlike MP zones, these use config-driven RRtype
	// restrictions and allow non-apex owners.
	ProviderZones []ProviderZoneConf `yaml:"provider-zones" mapstructure:"provider-zones"`

	// === Signer-specific fields ===

	// SignerOptions: list of signer-specific option strings parsed at startup.
	SignerOptionsStrs []string              `yaml:"signer-options" mapstructure:"signer-options"`
	SignerOptions     map[SignerOption]bool `yaml:"-" mapstructure:"-"`

	// === Agent-specific fields ===

	// AgentOptions: list of agent-specific option strings parsed at startup.
	AgentOptionsStrs []string             `yaml:"agent-options" mapstructure:"agent-options"`
	AgentOptions     map[AgentOption]bool `yaml:"-" mapstructure:"-"`
	// SupportedMechanisms: List of active transport mechanisms (default: ["api", "dns"] if both configured)
	SupportedMechanisms []string `yaml:"supported_mechanisms" mapstructure:"supported_mechanisms"`
	Local               struct {
		Notify      []string
		Nameservers []string `yaml:"nameservers,omitempty"`
	}
	Remote struct {
		LocateInterval int
		BeatInterval   uint32
	}
	// Syncengine.Intervals: the hsync engine's protocol timers, in seconds
	// (YAML: multi-provider.syncengine.intervals). Zero or absent means the
	// engine's built-in default (hsync.DefaultConfig); hsyncConfigFromMp
	// turns the block into the engine's hsync.Config. beatinterval is
	// reconciled with the older remote.beatinterval by the config parser
	// (normalizeSyncengineIntervals) so that every reader of the beat
	// interval sees one value.
	Syncengine struct {
		Intervals struct {
			BeatInterval      int `yaml:"beatinterval" mapstructure:"beatinterval"`
			HelloRetry        int `yaml:"helloretry" mapstructure:"helloretry"`
			DiscoveryRetry    int `yaml:"discoveryretry" mapstructure:"discoveryretry"`
			Reconcile         int `yaml:"reconcile" mapstructure:"reconcile"`
			HelloFastAttempts int `yaml:"hello_fast_attempts" mapstructure:"hello_fast_attempts"`
			HelloFastInterval int `yaml:"hello_fast_interval" mapstructure:"hello_fast_interval"`
		} `yaml:"intervals" mapstructure:"intervals"`
	} `yaml:"syncengine" mapstructure:"syncengine"`
	Api LocalAgentApiConf
	Dns LocalAgentDnsConf
	// Combiner peer (agent only): address and combiner's JOSE public key path for secure CHUNK
	Combiner *PeerConf `yaml:"combiner"`
	// Signer peer (agent only): address and JOSE public key path for KEYSTATE signaling
	Signer *PeerConf `yaml:"signer"`
	// AuthorizedPeers: List of agent identities authorized to communicate
	AuthorizedPeers []string `yaml:"authorized_peers"`
	// Peers (DEPRECATED): Old format with embedded addresses/keys - use authorized_peers instead
	Peers map[string]*PeerConf `yaml:"peers"`
	Xfr   struct {
		Outgoing struct {
			Addresses []string `yaml:"addresses,omitempty"`
			Auth      []string `yaml:"auth,omitempty"`
		}
		Incoming struct {
			Addresses []string `yaml:"addresses,omitempty"`
			Auth      []string `yaml:"auth,omitempty"`
		}
	}
}

// FindAgent returns the PeerConf for the agent with the given identity, or nil if not found.
func (c *MultiProviderConf) FindAgent(identity string) *PeerConf {
	for _, a := range c.Agents {
		if a.Identity == identity {
			return a
		}
	}
	return nil
}

// PeerConf describes a peer (agent or combiner/signer counterpart):
// its identity, transport addresses, and JOSE public key path.
type PeerConf struct {
	Address            string `yaml:"address"`
	LongTermJosePubKey string `yaml:"long_term_jose_pub_key"`
	ApiBaseUrl         string `yaml:"api_base_url,omitempty"` // Optional: for API transport (e.g. https://combiner:8085/api/v1)
	Identity           string `yaml:"identity"`               // Peer identity (FQDN); required for combiner agents, optional for agent combiner
}

// ProviderZoneConf describes a provider-owned zone where targeted
// edits from agents are permitted (e.g. _signal KEY records).
type ProviderZoneConf struct {
	Zone           string   `yaml:"zone"`
	AllowedRRtypes []string `yaml:"allowed-rrtypes" mapstructure:"allowed-rrtypes"`
}

// LocalAgentApiConf is the agent role's HTTPS API server config.
//
// YAML keys use the no-underscore lowercase form (baseurl, certfile,
// keyfile) to match the operator's existing config files. CertData /
// KeyData are runtime-only — populated by agent_setup.go from
// CertFile / KeyFile contents and not read from YAML.
type LocalAgentApiConf struct {
	Addresses struct {
		Publish []string `yaml:"publish" mapstructure:"publish"`
		Listen  []string `yaml:"listen"  mapstructure:"listen"`
	} `yaml:"addresses" mapstructure:"addresses"`
	BaseUrl  string `yaml:"baseurl"  mapstructure:"baseurl"`
	Port     uint16 `yaml:"port"     mapstructure:"port"`
	CertFile string `yaml:"certfile" mapstructure:"certfile"`
	KeyFile  string `yaml:"keyfile"  mapstructure:"keyfile"`
	CertData string `yaml:"-"        mapstructure:"-"`
	KeyData  string `yaml:"-"        mapstructure:"-"`
}

// LocalAgentDnsConf is the agent role's DNS transport config
// (NOTIFY(CHUNK) listener + outbound transport tuning).
//
// YAML keys use the no-underscore lowercase form for BaseUrl / Port
// to match the operator's existing config files. The other fields
// (ControlZone, ChunkMode, etc.) use snake_case as established
// elsewhere in this struct.
type LocalAgentDnsConf struct {
	Addresses struct {
		Publish []string `yaml:"publish" mapstructure:"publish"`
		Listen  []string `yaml:"listen"  mapstructure:"listen"`
	} `yaml:"addresses" mapstructure:"addresses"`
	BaseUrl     string `yaml:"baseurl" mapstructure:"baseurl"`
	Port        uint16 `yaml:"port"    mapstructure:"port"`
	ControlZone string `yaml:"control_zone" mapstructure:"control_zone"` // Zone used for NOTIFY(CHUNK) QNAMEs in DNS mode (default: agent identity)
	// Chunk config (same key names as combiner for consistency)
	ChunkMode          string `yaml:"chunk_mode" mapstructure:"chunk_mode"`                     // "edns0" | "query"; query = store payload, receiver fetches via CHUNK query (default: edns0)
	ChunkQueryEndpoint string `yaml:"chunk_query_endpoint" mapstructure:"chunk_query_endpoint"` // "include" | "none"; required when chunk_mode=query. include = signal in NOTIFY (EDNS0); none = receiver uses combiner.agents[].address
	// ChunkMaxSize: maximum size (bytes) of each data chunk when fragmenting payloads via PrepareDistributionChunks.
	// 0 = default (60000). Useful for testing fragmentation with small values (e.g. 500).
	ChunkMaxSize int `yaml:"chunk_max_size" mapstructure:"chunk_max_size"`
	// MessageRetention: retention times for different message types in CHUNK distributions.
	// References the tdnsmp-local MessageRetentionConf in mp_msg_types.go.
	MessageRetention MessageRetentionConf `yaml:"message_retention" mapstructure:"message_retention"`
}

// CombinerOption identifies a combiner-specific behaviour flag.
type CombinerOption uint8

const (
	CombinerOptAddSignature CombinerOption = iota + 1
)

var CombinerOptionToString = map[CombinerOption]string{
	CombinerOptAddSignature: "add-signature",
}

var StringToCombinerOption = map[string]CombinerOption{
	"add-signature": CombinerOptAddSignature,
}

// SignerOption identifies a signer-specific behaviour flag.
// No options defined yet; the type and maps exist for symmetry and
// future expansion.
type SignerOption uint8

var SignerOptionToString = map[SignerOption]string{}
var StringToSignerOption = map[string]SignerOption{}

// AgentOption identifies an agent-specific behaviour flag.
// No options defined yet; the type and maps exist for symmetry and
// future expansion.
type AgentOption uint8

var AgentOptionToString = map[AgentOption]string{}
var StringToAgentOption = map[string]AgentOption{}
