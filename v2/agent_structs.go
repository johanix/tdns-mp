/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"net/http"
	"sync"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

type AgentState uint8

const (
	AgentStateNeeded      AgentState = iota + 1 // Agent is required but we don't have complete information
	AgentStateKnown                             // We have complete information but haven't established communication
	AgentStateIntroduced                        // We got a nice reply to our HELLO
	AgentStateOperational                       // We got a nice reply to our (secure) BEAT
	AgentStateLegacy                            // Established relationship but no shared zones (previously OPERATIONAL)
	AgentStateDegraded                          // Last successful heartbeat (in either direction) was more than 2x normal interval ago
	AgentStateInterrupted                       // Last successful heartbeat (in either direction) was more than 10x normal interval ago
	AgentStateError                             // We have tried to establish communication but failed
)

var AgentStateToString = map[AgentState]string{
	AgentStateNeeded:      "NEEDED",
	AgentStateKnown:       "KNOWN",
	AgentStateIntroduced:  "INTRODUCED",
	AgentStateOperational: "OPERATIONAL",
	AgentStateLegacy:      "LEGACY",
	AgentStateDegraded:    "DEGRADED",
	AgentStateInterrupted: "INTERRUPTED",
	AgentStateError:       "ERROR",
}

// AgentMsg and related constants are defined in core package to avoid circular dependencies
type AgentMsg = core.AgentMsg

const (
	AgentMsgHello  = core.AgentMsgHello
	AgentMsgBeat   = core.AgentMsgBeat
	AgentMsgNotify = core.AgentMsgNotify
	AgentMsgRfi    = core.AgentMsgRfi
	AgentMsgStatus = core.AgentMsgStatus
	AgentMsgPing   = core.AgentMsgPing
	AgentMsgEdits  = core.AgentMsgEdits
)

var AgentMsgToString = core.AgentMsgToString

// Agent is the MP-side view of a peer (END.1 / addendum §3). It embeds the thin
// *hsync.Peer (the surviving MP coordination/identity holder) and promotes its
// ID / Mu / Zones / Deferred — the END.1 "dedupe Identity/PeerID -> hsync.Peer.ID"
// (E1.a). hsync.Peer is allocated 1:1 with the Agent; the bridge keeps the two
// objects in sync until E1.b collapses them to one object.
//
// The connection-state fields (ApiDetails/DnsDetails/State/ApiMethod/DnsMethod/
// IsInfraPeer/LastState) are KEPT here, shadowing the same-named fields on the
// embedded *hsync.Peer. They are retired to transport.Peer in A5/Stage D, not
// END.1 — except their values are dead post-D2.5 (no production reader of the
// connection-state half). Keeping them avoids a type cascade (ApiDetails is
// *AgentDetails here, *hsync.PeerDetails on the embed).
//
// E1.a dedupes every field whose type already matches the embedded hsync.Peer
// (no type cascade): ID (Identity/PeerID), Mu, Zones, Deferred, ApiMethod,
// DnsMethod, IsInfraPeer, LastState — all PROMOTE from *hsync.Peer, so e.g.
// agent.ApiMethod IS agent.Peer.ApiMethod (one copy; engine and MP read the same
// field). Only the DIFFERENT-typed connection-state fields stay on Agent,
// shadowing the embed's same-named ones: ApiDetails/DnsDetails (*AgentDetails vs
// *hsync.PeerDetails) and State (AgentState vs hsync.PeerState). Those retire to
// transport.Peer in A5/Stage D.
//
// Access notes after the embed:
//   - agent.ID (was agent.Identity / agent.PeerID) — type AgentId (= hsync.PeerID)
//   - agent.Mu / agent.Zones / agent.Deferred (was DeferredTasks),
//     agent.ApiMethod / agent.DnsMethod / agent.IsInfraPeer / agent.LastState — from *hsync.Peer
type Agent struct {
	*hsync.Peer // ID, Mu, Zones, Deferred, ApiMethod, DnsMethod, IsInfraPeer, LastState

	InitialZone ZoneName
	ApiDetails  *AgentDetails // shadows hsync.Peer.ApiDetails (different type); retires A5/D
	DnsDetails  *AgentDetails // shadows hsync.Peer.DnsDetails (different type); retires A5/D
	Api         *AgentApi
	State       AgentState // shadows hsync.Peer.State (AgentState vs hsync.PeerState); retires A5/D
	ErrorMsg    string     // Error message if state is error
	// meta is the transitional MP-side sidecar (A3d): per-mechanism crypto
	// holding pen, en route to transport.Peer at E1. Reached via
	// ensureCrypto/cryptoFor; lazily allocated.
	meta *agentMeta
}

// NewAgent allocates an Agent view over a fresh thin hsync.Peer with the given
// identity (E1.a). Callers set the MP-only shadow fields (ApiDetails/DnsDetails/
// State/meta) and the promoted capability flags as needed.
func NewAgent(id AgentId) *Agent {
	return &Agent{Peer: hsync.NewPeer(id)}
}

type AgentDetails struct {
	State             AgentState
	LatestError       string
	LatestErrorTime   time.Time
	DiscoveryFailures uint32
	HelloTime         time.Time
	LastContactTime   time.Time
	BeatInterval      uint32
	SentBeats         uint32
	ReceivedBeats     uint32
	LatestSBeat       time.Time
	LatestRBeat       time.Time
}

// DeferredAgentTask aliases hsync.DeferredTask so the field promoted from the
// embedded *hsync.Peer (Deferred []hsync.DeferredTask) is type-identical to the
// existing DeferredAgentTask call sites (END.1 / E1.a). Same shape (Precondition
// / Action / Desc); the alias dedupes the type.
type DeferredAgentTask = hsync.DeferredTask

type AgentApi struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	ApiKey     string
	Authmethod string
	ApiClient  *tdns.ApiClient
}

type AgentRegistry struct {
	// *hsync.Registry is the single peer map + protocol methods (decision B,
	// docs/2026-05-30 §A3). A3d.1 embeds the SAME instance owned by
	// HsyncEngine (wired at engine construction). AgentRegistry.S stays
	// dual-mapped alongside it until A3d.4; the embedded registry's own S is
	// reached via ar.Registry.S. The outer S/mu (depth 0) shadow the
	// embedded ones, so all existing ar.S/ar.mu usage is unchanged.
	*hsync.Registry
	S                     core.ConcurrentMap[AgentId, *Agent]
	mu                    sync.RWMutex
	LocalAgent            *MultiProviderConf
	LocateInterval        int
	TransportManager      *transport.TransportManager
	MPTransport           *MPTransportBridge
	LeaderElectionManager *LeaderElectionManager
	ProviderGroupManager  *ProviderGroupManager
	GossipStateTable      *GossipStateTable
	HsyncEngine           *hsync.Engine
	AuditState            *AuditStateManager // auditor only: zone config checks
}

type AgentBeatPost struct {
	MessageType    AgentMsg
	MyIdentity     AgentId
	YourIdentity   AgentId
	MyBeatInterval uint32
	Zones          []string
	Time           time.Time
	Gossip         []GossipMessage `json:"Gossip,omitempty"`
}

type AgentBeatResponse struct {
	Status       string
	MyIdentity   AgentId
	YourIdentity AgentId
	Time         time.Time
	Client       string
	Msg          string
	Error        bool
	ErrorMsg     string
}

type AgentBeatReport struct {
	Time time.Time
	Beat AgentBeatPost
}

type AgentHelloPost struct {
	MessageType  AgentMsg
	Name         string `json:"name,omitempty"`
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string `json:"addresses,omitempty"`
	Port         uint16   `json:"port,omitempty"`
	TLSA         dns.TLSA `json:"tlsa,omitempty"`
	Zone         ZoneName
	Time         time.Time
}

type AgentHelloResponse struct {
	Status       string
	MyIdentity   AgentId
	YourIdentity AgentId
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
}

type AgentMsgPost struct {
	MessageType    AgentMsg
	OriginatorID   AgentId
	DeliveredBy    AgentId
	YourIdentity   AgentId
	Addresses      []string `json:"addresses,omitempty"`
	Port           uint16   `json:"port,omitempty"`
	TLSA           dns.TLSA `json:"tlsa,omitempty"`
	Zone           ZoneName
	Records        map[string][]string
	Operations     []core.RROperation
	Time           time.Time
	RfiType        string
	RfiSubtype     string
	DistributionID string
	Nonce          string
	ZoneClass      string
	Publish        *core.PublishInstruction
}

type AgentMsgPostPlus struct {
	AgentMsgPost
	Response chan *AgentMsgResponse
}

type AgentMsgResponse struct {
	Status      string
	Time        time.Time
	AgentId     AgentId
	Msg         string
	Zone        ZoneName
	RfiResponse map[AgentId]*RfiData
	Error       bool
	ErrorMsg    string
}

type RfiData struct {
	Status      string
	Time        time.Time
	Msg         string
	Error       bool
	ErrorMsg    string
	ZoneXfrSrcs []string
	ZoneXfrAuth []string
	ZoneXfrDsts []string
	AuditData   map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo `json:"audit_data,omitempty"`
	ConfigData  map[string]string                                   `json:"config_data,omitempty"`
}

type AgentPingPost struct {
	MessageType  AgentMsg
	MyIdentity   AgentId
	YourIdentity AgentId
	Nonce        string
	Time         time.Time
}

type AgentPingResponse struct {
	Status       string
	MyIdentity   AgentId
	YourIdentity AgentId
	Nonce        string
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
}

type AgentMgmtPost struct {
	Command     string `json:"command"`
	MessageType AgentMsg
	Zone        ZoneName `json:"zone"`
	AgentId     AgentId  `json:"agent_id"`
	RRType      uint16
	RR          string
	RRs         []string
	AddedRRs    []string
	RemovedRRs  []string
	Upstream    AgentId
	Downstream  AgentId
	RfiType     string
	RfiSubtype  string
	Data        map[string]interface{} `json:"data,omitempty"`
}

type AgentDebugPost struct {
	Command string   `json:"command"`
	Zone    ZoneName `json:"zone"`
	AgentId AgentId  `json:"agent_id"`
	RRType  uint16
	RR      string
	Data    ZoneUpdate
}

type KeystateInfo struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// AgentRegistryDump is the debug-only serialization of the agent registry for
// the dump-agentregistry command (the live registry's peer map is not directly
// JSON-encodable). Not a live registry store.
type AgentRegistryDump struct {
	Agents         map[AgentId]*Agent
	LocalAgent     *MultiProviderConf
	LocateInterval int
}

type AgentMgmtResponse struct {
	Identity       AgentId
	Status         string
	Time           time.Time
	Agents         []*Agent
	ZoneAgentData  *ZoneAgentData
	HsyncRRs       []string
	AgentConfig    MultiProviderConf
	RfiType        string
	RfiResponse    map[AgentId]*RfiData
	AgentRegistry  *AgentRegistryDump
	ZoneDataRepo   map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo
	KeystateStatus map[ZoneName]KeystateInfo `json:"keystate_status,omitempty"`
	Msg            string
	Error          bool
	ErrorMsg       string
	Data           interface{} `json:"data,omitempty"`

	HsyncPeers         []*HsyncPeerInfo         `json:"hsync_peers,omitempty"`
	HsyncSyncOps       []*HsyncSyncOpInfo       `json:"hsync_sync_ops,omitempty"`
	HsyncConfirmations []*HsyncConfirmationInfo `json:"hsync_confirmations,omitempty"`
	HsyncEvents        []*HsyncTransportEvent   `json:"hsync_events,omitempty"`
	HsyncMetrics       *HsyncMetricsInfo        `json:"hsync_metrics,omitempty"`
}

type HsyncPeerInfo struct {
	PeerID             string    `json:"peer_id"`
	State              string    `json:"state"`
	StateReason        string    `json:"state_reason,omitempty"`
	DiscoverySource    string    `json:"discovery_source,omitempty"`
	DiscoveryTime      time.Time `json:"discovery_time,omitempty"`
	PreferredTransport string    `json:"preferred_transport"`
	APIHost            string    `json:"api_host,omitempty"`
	APIPort            int       `json:"api_port,omitempty"`
	APIAvailable       bool      `json:"api_available"`
	DNSHost            string    `json:"dns_host,omitempty"`
	DNSPort            int       `json:"dns_port,omitempty"`
	DNSAvailable       bool      `json:"dns_available"`
	LastContactAt      time.Time `json:"last_contact_at,omitempty"`
	LastHelloAt        time.Time `json:"last_hello_at,omitempty"`
	LastBeatAt         time.Time `json:"last_beat_at,omitempty"`
	BeatInterval       int       `json:"beat_interval"`
	BeatsSent          int64     `json:"beats_sent"`
	BeatsReceived      int64     `json:"beats_received"`
	FailedContacts     int       `json:"failed_contacts"`
}

type HsyncSyncOpInfo struct {
	DistributionID string    `json:"distribution_id"`
	ZoneName       string    `json:"zone_name"`
	SyncType       string    `json:"sync_type"`
	Direction      string    `json:"direction"`
	SenderID       string    `json:"sender_id"`
	ReceiverID     string    `json:"receiver_id"`
	Status         string    `json:"status"`
	StatusMessage  string    `json:"status_message,omitempty"`
	Transport      string    `json:"transport,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	SentAt         time.Time `json:"sent_at,omitempty"`
	ReceivedAt     time.Time `json:"received_at,omitempty"`
	ConfirmedAt    time.Time `json:"confirmed_at,omitempty"`
	RetryCount     int       `json:"retry_count"`
}

type HsyncConfirmationInfo struct {
	DistributionID string    `json:"distribution_id"`
	ConfirmerID    string    `json:"confirmer_id"`
	Status         string    `json:"status"`
	Message        string    `json:"message,omitempty"`
	ConfirmedAt    time.Time `json:"confirmed_at"`
	ReceivedAt     time.Time `json:"received_at"`
}

type HsyncTransportEvent struct {
	EventTime    time.Time `json:"event_time"`
	PeerID       string    `json:"peer_id,omitempty"`
	ZoneName     string    `json:"zone_name,omitempty"`
	EventType    string    `json:"event_type"`
	Transport    string    `json:"transport,omitempty"`
	Direction    string    `json:"direction,omitempty"`
	Success      bool      `json:"success"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

type HsyncMetricsInfo struct {
	SyncsSent      int64 `json:"syncs_sent"`
	SyncsReceived  int64 `json:"syncs_received"`
	SyncsConfirmed int64 `json:"syncs_confirmed"`
	SyncsFailed    int64 `json:"syncs_failed"`
	BeatsSent      int64 `json:"beats_sent"`
	BeatsReceived  int64 `json:"beats_received"`
	BeatsMissed    int64 `json:"beats_missed"`
	AvgLatency     int64 `json:"avg_latency"`
	MaxLatency     int64 `json:"max_latency"`
	APIOperations  int64 `json:"api_operations"`
	DNSOperations  int64 `json:"dns_operations"`
}

type AgentMgmtPostPlus struct {
	AgentMgmtPost
	Response chan *AgentMgmtResponse
}

type AgentMsgReport struct {
	Transport      string
	MessageType    AgentMsg
	Zone           ZoneName
	Identity       AgentId
	BeatInterval   uint32
	Msg            interface{}
	RfiType        string
	DistributionID string
	Response       chan *SynchedDataResponse
}
