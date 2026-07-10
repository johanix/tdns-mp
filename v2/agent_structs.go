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
// E1.a dedupes every field whose type already matches the embedded hsync.Peer
// (no type cascade): ID (Identity/PeerID), Mu, Zones, Deferred, ApiMethod,
// DnsMethod, IsInfraPeer, LastState — all PROMOTE from *hsync.Peer, so e.g.
// agent.ApiMethod IS agent.Peer.ApiMethod (one copy; engine and MP read the same
// field).
//
// Phase 2 deleted the AgentDetails shadows entirely (connection state +
// telemetry live on transport.Peer). CAUTION: because of the embed,
// `agent.ApiDetails`/`agent.DnsDetails` still RESOLVE — to the embedded
// hsync.Peer's *hsync.PeerDetails (the retired NG store). Do not reintroduce
// readers/writers through those names; the hsync.PeerDetails deletion (Stage
// D / Phase 3) removes the trap. Only State (AgentState vs hsync.PeerState)
// still shadows the embed, as the DTO display field.
//
// Access notes after the embed:
//   - agent.ID (was agent.Identity / agent.PeerID) — type AgentId (= hsync.PeerID)
//   - agent.Mu / agent.Zones / agent.Deferred (was DeferredTasks),
//     agent.ApiMethod / agent.DnsMethod / agent.IsInfraPeer / agent.LastState — from *hsync.Peer
type Agent struct {
	*hsync.Peer // ID, Mu, Zones, Deferred, ApiMethod, DnsMethod, IsInfraPeer, LastState

	InitialZone ZoneName
	Api         *AgentApi
	State       AgentState // shadows hsync.Peer.State (AgentState vs hsync.PeerState); DTO display field, stamped from effectiveAgentState; retires with the DTO rework
	ErrorMsg    string     // Error message if state is error
}

// NewAgent allocates an Agent view over a fresh thin hsync.Peer with the given
// identity (E1.a). Callers set the MP-only shadow fields (State/meta) and the
// promoted capability flags as needed.
func NewAgent(id AgentId) *Agent {
	return &Agent{Peer: hsync.NewPeer(id)}
}

// newAgentView builds an *Agent view SHARING the given peer pointer (E1.b) —
// never a copy. Since Phase 2 (AgentDetails deleted) this is just the shared
// embed; kept as the named constructor for the view semantics.
func newAgentView(peer *hsync.Peer) *Agent {
	return &Agent{Peer: peer}
}

// materializeAgentView returns the ar.S *Agent view over an engine-owned
// hsync.Peer, creating and storing it if absent (E1.b). Once materialized the
// view is NEVER replaced: MP-only fields (meta/Api/InitialZone/ErrorMsg and
// the dead shadows) accumulate on the one view — the pre-E1.b bridge rebuilt
// and re-Set a fresh wrapper on every store/hello/beat, silently wiping them.
// Atomic via Upsert so concurrent materializations converge on a single view.
func (ar *AgentRegistry) materializeAgentView(peer *hsync.Peer) *Agent {
	if ar == nil || peer == nil {
		return nil
	}
	return ar.S.Upsert(peer.ID, nil, func(exist bool, current *Agent, _ *Agent) *Agent {
		if exist && current != nil {
			if current.Peer != peer {
				// Every create path shares the pointer post-E1.b, so this is
				// a divergent allocation — keep the stored view (live readers
				// hold it) and log loudly.
				lgAgent.Error("agent view wraps a different hsync.Peer allocation; keeping the stored view",
					"peer", peer.ID)
			}
			return current
		}
		return newAgentView(peer)
	})
}

// agentViewForIdentity returns the ar.S view for an identity, wrapping the
// ENGINE's hsync.Peer — never allocating a second peer for a known identity
// (E1.b). When the engine has not seen the identity yet (true out-of-band
// discoveries: the chunk-notify kick, distrib-time discovery), the peer is
// created IN the embedded engine registry with the same capability seeding as
// the engine's MarkNeeded — being in the engine map is also what lets
// retryPendingDiscoveries start the peer's Hello (D2.5). Falls back to an
// agent-only view (the infra-peer shape) when no engine registry is wired.
func (ar *AgentRegistry) agentViewForIdentity(id AgentId, apiSupported, dnsSupported bool) *Agent {
	if ar == nil {
		return nil
	}
	if agent, ok := ar.S.Get(id); ok {
		return agent
	}
	if ar.Registry == nil {
		// No engine wired (harness/edge case): agent-only view, one
		// allocation — the same shape as the infra peers.
		agent := newAgentView(hsync.NewPeer(id))
		ar.S.Set(agent.ID, agent)
		return agent
	}
	hpeer := ar.Registry.S.Upsert(id, nil, func(exist bool, current *hsync.Peer, _ *hsync.Peer) *hsync.Peer {
		if exist && current != nil {
			return current
		}
		np := hsync.NewPeer(id)
		np.ApiMethod = apiSupported
		np.DnsMethod = dnsSupported
		return np
	})
	return ar.materializeAgentView(hpeer)
}

// removePeerView drops the MP view and the transport peer for a removed
// peer (Phase 3c: the engine's RemovePeer fires OnPeerRemoved, and the
// removal propagates promptly instead of waiting for a scan).
func (ar *AgentRegistry) removePeerView(id AgentId) {
	if ar == nil {
		return
	}
	ar.S.Remove(id)
	if ar.TransportManager != nil {
		ar.TransportManager.PeerRegistry.Remove(string(id))
	}
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
