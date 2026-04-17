/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"context"
	"net/http"
	"sync"
	"time"

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

type Agent struct {
	Identity      AgentId
	Mu            sync.RWMutex
	InitialZone   ZoneName
	ApiDetails    *AgentDetails
	DnsDetails    *AgentDetails
	ApiMethod     bool
	DnsMethod     bool
	IsInfraPeer   bool // true for combiner/signer — handled by StartInfraBeatLoop, not SendHeartbeats
	Zones         map[ZoneName]bool
	Api           *AgentApi
	State         AgentState // Agent states: needed, known, hello-done, operational, error
	LastState     time.Time  // When state last changed
	ErrorMsg      string     // Error message if state is error
	DeferredTasks []DeferredAgentTask
}

type AgentDetails struct {
	Addrs             []string
	Port              uint16
	BaseUri           string
	UriRR             *dns.URI
	Host              string
	KeyRR             *dns.KEY
	JWKData           string
	KeyAlgorithm      string
	TlsaRR            *dns.TLSA
	Endpoint          string
	ContactInfo       string
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

func (a *Agent) IsAnyTransportOperational() bool {
	if a.DnsDetails != nil && a.DnsDetails.State == AgentStateOperational {
		return true
	}
	if a.ApiDetails != nil && a.ApiDetails.State == AgentStateOperational {
		return true
	}
	return false
}

func (a *Agent) EffectiveState() AgentState {
	// Return the best active transport state. OPERATIONAL is best,
	// followed by LEGACY, DEGRADED, INTERRUPTED. If neither transport
	// has reached an active state, fall back to a.State.
	best := AgentState(0)
	for _, s := range []AgentState{
		a.apiState(), a.dnsState(),
	} {
		switch s {
		case AgentStateOperational, AgentStateLegacy, AgentStateDegraded, AgentStateInterrupted:
			if best == 0 || s < best {
				best = s // lower numeric = better (OPERATIONAL < DEGRADED)
			}
		}
	}
	if best != 0 {
		return best
	}
	return a.State
}

func (a *Agent) apiState() AgentState {
	if a.ApiDetails != nil {
		return a.ApiDetails.State
	}
	return 0
}

func (a *Agent) dnsState() AgentState {
	if a.DnsDetails != nil {
		return a.DnsDetails.State
	}
	return 0
}

type DeferredAgentTask struct {
	Precondition func() bool
	Action       func() (bool, error)
	Desc         string
}

type AgentApi struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	ApiKey     string
	Authmethod string
	ApiClient  *tdns.ApiClient
}

type AgentRegistry struct {
	S                     core.ConcurrentMap[AgentId, *Agent]
	RegularS              map[AgentId]*Agent
	RemoteAgents          map[ZoneName][]AgentId
	mu                    sync.RWMutex
	LocalAgent            *tdns.MultiProviderConf
	LocateInterval        int
	helloContexts         map[AgentId]context.CancelFunc
	TransportManager      *transport.TransportManager
	MPTransport           *MPTransportBridge
	LeaderElectionManager *LeaderElectionManager
	ProviderGroupManager  *ProviderGroupManager
	GossipStateTable      *GossipStateTable
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

type AgentMgmtResponse struct {
	Identity       AgentId
	Status         string
	Time           time.Time
	Agents         []*Agent
	ZoneAgentData  *ZoneAgentData
	HsyncRRs       []string
	AgentConfig    tdns.MultiProviderConf
	RfiType        string
	RfiResponse    map[AgentId]*RfiData
	AgentRegistry  *AgentRegistry
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
