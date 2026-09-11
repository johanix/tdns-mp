/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"sync"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// PeerID is the multi-provider identity (typically an FQDN).
type PeerID string

func (id PeerID) String() string { return string(id) }

// ZoneName is a DNS zone name served in the HSYNC group.
type ZoneName string

// String lets ZoneName satisfy core.Stringer (used by tdnsmp via the
// ZoneName = hsync.ZoneName alias, E1.a).
func (zn ZoneName) String() string { return string(zn) }

// PeerState is the HSYNC peer lifecycle state.
type PeerState uint8

const (
	PeerStateNeeded PeerState = iota + 1
	PeerStateKnown
	PeerStateIntroduced
	PeerStateOperational
	PeerStateLegacy
	PeerStateDegraded
	PeerStateInterrupted
	PeerStateError
)

var StateToString = map[PeerState]string{
	PeerStateNeeded:      "NEEDED",
	PeerStateKnown:       "KNOWN",
	PeerStateIntroduced:  "INTRODUCED",
	PeerStateOperational: "OPERATIONAL",
	PeerStateLegacy:      "LEGACY",
	PeerStateDegraded:    "DEGRADED",
	PeerStateInterrupted: "INTERRUPTED",
	PeerStateError:       "ERROR",
}

// AgentMsg mirrors core.AgentMsg for inbound dispatch.
type AgentMsg = core.AgentMsg

const (
	MsgHello  = core.AgentMsgHello
	MsgBeat   = core.AgentMsgBeat
	MsgNotify = core.AgentMsgNotify
	MsgRfi    = core.AgentMsgRfi
	MsgStatus = core.AgentMsgStatus
	MsgPing   = core.AgentMsgPing
	MsgEdits  = core.AgentMsgEdits
)

// DeferredTask runs after a peer reaches OPERATIONAL.
type DeferredTask struct {
	Precondition func() bool
	Action       func() (bool, error)
	Desc         string
}

// PeerDetails holds per-transport contact and beat state.
type PeerDetails struct {
	Addrs             []string
	Port              uint16
	BaseUri           string
	State             PeerState
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

// Peer is one remote HSYNC participant in the registry.
type Peer struct {
	ID          PeerID
	TransportID string
	Mu          sync.RWMutex
	ApiDetails  *PeerDetails
	DnsDetails  *PeerDetails
	ApiMethod   bool
	DnsMethod   bool
	IsInfraPeer bool
	Zones       map[ZoneName]bool
	State       PeerState
	LastState   time.Time
	Deferred    []DeferredTask
}

func NewPeer(id PeerID) *Peer {
	return &Peer{
		ID:          id,
		TransportID: string(id),
		ApiDetails:  &PeerDetails{State: PeerStateNeeded},
		DnsDetails:  &PeerDetails{State: PeerStateNeeded},
		ApiMethod:   false,
		DnsMethod:   false,
		Zones:       make(map[ZoneName]bool),
		State:       PeerStateNeeded,
		LastState:   time.Now(),
	}
}

// EffectiveState picks the best participating per-mechanism state, falling back
// to the top-level marker. D2.5 note: the engine's send-decision and beat
// gates no longer call this — they read transport.Peer (via mechPeerState).
// This survives only for the hsync GossipStateTable (dead in production: agent
// and auditor wire the no-op agentGossipPort and refresh gossip MP-side from
// transport.Peer; reachable only via NewEngine's nil-Gossip fallback + tests).
// It is removed wholesale with that gossip table in a later, dedicated cleanup.
func (p *Peer) EffectiveState() PeerState {
	p.Mu.RLock()
	defer p.Mu.RUnlock()
	best := PeerState(0)
	consider := func(enabled bool, td *PeerDetails) {
		if !enabled || td == nil || !transportParticipating(td.State) {
			return
		}
		switch td.State {
		case PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
			if best == 0 || td.State < best {
				best = td.State
			}
		}
	}
	consider(p.DnsMethod, p.DnsDetails)
	consider(p.ApiMethod, p.ApiDetails)
	if best != 0 {
		return best
	}
	return p.State
}

// D2.5: Peer.apiState/dnsState/IsAnyTransportOperational removed — they had no
// caller and read the retired hsync.PeerDetails.State sidecar.

// InboundReport is a decoded hello or beat from the transport bridge.
type InboundReport struct {
	Transport    string
	MessageType  AgentMsg
	Zone         ZoneName
	Identity     PeerID
	BeatInterval uint32
	Msg          interface{}
}

// BeatPost is the wire payload for outbound/inbound beats.
type BeatPost struct {
	MessageType    AgentMsg
	MyIdentity     PeerID
	YourIdentity   PeerID
	MyBeatInterval uint32
	Zones          []string
	Time           time.Time
	Gossip         []GossipMessage
}

// HelloPost is the wire payload for HELLO.
type HelloPost struct {
	MessageType  AgentMsg
	MyIdentity   PeerID
	YourIdentity PeerID
	Zone         ZoneName
	Time         time.Time
}
