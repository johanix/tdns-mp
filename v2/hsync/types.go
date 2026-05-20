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
		ApiMethod:   true,
		DnsMethod:   true,
		Zones:       make(map[ZoneName]bool),
		State:       PeerStateNeeded,
		LastState:   time.Now(),
	}
}

func (p *Peer) EffectiveState() PeerState {
	best := PeerState(0)
	for _, s := range []PeerState{p.apiState(), p.dnsState()} {
		switch s {
		case PeerStateOperational, PeerStateLegacy, PeerStateDegraded, PeerStateInterrupted:
			if best == 0 || s < best {
				best = s
			}
		}
	}
	if best != 0 {
		return best
	}
	return p.State
}

func (p *Peer) apiState() PeerState {
	if p.ApiDetails != nil {
		return p.ApiDetails.State
	}
	return 0
}

func (p *Peer) dnsState() PeerState {
	if p.DnsDetails != nil {
		return p.DnsDetails.State
	}
	return 0
}

func (p *Peer) IsAnyTransportOperational() bool {
	if p.DnsDetails != nil && p.DnsDetails.State == PeerStateOperational {
		return true
	}
	if p.ApiDetails != nil && p.ApiDetails.State == PeerStateOperational {
		return true
	}
	return false
}

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
