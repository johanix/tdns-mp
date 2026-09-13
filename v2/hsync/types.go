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

// Connection state is transport.PeerState, read from the canonical
// transport.Peer through mechPeerState (transport_peer.go); the engine has
// no state vocabulary of its own (cleanup plan, step 6). LEGACY is not a
// state but a fact the application derives (an established peer that
// shares no participant zone), in one place: tdnsmp's agent view.

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

// Peer is one remote HSYNC participant in the registry.
type Peer struct {
	ID          PeerID
	TransportID string
	Mu          sync.RWMutex
	ApiMethod   bool
	DnsMethod   bool
	IsInfraPeer bool
	Zones       map[ZoneName]bool
	LastState   time.Time
	Deferred    []DeferredTask
}

func NewPeer(id PeerID) *Peer {
	return &Peer{
		ID:          id,
		TransportID: string(id),
		ApiMethod:   false,
		DnsMethod:   false,
		Zones:       make(map[ZoneName]bool),
		LastState:   time.Now(),
	}
}

// D0 (2026-09-09): the NG PeerDetails sidecar (ApiDetails/DnsDetails) and
// EffectiveState are gone; per-mechanism state lives on transport.Peer.

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
