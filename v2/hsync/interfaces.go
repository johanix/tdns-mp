/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"context"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// ZoneView exposes one MP zone to the engine.
type ZoneView interface {
	ZoneName() string
	HSYNC3() []dns.RR
	IsMultiProvider() bool
	// Participants returns the identities that hold a membership-conferring
	// HSYNCPARAM role in this zone (resolved via the zone's ON HSYNC3
	// label→identity map). HSYNC3 alone is just an identity↔label mapping
	// and confers no membership, so the host must derive this from
	// HSYNCPARAM — the engine treats it as the authoritative member set.
	Participants() []PeerID
}

// ZoneLookup enumerates MP zones for reconcile and hello validation.
type ZoneLookup interface {
	Get(zone string) (ZoneView, bool)
	Items() map[string]ZoneView
}

// ProviderGroupInfo is a snapshot of one provider group.
type ProviderGroupInfo struct {
	GroupHash string
	Members   []string
	Zones     []ZoneName
}

// ProviderGroupLookup supplies group membership for gossip.
type ProviderGroupLookup interface {
	Groups() []ProviderGroupInfo
	GetGroup(groupHash string) *ProviderGroupInfo
}

// ElectionStateLookup supplies live election state for outbound gossip.
type ElectionStateLookup interface {
	GetGroupElectionState(groupHash string) GroupElectionState
}

// DiscoveryResult holds IMR discovery output before registration.
type DiscoveryResult struct {
	Identity string
	APIUri   string
	DNSUri   string
	Error    error
}

// TransportBridge is the hsync-facing surface of MP transport wiring.
// Satisfied by tdnsmp.MPTransportBridge at integration time.
type TransportBridge interface {
	DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error)
	RegisterDiscovered(peer *Peer, result *DiscoveryResult) error
	SendHello(ctx context.Context, peer *Peer, sharedZones []string) error
	SendBeat(ctx context.Context, peer *Peer, sequence uint64) (ack bool, usedTransport string, err error)
	MechanismSupported(name string) bool
	FireDiscoveryFailed(peerID PeerID, err error)
	SyncPeerZones(peer *Peer)
	AfterDiscoverPeer(peer *Peer)
	PeerRegistry() *transport.PeerRegistry
}

// HostCallbacks are role-specific hooks (election, RFI) owned by tdnsmp.
type HostCallbacks struct {
	OnHsync3Changed    func(zone ZoneName)
	OnGroupOperational func(groupHash string)
	OnGroupDegraded    func(groupHash string)
	OnElectionGossip   func(groupHash string, state GroupElectionState)
	OnLocalRemoved     func(zone ZoneName)
	BeforeHeartbeats   func()
}

// PeerHooks are optional callbacks when registry peers change.
type PeerHooks struct {
	OnPeerStored func(*Peer)
}

// Deps bundles injected dependencies for NewEngine.
type Deps struct {
	LocalID           PeerID
	LocalBeatInterval uint32
	Zones             ZoneLookup
	Transport         TransportBridge
	Gossip            GossipPort
	ProviderGroups    ProviderGroupLookup
	Elections         ElectionStateLookup
	Host              HostCallbacks
	PeerHooks         PeerHooks
}
