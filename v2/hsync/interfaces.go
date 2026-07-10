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

// TransportBridge is the hsync-facing surface of MP transport wiring.
// Satisfied by tdnsmp.MPTransportBridge at integration time.
// (Phase 2.6: RegisterDiscovered + DiscoveryResult deleted — the discovery
// process lives in tdns-transport; registration happens inside
// transport.TransportManager.DiscoverPeer/DiscoverAndRegisterPeer, which
// fires OnPeerDiscovered for the application's view materialization.)
type TransportBridge interface {
	DiscoverPeer(ctx context.Context, identity string) (*transport.Peer, error)
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
	// OnHsyncMembersAdded fires after ApplyHsyncDiff has registered member
	// adds for a zone, carrying the (HSYNCPARAM-gated, non-local) added
	// identities and whether the local identity was itself added. The agent
	// uses it to re-home the upstream/downstream CONFIG RFI deferred tasks and
	// the membership-change election kick that used to live in UpdateAgents.
	OnHsyncMembersAdded func(zone ZoneName, added []PeerID, localAdded bool)
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
	// GateOnLocalPresence makes ApplyHsyncDiff mirror the legacy weAreInHSYNC
	// abort: when the local identity is absent from the zone's current HSYNC3
	// RRset, skip remote add/remove processing and the group recompute (a
	// local-remove RR still fires OnLocalRemoved). Set by the agent; the
	// auditor observes zones it is not a member of, so it leaves this false.
	GateOnLocalPresence bool
}
