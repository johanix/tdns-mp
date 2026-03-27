/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp Config: wraps a pointer to tdns.Config, adds MP-specific state.
 * MainInit and StartMPSigner are receiver methods on this type.
 */
package tdnsmp

import (
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

// Config wraps a pointer to the tdns.Config (typically &tdns.Conf)
// and adds MP-specific configuration and internal state.
//
// Using a pointer ensures that tdns code accessing the global
// tdns.Conf sees the same state as tdns-mp code.
type Config struct {
	*tdns.Config
	InternalMp InternalMpConf
}

// InternalMpConf holds multi-provider internal state local to
// tdns-mp. Mirrors tdns.InternalMpConf field-by-field. During
// migration, both exist — code in tdns-mp reads from here,
// code in tdns reads from tdns.Config.Internal.
type InternalMpConf struct {
	SyncQ                 chan SyncRequest
	MsgQs                 *MsgQs
	SyncStatusQ           chan SyncStatus
	AgentRegistry         *AgentRegistry
	ZoneDataRepo          *ZoneDataRepo
	CombinerState         *CombinerState
	TransportManager      *transport.TransportManager
	MPTransport           *MPTransportBridge
	LeaderElectionManager *LeaderElectionManager
	ChunkPayloadStore     ChunkPayloadStore
	MPZoneNames           []string
	DistributionCache     *DistributionCache
}
