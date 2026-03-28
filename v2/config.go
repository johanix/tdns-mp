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

// RegisterMPRefreshCallbacks appends tdns-mp PreRefresh/PostRefresh
// closures to all MP zones that don't already have them. Called at
// startup and after every zone reload (SIGHUP / "config reload-zones")
// via the PostParseZonesHook.
func (conf *Config) RegisterMPRefreshCallbacks() {
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	mp := conf.Config.MultiProvider
	if conf.InternalMp.refreshRegistered == nil {
		conf.InternalMp.refreshRegistered = make(map[string]bool)
	}
	for _, zoneName := range conf.Config.Internal.MPZoneNames {
		if conf.InternalMp.refreshRegistered[zoneName] {
			continue
		}
		zd, ok := tdns.Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		conf.InternalMp.refreshRegistered[zoneName] = true
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				MPPreRefresh(zd, new_zd, tm, msgQs, mp)
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				MPPostRefresh(zd, tm, msgQs)
			})
	}
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
	refreshRegistered     map[string]bool // tracks which zones have tdns-mp refresh callbacks
}
