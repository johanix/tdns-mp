package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
)

// SetupMPAgentRoutes registers agent-specific API routes on the
// existing API router. Called from main.go after SetupAPIRouter.
func (conf *Config) SetupMPAgentRoutes(ctx context.Context, apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/agent", conf.APIagent(conf.Config.Internal.RefreshZoneCh, NewHsyncDB(kdb))).Methods("POST")
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/agent/hsync", conf.APIagentHsync(conf.InternalMp.HsyncDB)).Methods("POST")
	sr.HandleFunc("/zone/mplist", conf.APImplist()).Methods("POST")
	sr.HandleFunc("/agent/distrib", conf.APIagentDistrib(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/agent/transaction", conf.APIagentTransaction(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/agent/debug", conf.APIagentDebug()).Methods("POST")
	sr.HandleFunc("/keystore", conf.InternalMp.HsyncDB.APIkeystoreMP(conf)).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone/dsync", tdns.APIzoneDsync(ctx, &tdns.Globals.App, conf.Config.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/delegation", tdns.APIdelegation(conf.Config.Internal.DelegationSyncQ)).Methods("POST")
}
