package tdnsmp

import (
	"github.com/gorilla/mux"
)

// SetupMPAgentRoutes registers agent-specific API routes on the
// existing API router. Called from main.go after SetupAPIRouter.
func (conf *Config) SetupMPAgentRoutes(apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/agent", conf.APIagent(conf.Config.Internal.RefreshZoneCh, kdb)).Methods("POST")
	sr.HandleFunc("/agent/distrib", conf.APIagentDistrib(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/agent/transaction", conf.APIagentTransaction(conf.InternalMp.DistributionCache)).Methods("POST")
	sr.HandleFunc("/agent/debug", conf.APIagentDebug()).Methods("POST")
}
