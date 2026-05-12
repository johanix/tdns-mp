package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
)

// SetupMPAuditorRoutes registers auditor-specific API routes.
// Mirrors the role-shared transport endpoints (/gossip, /router,
// /peer) used by agent/combiner/signer, the auditor's own
// management endpoint at /auditor, and (like agent) the keystore +
// truststore endpoints for inspecting the auto-zone's signing
// material.
func (conf *Config) SetupMPAuditorRoutes(ctx context.Context, apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/auditor", conf.APIauditor()).Methods("POST")
	sr.HandleFunc("/keystore", conf.InternalMp.HsyncDB.APIkeystoreMP(conf)).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/auditor/distrib", conf.APIauditorDistrib()).Methods("POST")
}
