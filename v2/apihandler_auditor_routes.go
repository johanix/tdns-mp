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
// material and /imr for inspecting its resolver cache.
func (conf *Config) SetupMPAuditorRoutes(ctx context.Context, apirouter *mux.Router) {
	kdb := conf.Config.Internal.KeyDB
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/gossip", APIgossip(conf)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/auditor", conf.APIauditor()).Methods("POST")
	sr.HandleFunc("/imr", conf.APIimr()).Methods("POST")
	sr.HandleFunc("/keystore", conf.Config.Internal.KeyDB.APIkeystore(conf.Config)).Methods("POST")
	sr.HandleFunc("/truststore", kdb.APItruststore()).Methods("POST")
	sr.HandleFunc("/zone/mplist", conf.APImplist()).Methods("POST")
	sr.HandleFunc("/auditor/distrib", conf.APIauditorDistrib(conf.InternalMp.DistributionCache)).Methods("POST")
}
