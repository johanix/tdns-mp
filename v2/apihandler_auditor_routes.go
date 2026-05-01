package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
)

// SetupMPAuditorRoutes registers auditor-specific API routes.
// Mirrors the role-shared transport endpoints (/gossip, /router,
// /peer) used by agent/combiner/signer, plus the auditor's own
// management endpoint at /auditor.
func (conf *Config) SetupMPAuditorRoutes(ctx context.Context, apirouter *mux.Router) {
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
	sr.HandleFunc("/router", APIrouter(conf.InternalMp.TransportManager)).Methods("POST")
	sr.HandleFunc("/peer", APIpeer(conf, conf.InternalMp.TransportManager, conf.InternalMp.AgentRegistry)).Methods("POST")
	sr.HandleFunc("/auditor", conf.APIauditor()).Methods("POST")
}
