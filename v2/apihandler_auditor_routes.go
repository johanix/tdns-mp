package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
)

// SetupMPAuditorRoutes registers auditor-specific API routes.
// MPAuditor is future work; transport-layer endpoints are
// registered today so auditor instances can be introspected.
func (conf *Config) SetupMPAuditorRoutes(ctx context.Context, apirouter *mux.Router) {
	sr := apirouter.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/gossip", APIgossip(conf.InternalMp.AgentRegistry, conf.InternalMp.LeaderElectionManager)).Methods("POST")
}
