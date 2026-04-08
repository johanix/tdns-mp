package tdnsmp

import (
	"context"

	"github.com/gorilla/mux"
)

// SetupMPAuditorRoutes registers auditor-specific API routes.
// MPAuditor is future work; this is a placeholder.
func (conf *Config) SetupMPAuditorRoutes(ctx context.Context, apirouter *mux.Router) {
}
