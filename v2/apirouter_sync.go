/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Sync API routers for agent-to-agent and agent-to-combiner
 * HTTPS communication (mutual TLS with TLSA verification).
 */
package tdnsmp

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
)

// SetupAgentSyncRouter creates the HTTPS sync API router for agent role.
func (conf *Config) SetupAgentSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "AgentSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.APIhello()).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("AgentSyncApi"))

	secureRouter.HandleFunc("/ping", tdns.APIping(conf.Config)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.APIbeat()).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.APImsg()).Methods("POST")

	return r, nil
}

// SetupCombinerSyncRouter creates the HTTPS sync API router for combiner role.
func (conf *Config) SetupCombinerSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "CombinerSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.APIhello()).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("CombinerSyncApi"))

	secureRouter.HandleFunc("/ping", tdns.APIping(conf.Config)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.APIbeat()).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.APImsg()).Methods("POST")

	return r, nil
}

// tlsaVerificationMiddleware returns middleware that verifies client
// certificates against TLSA records in the AgentRegistry.
func (conf *Config) tlsaVerificationMiddleware(apiName string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/hello" {
				next.ServeHTTP(w, r)
				return
			}

			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, apiName+": Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]

			clientId := clientCert.Subject.CommonName
			agent, ok := conf.InternalMp.AgentRegistry.S.Get(AgentId(clientId))
			if !ok {
				lgApi.Warn(apiName+": unknown remote agent identity", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			agent.Mu.RLock()
			apiDetails := agent.ApiDetails
			agent.Mu.RUnlock()
			if apiDetails == nil {
				lgApi.Warn(apiName+": no API details for client", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}
			tlsaRR := apiDetails.TlsaRR
			if tlsaRR == nil {
				lgApi.Warn(apiName+": no TLSA record for client", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			if err := tdns.VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw); err != nil {
				lgApi.Warn(apiName+": certificate verification failed", "clientId", clientId, "err", err)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
