/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Sync API routers for agent-to-agent and agent-to-combiner
 * HTTPS communication (mutual TLS with TLSA verification). The endpoints
 * are the transport's receive pipeline (api_receive.go).
 */
package tdnsmp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SetupAgentSyncRouter creates the HTTPS sync API router for agent role.
func (conf *Config) SetupAgentSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "AgentSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	// Every endpoint, /hello included, takes a client certificate the
	// TLSA middleware has checked.
	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("AgentSyncApi"))

	secureRouter.HandleFunc("/hello", conf.apiSyncEndpoint(apiEndpointHello)).Methods("POST")
	secureRouter.HandleFunc("/ping", tdns.APIping(conf.Config)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.apiSyncEndpoint(apiEndpointPing)).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.apiSyncEndpoint(apiEndpointBeat)).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.apiSyncEndpoint(apiEndpointMsg)).Methods("POST")

	return r, nil
}

// SetupCombinerSyncRouter creates the HTTPS sync API router for combiner role.
func (conf *Config) SetupCombinerSyncRouter(ctx context.Context) (*mux.Router, error) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "CombinerSyncApi: Root endpoint is not allowed", http.StatusForbidden)
	})

	// Every endpoint, /hello included, takes a client certificate the
	// TLSA middleware has checked.
	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("CombinerSyncApi"))

	secureRouter.HandleFunc("/hello", conf.apiSyncEndpoint(apiEndpointHello)).Methods("POST")
	secureRouter.HandleFunc("/ping", tdns.APIping(conf.Config)).Methods("POST")
	secureRouter.HandleFunc("/sync/ping", conf.apiSyncEndpoint(apiEndpointPing)).Methods("POST")
	secureRouter.HandleFunc("/beat", conf.apiSyncEndpoint(apiEndpointBeat)).Methods("POST")
	secureRouter.HandleFunc("/msg", conf.apiSyncEndpoint(apiEndpointMsg)).Methods("POST")

	return r, nil
}

// tlsaVerificationMiddleware returns middleware that checks the client's
// certificate against the client's TLSA RRset, with the transport's checker
// (the sending end uses the same one): any usable record of the set may
// match, the set is looked up through the resolver within its TTL, and an
// answer DNSSEC has not validated is refused unless validation is off. A
// passed check holds for a minute for that peer and certificate, so a burst
// of requests means one check; a peer whose set is empty is refused at once.
//
// A hello may come from an agent this one does not know yet, or before this
// one has the sender's TLSA. It is checked like any request when the TLSA
// is known. When it is not, the hello is refused retryably (503), and an
// agent this one knows is looked up, at most once a minute, so that a later
// hello passes (#56).
func (conf *Config) tlsaVerificationMiddleware(apiName string) mux.MiddlewareFunc {
	passed := &tlsaVerdicts{hold: time.Minute}
	lookedUp := &tlsaVerdicts{hold: time.Minute} // by identity
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hello := r.URL.Path == "/api/v1/hello"

			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, apiName+": Client certificate required", http.StatusUnauthorized)
				return
			}
			clientCert := r.TLS.PeerCertificates[0]

			// The name as the receive pipeline reads it (api_receive.go):
			// the certificate may leave out the trailing dot.
			clientId := core.CanonicalizeName(dns.Fqdn(clientCert.Subject.CommonName))
			ar := conf.InternalMp.AgentRegistry
			if ar == nil || ar.TransportManager == nil || ar.TransportManager.APITransport == nil || ar.TransportManager.APITransport.TLSA == nil {
				lgApi.Warn(apiName+": no agent registry or TLSA checker, client refused", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}
			_, known := ar.S.Get(AgentId(clientId))
			if !known && !hello {
				lgApi.Warn(apiName+": unknown remote agent identity", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}
			tm := ar.TransportManager
			peer, ok := tm.PeerRegistry.Get(clientId)
			if hello && (!ok || !peer.HasMechanismTLSA("API")) {
				if known && !lookedUp.holdsKey(clientId) {
					lookedUp.passKey(clientId)
					go func() {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						if _, err := tm.DiscoverPeer(ctx, clientId); err != nil {
							lgApi.Debug(apiName+": looking up a hello's sender failed", "clientId", clientId, "err", err)
						}
					}()
				}
				lgApi.Debug(apiName+": hello refused until the sender's TLSA is known", "clientId", clientId, "known", known)
				w.Header().Set("Retry-After", "15")
				http.Error(w, apiName+": the sender's TLSA is not known yet; try again", http.StatusServiceUnavailable)
				return
			}
			if !ok {
				lgApi.Warn(apiName+": client not in the peer registry", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			if !peer.HasMechanismTLSA("API") || !passed.holds(clientId, clientCert) {
				// Not the request's context: a client that hangs up
				// mid-lookup must not cancel it (the checker bounds it).
				ctx := context.WithoutCancel(r.Context())
				if err := tm.APITransport.TLSA.CheckClient(ctx, peer, "API", clientCert); err != nil {
					// The checker logs a missing TLSA, a mismatch and a
					// failed lookup itself, rate-limited.
					lgApi.Debug(apiName+": client certificate refused", "clientId", clientId, "err", err)
					http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
					return
				}
				passed.pass(clientId, clientCert)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// tlsaVerdicts remembers, for a while, which certificate passed the TLSA
// check for which peer.
type tlsaVerdicts struct {
	hold time.Duration
	now  func() time.Time // nil: time.Now
	mu   sync.Mutex
	at   map[string]time.Time
}

func tlsaVerdictKey(peer string, cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return peer + "|" + hex.EncodeToString(sum[:])
}

func (v *tlsaVerdicts) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// holds reports whether cert passed for peer less than hold ago.
func (v *tlsaVerdicts) holds(peer string, cert *x509.Certificate) bool {
	return v.holdsKey(tlsaVerdictKey(peer, cert))
}

// pass notes that cert passed for peer now, and forgets verdicts too old to
// hold.
func (v *tlsaVerdicts) pass(peer string, cert *x509.Certificate) {
	v.passKey(tlsaVerdictKey(peer, cert))
}

// holdsKey reports whether key was noted less than hold ago.
func (v *tlsaVerdicts) holdsKey(key string) bool {
	now := v.clock()
	v.mu.Lock()
	defer v.mu.Unlock()
	at, ok := v.at[key]
	return ok && now.Sub(at) < v.hold
}

// passKey notes key now, and forgets entries too old to hold.
func (v *tlsaVerdicts) passKey(key string) {
	now := v.clock()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.at == nil {
		v.at = make(map[string]time.Time)
	}
	for k, at := range v.at {
		if now.Sub(at) >= v.hold {
			delete(v.at, k)
		}
	}
	v.at[key] = now
}
