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
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/johanix/tdns-transport/v2/transport"
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

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.apiSyncEndpoint(apiEndpointHello)).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("AgentSyncApi"))

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

	sr := r.PathPrefix("/api/v1").Subrouter()
	sr.HandleFunc("/hello", conf.apiSyncEndpoint(apiEndpointHello)).Methods("POST")

	secureRouter := r.PathPrefix("/api/v1").Subrouter()
	secureRouter.Use(conf.tlsaVerificationMiddleware("CombinerSyncApi"))

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
func (conf *Config) tlsaVerificationMiddleware(apiName string) mux.MiddlewareFunc {
	passed := &tlsaVerdicts{hold: time.Minute}
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

			// The name as the receive pipeline reads it (api_receive.go):
			// the certificate may leave out the trailing dot.
			clientId := core.CanonicalizeName(dns.Fqdn(clientCert.Subject.CommonName))
			ar := conf.InternalMp.AgentRegistry
			if ar == nil || ar.TransportManager == nil || ar.TransportManager.APITransport == nil || ar.TransportManager.APITransport.TLSA == nil {
				lgApi.Warn(apiName+": no agent registry or TLSA checker, client refused", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}
			if _, ok := ar.S.Get(AgentId(clientId)); !ok {
				lgApi.Warn(apiName+": unknown remote agent identity", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}
			tm := ar.TransportManager
			peer, ok := tm.PeerRegistry.Get(clientId)
			if !ok {
				lgApi.Warn(apiName+": client not in the peer registry", "clientId", clientId)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			err := passed.checkClient(peer, clientCert, func() error {
				// Not the request's context: a client that hangs up
				// mid-lookup must not cancel it (the checker bounds it).
				ctx := context.WithoutCancel(r.Context())
				return tm.APITransport.TLSA.CheckClient(ctx, peer, "API", clientCert)
			})
			if err != nil {
				// The checker logs a missing TLSA, a mismatch and a
				// failed lookup itself, rate-limited.
				lgApi.Debug(apiName+": client certificate refused", "clientId", clientId, "err", err)
				http.Error(w, apiName+": Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// tlsaVerdictPeer names what a verdict holds for: this peer instance and
// the TLSA set it was checked against. A set replaced by another, or a peer
// removed and created again, is checked afresh.
func tlsaVerdictPeer(peer *transport.Peer) string {
	recs := peer.MechanismTLSA("API").Records
	parts := make([]string, 0, len(recs))
	for _, rr := range recs {
		parts = append(parts, fmt.Sprintf("%d %d %d %s", rr.Usage, rr.Selector, rr.MatchingType, strings.ToLower(rr.Certificate)))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s|%p|%s", peer.ID, peer, strings.Join(parts, ","))
}

// checkClient runs check on cert for peer unless a pass for it still
// holds. A pass is remembered only if the TLSA set held is the one held
// before the check: a set replaced while the check ran (by the check's own
// lookup, or another writer) may not be the set cert was checked against,
// and the next request is checked afresh.
func (v *tlsaVerdicts) checkClient(peer *transport.Peer, cert *x509.Certificate, check func() error) error {
	key := tlsaVerdictPeer(peer)
	if peer.HasMechanismTLSA("API") && v.holds(key, cert) {
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	if tlsaVerdictPeer(peer) == key {
		v.pass(key, cert)
	}
	return nil
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
	now := v.clock()
	v.mu.Lock()
	defer v.mu.Unlock()
	at, ok := v.at[tlsaVerdictKey(peer, cert)]
	return ok && now.Sub(at) < v.hold
}

// pass notes that cert passed for peer now, and forgets verdicts too old to
// hold.
func (v *tlsaVerdicts) pass(peer string, cert *x509.Certificate) {
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
	v.at[tlsaVerdictKey(peer, cert)] = now
}
