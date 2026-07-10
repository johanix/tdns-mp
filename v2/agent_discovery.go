/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent discovery: DNS-based lookup of agent contact information and keys.
 * Allows agents to dynamically discover peers by identity without prior configuration.
 */

package tdnsmp

import (
	"context"
	"crypto"
	"fmt"
	"net/url"
	"strconv"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// AgentDiscoveryResult holds the result of discovering an agent.
type AgentDiscoveryResult struct {
	Identity     string
	APIUri       string           // Base URI from URI record (e.g., https://agent.example.com:8443/api)
	DNSUri       string           // DNS endpoint if discovered
	JWKData      string           // Base64url-encoded JWK (preferred)
	PublicKey    crypto.PublicKey // Decoded public key from JWK
	KeyAlgorithm string           // Algorithm from JWK (e.g., "ES256")
	LegacyKeyRR  *dns.KEY         // Legacy KEY record (fallback if no JWK)
	TLSA         *dns.TLSA        // TLSA record for TLS verification
	APIAddresses []string         // IP addresses for API service from SVCB
	DNSAddresses []string         // IP addresses for DNS service from SVCB
	Port         uint16           // Port from URI record
	Error        error            // Any error during discovery
	Partial      bool             // True if some records were found but discovery incomplete
}

// DiscoverAgentAPI performs DNS-based discovery of an agent's API transport.
//  1. URI record at _https._tcp.<identity> → get API endpoint URI and port
//  2. SVCB record at api.<identity> → get ipv4hint/ipv6hint addresses
//  3. TLSA record at _<port>._tcp.api.<identity> → get TLS certificate for verification
func (imr *Imr) DiscoverAgentAPI(ctx context.Context, identity string, result *AgentDiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	apiUri, apiHost, apiPort, err := imr.LookupAgentAPIEndpoint(ctx, identity)
	if err == nil {
		result.APIUri = apiUri
		result.Port = apiPort

		// Look up SVCB at api.<identity> to get IP addresses
		apiServiceName := "api." + identity
		addresses, err := imr.LookupServiceAddresses(ctx, apiServiceName)
		if err == nil {
			result.APIAddresses = addresses
		} else {
			lgAgent.Debug("no SVCB record for API service", "service", apiServiceName, "err", err)
			result.Partial = true
		}

		// Look up TLSA at _<port>._tcp.api.<identity> for TLS verification
		tlsaRR, err := imr.LookupAgentTLSA(ctx, apiServiceName, apiPort)
		if err == nil {
			result.TLSA = tlsaRR
		} else {
			lgAgent.Debug("no TLSA record for API service", "err", err)
			result.Partial = true
		}

		lgAgent.Info("found API endpoint", "uri", apiUri, "host", apiHost)
	} else {
		lgAgent.Debug("no API URI record found", "err", err)
		result.Partial = true
	}
}

// DiscoverAgentDNS performs DNS-based discovery of an agent's DNS transport.
//  1. URI record at _dns._tcp.<identity> → get DNS endpoint URI and port
//  2. SVCB record at dns.<identity> → get ipv4hint/ipv6hint addresses
//  3. JWK record at dns.<identity> → get JOSE/HPKE public key (preferred)
//  4. KEY record at dns.<identity> → get SIG(0) public key (legacy fallback if no JWK)
func (imr *Imr) DiscoverAgentDNS(ctx context.Context, identity string, result *AgentDiscoveryResult) {
	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		result.Partial = true
		return
	}
	identity = dns.Fqdn(identity)

	dnsUri, dnsHost, dnsPort, err := imr.LookupAgentDNSEndpoint(ctx, identity)
	if err == nil {
		result.DNSUri = dnsUri

		// Look up SVCB at dns.<identity> to get IP addresses
		dnsServiceName := "dns." + identity
		addresses, err := imr.LookupServiceAddresses(ctx, dnsServiceName)
		if err == nil {
			result.DNSAddresses = addresses
		} else {
			lgAgent.Warn("SVCB lookup failed for DNS service", "service", dnsServiceName, "err", err)
			result.Partial = true
		}

		// Look up JWK at dns.<identity> for JOSE/HPKE public key
		jwkData, publicKey, algorithm, err := imr.LookupAgentJWK(ctx, identity)
		if err == nil {
			result.JWKData = jwkData
			result.PublicKey = publicKey
			result.KeyAlgorithm = algorithm
			lgAgent.Info("found JWK record", "identity", identity, "algorithm", algorithm)
		} else {
			lgAgent.Warn("JWK lookup failed", "identity", identity, "err", err)

			// Fallback to KEY record for legacy support
			keyRR, err := imr.LookupAgentKEY(ctx, identity)
			if err == nil {
				result.LegacyKeyRR = keyRR
				lgAgent.Info("using legacy KEY record", "identity", identity, "algorithm", keyRR.Algorithm)
			} else {
				lgAgent.Warn("KEY lookup failed (legacy fallback)", "identity", identity, "err", err)
				result.Partial = true
			}
		}

		lgAgent.Info("found DNS endpoint", "uri", dnsUri, "host", dnsHost, "port", dnsPort)
	} else {
		lgAgent.Debug("no DNS URI record found (optional)", "err", err)
	}
}

// DiscoverAgent performs DNS-based discovery of an agent's contact
// information, but only for transports the local agent itself supports
// (apiSupported/dnsSupported). An agent only establishes connectivity
// over mechanisms it can actually use, so probing for an unsupported
// transport is pointless: it emits failing lookups (e.g. _https._tcp.<id>
// URI on a DNS-only fleet) and sets a spurious result.Partial. Each
// supported leg is run via DiscoverAgentAPI / DiscoverAgentDNS.
func (imr *Imr) DiscoverAgent(ctx context.Context, identity string, apiSupported, dnsSupported bool) *AgentDiscoveryResult {
	result := &AgentDiscoveryResult{
		Identity: identity,
	}

	if imr == nil || imr.Imr == nil {
		result.Error = fmt.Errorf("IMR engine not initialized")
		return result
	}

	if apiSupported {
		imr.DiscoverAgentAPI(ctx, identity, result)
	}
	if dnsSupported {
		imr.DiscoverAgentDNS(ctx, identity, result)
	}

	// Check if we have enough information to contact the agent
	if result.APIUri == "" && result.DNSUri == "" {
		result.Error = fmt.Errorf("no contact endpoints found (no API or DNS URI records)")
		return result
	}

	lgAgent.Info("discovery complete", "identity", identity, "apiUri", result.APIUri, "dnsUri", result.DNSUri)
	return result
}

// RegisterDiscoveredAgent adds a discovered agent to the PeerRegistry and optionally to AgentRegistry.
func (tm *MPTransportBridge) RegisterDiscoveredAgent(result *AgentDiscoveryResult) error {
	if result.Error != nil {
		return fmt.Errorf("cannot register agent with discovery error: %w", result.Error)
	}

	// Get or create peer in PeerRegistry. The top-level peer State is set
	// to KNOWN further down, but ONLY for a mechanism that actually became
	// usable (URI + resolved address) — see the apiUsable/dnsUsable blocks.
	// Setting it unconditionally here made EffectiveState() report KNOWN
	// for an unreachable peer (no address) while peer list correctly showed
	// the per-mechanism NEEDED — a KNOWN/NEEDED contradiction (Fix C).
	peer := tm.PeerRegistry.GetOrCreate(result.Identity)

	// Register API transport address
	if result.APIUri != "" {
		parsed, err := url.Parse(result.APIUri)
		if err != nil {
			return fmt.Errorf("invalid API URI %q: %w", result.APIUri, err)
		}

		port := uint16(443) // default
		if parsed.Port() != "" {
			p, err := strconv.Atoi(parsed.Port())
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid API URI port %q: %v", parsed.Port(), err)
			}
			port = uint16(p)
		}

		// Use discovered IP address instead of hostname (DNS-34 fix)
		// Non-fatal: skip API peer registration if SVCB addresses are missing,
		// but continue to DNS and AgentRegistry update.
		if len(result.APIAddresses) == 0 {
			lgAgent.Warn("no SVCB addresses for API transport, skipping API peer registration", "identity", result.Identity)
		} else {
			host := result.APIAddresses[0]
			lgAgent.Debug("using discovered IP for API transport", "host", host)

			addr := &transport.Address{
				Host:      host,
				Port:      port,
				Transport: "https",
				Path:      parsed.Path,
			}
			peer.SetDiscoveryAddress(addr)
			peer.APIEndpoint = result.APIUri
			peer.PreferredTransport = "API"

			lgAgent.Info("registered peer with API endpoint", "identity", result.Identity, "endpoint", result.APIUri, "address", host, "port", port)
		}
	}

	// Register DNS transport address (DNS-33 fix: NOT else if - both can exist)
	if result.DNSUri != "" {
		parsed, err := url.Parse(result.DNSUri)
		if err != nil {
			return fmt.Errorf("invalid DNS URI %q: %w", result.DNSUri, err)
		}

		port := uint16(53) // default DNS port
		if parsed.Port() != "" {
			p, err := strconv.Atoi(parsed.Port())
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid DNS URI port %q: %v", parsed.Port(), err)
			}
			port = uint16(p)
		}

		// Use discovered IP address instead of hostname (DNS-34 fix)
		// Non-fatal: skip DNS peer registration if SVCB addresses are missing,
		// but continue to AgentRegistry update.
		if len(result.DNSAddresses) == 0 {
			lgAgent.Warn("no SVCB addresses for DNS transport, skipping DNS peer registration", "identity", result.Identity)
		} else {
			host := result.DNSAddresses[0]
			lgAgent.Debug("using discovered IP for DNS transport", "host", host)

			addr := &transport.Address{
				Host:      host,
				Port:      port,
				Transport: "udp",
			}

			// If both transports exist, DNS address goes to DiscoveryAddress (preferred for ping)
			// API address was already set above but will be overwritten
			peer.SetDiscoveryAddress(addr)
			peer.DNSEndpoint = result.DNSUri // display/diagnostics (S2)
			peer.PreferredTransport = "DNS"

			lgAgent.Info("registered peer with DNS endpoint", "identity", result.Identity, "endpoint", result.DNSUri, "address", host, "port", port)
		}
	}

	// Store TLSA for TLS verification
	if result.TLSA != nil {
		peer.TLSARecord = []byte(result.TLSA.Certificate) // Store the certificate data
	}

	// Store JWK public key if available (preferred)
	if result.JWKData != "" && result.PublicKey != nil {
		// Add peer's public key to PayloadCrypto for encryption
		if tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
			payloadCrypto := tm.DNSTransport.SecureWrapper.GetCrypto()
			if payloadCrypto != nil && payloadCrypto.Backend != nil {
				// Wrap the stdlib crypto.PublicKey in a backend-specific wrapper
				// The backend can reconstruct its own PublicKey type from the raw key
				wrappedKey, err := payloadCrypto.Backend.PublicKeyFromStdlib(result.PublicKey)
				if err != nil {
					lgAgent.Warn("failed to wrap public key", "identity", result.Identity, "err", err)
				} else {
					payloadCrypto.AddPeerKey(result.Identity, wrappedKey)
					payloadCrypto.AddPeerVerificationKey(result.Identity, wrappedKey)
					lgAgent.Info("added JWK public key to PayloadCrypto", "identity", result.Identity, "algorithm", result.KeyAlgorithm)
				}
			} else {
				lgAgent.Warn("cannot add peer key - PayloadCrypto not configured")
			}
		} else {
			lgAgent.Warn("cannot add peer key - SecureWrapper not configured")
		}
	}

	// Verify that a verification key was actually registered.
	// If no JWK or KEY was found, the peer is unusable for encrypted communication.
	hasVerificationKey := false
	if tm.DNSTransport != nil && tm.DNSTransport.SecureWrapper != nil {
		if pc := tm.DNSTransport.SecureWrapper.GetCrypto(); pc != nil {
			_, hasVerificationKey = pc.GetPeerVerificationKey(result.Identity)
		}
	}
	if !hasVerificationKey {
		return fmt.Errorf("discovery for %s found endpoint but no verification key (JWK/KEY lookup failed)", result.Identity)
	}

	// Also add to AgentRegistry if available (for backward compatibility)
	if tm.agentRegistry != nil {
		agent := tm.agentRegistry.agentViewForIdentity(AgentId(result.Identity),
			tm.isTransportSupported("api"), tm.isTransportSupported("dns"))

		// Update agent details — only set state to KNOWN if not already beyond it.
		// Re-discovery must not regress an OPERATIONAL or INTRODUCED transport.
		// A transport is USABLE only with both a URI and a resolved
		// address (see the DNS branch below for the full rationale).
		apiUsable := result.APIUri != "" && len(result.APIAddresses) > 0
		if apiUsable {
			// Address/URI live on transport.Peer (peer.APIEndpoint + the
			// API mechanism address, set on the transport side above).
			peer.SetMechanismContactInfo("API", "complete")
			// END.0: promote the canonical API mechanism state to KNOWN
			// (guarded: do not regress an already-established mechanism). This
			// is the per-mechanism discovery-phase write the send gates read.
			if raw, ok := peer.MechanismRawState("API"); !ok || raw <= transport.PeerStateNeeded {
				peer.SetMechanismState("API", transport.PeerStateKnown, "discovered via DNS (API usable)")
			}
			if peer.GetState() < transport.PeerStateKnown {
				peer.SetState(transport.PeerStateKnown, "discovered via DNS (API usable)")
			}
			// Phase 2.5: crypto lives on transport.Peer's per-mechanism
			// slots (self-locking). Capability flag under the peer lock.
			peer.SetMechanismTLSA("API", result.TLSA)
			agent.Mu.Lock()
			agent.ApiMethod = true
			agent.Mu.Unlock()
		} else if result.APIUri != "" {
			// URI found but no resolved address: keep retrying, leave a
			// not-yet-established peer NEEDED, do not advertise an unusable
			// URL (the transport side withholds the address), and do not
			// regress an already-established peer.
			agent.Mu.Lock()
			agent.ApiMethod = true
			agent.Mu.Unlock()
			apiSt, _ := mechStateForGate(peer, "API")
			lgAgent.Warn("API endpoint URI found but no resolved address; not marking usable",
				"identity", result.Identity, "uri", result.APIUri, "state", AgentStateToString[apiSt])
		} else {
			// No API endpoint found — clear the flag so DiscoveryRetrierNG
			// doesn't perpetually retry discovery for a non-existent transport.
			agent.Mu.Lock()
			agent.ApiMethod = false
			agent.Mu.Unlock()
		}
		// A transport is USABLE only if we resolved BOTH its URI and an
		// address to send to. A URI with no resolved address (e.g. the
		// SVCB/IP lookup at dns.<identity> returned NXDOMAIN) is NOT a
		// usable endpoint: marking it "complete"/KNOWN strands the peer
		// looking operational while every send fails "no address
		// available". In that case keep the mechanism NEEDED so the
		// retrier revisits it, and do not advertise a contact URL.
		dnsUsable := result.DNSUri != "" && len(result.DNSAddresses) > 0
		if dnsUsable {
			// Address/URI live on transport.Peer (peer.DNSEndpoint + the
			// DNS mechanism address, set on the transport side above).
			peer.SetMechanismContactInfo("DNS", "complete")
			// END.0: promote the canonical DNS mechanism state to KNOWN
			// (guarded against regression). The send gates read this.
			if raw, ok := peer.MechanismRawState("DNS"); !ok || raw <= transport.PeerStateNeeded {
				peer.SetMechanismState("DNS", transport.PeerStateKnown, "discovered via DNS (DNS usable)")
			}
			if peer.GetState() < transport.PeerStateKnown {
				peer.SetState(transport.PeerStateKnown, "discovered via DNS (DNS usable)")
			}

			// Phase 2.5: crypto lives on transport.Peer's per-mechanism
			// slots. JWK only when discovered (re-discovery must not wipe a
			// previous JWK with an empty result); KEY record replace-style
			// (legacy fallback).
			if result.JWKData != "" {
				peer.SetMechanismJWK("DNS", result.JWKData, result.KeyAlgorithm)
			}
			peer.SetMechanismKeyRR("DNS", result.LegacyKeyRR)
			agent.Mu.Lock()
			agent.DnsMethod = true
			agent.Mu.Unlock()
		} else if result.DNSUri != "" {
			// URI found but no resolved address. Keep DnsMethod enabled so
			// the retrier keeps trying. Leave a not-yet-established peer
			// NEEDED; do not advertise a contact URL (the transport side
			// withholds the address). Do NOT regress an already-established
			// peer on a transient address-less round — its prior good
			// address/state stand until liveness demotes it (Fix B).
			agent.Mu.Lock()
			agent.DnsMethod = true
			agent.Mu.Unlock()
			dnsSt, _ := mechStateForGate(peer, "DNS")
			lgAgent.Warn("DNS endpoint URI found but no resolved address; not marking usable",
				"identity", result.Identity, "uri", result.DNSUri, "state", AgentStateToString[dnsSt])
		} else {
			// No DNS endpoint found — clear the flag so DiscoveryRetrierNG
			// doesn't perpetually retry discovery for a non-existent transport.
			agent.Mu.Lock()
			agent.DnsMethod = false
			agent.Mu.Unlock()
		}

		// E1.b: no trailing ar.S.Set — the view is already in the map (shared
		// pointer); the writes above mutated it in place.
		lgAgent.Debug("agent view updated in AgentRegistry", "identity", result.Identity)
	}

	return nil
}

// DiscoverAndRegisterAgent performs discovery and registration in one step.
func (tm *MPTransportBridge) DiscoverAndRegisterAgent(ctx context.Context, identity string) error {
	lgAgent.Info("starting discovery for agent", "identity", identity)

	// Get IMR engine via injected callback (late-binding: IMR starts asynchronously)
	if tm.getImrEngine == nil {
		return fmt.Errorf("IMR engine not configured for this TransportManager")
	}
	imr := tm.getImrEngine()
	if imr == nil || imr.Imr == nil || imr.Cache == nil {
		return fmt.Errorf("IMR engine not available for discovery (not yet started)")
	}

	// Only discover transports this agent itself supports (an agent
	// establishes connectivity over mechanisms it can actually use).
	result := imr.DiscoverAgent(ctx, identity, tm.isTransportSupported("api"), tm.isTransportSupported("dns"))
	if result.Error != nil {
		return fmt.Errorf("discovery failed for %s: %w", identity, result.Error)
	}

	if result.Partial {
		lgAgent.Warn("partial discovery (some records missing)", "identity", identity)
	}

	err := tm.RegisterDiscoveredAgent(result)
	if err != nil {
		return fmt.Errorf("failed to register discovered agent %s: %w", identity, err)
	}

	lgAgent.Info("successfully discovered and registered agent", "identity", identity)
	return nil
}
