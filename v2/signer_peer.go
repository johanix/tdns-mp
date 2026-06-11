/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Registers the signer (tdns-auth) as a virtual peer in the agent's AgentRegistry,
 * mirroring InitializeCombinerAsPeer. This allows the signer to appear in
 * "agent peer list" and enables agent->signer DNS CHUNK ping.
 */

package tdnsmp

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	"github.com/miekg/dns"
)

// InitializeSignerAsPeer registers the signer as a virtual peer in the AgentRegistry
// so that it shows up in "agent peer list" and can be pinged via "agent peer ping".
// Mirrors InitializeCombinerAsPeer for the signer role.
func (ar *AgentRegistry) InitializeSignerAsPeer(conf *Config) error {
	mp := conf.MpConfig()
	if mp == nil || mp.Signer == nil {
		lgSigner.Debug("no signer configured, skipping peer registration")
		return nil
	}

	if mp.Signer.Address == "" {
		lgSigner.Debug("signer address not configured, skipping peer registration")
		return nil
	}

	// Parse signer address
	host, portStr, err := net.SplitHostPort(mp.Signer.Address)
	if err != nil {
		return fmt.Errorf("invalid signer address %q: %w", mp.Signer.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in signer address %q", mp.Signer.Address)
	}

	signerID := AgentId("signer")
	if mp.Signer.Identity != "" {
		signerID = AgentId(dns.Fqdn(mp.Signer.Identity))
		lgSigner.Debug("using configured signer identity", "identity", signerID)
	} else {
		lgSigner.Warn("no signer identity configured, using default 'signer'")
	}

	// Create an agent entry for the signer
	signerAgent := &Agent{
		Identity:    signerID,
		PeerID:      string(signerID),
		DnsMethod:   true,  // Signer uses DNS transport (CHUNK)
		ApiMethod:   false, // No API transport for signer
		IsInfraPeer: true,  // handled by StartInfraBeatLoop, not SendHeartbeats
		DnsDetails: &AgentDetails{
			State:           AgentStateOperational,
			HelloTime:       time.Now(),
			LastContactTime: time.Now(),
		},
		ApiDetails: &AgentDetails{
			State: AgentStateNeeded,
		},
		Zones:     make(map[ZoneName]bool),
		State:     AgentStateOperational,
		LastState: time.Now(),
	}

	// Register in AgentRegistry
	ar.S.Set(signerID, signerAgent)
	lgSigner.Info("registered signer as virtual peer", "identity", signerID, "address", mp.Signer.Address)

	// S2: populate the transport.Peer address at registration so the
	// transport store is the SOLE address source (the GetOrCreatePeer
	// AgentDetails->transport restore is removed). Config-infra peers are
	// never discovered via DNS, so this is their only address source.
	if ar.TransportManager != nil {
		speer := ar.TransportManager.PeerRegistry.GetOrCreate(string(signerID))
		speer.SetDiscoveryAddress(&transport.Address{
			Host:      host,
			Port:      uint16(port),
			Transport: "udp",
		})
		speer.DNSEndpoint = fmt.Sprintf("dns://%s:%d/", host, port)
	}

	// Load and register signer's public key for encrypted communication
	if mp.Signer.LongTermJosePubKey == "" {
		return fmt.Errorf("signer configured but multi-provider.signer.long_term_jose_pub_key is not set - encrypted communication to signer is mandatory")
	}

	if conf.InternalMp.TransportManager == nil || conf.InternalMp.TransportManager.DNSTransport == nil || conf.InternalMp.TransportManager.DNSTransport.SecureWrapper == nil {
		return fmt.Errorf("TransportManager or DNSTransport or SecureWrapper not initialized - cannot load signer public key")
	}

	payloadCrypto := conf.InternalMp.TransportManager.DNSTransport.SecureWrapper.GetCrypto()
	if payloadCrypto == nil || payloadCrypto.Backend == nil {
		return fmt.Errorf("PayloadCrypto or Backend not initialized - cannot load signer public key")
	}

	signerPubKeyData, err := os.ReadFile(mp.Signer.LongTermJosePubKey)
	if err != nil {
		return fmt.Errorf("failed to read signer public key from %s: %w", mp.Signer.LongTermJosePubKey, err)
	}

	signerPubKey, err := payloadCrypto.Backend.ParsePublicKey(signerPubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse signer public key from %s: %w", mp.Signer.LongTermJosePubKey, err)
	}

	payloadCrypto.AddPeerKey(string(signerID), signerPubKey)
	payloadCrypto.AddPeerVerificationKey(string(signerID), signerPubKey)

	lgSigner.Info("loaded signer public key", "path", mp.Signer.LongTermJosePubKey)

	// Perform initial connectivity check
	if err := performSignerConnectivityCheck(conf); err != nil {
		lgSigner.Warn("initial connectivity check failed, signer pings will work once reachable", "err", err)
	} else {
		lgSigner.Info("initial signer connectivity check passed")
	}

	return nil
}

// performSignerConnectivityCheck verifies the signer is reachable via DNS ping.
func performSignerConnectivityCheck(conf *Config) error {
	if conf.InternalMp.TransportManager == nil {
		return fmt.Errorf("TransportManager not available")
	}

	mp := conf.MpConfig()

	host, portStr, err := net.SplitHostPort(mp.Signer.Address)
	if err != nil {
		return fmt.Errorf("invalid signer address %q: %w", mp.Signer.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in signer address %q", mp.Signer.Address)
	}

	signerID := "signer"
	if mp.Signer.Identity != "" {
		signerID = dns.Fqdn(mp.Signer.Identity)
	}
	peer := transport.NewPeer(signerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pingResp, err := conf.InternalMp.TransportManager.SendPing(ctx, peer)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	if !pingResp.OK {
		return fmt.Errorf("signer did not acknowledge ping (responder: %s)", pingResp.ResponderID)
	}

	return nil
}
