/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
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

// InitializeCombinerAsPeer registers the combiner as a virtual peer in the AgentRegistry
// so that the HsyncEngine's Beat mechanism will automatically send heartbeats to it.
// This ensures we verify combiner connectivity and get early warning of communication issues.
func (ar *AgentRegistry) InitializeCombinerAsPeer(conf *Config) error {
	mp := conf.MpConfig()
	if mp == nil || mp.Combiner == nil {
		lgCombiner.Debug("no combiner configured, skipping peer init")
		return nil
	}

	if mp.Combiner.Address == "" {
		lgCombiner.Debug("combiner address not configured, skipping peer init")
		return nil
	}

	// Parse combiner address
	host, portStr, err := net.SplitHostPort(mp.Combiner.Address)
	if err != nil {
		return fmt.Errorf("invalid combiner address %q: %w", mp.Combiner.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in combiner address %q", mp.Combiner.Address)
	}

	// Use configured combiner identity, or default to "combiner" for backwards compatibility
	combinerID := AgentId("combiner")
	if mp.Combiner.Identity != "" {
		combinerID = AgentId(mp.Combiner.Identity)
		lgCombiner.Info("using configured combiner identity", "identity", combinerID)
	} else {
		lgCombiner.Warn("no combiner identity configured, using default 'combiner' (agents with chunk_mode=query will fail)")
	}

	// Create an agent entry for the combiner
	combinerAgent := &Agent{
		Identity:    combinerID,
		PeerID:      string(combinerID),
		DnsMethod:   true,  // Combiner supports DNS transport (CHUNK)
		ApiMethod:   false, // API transport added when combiner.api is configured
		IsInfraPeer: true,  // handled by StartInfraBeatLoop, not SendHeartbeats
		DnsDetails: &AgentDetails{
			State:           AgentStateOperational, // Start as operational
			HelloTime:       time.Now(),
			LastContactTime: time.Now(),
		},
		ApiDetails: &AgentDetails{
			State: AgentStateNeeded, // Not using API transport
		},
		Zones:     make(map[ZoneName]bool),
		State:     AgentStateOperational,
		LastState: time.Now(),
	}

	// Register in AgentRegistry with configured identity
	ar.S.Set(combinerID, combinerAgent)
	lgCombiner.Info("registered combiner as virtual peer", "identity", combinerID, "address", mp.Combiner.Address)

	// S2: populate the transport.Peer address at registration so the
	// transport store is the SOLE address source (the GetOrCreatePeer
	// AgentDetails->transport restore is removed). Config-infra peers are
	// never discovered via DNS, so this is their only address source.
	if ar.TransportManager != nil {
		cpeer := ar.TransportManager.PeerRegistry.GetOrCreate(string(combinerID))
		cpeer.SetDiscoveryAddress(&transport.Address{
			Host:      host,
			Port:      uint16(port),
			Transport: "udp",
		})
		cpeer.DNSEndpoint = fmt.Sprintf("dns://%s:%d/", host, port)
	}

	// Load and register combiner's public key for encrypted communication
	// If combiner is configured, encryption is MANDATORY
	if mp.Combiner.LongTermJosePubKey == "" {
		return fmt.Errorf("combiner configured but multi-provider.combiner.long_term_jose_pub_key is not set - encrypted communication to combiner is mandatory")
	}

	if conf.InternalMp.TransportManager == nil || conf.InternalMp.TransportManager.DNSTransport == nil || conf.InternalMp.TransportManager.DNSTransport.SecureWrapper == nil {
		return fmt.Errorf("TransportManager or DNSTransport or SecureWrapper not initialized - cannot load combiner public key")
	}

	// Load combiner's public key from file
	payloadCrypto := conf.InternalMp.TransportManager.DNSTransport.SecureWrapper.GetCrypto()
	if payloadCrypto == nil || payloadCrypto.Backend == nil {
		return fmt.Errorf("PayloadCrypto or Backend not initialized - cannot load combiner public key")
	}

	combinerPubKeyData, err := os.ReadFile(mp.Combiner.LongTermJosePubKey)
	if err != nil {
		return fmt.Errorf("failed to read combiner public key from %s: %w", mp.Combiner.LongTermJosePubKey, err)
	}

	combinerPubKey, err := payloadCrypto.Backend.ParsePublicKey(combinerPubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse combiner public key from %s: %w", mp.Combiner.LongTermJosePubKey, err)
	}

	// Register combiner's public key for encryption and signature verification
	payloadCrypto.AddPeerKey(string(combinerID), combinerPubKey)
	payloadCrypto.AddPeerVerificationKey(string(combinerID), combinerPubKey)

	lgCombiner.Info("loaded combiner public key", "path", mp.Combiner.LongTermJosePubKey)

	// Perform initial connectivity check
	if err := performCombinerConnectivityCheck(conf); err != nil {
		lgCombiner.Warn("initial connectivity check failed, heartbeats will continue to retry", "err", err)
	} else {
		lgCombiner.Info("initial connectivity check passed")
	}

	return nil
}

// performCombinerConnectivityCheck verifies the combiner is reachable via DNS ping.
func performCombinerConnectivityCheck(conf *Config) error {
	if conf.InternalMp.TransportManager == nil {
		return fmt.Errorf("TransportManager not available")
	}

	mp := conf.MpConfig()

	// Parse combiner address
	host, portStr, err := net.SplitHostPort(mp.Combiner.Address)
	if err != nil {
		return fmt.Errorf("invalid combiner address %q: %w", mp.Combiner.Address, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in combiner address %q", mp.Combiner.Address)
	}

	// Create peer for combiner — use configured identity so CHUNK qname matches
	combinerID := "combiner"
	if mp.Combiner.Identity != "" {
		combinerID = dns.Fqdn(mp.Combiner.Identity)
	}
	peer := transport.NewPeer(combinerID)
	peer.SetDiscoveryAddress(&transport.Address{
		Host:      host,
		Port:      uint16(port),
		Transport: "udp",
	})

	// Send ping with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pingResp, err := conf.InternalMp.TransportManager.SendPing(ctx, peer)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	if !pingResp.OK {
		return fmt.Errorf("combiner did not acknowledge ping (responder: %s)", pingResp.ResponderID)
	}

	return nil
}
