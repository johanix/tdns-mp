/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"fmt"
	"os"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto/jose"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
)

var lgCrypto = tdns.Logger("crypto")

// StripKeyFileComments removes lines that are empty or start with '#' (after trim),
// so JWK/key files with comment headers parse as valid JSON.
func StripKeyFileComments(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
		}
	}
	return []byte(strings.Join(out, "\n"))
}

func InitCombinerCrypto(conf *tdns.Config) (*transport.SecurePayloadWrapper, error) {
	backend := jose.NewBackend()
	privKeyPath := strings.TrimSpace(conf.MultiProvider.LongTermJosePrivKey)
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("combiner private key file not found: %q: %w", privKeyPath, err)
		}
		return nil, fmt.Errorf("failed to read combiner private key %q: %w", privKeyPath, err)
	}
	privKeyData = StripKeyFileComments(privKeyData)
	localPrivKey, err := backend.ParsePrivateKey(privKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse combiner private key: %w", err)
	}
	lgCrypto.Info("loaded combiner private key", "path", privKeyPath)
	joseBackend, ok := backend.(*jose.Backend)
	if !ok {
		return nil, fmt.Errorf("backend is not JOSE")
	}
	localPubKey, err := joseBackend.PublicFromPrivate(localPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create PayloadCrypto: %w", err)
	}
	pc.SetLocalKeys(localPrivKey, localPubKey)
	if len(conf.MultiProvider.Agents) == 0 {
		return nil, fmt.Errorf("multi-provider.agents not configured (need at least one agent)")
	}
	for _, agent := range conf.MultiProvider.Agents {
		if strings.TrimSpace(agent.Identity) == "" {
			return nil, fmt.Errorf("multi-provider.agents: agent entry missing required identity field")
		}
		if strings.TrimSpace(agent.LongTermJosePubKey) == "" {
			return nil, fmt.Errorf("multi-provider.agents[%s]: long_term_jose_pub_key not configured", agent.Identity)
		}
		agentPubKeyPath := strings.TrimSpace(agent.LongTermJosePubKey)
		agentPubKeyData, err := os.ReadFile(agentPubKeyPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("agent public key file not found for %s: %q: %w", agent.Identity, agentPubKeyPath, err)
			}
			return nil, fmt.Errorf("failed to read agent public key for %s: %q: %w", agent.Identity, agentPubKeyPath, err)
		}
		agentPubKeyData = StripKeyFileComments(agentPubKeyData)
		agentVerifyKey, err := backend.ParsePublicKey(agentPubKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse agent public key for %s: %w", agent.Identity, err)
		}
		pc.AddPeerKey(agent.Identity, agentVerifyKey)
		pc.AddPeerVerificationKey(agent.Identity, agentVerifyKey)
		lgCrypto.Info("loaded public key for agent", "agent", agent.Identity, "path", agentPubKeyPath)
	}
	return transport.NewSecurePayloadWrapper(pc), nil
}
