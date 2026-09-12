/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Payload crypto for every role, in one place (cleanup plan, step 7).
 *
 * The backend comes from the configuration (multi-provider.crypto_backend,
 * default "jose") through transport's backend registry; nothing here names
 * a backend package. The role decides whose public keys are loaded next to
 * the local key pair and whether a missing one is an error or a warning:
 *
 *   agent, auditor  the combiner's key, when a combiner is configured (error)
 *   combiner        every agent's key (all required; the combiner cannot
 *                   run without them)
 *   signer          every agent's key that is configured and readable
 *                   (a bad one is skipped with a warning)
 *
 * Until step 7 this code existed four times, once per role, each
 * constructing the JOSE backend directly.
 */

package tdnsmp

import (
	"fmt"
	"os"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose" // the default backend registers itself
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var lgCrypto = tdns.Logger("crypto")

// DefaultCryptoBackend is the backend used when the configuration names none.
const DefaultCryptoBackend = "jose"

// cryptoBackend returns the configured payload-crypto backend.
func cryptoBackend(mp *MultiProviderConf) (crypto.Backend, error) {
	name := DefaultCryptoBackend
	if mp != nil && strings.TrimSpace(mp.CryptoBackend) != "" {
		name = strings.ToLower(strings.TrimSpace(mp.CryptoBackend))
	}
	backend, err := crypto.GetBackend(name)
	if err != nil {
		return nil, fmt.Errorf("multi-provider.crypto_backend %q: %w (registered: %s)", name, err, strings.Join(crypto.ListBackends(), ", "))
	}
	return backend, nil
}

// readKeyFile reads a key file and strips the comment header the CLI
// writes above the key material.
func readKeyFile(path, what string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s file not found: %q: %w", what, path, err)
		}
		return nil, fmt.Errorf("read %s %q: %w", what, path, err)
	}
	return tdns.StripKeyFileComments(data), nil
}

// loadLocalKeyPair parses the role's private key and derives its public half.
func loadLocalKeyPair(backend crypto.Backend, path, what string) (crypto.PrivateKey, crypto.PublicKey, error) {
	data, err := readKeyFile(path, what)
	if err != nil {
		return nil, nil, err
	}
	priv, err := backend.ParsePrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", what, err)
	}
	pub, err := backend.PublicFromPrivate(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("derive %s public key: %w", what, err)
	}
	return priv, pub, nil
}

// peerKeySpec is one peer whose public key a role installs for encryption
// and verification. A required key that cannot be loaded fails the role's
// start-up; an optional one is skipped with a warning.
type peerKeySpec struct {
	id       string
	path     string
	what     string
	required bool
}

// peerKeysForRole lists the peers whose keys the role loads.
func peerKeysForRole(mp *MultiProviderConf, role string) ([]peerKeySpec, error) {
	var specs []peerKeySpec
	switch role {
	case roleAgent, roleAuditor:
		if mp.Combiner != nil && strings.TrimSpace(mp.Combiner.LongTermJosePubKey) != "" {
			specs = append(specs, peerKeySpec{
				id:       dns.Fqdn(mp.Combiner.Identity),
				path:     strings.TrimSpace(mp.Combiner.LongTermJosePubKey),
				what:     "combiner public key",
				required: true,
			})
		}
	case roleCombiner:
		if len(mp.Agents) == 0 {
			return nil, fmt.Errorf("multi-provider.agents not configured (need at least one agent)")
		}
		for _, agent := range mp.Agents {
			if agent == nil || strings.TrimSpace(agent.Identity) == "" {
				return nil, fmt.Errorf("multi-provider.agents: agent entry missing required identity field")
			}
			if strings.TrimSpace(agent.LongTermJosePubKey) == "" {
				return nil, fmt.Errorf("multi-provider.agents[%s]: long_term_jose_pub_key not configured", agent.Identity)
			}
			specs = append(specs, peerKeySpec{
				id:       agent.Identity,
				path:     strings.TrimSpace(agent.LongTermJosePubKey),
				what:     fmt.Sprintf("agent %s public key", agent.Identity),
				required: true,
			})
		}
	case roleSigner:
		for i, agent := range mp.Agents {
			if agent == nil || strings.TrimSpace(agent.LongTermJosePubKey) == "" {
				continue
			}
			id := agent.Identity
			if id == "" {
				id = fmt.Sprintf("agent-%d", i)
			}
			specs = append(specs, peerKeySpec{
				id:       id,
				path:     strings.TrimSpace(agent.LongTermJosePubKey),
				what:     fmt.Sprintf("agent %s public key", id),
				required: false,
			})
		}
	default:
		return nil, fmt.Errorf("no payload crypto for role %q", role)
	}
	return specs, nil
}

// newPayloadCrypto builds the role's PayloadCrypto: the configured backend,
// the local key pair from long_term_jose_priv_key, and the peers' keys the
// role needs. The caller decides whether crypto is configured at all (a
// role without a private key runs without payload crypto).
func newPayloadCrypto(mp *MultiProviderConf, role string) (*transport.PayloadCrypto, error) {
	if mp == nil {
		return nil, fmt.Errorf("multi-provider config is not set")
	}
	backend, err := cryptoBackend(mp)
	if err != nil {
		return nil, err
	}

	privPath := strings.TrimSpace(mp.LongTermJosePrivKey)
	priv, pub, err := loadLocalKeyPair(backend, privPath, role+" private key")
	if err != nil {
		return nil, err
	}

	pc, err := transport.NewPayloadCrypto(&transport.PayloadCryptoConfig{
		Backend: backend,
		Enabled: true,
	})
	if err != nil {
		return nil, fmt.Errorf("create PayloadCrypto: %w", err)
	}
	pc.SetLocalKeys(priv, pub)
	lgCrypto.Info("loaded local key", "role", role, "backend", backend.Name(), "path", privPath)

	specs, err := peerKeysForRole(mp, role)
	if err != nil {
		return nil, err
	}
	for _, spec := range specs {
		data, err := readKeyFile(spec.path, spec.what)
		if err == nil {
			var key crypto.PublicKey
			key, err = backend.ParsePublicKey(data)
			if err != nil {
				err = fmt.Errorf("parse %s: %w", spec.what, err)
			} else {
				pc.AddPeerKey(spec.id, key)
				pc.AddPeerVerificationKey(spec.id, key)
				lgCrypto.Info("loaded peer key", "role", role, "peer", spec.id, "path", spec.path)
				continue
			}
		}
		if spec.required {
			return nil, err
		}
		lgCrypto.Warn("peer key not loaded, encryption to this peer disabled", "role", role, "peer", spec.id, "err", err)
	}

	return pc, nil
}
