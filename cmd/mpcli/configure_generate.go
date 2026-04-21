/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: generation of missing material.
 *
 * Three kinds of "missing file" are generated on demand:
 *
 *   - API keys   — crypto/rand, 32 bytes hex.
 *   - JOSE keys  — via tdns-transport jose backend; written with
 *                  the same comment header and 0600/0644 perms
 *                  as the existing `tdns-cli keys generate` tool.
 *   - TLS certs  — self-signed via `openssl req -x509`, SAN
 *                  derived from the role's identity + listen IP.
 *                  Mirrors tdns/utils/gen-cert.sh logic, called
 *                  non-interactively.
 *
 * Reuse existing material whenever a path is already populated.
 * Rotation (overwriting an existing file) is explicitly out of
 * scope for this tool.
 */
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto"
	_ "github.com/johanix/tdns-transport/v2/crypto/jose"
)

// generateApiKey returns a hex-encoded 32-byte random key.
func generateApiKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// ensureApiKey returns current if non-empty, otherwise a freshly
// generated one.
func ensureApiKey(current string) (string, error) {
	if current != "" {
		return current, nil
	}
	return generateApiKey()
}

// ensureJoseKeypair generates a JOSE keypair at privPath (+
// matching pubPath) if privPath does not already exist. The pub
// path is derived from the priv path by substituting ".priv."
// with ".pub." in the filename.
//
// Returns the pub path (derived or pre-existing), the KeyID for
// display, and a bool indicating whether generation actually ran.
func ensureJoseKeypair(privPath string) (pubPath, keyID string, generated bool, err error) {
	pubPath = derivePubPath(privPath)

	if _, statErr := os.Stat(privPath); statErr == nil {
		// Priv exists — reuse. We don't touch pubPath on reuse.
		return pubPath, "", false, nil
	} else if !os.IsNotExist(statErr) {
		return "", "", false, fmt.Errorf("stat %s: %w", privPath, statErr)
	}

	if err := os.MkdirAll(filepath.Dir(privPath), 0o700); err != nil {
		return "", "", false, fmt.Errorf("mkdir %s: %w", filepath.Dir(privPath), err)
	}

	backend, err := crypto.GetBackend("jose")
	if err != nil {
		return "", "", false, fmt.Errorf("jose backend: %w", err)
	}
	priv, pub, err := backend.GenerateKeypair()
	if err != nil {
		return "", "", false, fmt.Errorf("generate jose keypair: %w", err)
	}
	privBytes, err := backend.SerializePrivateKey(priv)
	if err != nil {
		return "", "", false, fmt.Errorf("serialize priv: %w", err)
	}
	pubBytes, err := backend.SerializePublicKey(pub)
	if err != nil {
		return "", "", false, fmt.Errorf("serialize pub: %w", err)
	}
	defer zero(privBytes)

	keyID = joseKeyID(pubBytes)

	privPretty, err := prettyJSON(privBytes)
	if err != nil {
		return "", "", false, err
	}
	defer zero(privPretty)
	pubPretty, err := prettyJSON(pubBytes)
	if err != nil {
		return "", "", false, err
	}

	header := fmt.Sprintf(`# JOSE Private Key
# KeyID: %s
# Config: long_term_jose_priv_key: %s
# WARNING: This is a PRIVATE KEY. Keep it secret.
#
`, keyID, privPath)
	content := []byte(header + string(privPretty) + "\n")
	defer zero(content)

	f, err := os.OpenFile(privPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", false, fmt.Errorf("create %s: %w", privPath, err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return "", "", false, fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := f.Close(); err != nil {
		return "", "", false, fmt.Errorf("close %s: %w", privPath, err)
	}

	if err := os.WriteFile(pubPath, append(pubPretty, '\n'), 0o644); err != nil {
		return "", "", false, fmt.Errorf("write %s: %w", pubPath, err)
	}

	return pubPath, keyID, true, nil
}

// derivePubPath turns "…/foo.jose.priv.json" into
// "…/foo.jose.pub.json". If ".priv." is absent the path is
// returned with ".pub" appended before the extension.
func derivePubPath(priv string) string {
	if strings.Contains(priv, ".priv.") {
		return strings.Replace(priv, ".priv.", ".pub.", 1)
	}
	ext := filepath.Ext(priv)
	return strings.TrimSuffix(priv, ext) + ".pub" + ext
}

func joseKeyID(pubBytes []byte) string {
	// Match the existing tdns-cli keys generate format for KeyID.
	const n = 8
	if len(pubBytes) < n {
		return "jose_" + hex.EncodeToString(pubBytes)
	}
	h := hex.EncodeToString(pubBytes)
	if len(h) < n {
		return "jose_" + h
	}
	return "jose_" + h[:n]
}

func prettyJSON(raw []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return json.MarshalIndent(v, "", "  ")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ensureTLSCert writes a self-signed cert + key to certPath /
// keyPath if certPath does not already exist.
//
// SAN = DNS:<cn>, DNS:localhost, IP:<listenIP>, IP:127.0.0.1 (deduped).
// The CN is the role identity with the trailing dot stripped.
//
// Requires `openssl` on PATH. Non-interactive.
func ensureTLSCert(certPath, keyPath, identity, listenHostPort string) (generated bool, err error) {
	if _, statErr := os.Stat(certPath); statErr == nil {
		return false, nil
	} else if !os.IsNotExist(statErr) {
		return false, fmt.Errorf("stat %s: %w", certPath, statErr)
	}

	if _, err := exec.LookPath("openssl"); err != nil {
		return false, fmt.Errorf("openssl not found on PATH: %w", err)
	}

	cn := strings.TrimSuffix(identity, ".")
	if cn == "" {
		return false, fmt.Errorf("identity is required for cert CN")
	}

	host, _, splitErr := net.SplitHostPort(listenHostPort)
	if splitErr != nil {
		// Non-fatal: fall back to 127.0.0.1 only.
		host = ""
	}

	dnsNames := dedup([]string{cn, "localhost"})
	ips := dedup(trimEmpty([]string{host, "127.0.0.1"}))

	san := buildSAN(dnsNames, ips)

	for _, p := range []string{certPath, keyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
		}
	}

	tmp, err := os.CreateTemp("", "openssl-san-*.cnf")
	if err != nil {
		return false, fmt.Errorf("tempfile: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	cnf := fmt.Sprintf(`[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req
prompt             = no

[ req_distinguished_name ]
CN = %s

[ v3_req ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = %s
`, cn, san)

	if _, err := tmp.WriteString(cnf); err != nil {
		tmp.Close()
		return false, fmt.Errorf("write openssl cnf: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close openssl cnf: %w", err)
	}

	cmd := exec.Command(
		"openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath,
		"-out", certPath,
		"-days", "3650",
		"-config", tmpName,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("openssl req: %w", err)
	}
	// Private keys should not be world-readable.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return false, fmt.Errorf("chmod %s: %w", keyPath, err)
	}
	return true, nil
}

func buildSAN(dns, ips []string) string {
	var parts []string
	for _, n := range dns {
		parts = append(parts, "DNS:"+n)
	}
	for _, ip := range ips {
		parts = append(parts, "IP:"+ip)
	}
	return strings.Join(parts, ",")
}

func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func trimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}
