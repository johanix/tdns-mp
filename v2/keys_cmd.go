/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * JOSE keypair CLI (generate, show). Used by CLI commands that
 * manage long_term_jose_priv_key for any role that publishes
 * JWK records.
 *
 * Loads just the multi-provider: subtree of the server's YAML
 * config — does not invoke ParseConfig and does not depend on
 * tdns.Config.MultiProvider (which is removed in bite 9b).
 */

package tdnsmp

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/johanix/tdns-transport/v2/crypto"
	tdns "github.com/johanix/tdns/v2"
	"gopkg.in/yaml.v3"
)

// LoadMpConfigForKeys reads the given YAML config file and decodes
// just the multi-provider: subtree into a tdnsmp.MultiProviderConf.
// Used by CLI keys commands to read long_term_jose_priv_key without
// invoking ParseConfig.
//
// Returns nil, nil when the config file has no multi-provider: block
// (caller decides whether that's an error).
func LoadMpConfigForKeys(path string) (*MultiProviderConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	// Pointer field distinguishes "no multi-provider: section" from
	// "section present but zero-valued".
	var raw struct {
		MultiProvider *MultiProviderConf `yaml:"multi-provider"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse multi-provider section of %q: %w", path, err)
	}
	return raw.MultiProvider, nil
}

// RunKeysCmd runs the "keys" subcommand (generate | show). The
// caller (a cobra command) is expected to pass a valid subcommand;
// arg validation lives in the cobra layer.
func RunKeysCmd(mp *MultiProviderConf, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing subcommand (generate or show)")
	}

	backend, err := cryptoBackend(mp)
	if err != nil {
		return err
	}

	switch args[0] {
	case "generate":
		return runKeysGenerate(mp, backend, args[1:])
	case "show":
		return runKeysShow(mp, backend, args[1:])
	default:
		return fmt.Errorf("unknown keys command: %q", args[0])
	}
}

func runKeysGenerate(mp *MultiProviderConf, backend crypto.Backend, args []string) error {
	fs := flag.NewFlagSet("keys generate", flag.ContinueOnError)
	output := fs.String("output", "", "path for generated private key (default from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	privPath := strings.TrimSpace(getKeysPrivKeyPath(mp))
	if *output != "" {
		privPath = strings.TrimSpace(*output)
	}
	if privPath == "" {
		return fmt.Errorf("no key path: set long_term_jose_priv_key in server config or use -output")
	}

	privKey, pubKey, err := backend.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	privJSON, err := backend.SerializePrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("serialize private key: %w", err)
	}
	pubJSON, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize public key: %w", err)
	}

	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(privPath, privJSON, 0600); err != nil {
		return fmt.Errorf("write %s: %w", privPath, err)
	}
	pubPath := privPath + ".pub"
	if err := os.WriteFile(pubPath, pubJSON, 0644); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}

	fmt.Printf("Generated %s keypair:\n  private: %s\n  public:  %s\n", backend.Name(), privPath, pubPath)
	return nil
}

func runKeysShow(mp *MultiProviderConf, backend crypto.Backend, args []string) error {
	privPath := strings.TrimSpace(getKeysPrivKeyPath(mp))
	if privPath == "" {
		return fmt.Errorf("no key path: set long_term_jose_priv_key in server config")
	}

	data, err := os.ReadFile(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("private key file not found: %q: %w", privPath, err)
		}
		return fmt.Errorf("read %q: %w", privPath, err)
	}
	data = tdns.StripKeyFileComments(data)

	privKey, err := backend.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	pubKey, err := backend.PublicFromPrivate(privKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	pubJSON, err := backend.SerializePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("serialize public key: %w", err)
	}
	fmt.Println(string(pubJSON))
	return nil
}

func getKeysPrivKeyPath(mp *MultiProviderConf) string {
	if mp != nil {
		return mp.LongTermJosePrivKey
	}
	return ""
}
