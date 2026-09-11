/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 *
 * Instance trees: the same commands as the canonical tree, wired from the
 * config, refused when the name would collide.
 */
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	mpcli "github.com/johanix/tdns-mp/v2/cli"
)

// deliberatelyAbsent are the canonical-tree subtrees an instance does not
// get. All four are package-level command vars, which can hang off one tree
// only; and none of them targets an mp daemon: auth and report are tdns
// tools (auth talks to a tdns-auth this CLI has no client for), keys and jwt
// are offline.
var deliberatelyAbsent = map[string]string{
	"signer auth":   "tdns auth tree; static var; targets tdns-auth, not an mp daemon",
	"signer report": "tdns report tool; static var; not an API client",
	"signer keys":   "offline JOSE keypair generation; static var",
	"signer jwt":    "offline JWT inspection; static var",
}

// paths returns every command path below root, with the root's own name
// stripped, so two trees rooted at different words compare directly.
func paths(root *cobra.Command) map[string]bool {
	out := map[string]bool{}
	var walk func(c *cobra.Command, prefix string)
	walk = func(c *cobra.Command, prefix string) {
		for _, sub := range c.Commands() {
			p := strings.TrimSpace(prefix + " " + sub.Name())
			out[p] = true
			walk(sub, p)
		}
	}
	walk(root, "")
	return out
}

func findRootChild(name string) *cobra.Command {
	for _, c := range rootCmd.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// TestInstanceTreeMatchesCanonicalTree: for each daemon kind, an instance
// tree must offer exactly the canonical tree minus the deliberately-absent
// subtrees. The canonical trees are only FULLY wired once this binary's
// init()s have run, which is why the test lives here and not in v2/cli.
func TestInstanceTreeMatchesCanonicalTree(t *testing.T) {
	factories := map[string]func(use, role string) *cobra.Command{
		"agent":    mpcli.NewAgentTree,
		"combiner": mpcli.NewCombinerTree,
		"signer":   mpcli.NewSignerTree,
		"auditor":  mpcli.NewAuditorTree,
	}
	for kind, newTree := range factories {
		canonical := findRootChild(kind)
		if canonical == nil {
			t.Fatalf("no canonical %q tree on the root", kind)
		}
		cp := paths(canonical)
		ip := paths(newTree("x-"+kind, "x-"+kind))
		if len(cp) == 0 || len(ip) == 0 {
			t.Fatalf("%s: empty tree: canonical=%d instance=%d", kind, len(cp), len(ip))
		}
		for p := range cp {
			if ip[p] {
				continue
			}
			absent := false
			for a := range deliberatelyAbsent {
				if kind+" "+p == a || strings.HasPrefix(kind+" "+p, a+" ") {
					absent = true
				}
			}
			if !absent {
				t.Errorf("%s: %q is on the canonical tree but not on an instance tree", kind, p)
			}
		}
		for p := range ip {
			if !cp[p] {
				t.Errorf("%s: %q is on an instance tree but not on the canonical tree", kind, p)
			}
		}
	}
	// Every deliberately-absent entry must still exist on the canonical
	// tree, or the list is stale.
	for a := range deliberatelyAbsent {
		kind, rest, _ := strings.Cut(a, " ")
		if !paths(findRootChild(kind))[rest] {
			t.Errorf("deliberatelyAbsent lists %q, which the canonical tree no longer has", a)
		}
	}
}

// TestInstanceWiringFromConfig: a config with one role: entry per kind
// yields one instance word per kind; a name that collides with a built-in
// role, with an existing command, or with an earlier entry is refused with
// a message that says which; an entry without a name is skipped.
func TestInstanceWiringFromConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-mpcli.yaml")
	body := `apiservers:
   - name: tdns-mpagent
     baseurl: https://127.0.0.1:7054/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: p2-agent
     role: agent
     baseurl: https://127.0.0.1:7254/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: p2-combiner
     role: combiner
     baseurl: https://127.0.0.1:7255/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: p2-signer
     role: signer
     baseurl: https://127.0.0.1:7253/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: aud
     role: auditor
     baseurl: https://127.0.0.1:7456/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: agent
     role: combiner
     baseurl: https://127.0.0.1:1/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: version
     role: agent
     baseurl: https://127.0.0.1:1/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: p2-agent
     role: agent
     baseurl: https://127.0.0.1:1/api/v1
     apikey: x
     authmethod: X-API-Key
   - name: nobody
     role: imr
     baseurl: https://127.0.0.1:1/api/v1
     apikey: x
     authmethod: X-API-Key
   - role: agent
     baseurl: https://127.0.0.1:1/api/v1
     apikey: x
     authmethod: X-API-Key
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "tdns-mpcli"}
	root.AddCommand(&cobra.Command{Use: "agent"}, &cobra.Command{Use: "version"})
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	entries := mpcli.EarlyApiServers(cfg)
	if len(entries) != 10 {
		t.Fatalf("EarlyApiServers: got %d entries, want 10", len(entries))
	}
	warnings := mpcli.WireInstanceTrees(root, entries)

	for _, want := range []string{"p2-agent", "p2-combiner", "p2-signer", "aud"} {
		c := findChild(root, want)
		if c == nil {
			t.Errorf("instance %q not wired", want)
			continue
		}
		if got := mpcli.RoleForCmd(c); got != want {
			t.Errorf("instance %q targets %q", want, got)
		}
	}
	wantWarnings := []string{
		`apiservers entry "agent": name collides with a built-in role`,
		`apiservers entry "version": name collides with the existing "version" command`,
		`apiservers entry "p2-agent": name collides with an earlier apiservers entry with the same name`,
		`apiservers entry "nobody": role "imr" has no command tree`,
		`apiservers entry with role but no name`,
	}
	for _, w := range wantWarnings {
		found := false
		for _, got := range warnings {
			if strings.Contains(got, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing warning %q\n got: %s", w, strings.Join(warnings, "\n      "))
		}
	}
	if len(warnings) != len(wantWarnings) {
		t.Errorf("got %d warnings, want %d:\n  %s", len(warnings), len(wantWarnings), strings.Join(warnings, "\n  "))
	}
}

func findChild(root *cobra.Command, name string) *cobra.Command {
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// TestConfigPathPrecedence: --config beats $TDNS_MPCLI_CONFIG beats the
// default.
func TestConfigPathPrecedence(t *testing.T) {
	t.Setenv(mpcli.ConfigEnvVar, "/from/env.yaml")
	if got := mpcli.ConfigPathFromArgs([]string{"agent", "ping"}); got != "/from/env.yaml" {
		t.Errorf("env: got %q", got)
	}
	if got := mpcli.ConfigPathFromArgs([]string{"--config", "/from/flag.yaml", "agent"}); got != "/from/flag.yaml" {
		t.Errorf("flag: got %q", got)
	}
	if got := mpcli.ConfigPathFromArgs([]string{"--config=/from/flag2.yaml"}); got != "/from/flag2.yaml" {
		t.Errorf("flag=: got %q", got)
	}
	t.Setenv(mpcli.ConfigEnvVar, "")
	if got := mpcli.ConfigPathFromArgs(nil); got != mpcli.DefaultConfigFile {
		t.Errorf("default: got %q", got)
	}
}
