/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The command tree as a golden file.
 *
 * Every command tdns-mpcli offers, with its Use/Short/Long text, its own
 * flags and its inherited persistent flags, rendered deterministically and
 * compared with testdata/tree-golden.txt. This is the oracle for the
 * refactor that turns the static command vars into factories: the tree
 * must come out byte-identical, and where it deliberately does not (the
 * duplicated `agent zone` children), the golden is regenerated in that one
 * commit with the diff explained there.
 *
 *   go test ./cmd/mpcli -run TestCommandTreeGolden            # compare
 *   go test ./cmd/mpcli -run TestCommandTreeGolden -update    # regenerate
 *
 * Duplicate command names under one parent are rendered with a "#2", "#3"
 * suffix so they show up in the golden instead of hiding behind each other.
 */
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/tree-golden.txt from the current command tree")

// renderTree writes one block per command, depth first, children sorted by
// name so the output does not depend on init() order.
func renderTree(root *cobra.Command) string {
	var b bytes.Buffer
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		fmt.Fprintf(&b, "=== %s\n", path)
		fmt.Fprintf(&b, "use: %s\n", c.Use)
		if c.Short != "" {
			fmt.Fprintf(&b, "short: %s\n", c.Short)
		}
		if c.Long != "" {
			fmt.Fprintf(&b, "long: |\n%s\n", indent(c.Long))
		}
		if c.Hidden {
			fmt.Fprintln(&b, "hidden: true")
		}
		if len(c.Aliases) > 0 {
			fmt.Fprintf(&b, "aliases: %s\n", strings.Join(c.Aliases, ","))
		}
		if fu := c.LocalFlags().FlagUsages(); fu != "" {
			fmt.Fprintf(&b, "flags: |\n%s", fu)
		}
		if fu := c.InheritedFlags().FlagUsages(); fu != "" {
			fmt.Fprintf(&b, "inherited: |\n%s", fu)
		}
		fmt.Fprintln(&b)

		subs := append([]*cobra.Command(nil), c.Commands()...)
		sort.SliceStable(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		seen := map[string]int{}
		for _, s := range subs {
			name := s.Name()
			seen[name]++
			if seen[name] > 1 {
				name = fmt.Sprintf("%s#%d", name, seen[name])
			}
			walk(s, path+" "+name)
		}
	}
	walk(root, root.Name())
	return b.String()
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}

func TestCommandTreeGolden(t *testing.T) {
	// cobra adds help and completion lazily during Execute; the golden
	// should not depend on whether a test happened to run Execute first.
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()

	got := renderTree(rootCmd)
	golden := filepath.Join("testdata", "tree-golden.txt")

	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", golden, len(got))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("no golden file (%v); run with -update to create it", err)
	}
	if string(want) == got {
		return
	}
	// Report the first differing line with context rather than dumping both.
	wl := strings.Split(string(want), "\n")
	gl := strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			lo := i - 3
			if lo < 0 {
				lo = 0
			}
			t.Errorf("command tree differs from %s at line %d\n want: %q\n  got: %q\n context (want):\n  %s",
				golden, i+1, w, g, strings.Join(wl[lo:min(i+3, len(wl))], "\n  "))
			break
		}
	}
	t.Errorf("run with -update if the change is intended, and say why in the commit message")
}
