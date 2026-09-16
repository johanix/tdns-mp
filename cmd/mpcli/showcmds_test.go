/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * show-cmds: tdns's command-tree lister, attached to tdns-mpcli's tree.
 */
package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	mpcli "github.com/johanix/tdns-mp/v2/cli"
	cli "github.com/johanix/tdns/v2/cli"
)

// attachShowCmdsForTest attaches show-cmds to the package rootCmd the way
// ExecuteContext does, and removes every copy again when the test ends, so
// the golden tree test sees the tree the init()s build whatever order the
// tests run in.
func attachShowCmdsForTest(t *testing.T) {
	t.Helper()
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	cli.AttachShowCmds(rootCmd)
	t.Cleanup(func() { detachShowCmds(rootCmd) })
}

func detachShowCmds(c *cobra.Command) {
	for _, sub := range append([]*cobra.Command(nil), c.Commands()...) {
		if sub.Name() == cli.ShowCmdsName {
			c.RemoveCommand(sub)
			continue
		}
		detachShowCmds(sub)
	}
}

// runRoot executes rootCmd with args and returns what show-cmds printed; it
// writes to os.Stdout, not to the command's output stream.
func runRoot(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	rootCmd.SetArgs(args)
	runErr := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	w.Close()
	os.Stdout = orig
	out := <-done
	if runErr != nil {
		t.Fatalf("tdns-mpcli %s: %v", strings.Join(args, " "), runErr)
	}
	return out
}

// TestShowCmdsAttached: show-cmds hangs off the root and every command with
// subcommands; it is listed in -h at the root and under each role word, and
// hidden deeper down.
func TestShowCmdsAttached(t *testing.T) {
	attachShowCmdsForTest(t)
	for _, tc := range []struct {
		path   []string
		hidden bool
	}{
		{nil, false},
		{[]string{"agent"}, false},
		{[]string{"signer"}, false},
		{[]string{"combiner"}, false},
		{[]string{"auditor"}, false},
		{[]string{"agent", "zone"}, true},
	} {
		parent := rootCmd
		if tc.path != nil {
			c, rest, err := rootCmd.Find(tc.path)
			if err != nil || len(rest) > 0 {
				t.Fatalf("%v: not in the tree (rest %v, err %v)", tc.path, rest, err)
			}
			parent = c
		}
		var sc *cobra.Command
		for _, c := range parent.Commands() {
			if c.Name() == cli.ShowCmdsName {
				sc = c
			}
		}
		if sc == nil {
			t.Errorf("%s: no show-cmds", parent.CommandPath())
			continue
		}
		if sc.Hidden != tc.hidden {
			t.Errorf("%s show-cmds: hidden=%v, want %v", parent.CommandPath(), sc.Hidden, tc.hidden)
		}
	}
}

// TestShowCmdsNeedsNoConfig: show-cmds only inspects the command tree, so it
// runs with no config file (a missing config would otherwise end the process
// in initConfig) and lists the subtree it hangs off.
func TestShowCmdsNeedsNoConfig(t *testing.T) {
	attachShowCmdsForTest(t)
	t.Setenv(mpcli.ConfigEnvVar, filepath.Join(t.TempDir(), "absent.yaml"))

	out := runRoot(t, "agent", cli.ShowCmdsName)
	for _, want := range []string{
		"tdns-mpcli agent has the following command structure:",
		"tdns-mpcli agent zone mplist\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("agent show-cmds output lacks %q", want)
		}
	}
	if strings.Contains(out, "tdns-mpcli signer") {
		t.Errorf("agent show-cmds lists another subtree:\n%s", out)
	}

	out = runRoot(t, cli.ShowCmdsName, "--depth", "1")
	for _, word := range []string{"agent", "auditor", "combiner", "configure", "signer", "version"} {
		if !strings.Contains(out, "tdns-mpcli "+word+"\n") {
			t.Errorf("show-cmds --depth 1 lacks %q", word)
		}
	}
	if strings.Contains(out, "tdns-mpcli agent zone") {
		t.Errorf("show-cmds --depth 1 descended below the first level:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, " "+cli.ShowCmdsName) {
			t.Errorf("show-cmds lists itself: %q", line)
		}
	}
}
