/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestNoHardcodedRoleRemains fails on any GetApiClient call in this package
// whose first argument is a string literal.
//
// Such a call targets one fixed daemon no matter which tree the command sits
// in. With one instance per daemon that is invisible; with two it silently
// drives the wrong one. 29 sites did this until 2026-09; they now resolve
// off the command tree (GetApiClientForCmd). This test keeps it that way.
//
// It parses rather than greps: a grep matches prose about the problem, and a
// guard that cries wolf gets deleted.
func TestNoHardcodedRoleRemains(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var fn string
			switch e := call.Fun.(type) {
			case *ast.SelectorExpr:
				fn = e.Sel.Name
			case *ast.Ident:
				fn = e.Name
			}
			if fn != "GetApiClient" {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				offenders = append(offenders, fset.Position(call.Pos()).String()+": GetApiClient("+lit.Value+", …)")
			}
			return true
		})
	}
	if len(offenders) > 0 {
		t.Errorf("GetApiClient called with a literal role; use GetApiClientForCmd(cmd, …) so the target comes from the command tree:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// TestRoleForCmdWalksUp: a leaf three levels below a tagged root reports the
// root's role; a subtree tag overrides it; an untagged tree reports "".
func TestRoleForCmdWalksUp(t *testing.T) {
	root := TagRole(&cobra.Command{Use: "root"}, "p2-agent")
	mid := &cobra.Command{Use: "mid"}
	leaf := &cobra.Command{Use: "leaf"}
	root.AddCommand(mid)
	mid.AddCommand(leaf)
	if got := RoleForCmd(leaf); got != "p2-agent" {
		t.Errorf("leaf: got %q, want p2-agent", got)
	}
	TagRole(mid, "other")
	if got := RoleForCmd(leaf); got != "other" {
		t.Errorf("leaf under retagged subtree: got %q, want other", got)
	}
	if got := RoleForCmd(&cobra.Command{Use: "loose"}); got != "" {
		t.Errorf("untagged: got %q, want empty", got)
	}
	if _, err := GetApiClientForCmd(&cobra.Command{Use: "loose"}, false); err == nil {
		t.Errorf("untagged tree must be an error, not a default target")
	}
}

// TestEveryTreeLeafResolvesItsInstance walks each of the four tree factories
// instantiated as an instance and checks that every command in it resolves
// to that instance -- the property the whole mechanism exists for.
func TestEveryTreeLeafResolvesItsInstance(t *testing.T) {
	for kind, newTree := range knownInstanceRoles {
		name := "x-" + kind
		root := newTree(name, name)
		var walk func(c *cobra.Command)
		walk = func(c *cobra.Command) {
			if got := RoleForCmd(c); got != name {
				t.Errorf("%s: %s resolves to %q, want %q", kind, c.CommandPath(), got, name)
			}
			for _, sub := range c.Commands() {
				walk(sub)
			}
		}
		walk(root)
	}
}
