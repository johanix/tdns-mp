/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// tdns's PrepArgs exits on an argument it does not know ("Unknown required
// argument"), before the command does anything. Its "identity" case was
// taken out, and send-rfi and send-notify, which still asked for it, exited
// at once (#258). No command here asks PrepArgs for an argument tdns's
// PrepArgs does not have.
func TestNoCommandAsksPrepArgsForAnArgumentItDoesNotKnow(t *testing.T) {
	gone := map[string]bool{"identity": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "PrepArgs" {
				return true
			}
			for _, a := range call.Args {
				lit, ok := a.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, _ := strconv.Unquote(lit.Value); gone[v] {
					t.Errorf("%s: PrepArgs(%s): tdns's PrepArgs has no such argument and exits", fset.Position(call.Pos()), lit.Value)
				}
			}
			return true
		})
	}
}
