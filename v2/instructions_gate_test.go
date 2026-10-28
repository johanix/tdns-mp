/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Design rule 5, plan S3: nothing decides from a zone's HSYNC3 or HSYNCPARAM
// records but through the one accessor. Every Go file of the repository but
// the tests is parsed, and a read of the records outside the canonical
// reading fails the test: the RR types as a selector on tdns's core package,
// a type assertion to their data, or getHSYNCPARAM. Building a record from a
// reading for display is no read. This scans source, so it holds for code no
// test exercises.
func TestNoDecisionReadsTheZonesOwnHSYNCRecords(t *testing.T) {
	const corePath = "github.com/johanix/tdns/v2/core"
	rrtypes := map[string]bool{"TypeHSYNC3": true, "TypeHSYNCPARAM": true, "TypeHSYNC": true, "TypeHSYNC2": true}
	data := map[string]bool{"HSYNC3": true, "HSYNCPARAM": true, "HSYNC": true, "HSYNC2": true}
	// Allowed by name: the reading itself; the CLI, which queries a zone's
	// HSYNC3 RRset and prints what it got; and the configure tool's check of
	// an operator's own zone file.
	allowed := map[string]bool{
		"v2/instructions.go":              true,
		"v2/cli/hsync_cmds.go":            true,
		"v2/cli/configure/examplezone.go": true,
	}
	root := ".." // the repository: v2 with its subpackages, and cmd
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "docs", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[filepath.ToSlash(rel)] {
			return nil
		}
		files++
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		alias := ""
		for _, imp := range af.Imports {
			if strings.Trim(imp.Path.Value, `"`) != corePath {
				continue
			}
			alias = "core"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
		isCore := func(e ast.Expr, names map[string]bool) (string, bool) {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return "", false
			}
			id, ok := sel.X.(*ast.Ident)
			return sel.Sel.Name, ok && id.Name == alias && names[sel.Sel.Name]
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if name, ok := isCore(x, rrtypes); ok && alias != "" {
					t.Errorf("%s: %s.%s: the zone's records are read outside the accessor (rule 5)", fset.Position(x.Pos()), alias, name)
				}
				if x.Sel.Name == "getHSYNCPARAM" {
					t.Errorf("%s: getHSYNCPARAM: the zone's HSYNCPARAM is read outside the accessor (rule 5)", fset.Position(x.Pos()))
				}
			case *ast.TypeAssertExpr:
				if star, ok := x.Type.(*ast.StarExpr); ok && alias != "" {
					if name, ok := isCore(star.X, data); ok {
						t.Errorf("%s: .(*%s.%s): the zone's records are read outside the accessor (rule 5)", fset.Position(x.Pos()), alias, name)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("parsed %d files; the walk did not reach the repository", files)
	}
}
