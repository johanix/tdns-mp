/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
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

// T4.1, tdns-mp's half: no caller of tdns's key lifecycle hook registration
// is left in tdns-mp (design S4a: tdns-mp registers no hook any more; S4
// deletes the hooks in tdns on that condition). Every Go file of the
// repository is parsed, tests included, and a selector on the tdns import
// naming RegisterKeyLifecycleHooks or KeyLifecycleHooks fails the test. This
// scans source, so it holds for code no test exercises, and it keeps holding
// while tdns still exports the hooks, which compilation alone would not.
func TestNoKeyLifecycleHookRegistrationIsLeft(t *testing.T) {
	const tdnsPath = "github.com/johanix/tdns/v2"
	forbidden := map[string]bool{"RegisterKeyLifecycleHooks": true, "KeyLifecycleHooks": true}
	root := ".." // the repository: v2 with its subpackages, and cmd
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "docs", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		files++
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		// the identifier this file imports tdns under; "." makes the
		// hooks bare identifiers
		alias := ""
		for _, imp := range af.Imports {
			if strings.Trim(imp.Path.Value, `"`) != tdnsPath {
				continue
			}
			alias = "tdns"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
		}
		if alias == "" || alias == "_" {
			return nil
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == alias && forbidden[x.Sel.Name] {
					t.Errorf("%s: %s.%s is referenced; tdns-mp registers no key lifecycle hook (design S4a)", fset.Position(x.Pos()), alias, x.Sel.Name)
				}
			case *ast.Ident:
				if alias == "." && forbidden[x.Name] {
					t.Errorf("%s: %s is referenced through a dot import; tdns-mp registers no key lifecycle hook (design S4a)", fset.Position(x.Pos()), x.Name)
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
		t.Fatalf("only %d Go files scanned under %s; the scan is broken", files, root)
	}
}
