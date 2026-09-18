package lifecycle

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRemovalAuthorityTripwire proves the package doc's promise: os.Remove,
// os.RemoveAll and os.Rename appear ONLY in removal.go inside this
// package — removal.go is the single audited authority for destructive
// filesystem mutation.
//
// The check is deliberately PACKAGE-SCOPED, not repo-wide: other packages
// legitimately use os.Rename for atomic JSON publication (e.g. the vault
// registry) without holding removal authority over user content; the
// boundary that matters is this package, where the removalPermit lives.
// Import-alias-aware so `o "os"; o.Remove(...)` cannot evade it.
func TestRemovalAuthorityTripwire(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob *.go: %v (running from the wrong directory?)", err)
	}
	sort.Strings(files)

	var violations []string
	removalUses := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue // tests may clean up fixtures; the authority is production code
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		osAlias := ""
		for _, imp := range af.Imports {
			if imp.Path.Value == `"os"` {
				osAlias = "os"
				if imp.Name != nil {
					osAlias = imp.Name.Name
				}
			}
		}
		if osAlias == "" {
			continue
		}
		ast.Inspect(af, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != osAlias {
				return true
			}
			switch sel.Sel.Name {
			case "Remove", "RemoveAll", "Rename":
				pos := fset.Position(sel.Pos())
				if file == "removal.go" {
					removalUses++
				} else {
					violations = append(violations, fmt.Sprintf("%s:%d: os.%s outside removal.go", file, pos.Line, sel.Sel.Name))
				}
			}
			return true
		})
	}
	if len(violations) > 0 {
		t.Errorf("removal-authority tripwire violations (os.Remove/RemoveAll/Rename may appear ONLY in removal.go):\n\t%s",
			strings.Join(violations, "\n\t"))
	}
	if removalUses == 0 {
		t.Error("removal.go no longer calls os.Remove/RemoveAll/Rename — the audited authority moved; update the tripwire and the package doc together")
	}
}
