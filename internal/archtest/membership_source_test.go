package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoMembershipsFromLoginCredentials pins RD-1291. Login used to create
// group memberships, tagged rbac.MembershipSourceZKAttested, from credential
// data that the ZK verifier never checked. Memberships now come only from the
// admin API and the Azure AD tenant mapping, so no shipped Go code may name
// that source; rows written by earlier versions are still read through the
// type, not the constant. The gate scans source files, so it holds however a
// new writer would be wired.
func TestNoMembershipsFromLoginCredentials(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const declaredIn = "internal/rbac/models.go"
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".tmp", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == declaredIn {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "MembershipSourceZKAttested" {
				offenders = append(offenders, rel)
				return false
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range offenders {
		t.Errorf("%s names rbac.MembershipSourceZKAttested: login credentials must not create memberships (RD-1291)", rel)
	}
}
