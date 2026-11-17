package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Group memberships decide who is an org admin, so every place that can grant
// or rewrite one is listed here (RD-1291). Login once added memberships from
// credential data in the wallet's response that nothing had verified; a new
// writer must now be added to these lists, with its reason, in a reviewed
// change.

// membershipWriters lists the functions outside internal/db that may call a
// membership writer, keyed by file and enclosing function.
var membershipWriters = map[string]string{
	"internal/rbac/access.go:(*AccessController).EnsureUserExists":       "a new user joins the default group",
	"internal/server/admin_rbac_user.go:(*Server).createMembershipByDID": "admin API",
	"internal/server/admin_rbac_user.go:(*Server).createUserMembership":  "admin API",
	"internal/server/auth_azure.go:(*Server).completeAzureLogin":         "Azure AD tenant mapping from the server-side allowlist",
	"internal/server/auth_dev_admin.go:(*Server).ensureMockUserIsAdmin":  "mockauth builds only; the production build compiles a no-op",
}

// membershipWriterCalls names every function in internal/db that inserts or
// rewrites a membership, directly or through another one.
// TestMembershipStoreWriters derives that set from the store's code and fails
// when this list differs from it.
var membershipWriterCalls = map[string]bool{
	"createMembership":               true,
	"CreateMembership":               true,
	"CreateMembershipIfNotExists":    true,
	"UpdateMembership":               true,
	"CreateUserWithMembership":       true,
	"EnsureUserExistsWithMembership": true,
}

// rawMembershipWrite matches SQL in a single string literal that inserts or
// rewrites membership rows.
var rawMembershipWrite = regexp.MustCompile(`(?i)\b(insert\s+into|update(\s+only)?|merge\s+into|copy)\s+("?public"?\s*\.\s*)?"?user_memberships\b`)

func TestMembershipStoreWriters(t *testing.T) {
	var units []codeUnit
	for _, f := range shippedGoFiles(t) {
		if strings.HasPrefix(f.rel, "internal/db/") {
			units = append(units, codeUnits(f)...)
		}
	}

	writers := map[string]bool{}
	isWriter := map[int]bool{}
	for i, u := range units {
		if u.rawWrite {
			isWriter[i] = true
			for _, name := range u.declares {
				writers[name] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for i, u := range units {
			if isWriter[i] {
				continue
			}
			for ref := range u.refs {
				if writers[ref] {
					isWriter[i] = true
					for _, name := range u.declares {
						writers[name] = true
					}
					changed = true
					break
				}
			}
		}
	}
	for i, u := range units {
		if isWriter[i] && len(u.declares) == 0 {
			t.Errorf("internal/db: %s writes memberships without a name callers can be checked by", u.name)
		}
	}

	for name := range writers {
		if !membershipWriterCalls[name] {
			t.Errorf("internal/db: %s inserts or rewrites memberships; add it to membershipWriterCalls so its callers are checked", name)
		}
	}
	for name := range membershipWriterCalls {
		if !writers[name] {
			t.Errorf("membershipWriterCalls lists %s, which no longer writes memberships; remove it", name)
		}
	}
}

func TestMembershipWriters(t *testing.T) {
	found := map[string]bool{}
	for _, f := range shippedGoFiles(t) {
		if strings.HasPrefix(f.rel, "internal/db/") {
			continue
		}
		for _, u := range codeUnits(f) {
			for ref := range u.refs {
				if membershipWriterCalls[ref] {
					found[f.rel+":"+u.name] = true
				}
			}
		}
	}

	for site := range found {
		if _, ok := membershipWriters[site]; !ok {
			t.Errorf("%s writes group memberships but is not in membershipWriters; add it, with its reason, only if it may grant a membership", site)
		}
	}
	for site := range membershipWriters {
		if !found[site] {
			t.Errorf("membershipWriters lists %s, which no longer writes memberships; remove it", site)
		}
	}
}

func TestNoRawMembershipWritesOutsideStore(t *testing.T) {
	for _, f := range shippedGoFiles(t) {
		if strings.HasPrefix(f.rel, "internal/db/") {
			continue // TestMembershipStoreWriters covers the store
		}
		eachString(f, func(s string, pos token.Pos) {
			if rawMembershipWrite.MatchString(s) {
				t.Errorf("%s:%d writes user_memberships directly; go through the store in internal/db", f.rel, f.fset.Position(pos).Line)
			}
		})
	}
}

// TestNoMembershipsFromLoginCredentials keeps the source login used for those
// memberships out of new code. Rows written by earlier versions are still
// read through the type; only the declaration may name the source.
func TestNoMembershipsFromLoginCredentials(t *testing.T) {
	const declaredIn = "internal/rbac/models.go"
	for _, f := range shippedGoFiles(t) {
		if f.rel == declaredIn {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "MembershipSourceZKAttested" {
				t.Errorf("%s:%d names rbac.MembershipSourceZKAttested: login credentials must not create memberships", f.rel, f.fset.Position(id.Pos()).Line)
			}
			return true
		})
		eachString(f, func(s string, pos token.Pos) {
			if strings.Contains(s, "zk_attested") {
				t.Errorf("%s:%d names the zk_attested membership source: login credentials must not create memberships", f.rel, f.fset.Position(pos).Line)
			}
		})
	}
}

// TestNoReaderOfWalletPresentation keeps credential data from a wallet's
// response out of shipped code. The verifier checks only the proofs a
// request asks for, and each of those proves only the queried field; the
// rest of the presentation is whatever the wallet sent.
func TestNoReaderOfWalletPresentation(t *testing.T) {
	for _, f := range shippedGoFiles(t) {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "VerifiablePresentation" {
				t.Errorf("%s:%d reads the wallet's verifiable presentation, which is not verified", f.rel, f.fset.Position(sel.Pos()).Line)
			}
			return true
		})
	}
}

// codeUnit is a function declaration, or a package-level declaration (whose
// initialisers can hold function literals).
type codeUnit struct {
	name     string
	declares []string        // names other code calls it by
	refs     map[string]bool // selector and identifier names it uses, calls and method values alike
	rawWrite bool            // holds SQL that writes user_memberships
}

func codeUnits(f goFile) []codeUnit {
	var units []codeUnit
	for _, decl := range f.ast.Decls {
		u := codeUnit{refs: map[string]bool{}}
		switch d := decl.(type) {
		case *ast.FuncDecl:
			u.name = funcName(d)
			u.declares = []string{d.Name.Name}
		case *ast.GenDecl:
			u.name = "package-level " + d.Tok.String()
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, id := range vs.Names {
						u.declares = append(u.declares, id.Name)
					}
				}
			}
		default:
			continue
		}
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch x := n.(type) {
			// Declared names (interface methods, fields, vars, types) are
			// not uses; walk only what they are declared as or assigned.
			case *ast.Field:
				ast.Inspect(x.Type, visit)
				return false
			case *ast.ValueSpec:
				if x.Type != nil {
					ast.Inspect(x.Type, visit)
				}
				for _, v := range x.Values {
					ast.Inspect(v, visit)
				}
				return false
			case *ast.TypeSpec:
				ast.Inspect(x.Type, visit)
				return false
			case *ast.SelectorExpr:
				u.refs[x.Sel.Name] = true
			case *ast.Ident:
				u.refs[x.Name] = true
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, err := strconv.Unquote(x.Value); err == nil && rawMembershipWrite.MatchString(s) {
						u.rawWrite = true
					}
				}
			}
			return true
		}
		if fn, ok := decl.(*ast.FuncDecl); ok {
			// The receiver and parameters are declarations; the body is use.
			if fn.Body != nil {
				ast.Inspect(fn.Body, visit)
			}
		} else {
			ast.Inspect(decl, visit)
		}
		units = append(units, u)
	}
	return units
}

func eachString(f goFile, visit func(s string, pos token.Pos)) {
	ast.Inspect(f.ast, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				visit(s, lit.Pos())
			}
		}
		return true
	})
}

type goFile struct {
	rel  string
	fset *token.FileSet
	ast  *ast.File
}

// shippedGoFiles parses the module's non-test Go files. It skips directories
// starting with "." (no import path can reach them, and local checkouts
// under .claude/ or .tmp/ live there), nested modules, vendor, node_modules
// and the e2e harness, which no binary links.
func shippedGoFiles(t *testing.T) []goFile {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var files []goFile
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" ||
				path == filepath.Join(root, "e2e") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
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
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, goFile{rel: filepath.ToSlash(rel), fset: fset, ast: file})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files
}

// funcName names a function declaration the way the allowlist keys it:
// "Name", "(T).Name" or "(*T).Name".
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	star := ""
	if s, ok := typ.(*ast.StarExpr); ok {
		star, typ = "*", s.X
	}
	switch g := typ.(type) { // generic receivers
	case *ast.IndexExpr:
		typ = g.X
	case *ast.IndexListExpr:
		typ = g.X
	}
	return fmt.Sprintf("(%s%s).%s", star, typ, fn.Name.Name)
}
