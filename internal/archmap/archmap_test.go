package archmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"internal/server/auth*.go", "internal/server/auth.go", true},
		{"internal/server/auth*.go", "internal/server/auth_azure.go", true},
		{"internal/server/auth*.go", "internal/server/oauth.go", false},
		{"internal/server/auth*.go", "internal/server/sub/auth.go", false},
		{"internal/auth/**", "internal/auth/jwt.go", true},
		{"internal/auth/**", "internal/auth/deep/nested/x.go", true},
		{"internal/auth/**", "internal/authz/x.go", false},
		{"**/*_test.go", "internal/server/auth_test.go", true},
		{"**/*_test.go", "auth_test.go", true},
		{"**/testdata/**", "internal/archtest/testdata/a/b.go", true},
		{"node/reth/src/**/*.rs", "node/reth/src/lib.rs", true},
		{"node/reth/src/**/*.rs", "node/reth/src/a/b.rs", true},
		{"frontend/src/**/*.{ts,tsx}", "frontend/src/App.tsx", true},
		{"frontend/src/**/*.{ts,tsx}", "frontend/src/lib/api.ts", true},
		{"frontend/src/**/*.{ts,tsx}", "frontend/src/index.css", false},
	}
	for _, tt := range tests {
		got, err := Match(tt.pattern, tt.path)
		require.NoError(t, err, tt.pattern)
		require.Equal(t, tt.want, got, "%s ~ %s", tt.pattern, tt.path)
	}
	_, err := Match("internal/[", "internal/x")
	require.Error(t, err)
}

const validManifest = `
[scope]
include = ["src/**/*.go"]
exclude = ["**/*_test.go"]

[[module]]
name = "gate"
tier = "core"
audit_scope = "access"
summary = "decides access"
owner = "maintainers"
paths = ["src/gate/**"]

[[module]]
name = "store"
tier = "core"
audit_scope = "access"
data = true
summary = "reads rows"
owner = "maintainers"
paths = ["src/store/**"]

[[module]]
name = "ui"
tier = "outside"
summary = "renders"
owner = "maintainers"
paths = ["src/ui/**"]

[[module]]
name = "metrics"
tier = "outside"
summary = "counters"
owner = "maintainers"
paths = ["src/metrics/**"]

[[dispatch]]
file = "src/gate/check.go"
function = "Router.Serve"
objects = ["Old"]
reason = "selects the legacy path only in legacy mode"
`

func TestParseValidManifest(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	require.NoError(t, err)
	require.Len(t, m.Modules, 4)
	gate := m.Module("gate")
	require.NotNil(t, gate)
	require.Equal(t, TierCore, gate.Tier)
	require.True(t, m.Module("store").Data)
	require.Equal(t, "access", gate.AuditScope)
	require.Nil(t, m.Module("missing"))
	require.True(t, m.MayDispatch("src/gate/check.go", "Router.Serve", "Old"))
	require.False(t, m.MayDispatch("src/gate/check.go", "Router.Serve", "Other"))
	require.False(t, m.MayDispatch("src/gate/check.go", "Router.Other", "Old"))
}

func TestParseRejectsInvalidManifests(t *testing.T) {
	tests := []struct {
		name, edit, wantErr string
	}{
		{"duplicate name", `name = "store"`, `duplicate module "store"`},
		{"bad tier", `tier = "edge"`, `unknown tier "edge"`},
		{"missing summary", `summary = "decides access"`, `module "gate" needs a summary`},
		{"core without audit scope", `audit_scope = "access"
summary = "decides access"`, `module "gate": core modules need an audit_scope`},
		{"dispatch without objects", `objects = ["Old"]
`, `dispatch src/gate/check.go Router.Serve needs the legacy objects it may name`},
		{"dispatch without reason", `reason = "selects the legacy path only in legacy mode"`, `dispatch src/gate/check.go Router.Serve needs a reason`},
		{"no paths", `paths = ["src/gate/**"]`, `module "gate" has no paths`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var src string
			switch tt.name {
			case "duplicate name":
				src = strings.Replace(validManifest, `name = "gate"`, tt.edit, 1)
			case "bad tier":
				src = strings.Replace(validManifest, `tier = "core"`, tt.edit, 1)
			case "missing summary":
				src = strings.Replace(validManifest, tt.edit, "", 1)
			case "dispatch without objects":
				src = strings.Replace(validManifest, tt.edit, "", 1)
			case "core without audit scope":
				src = strings.Replace(validManifest, tt.edit, `summary = "decides access"`, 1)
			case "dispatch without reason":
				src = strings.Replace(validManifest, tt.edit, `reason = ""`, 1)
			case "no paths":
				src = strings.Replace(validManifest, tt.edit, "paths = []", 1)
			default:
				t.Fatalf("no edit rule for %q", tt.name)
			}
			_, err := Parse([]byte(src))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestClassifyAndSources(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	write("src/gate/check.go", "package gate\n")
	write("src/gate/check_test.go", "package gate\n")
	write("src/store/rows.go", "package store\n")
	write("src/ui/page.go", "package ui\n")
	write("src/orphan/x.go", "package orphan\n")
	write("src/README.md", "not source\n")

	m, err := Parse([]byte(validManifest))
	require.NoError(t, err)
	files, err := m.Sources(root)
	require.NoError(t, err)
	require.Equal(t, []string{"src/gate/check.go", "src/orphan/x.go", "src/store/rows.go", "src/ui/page.go"}, files)

	mods, err := m.Classify("src/gate/check.go")
	require.NoError(t, err)
	require.Len(t, mods, 1)
	require.Equal(t, "gate", mods[0].Name)
	mods, err = m.Classify("src/orphan/x.go")
	require.NoError(t, err)
	require.Empty(t, mods)

	overlap := validManifest + `
[[module]]
name = "dup"
tier = "outside"
summary = "overlaps gate"
owner = "maintainers"
paths = ["src/gate/check.go"]
`
	m, err = Parse([]byte(overlap))
	require.NoError(t, err)
	mods, err = m.Classify("src/gate/check.go")
	require.NoError(t, err)
	require.Len(t, mods, 2)

	carved := strings.Replace(overlap, `paths = ["src/gate/**"]`, `paths = ["src/gate/**"]
except = ["src/gate/check.go"]`, 1)
	m, err = Parse([]byte(carved))
	require.NoError(t, err)
	mods, err = m.Classify("src/gate/check.go")
	require.NoError(t, err)
	require.Len(t, mods, 1)
	require.Equal(t, "dup", mods[0].Name)
}

func TestCountGo(t *testing.T) {
	src := "// Package x does things.\npackage x\n\n/* block\n   comment */\nimport \"fmt\"\n\nvar raw = `line1\nline2\nline3`\n\nfunc F() { // trailing\n\tfmt.Println(\"// not a comment\")\n}\n"
	n, err := CountGo([]byte(src))
	require.NoError(t, err)
	// package, import, raw (3 lines), func, Println, closing brace.
	require.Equal(t, 8, n)
}

func TestCountCLike(t *testing.T) {
	src := "//! crate doc\n/// item doc\nfn main() {\n    /* inline */ let x = 1;\n    /* start\n       still */ let y = 2;\n\n    // gone\n}\n"
	require.Equal(t, 4, CountCLike([]byte(src)))
}

func TestCountSQL(t *testing.T) {
	src := "-- header\nCREATE TABLE t (\n  id INT -- inline\n);\n/* block */\nGRANT SELECT ON t TO app;\n---- create above / drop below ----\nDROP TABLE t;\n"
	require.Equal(t, 4, CountSQL([]byte(src)))
}

func TestInScope(t *testing.T) {
	m, err := Parse([]byte(validManifest))
	require.NoError(t, err)
	for path, want := range map[string]bool{
		"src/gate/check.go":      true,
		"src/gate/check_test.go": false,
		"src/gone/deleted.go":    true,
		"README.md":              false,
	} {
		got, err := m.InScope(path)
		require.NoError(t, err)
		require.Equal(t, want, got, path)
	}
}
