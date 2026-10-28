package archtest

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privacy-proxy/internal/archmap"

	// Blank-import the server so any change in a shipped package invalidates
	// the cached result of these gates (see depdirection_test.go).
	_ "privacy-proxy/internal/server"
)

// The security perimeter gates (RD-1367). docs/architecture/modules.toml
// assigns every source file to one module and tier; these tests keep that map
// complete, keep the size report current and enforce the boundaries between
// tiers (see docs/architecture/security-perimeter.md).

func loadModuleMap(t *testing.T) (*archmap.Manifest, string) {
	t.Helper()
	root := moduleRoot(t)
	m, err := archmap.Load(filepath.Join(root, archmap.ManifestPath))
	if err != nil {
		t.Fatalf("module map: %v", err)
	}
	return m, root
}

// TestEverySourceFileHasOneModule fails on a source file that no module, or
// more than one module, claims. A new file has to be placed in the map, which
// decides whether it is inside the audited perimeter.
func TestEverySourceFileHasOneModule(t *testing.T) {
	m, root := loadModuleMap(t)
	_, err := archmap.Measure(m, root)
	var ce *archmap.ClassificationError
	if errors.As(err, &ce) {
		t.Fatalf("%v\nadd each file to a module in %s", err, archmap.ManifestPath)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestPerimeterReportIsCurrent fails when the committed size report no longer
// matches the code. Regenerate it with `make perimeter-report`.
func TestPerimeterReportIsCurrent(t *testing.T) {
	m, root := loadModuleMap(t)
	sizes, err := archmap.Measure(m, root)
	if err != nil {
		t.Fatal(err)
	}
	want := archmap.Report(m, sizes, archmap.ReportOptions{})
	got, err := os.ReadFile(filepath.Join(root, archmap.ReportPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s is out of date; run `make perimeter-report` and commit the result", archmap.ReportPath)
	}
}

// TestPerimeterBoundaries type-checks the shipped packages and fails on any
// boundary violation: shipped code classified outside the perimeter,
// legacy-mode code named or installed outside a declared dispatch function,
// legacy code that runs at startup or adds interface methods to perimeter
// types, or a stale dispatch entry.
func TestPerimeterBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("type-checks every shipped package")
	}
	m, root := loadModuleMap(t)
	violations, analysis, err := archmap.CheckRepository(m, root)
	if err != nil {
		t.Fatal(err)
	}
	// A pass must mean every shipped file was checked, not that the load
	// silently covered less.
	shipped, err := archmap.ShippedFiles(root, archmap.ModulePrefix, archmap.ProductionBuildFlags, archmap.ShippedMains...)
	if err != nil {
		t.Fatal(err)
	}
	if len(shipped) == 0 {
		t.Fatal("no shipped Go files found")
	}
	for _, f := range shipped {
		if analysis.Files[f] == nil {
			t.Errorf("shipped file %s was not analyzed", f)
		}
	}
	if len(violations) > 0 {
		lines := make([]string, len(violations))
		for i, v := range violations {
			lines[i] = v.String()
		}
		t.Fatalf("%d perimeter boundary violation(s):\n  %s\nsee docs/architecture/security-perimeter.md",
			len(violations), strings.Join(lines, "\n  "))
	}
}
