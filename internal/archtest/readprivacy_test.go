package archtest

import (
	"os/exec"
	"strings"
	"testing"

	_ "privacy-proxy/internal/readprivacy"
)

func TestReadPrivacyDecisionsAreStandardLibraryOnly(t *testing.T) {
	const pkg = "privacy-proxy/internal/readprivacy"
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
	cmd.Dir = moduleRoot(t)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read privacy dependency closure: %v\n%s", err, raw)
	}
	for _, dep := range strings.Fields(string(raw)) {
		if dep != pkg {
			t.Errorf("%s imports non-standard dependency %s", pkg, dep)
		}
	}
}
