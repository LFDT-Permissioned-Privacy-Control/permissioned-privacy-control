package archtest

import (
	"os/exec"
	"strings"
	"testing"

	// Dependencies keep go-list based architecture assertions out of stale cache.
	_ "privacy-proxy/internal/rpcenvelope"
	_ "privacy-proxy/internal/rpcmetadatapolicy"
)

func TestMetadataPolicyAndEnvelopeAreStandardLibraryOnly(t *testing.T) {
	for _, pkg := range []string{"privacy-proxy/internal/rpcenvelope", "privacy-proxy/internal/rpcmetadatapolicy"} {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
		cmd.Dir = moduleRoot(t)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("metadata leaf closure: %v\n%s", err, raw)
		}
		for _, dep := range strings.Fields(string(raw)) {
			if dep != pkg {
				t.Errorf("%s imports non-standard dependency %s", pkg, dep)
			}
		}
	}
}
