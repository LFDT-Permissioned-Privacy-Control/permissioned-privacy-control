package archtest

import (
	"os/exec"
	"strings"
	"testing"

	_ "privacy-proxy/internal/admissionsharedata"
)

func TestAdmissionShareDataIsLowerThanCurrentHistory(t *testing.T) {
	const pkg = "privacy-proxy/internal/admissionsharedata"
	for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
		for _, prefix := range []string{"privacy-proxy/internal/historyfacts", "privacy-proxy/internal/walletadapter", "privacy-proxy/internal/walletops", "privacy-proxy/internal/explorer", "privacy-proxy/internal/readprivacy", "privacy-proxy/internal/operational/", "privacy-proxy/internal/rbac", "privacy-proxy/internal/db", "privacy-proxy/internal/server", "github.com/jackc/pgx", "github.com/redis/", "github.com/cockroachdb/pebble"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("admitted-share data acquired consumer/storage dependency %s", dep)
			}
		}
	}
	cmd := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, pkg)
	cmd.Dir = moduleRoot(t)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("direct imports: %v %s", err, raw)
	}
	for _, dep := range strings.Fields(string(raw)) {
		if strings.HasPrefix(dep, "privacy-proxy/") && dep != "privacy-proxy/internal/admission" && dep != "privacy-proxy/internal/networkidentity" {
			t.Errorf("share data direct application import %s", dep)
		}
		if dep == "database/sql" || dep == "database/sql/driver" || dep == "net/http" {
			t.Errorf("share data direct I/O dependency %s", dep)
		}
	}
}
