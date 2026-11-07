package archtest

import (
	"os/exec"
	"strings"
	"testing"
)

func TestActivityRecorderHasNoSQLOrLegacyAuthority(t *testing.T) {
	allowed := map[string]bool{}
	for _, name := range []string{"activitylog", "audit/buffer", "audit/sealer", "identity", "networkidentity", "strictjson"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/activitylog") {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("recorder imports application authority %s", dep)
		}
		// UUID's stdlib database/sql/driver conversion interface opens no DB.
		if dep == "database/sql" {
			t.Errorf("recorder imports SQL connection machinery %s", dep)
		}
		for _, p := range []string{"github.com/jackc/", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
			if dep == p || strings.HasPrefix(dep, p) {
				t.Errorf("recorder imports SQL/VM infrastructure %s", dep)
			}
		}
	}
}
func TestActivityOperationalBoundary(t *testing.T) {
	for _, pkg := range []string{"privacy-proxy/internal/operational/activitysql", "privacy-proxy/internal/operational/activitysource"} {
		for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
			for _, p := range []string{"privacy-proxy/internal/db", "privacy-proxy/internal/server", "privacy-proxy/internal/rbac", "privacy-proxy/internal/disclosurewallet", "privacy-proxy/internal/operational/walletsql", "privacy-proxy/internal/operational/admissionsql", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
				if dep == p || strings.HasPrefix(dep, p+"/") || strings.HasSuffix(p, "/") && strings.HasPrefix(dep, p) {
					t.Errorf("activity operational source imports unrelated authority %s", dep)
				}
			}
		}
	}
}
func TestActivityChainLockStandardLibraryOnly(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, "privacy-proxy/internal/audit/chainlock")
	cmd.Dir = moduleRoot(t)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chain lock closure: %v %s", err, raw)
	}
	for _, dep := range strings.Fields(string(raw)) {
		if dep != "privacy-proxy/internal/audit/chainlock" {
			t.Errorf("chain lock imports nonstdlib %s", dep)
		}
	}
}
