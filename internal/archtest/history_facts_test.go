package archtest

import (
	"strings"
	"testing"

	_ "privacy-proxy/internal/historyfacts"
)

func TestHistoryCurrentFactsExcludeOperationalAndLegacyPolicyStorage(t *testing.T) {
	deps := transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/historyfacts")
	for dep := range deps {
		for _, prefix := range []string{"privacy-proxy/internal/operational/", "privacy-proxy/internal/rbac", "privacy-proxy/internal/db", "privacy-proxy/internal/server", "privacy-proxy/internal/explorer", "privacy-proxy/internal/policyvm", "privacy-proxy/internal/policycompiler", "github.com/jackc/pgx", "github.com/redis/", "github.com/cockroachdb/pebble"} {
			// The actual data-only Explorer DTO leaf is allowed.
			if dep == "privacy-proxy/internal/explorerdata" {
				continue
			}
			if strings.HasPrefix(dep, prefix) {
				t.Fatal("current read facts imported legacy/storage authority", dep)
			}
		}
	}
	for _, required := range []string{"privacy-proxy/internal/runtimepolicy", "privacy-proxy/internal/walletadapter", "privacy-proxy/internal/readprivacy", "privacy-proxy/internal/readprivacyabi"} {
		if !deps[required] {
			t.Fatal("lost actual shared current-fact boundary", required)
		}
	}
}
