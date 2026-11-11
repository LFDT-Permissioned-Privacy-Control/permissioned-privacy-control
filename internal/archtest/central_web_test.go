package archtest

import (
	"strings"
	"testing"

	// Make the test cache depend on the packages checked by subprocess go list.
	_ "privacy-proxy/internal/operational/identityweb"
	_ "privacy-proxy/internal/selfhttp"
)

func TestCentralSelfAndWebDependencyBoundary(t *testing.T) {
	for _, pkg := range []string{"privacy-proxy/internal/selfhttp", "privacy-proxy/internal/operational/identityweb"} {
		for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/internal/operational/") && dep != pkg {
				t.Error(pkg, "acquired operational storage/runtime", dep)
			}
			for _, prefix := range []string{"privacy-proxy/internal/identitybroker", "privacy-proxy/internal/identityhttp", "privacy-proxy/internal/rbac", "privacy-proxy/internal/operational/identitysql", "privacy-proxy/internal/operational/ssosql", "github.com/jackc/pgx", "github.com/redis/", "github.com/ethereum/go-ethereum/core/vm", "github.com/ethereum/go-ethereum/core/state", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) {
					t.Error(pkg, "acquired authentication/store/legacy closure", dep)
				}
			}
		}
	}
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/rpcengine") {
		if dep == "privacy-proxy/internal/operational/identityweb" {
			t.Fatal("Core acquired browser serving")
		}
	}
}
