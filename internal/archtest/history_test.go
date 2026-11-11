package archtest

import (
	"strings"
	"testing"

	_ "privacy-proxy/internal/explorerdata"
	_ "privacy-proxy/internal/historyfacts"
	_ "privacy-proxy/internal/readprivacy"
	_ "privacy-proxy/internal/readprivacyabi"
	_ "privacy-proxy/internal/rpchistorypolicy"
)

func TestHistoryConsumerCurrentFactsAndPurePrivacyBoundary(t *testing.T) {
	root := moduleRoot(t)
	for _, name := range []string{"rpchistorypolicy", "readprivacy", "readprivacyabi", "explorerdata", "historyfacts", "rpcengine"} {
		pkg := "privacy-proxy/internal/" + name
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/internal/operational/") || strings.HasPrefix(dep, "privacy-proxy/internal/audit") || dep == "privacy-proxy/internal/activitylog" || dep == "privacy-proxy/internal/rbac" || dep == "privacy-proxy/internal/explorer" || dep == "privacy-proxy/internal/server" || dep == "privacy-proxy/internal/db" || dep == "privacy-proxy/internal/config" {
				t.Error(pkg, "imports persistence, recording or legacy authority", dep)
			}
			for _, prefix := range []string{"github.com/jackc/", "github.com/redis/", "github.com/cockroachdb/pebble", "github.com/ethereum/go-ethereum/core/vm", "github.com/ethereum/go-ethereum/core/state", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) {
					t.Error(pkg, "imports storage or VM machinery", dep)
				}
			}
			if name == "rpchistorypolicy" && strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && dep != "privacy-proxy/internal/rpcmetadatapolicy" {
				t.Error("history declaration compiler imported runtime authority", dep)
			}
			if name == "readprivacy" && strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg {
				t.Error("shared decisions stopped being pure", dep)
			}
		}
	}
}
