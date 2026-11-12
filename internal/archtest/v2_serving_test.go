package archtest

import (
	_ "privacy-proxy/internal/operational/v2server"
	"strings"
	"testing"
)

func TestNativeV2ServingExcludesLegacyServerAndEVMPolicyBackend(t *testing.T) {
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/operational/v2server") {
		for _, prefix := range []string{"privacy-proxy/internal/server", "privacy-proxy/internal/db", "privacy-proxy/internal/policybackend/evm", "github.com/ethereum/go-ethereum/core/vm", "github.com/ethereum/go-ethereum/core/state", "github.com/ethereum/go-ethereum/triedb", "github.com/redis/"} {
			if dep == prefix || strings.HasPrefix(dep, prefix+"/") || strings.HasSuffix(prefix, "/") && strings.HasPrefix(dep, prefix) {
				t.Errorf("native serving acquired legacy infrastructure: %s", dep)
			}
		}
	}
}
