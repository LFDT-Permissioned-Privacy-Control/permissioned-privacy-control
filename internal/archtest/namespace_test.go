package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoricalNamespaceDependencyBoundary(t *testing.T) {
	root := moduleRoot(t)
	const pure = "privacy-proxy/internal/historynamespace"
	for dep := range transitiveDeps(t, root, pure) {
		if strings.HasPrefix(dep, "privacy-proxy/") && dep != pure && dep != "privacy-proxy/internal/strictjson" && dep != "privacy-proxy/internal/networkidentity" {
			t.Errorf("historical namespace model imports application infrastructure %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/", "github.com/redis/", "github.com/ethereum/go-ethereum/", "net/http"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("historical namespace model imports storage, network or VM machinery %s", dep)
			}
		}
	}
	command := filepath.Join(root, "cmd", "ops-v2-namespace")
	entries, err := os.ReadDir(command)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") {
			if _, err := os.ReadFile(filepath.Join(command, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	allowed := map[string]bool{}
	for _, name := range []string{"historynamespace", "networkidentity", "strictjson", "operational/admissionsql", "admission", "creationfacts", "creationcapture", "creationobserver", "rpcexecution", "transactioninput", "executionfacts", "nativeadmission", "policycore", "policybundle", "runtimepolicy", "identity", "disclosurepolicy", "disclosuredata", "compliancepolicy", "compliance", "pricefeedpolicy", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for dep := range transitiveDeps(t, root, "privacy-proxy/cmd/ops-v2-namespace") {
		if strings.HasPrefix(dep, "privacy-proxy/") && dep != "privacy-proxy/cmd/ops-v2-namespace" && !allowed[dep] {
			t.Errorf("offline namespace command imports unrelated infrastructure %s", dep)
		}
		if strings.HasPrefix(dep, "github.com/redis/") || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/") && !transactionPrimitive(dep) || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/triedb") {
			t.Errorf("offline namespace command imports excluded machinery %s", dep)
		}
	}
}
