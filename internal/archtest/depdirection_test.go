// Package archtest holds executable architecture gates. Like the OpenAPI
// route↔spec coverage gate, these are plain Go tests: `make test-unit` and the
// CI Go Tests job (`go test ./internal/...`) fail on drift, with no extra CI
// wiring to maintain.
package archtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	// Blank-import every package this gate polices. The assertions below run
	// `go list` as a subprocess, whose file reads the Go test cache cannot
	// see — without these imports a cached "ok" would be replayed even after
	// a forbidden import was added. With them, any change to a policed
	// package (or its dependency tree) invalidates the cache and re-runs the
	// gate.
	_ "privacy-proxy/internal/admission"
	_ "privacy-proxy/internal/apimodels"
	_ "privacy-proxy/internal/audit"
	_ "privacy-proxy/internal/brokerpolicy"
	_ "privacy-proxy/internal/compliance"
	_ "privacy-proxy/internal/compliancehttp"
	_ "privacy-proxy/internal/compliancepolicy"
	_ "privacy-proxy/internal/config"
	_ "privacy-proxy/internal/disclosurecase"
	_ "privacy-proxy/internal/disclosuredata"
	_ "privacy-proxy/internal/disclosurehttp"
	_ "privacy-proxy/internal/disclosurepolicy"
	_ "privacy-proxy/internal/disclosuresanctions"
	_ "privacy-proxy/internal/disclosurewallet"
	_ "privacy-proxy/internal/executionfacts"
	_ "privacy-proxy/internal/guardbridge"
	_ "privacy-proxy/internal/identity"
	_ "privacy-proxy/internal/identitybroker"
	_ "privacy-proxy/internal/identitybroker/azure"
	_ "privacy-proxy/internal/identitybroker/privado"
	_ "privacy-proxy/internal/identityhttp"
	_ "privacy-proxy/internal/nativeadmission"
	_ "privacy-proxy/internal/netguard"
	_ "privacy-proxy/internal/networkidentity"
	_ "privacy-proxy/internal/operational/admissionsql"
	_ "privacy-proxy/internal/operational/disclosuresql"
	_ "privacy-proxy/internal/operational/identitysql"
	_ "privacy-proxy/internal/operational/walletsql"
	_ "privacy-proxy/internal/policybundle"
	_ "privacy-proxy/internal/policycli"
	_ "privacy-proxy/internal/policycore"
	_ "privacy-proxy/internal/policyprofiles"
	_ "privacy-proxy/internal/pricefeedpolicy"
	_ "privacy-proxy/internal/quotefeed"
	_ "privacy-proxy/internal/rpcengine"
	_ "privacy-proxy/internal/rpcexecution"
	_ "privacy-proxy/internal/rpcmethoddata"
	_ "privacy-proxy/internal/runtimepolicy"
	_ "privacy-proxy/internal/server/middleware"
	_ "privacy-proxy/internal/strictjson"
	_ "privacy-proxy/internal/transactioninput"
	_ "privacy-proxy/internal/walletadapter"
	_ "privacy-proxy/internal/wallethttp"
	_ "privacy-proxy/internal/walletops"
	_ "privacy-proxy/internal/walletproof"
)

// TestDependencyDirection locks the dependency-direction invariants
// (RD-1255):
//
//   - internal/config must not depend, even transitively, on internal/audit
//     or internal/db. Config is the most widely imported package; the old
//     config→audit→db edge dragged ~744 transitive packages (the entire
//     persistence layer) into every importer of config.
//   - internal/audit must not depend on internal/db. Store implementations
//     over *db.DB belong to the consumer (see the checkpoint store note in
//     audit/checkpoint_worker.go and internal/server/retention_audit_store.go).
//   - internal/server/middleware must not depend on internal/server, db,
//     rbac or config (RD-1265). The middleware was extracted from the server
//     package precisely because it needs none of them; a new edge back would
//     undo the split and re-couple the request-path middleware to the
//     persistence layer. config is in the list because the package doc
//     promises these types are constructed from plain values and so are
//     testable without a config — an invariant the gate has to pin, not just
//     the doc assert.
func TestDependencyDirection(t *testing.T) {
	rules := []struct {
		pkg       string
		forbidden []string
	}{
		{
			pkg:       "privacy-proxy/internal/config",
			forbidden: []string{"privacy-proxy/internal/audit", "privacy-proxy/internal/db"},
		},
		{
			pkg:       "privacy-proxy/internal/audit",
			forbidden: []string{"privacy-proxy/internal/db"},
		},
		{
			pkg: "privacy-proxy/internal/server/middleware",
			forbidden: []string{
				"privacy-proxy/internal/server",
				"privacy-proxy/internal/db",
				"privacy-proxy/internal/rbac",
				"privacy-proxy/internal/config",
			},
		},
		{
			// internal/apimodels holds the request/response types the
			// published OpenAPI document is generated from (RD-1265). An edge
			// back to internal/server would be an import cycle the moment a
			// handler package imports apimodels, which is the whole point of
			// the package. Only that one edge is forbidden: these types
			// legitimately embed domain types (rbac.Contract,
			// disclosure.Scope, db rows), and duplicating them behind a DTO
			// mapping layer was explicitly rejected by the architecture
			// review.
			pkg:       "privacy-proxy/internal/apimodels",
			forbidden: []string{"privacy-proxy/internal/server"},
		},
	}

	root := moduleRoot(t)
	for _, rule := range rules {
		deps := transitiveDeps(t, root, rule.pkg)
		for _, forbidden := range rule.forbidden {
			if deps[forbidden] {
				t.Errorf("%s must not depend on %s (dependency-direction invariant, RD-1255); "+
					"run `go list -deps %s` to find the import chain",
					rule.pkg, forbidden, rule.pkg)
			}
		}
	}
}

// TestNativePolicyDependencyBoundary keeps the native runtime independent of
// the compatibility facade, optional VM backend and application infrastructure.
// Standard SQL Scanner/Valuer support in Ethereum primitive types is allowed;
// connecting storage clients and node execution machinery are not.
func TestNativePolicyDependencyBoundary(t *testing.T) {
	const pkg = "privacy-proxy/internal/policycore"
	deps := transitiveDeps(t, moduleRoot(t), pkg)
	for dep := range deps {
		if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg {
			t.Errorf("native policy runtime must not import application package %s", dep)
		}
		for _, forbidden := range []string{
			"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/",
			"github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb",
		} {
			if strings.HasPrefix(dep, forbidden) {
				t.Errorf("native policy runtime imports infrastructure dependency %s", dep)
			}
		}
	}
}

func TestNativeExecutionEvidenceDependencyBoundary(t *testing.T) {
	const pkg = "privacy-proxy/internal/executionfacts"
	for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
		if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg {
			t.Errorf("execution evidence parser must not import application infrastructure %s", dep)
		}
		for _, forbidden := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, forbidden) {
				t.Errorf("execution evidence parser imports storage or execution machinery %s", dep)
			}
		}
	}
}

func TestNativeCallRuntimeDependencyBoundary(t *testing.T) {
	for _, pkg := range []string{"privacy-proxy/internal/rpcexecution", "privacy-proxy/internal/nativeadmission", "privacy-proxy/internal/rpcengine"} {
		allowed := map[string]bool{pkg: true, "privacy-proxy/internal/executionfacts": true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/policybundle": true, "privacy-proxy/internal/policycore": true, "privacy-proxy/internal/strictjson": true, "privacy-proxy/internal/disclosurepolicy": true, "privacy-proxy/internal/compliancepolicy": true, "privacy-proxy/internal/compliance": true, "privacy-proxy/internal/brokerpolicy": true}
		allowed["privacy-proxy/internal/transactioninput"] = true
		allowed["privacy-proxy/internal/pricefeedpolicy"] = true
		if pkg != "privacy-proxy/internal/rpcexecution" {
			allowed["privacy-proxy/internal/runtimepolicy"] = true
			allowed["privacy-proxy/internal/rpcexecution"] = true
		}
		if pkg == "privacy-proxy/internal/rpcengine" {
			for _, name := range []string{"networkidentity", "nativeadmission", "admission", "walletadapter", "walletops", "walletproof", "guardbridge", "nodeapproval", "nodeapproval/approvalpb", "tracer", "nodehttp", "loggate"} {
				allowed["privacy-proxy/internal/"+name] = true
			}
		}
		for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
				t.Errorf("%s imports unapproved application infrastructure %s", pkg, dep)
			}
			for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) && !transactionPrimitive(dep) {
					t.Errorf("%s imports storage/VM machinery %s", pkg, dep)
				}
			}
		}
	}
}

func transactionPrimitive(dep string) bool {
	return dep == "github.com/ethereum/go-ethereum/core/types" || dep == "github.com/ethereum/go-ethereum/core/types/bal"
}

func TestSignedEvidenceDependencyBoundaries(t *testing.T) {
	for _, pkg := range []string{"privacy-proxy/internal/transactioninput", "privacy-proxy/internal/guardbridge"} {
		allowed := map[string]bool{pkg: true}
		if pkg == "privacy-proxy/internal/guardbridge" {
			allowed["privacy-proxy/internal/pricefeedpolicy"] = true
			for _, name := range []string{"transactioninput", "rpcexecution", "nodeapproval", "nodeapproval/approvalpb", "tracer", "nodehttp", "loggate", "executionfacts", "policybundle", "policycore", "identity", "disclosurepolicy", "compliancepolicy", "compliance", "brokerpolicy", "strictjson"} {
				allowed["privacy-proxy/internal/"+name] = true
			}
		}
		for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
				t.Errorf("%s imports unapproved infrastructure %s", pkg, dep)
			}
			for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) && !transactionPrimitive(dep) {
					t.Errorf("%s imports storage/VM machinery %s", pkg, dep)
				}
			}
		}
	}
}

func TestPolicyBundleDependencyBoundary(t *testing.T) {
	root := moduleRoot(t)
	for _, pkg := range []string{"privacy-proxy/internal/strictjson", "privacy-proxy/internal/policybundle"} {
		deps := transitiveDeps(t, root, pkg)
		for dep := range deps {
			if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && !(pkg == "privacy-proxy/internal/policybundle" && (dep == "privacy-proxy/internal/policycore" || dep == "privacy-proxy/internal/strictjson" || dep == "privacy-proxy/internal/identity" || dep == "privacy-proxy/internal/disclosurepolicy" || dep == "privacy-proxy/internal/compliancepolicy" || dep == "privacy-proxy/internal/compliance" || dep == "privacy-proxy/internal/pricefeedpolicy" || dep == "privacy-proxy/internal/brokerpolicy")) {
				t.Errorf("%s imports application infrastructure %s", pkg, dep)
			}
			for _, forbidden := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, forbidden) {
					t.Errorf("%s imports infrastructure dependency %s", pkg, dep)
				}
			}
		}
		if pkg == "privacy-proxy/internal/strictjson" {
			cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("strictjson dependency check: %v\n%s", err, out)
			}
			for _, dep := range strings.Fields(string(out)) {
				if dep != pkg {
					t.Errorf("strictjson must use only the standard library: %s", dep)
				}
			}
		}
	}
}

func TestIdentityDependencyBoundary(t *testing.T) {
	const pkg = "privacy-proxy/internal/identity"
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("identity dependency check: %v\n%s", err, out)
	}
	allowed := map[string]bool{pkg: true, "privacy-proxy/internal/strictjson": true, "github.com/golang-jwt/jwt/v5": true}
	for _, dep := range strings.Fields(string(out)) {
		if !allowed[dep] {
			t.Errorf("identity imports dependency outside its pure local verification boundary: %s", dep)
		}
	}
}

func TestRuntimePolicyDependencyBoundary(t *testing.T) {
	const pkg = "privacy-proxy/internal/runtimepolicy"
	allowed := map[string]bool{pkg: true, "privacy-proxy/internal/policybundle": true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/policycore": true, "privacy-proxy/internal/strictjson": true, "privacy-proxy/internal/disclosurepolicy": true, "privacy-proxy/internal/compliancepolicy": true, "privacy-proxy/internal/compliance": true, "privacy-proxy/internal/brokerpolicy": true}
	allowed["privacy-proxy/internal/pricefeedpolicy"] = true
	for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("runtime policy view imports application infrastructure %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("runtime policy view imports infrastructure %s", dep)
			}
		}
	}
}

func TestPolicyAuthoringDependencyBoundary(t *testing.T) {
	root := moduleRoot(t)
	// A main package cannot be blank-imported above. Read its source so the
	// test cache observes command changes as well as the importable packages.
	command := filepath.Join(root, "cmd", "ops-v2")
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
	allowed := map[string]bool{
		"privacy-proxy/cmd/ops-v2": true, "privacy-proxy/internal/policycli": true,
		"privacy-proxy/internal/pricefeedpolicy": true,
		"privacy-proxy/internal/policyprofiles":  true, "privacy-proxy/internal/rpcmethoddata": true,
		"privacy-proxy/internal/policybundle": true, "privacy-proxy/internal/identity": true,
		"privacy-proxy/internal/policycore": true, "privacy-proxy/internal/strictjson": true,
		"privacy-proxy/internal/disclosurepolicy": true, "privacy-proxy/internal/compliancepolicy": true, "privacy-proxy/internal/compliance": true, "privacy-proxy/internal/brokerpolicy": true,
	}
	for _, pkg := range []string{"privacy-proxy/cmd/ops-v2", "privacy-proxy/internal/policycli", "privacy-proxy/internal/policyprofiles", "privacy-proxy/internal/rpcmethoddata"} {
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
				t.Errorf("authoring tool imports application infrastructure %s", dep)
			}
			for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) {
					t.Errorf("authoring tool imports storage or execution machinery %s", dep)
				}
			}
		}
	}
	const leaf = "privacy-proxy/internal/rpcmethoddata"
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", leaf)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("method data dependency check: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep != leaf {
			t.Errorf("RPC method seed must use only the standard library: %s", dep)
		}
	}
}

func TestDisclosureDependencyBoundaries(t *testing.T) {
	root := moduleRoot(t)
	command := filepath.Join(root, "cmd", "ops-v2-disclosure-migrate")
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
	allowed := map[string]bool{"privacy-proxy/internal/disclosurepolicy": true, "privacy-proxy/internal/compliancepolicy": true, "privacy-proxy/internal/compliance": true, "privacy-proxy/internal/brokerpolicy": true, "privacy-proxy/internal/disclosurecase": true, "privacy-proxy/internal/disclosuredata": true, "privacy-proxy/internal/networkidentity": true, "privacy-proxy/internal/disclosurehttp": true, "privacy-proxy/internal/policybundle": true, "privacy-proxy/internal/policycore": true, "privacy-proxy/internal/policyprofiles": true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/strictjson": true, "privacy-proxy/internal/runtimepolicy": true}
	allowed["privacy-proxy/internal/pricefeedpolicy"] = true
	for _, pkg := range []string{"privacy-proxy/internal/disclosurepolicy", "privacy-proxy/internal/disclosurecase", "privacy-proxy/internal/disclosuredata", "privacy-proxy/internal/disclosurehttp", "privacy-proxy/internal/operational/disclosuresql", "privacy-proxy/cmd/ops-v2-disclosure-migrate"} {
		usesSQL := pkg == "privacy-proxy/internal/operational/disclosuresql" || pkg == "privacy-proxy/cmd/ops-v2-disclosure-migrate"
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && !allowed[dep] && !(usesSQL && dep == "privacy-proxy/internal/operational/disclosuresql") {
				t.Errorf("%s imports application infrastructure %s", pkg, dep)
			}
			for _, prefix := range []string{"github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb", "github.com/redis/"} {
				if strings.HasPrefix(dep, prefix) {
					t.Errorf("%s imports unsupported machinery %s", pkg, dep)
				}
			}
			if !usesSQL && (strings.HasPrefix(dep, "github.com/jackc/pgx") || strings.HasPrefix(dep, "github.com/jackc/tern")) {
				t.Errorf("pure disclosure authorization/HTTP imports SQL client %s", dep)
			}
		}
	}
}

func TestWalletDependencyBoundary(t *testing.T) {
	root := moduleRoot(t)
	command := filepath.Join(root, "cmd", "ops-v2-wallet-migrate")
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
	for _, name := range []string{"walletproof", "walletops", "wallethttp", "walletadapter", "identity", "runtimepolicy", "policybundle", "policycore", "strictjson", "disclosurepolicy", "compliancepolicy", "compliance", "nativeadmission", "rpcexecution", "executionfacts", "pricefeedpolicy", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for _, pkg := range []string{"privacy-proxy/internal/walletproof", "privacy-proxy/internal/walletops", "privacy-proxy/internal/wallethttp", "privacy-proxy/internal/walletadapter", "privacy-proxy/internal/operational/walletsql", "privacy-proxy/cmd/ops-v2-wallet-migrate"} {
		usesSQL := pkg == "privacy-proxy/internal/operational/walletsql" || pkg == "privacy-proxy/cmd/ops-v2-wallet-migrate"
		for dep := range transitiveDeps(t, root, pkg) {
			adapterPrimitive := pkg == "privacy-proxy/internal/walletadapter" && dep == "privacy-proxy/internal/transactioninput"
			if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && !allowed[dep] && !adapterPrimitive && !(usesSQL && dep == "privacy-proxy/internal/operational/walletsql") {
				t.Errorf("%s imports unapproved application infrastructure %s", pkg, dep)
			}
			for _, prefix := range []string{"github.com/ethereum/go-ethereum/core/vm", "github.com/ethereum/go-ethereum/core/state", "github.com/ethereum/go-ethereum/triedb", "github.com/redis/"} {
				if strings.HasPrefix(dep, prefix) {
					t.Errorf("%s imports unsupported machinery %s", pkg, dep)
				}
			}
			if !usesSQL && (strings.HasPrefix(dep, "github.com/jackc/pgx") || strings.HasPrefix(dep, "github.com/jackc/tern")) {
				t.Errorf("%s imports a SQL driver %s", pkg, dep)
			}
			if strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/") && !(pkg == "privacy-proxy/internal/walletadapter" && transactionPrimitive(dep)) {
				t.Errorf("%s imports execution types outside the signed adapter primitive %s", pkg, dep)
			}
			if pkg == "privacy-proxy/internal/walletproof" && ((strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg) || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/")) {
				t.Errorf("pure wallet proof imports application/execution types %s", dep)
			}
		}
	}
}

// TestNetguardIsStdlibOnly locks netguard's leaf-package contract: its doc
// promises "importing only the standard library", and packages like config
// rely on that to stay light. Anything non-stdlib in its transitive deps
// (other than netguard itself) fails the gate.
func TestNetguardIsStdlibOnly(t *testing.T) {
	const pkg = "privacy-proxy/internal/netguard"
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == pkg {
			continue
		}
		t.Errorf("%s must import only the standard library, but transitively depends on %s (RD-1255)", pkg, line)
	}
}

// transitiveDeps returns the transitive (non-test) dependency set of pkg.
func transitiveDeps(t *testing.T, root, pkg string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	deps := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			deps[line] = true
		}
	}
	return deps
}

// moduleRoot locates the repo root via the active go.mod, so the test works
// from any working directory (go test sets CWD to the package dir).
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatal("no active go.mod found")
	}
	return filepath.Dir(gomod)
}

func TestComplianceSourceDependencyBoundary(t *testing.T) {
	allowed := map[string]bool{"privacy-proxy/internal/compliance": true, "privacy-proxy/internal/brokerpolicy": true, "privacy-proxy/internal/compliancepolicy": true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/strictjson": true}
	for _, pkg := range []string{"privacy-proxy/internal/compliance", "privacy-proxy/internal/compliancepolicy"} {
		for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
				t.Errorf("%s imports application infrastructure %s", pkg, dep)
			}
			for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/core", "github.com/ethereum/go-ethereum/triedb"} {
				if strings.HasPrefix(dep, prefix) {
					t.Errorf("%s imports SQL/VM machinery %s", pkg, dep)
				}
			}
		}
	}
}

func TestNativeAdmissionStorageBoundary(t *testing.T) {
	root := moduleRoot(t)
	// Main packages cannot be blank-imported. Explicit reads make CLI-only
	// changes invalidate this go-test result before subprocess go-list checks.
	command := filepath.Join(root, "cmd", "ops-v2-admission-migrate")
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
	for _, name := range []string{"networkidentity", "admission", "compliancehttp", "compliance", "compliancepolicy", "disclosurepolicy", "identity", "strictjson", "policybundle", "policycore", "runtimepolicy", "nativeadmission", "rpcexecution", "executionfacts", "transactioninput", "pricefeedpolicy", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for _, pkg := range []string{"privacy-proxy/internal/admission", "privacy-proxy/internal/compliancehttp", "privacy-proxy/internal/operational/admissionsql", "privacy-proxy/cmd/ops-v2-admission-migrate"} {
		usesSQL := pkg == "privacy-proxy/internal/operational/admissionsql" || pkg == "privacy-proxy/cmd/ops-v2-admission-migrate"
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && !allowed[dep] && !(usesSQL && dep == "privacy-proxy/internal/operational/admissionsql") {
				t.Errorf("%s imports unapproved application infrastructure %s", pkg, dep)
			}
			if !usesSQL && (strings.HasPrefix(dep, "github.com/jackc/pgx") || strings.HasPrefix(dep, "github.com/jackc/tern")) {
				t.Errorf("%s imports SQL driver %s", pkg, dep)
			}
			if strings.HasPrefix(dep, "github.com/redis/") || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/") && !transactionPrimitive(dep) || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/triedb") {
				t.Errorf("%s imports excluded persistence/VM machinery %s", pkg, dep)
			}
		}
	}
}

func TestApprovedPriceFeedDependencyBoundary(t *testing.T) {
	root := moduleRoot(t)
	allowed := map[string]bool{}
	for _, name := range []string{"networkidentity", "pricefeedpolicy", "quotefeed", "admission", "compliance", "compliancepolicy", "disclosurepolicy", "identity", "strictjson", "policybundle", "policycore", "runtimepolicy", "nativeadmission", "rpcexecution", "executionfacts", "transactioninput", "netguard", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for _, pkg := range []string{"privacy-proxy/internal/pricefeedpolicy", "privacy-proxy/internal/quotefeed"} {
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
				t.Errorf("%s imports unapproved application package %s", pkg, dep)
			}
			if pkg == "privacy-proxy/internal/pricefeedpolicy" && strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && dep != "privacy-proxy/internal/compliancepolicy" && dep != "privacy-proxy/internal/compliance" && dep != "privacy-proxy/internal/identity" && dep != "privacy-proxy/internal/strictjson" {
				t.Errorf("pure price-feed policy imports runtime machinery %s", dep)
			}
			if strings.HasPrefix(dep, "github.com/jackc/pgx") || strings.HasPrefix(dep, "github.com/jackc/tern") || strings.HasPrefix(dep, "github.com/redis/") || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/") && !transactionPrimitive(dep) || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/triedb") {
				t.Errorf("%s imports SQL/VM machinery %s", pkg, dep)
			}
		}
	}
}

func TestIdentityBrokerDependencyBoundaries(t *testing.T) {
	root := moduleRoot(t)
	command := filepath.Join(root, "cmd", "ops-v2-identity-migrate")
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
	pure := map[string]bool{}
	for _, name := range []string{"brokerpolicy", "identity", "strictjson"} {
		pure["privacy-proxy/internal/"+name] = true
	}
	provider := map[string]bool{}
	for name := range pure {
		provider[name] = true
	}
	provider["privacy-proxy/internal/netguard"] = true
	provider["privacy-proxy/internal/identitybroker/azure"] = true
	service := map[string]bool{}
	for name := range provider {
		service[name] = true
	}
	// Multi-broker assembly owns the real verifier. The pure policy and Azure
	// provider allowlists above remain closed; Core/runtime checks are separate.
	service["privacy-proxy/internal/identitybroker/privado"] = true
	for _, name := range []string{"identitybroker", "policybundle", "policycore", "disclosurepolicy", "compliancepolicy", "compliance", "pricefeedpolicy"} {
		service["privacy-proxy/internal/"+name] = true
	}
	for _, pkg := range []string{"privacy-proxy/internal/brokerpolicy", "privacy-proxy/internal/identitybroker/azure", "privacy-proxy/internal/identitybroker", "privacy-proxy/internal/identityhttp", "privacy-proxy/internal/operational/identitysql", "privacy-proxy/cmd/ops-v2-identity-migrate"} {
		allowed := service
		if pkg == "privacy-proxy/internal/brokerpolicy" {
			allowed = pure
		}
		if pkg == "privacy-proxy/internal/identitybroker/azure" {
			allowed = provider
		}
		usesSQL := pkg == "privacy-proxy/internal/operational/identitysql" || pkg == "privacy-proxy/cmd/ops-v2-identity-migrate"
		for dep := range transitiveDeps(t, root, pkg) {
			if strings.HasPrefix(dep, "privacy-proxy/") && dep != pkg && !allowed[dep] && !(usesSQL && dep == "privacy-proxy/internal/operational/identitysql") {
				t.Errorf("%s imports unapproved infrastructure %s", pkg, dep)
			}
			if !usesSQL && (strings.HasPrefix(dep, "github.com/jackc/pgx") || strings.HasPrefix(dep, "github.com/jackc/tern")) {
				t.Errorf("provider/core session logic imports SQL driver %s", dep)
			}
			primitive := allowed["privacy-proxy/internal/identitybroker/privado"] && transactionPrimitive(dep)
			if strings.HasPrefix(dep, "github.com/redis/") || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core") && !primitive || strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/triedb") {
				t.Errorf("identity broker imports legacy persistence/VM %s", dep)
			}
			if pkg == "privacy-proxy/internal/brokerpolicy" && (dep == "net/http" || dep == "crypto/tls") {
				t.Errorf("public broker policy imports I/O %s", dep)
			}
		}
	}
}

// The real Privado verifier is a provider boundary, not a new Core dependency.
// Geth ABI/RPC primitive types and the pinned proof SDK are intentional here;
// they do not authorize SQL drivers, legacy session infrastructure or EVM code.
func TestPrivadoProviderDependencyBoundary(t *testing.T) {
	const pkg = "privacy-proxy/internal/identitybroker/privado"
	allowed := map[string]bool{pkg: true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/netguard": true, "privacy-proxy/internal/strictjson": true}
	for dep := range transitiveDeps(t, moduleRoot(t), pkg) {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("Privado provider imports application infrastructure %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/pgx", "github.com/jackc/tern", "github.com/redis/", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("Privado provider imports storage/execution machinery %s", dep)
			}
		}
		if strings.HasPrefix(dep, "github.com/ethereum/go-ethereum/core/") && !transactionPrimitive(dep) {
			t.Errorf("Privado provider imports EVM/state machinery %s", dep)
		}
	}
}

func TestNetworkIdentityIsStandardLibraryOnly(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-deps", "-f", `{{if not .Standard}}{{.ImportPath}}{{end}}`, "privacy-proxy/internal/networkidentity")
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("network helper dependencies: %v %s", err, raw)
	}
	for _, dep := range strings.Fields(string(raw)) {
		if dep != "privacy-proxy/internal/networkidentity" {
			t.Errorf("network identity imports nonstdlib %s", dep)
		}
	}
}
func TestProtectedDataPureBoundary(t *testing.T) {
	allowed := map[string]bool{"privacy-proxy/internal/disclosuredata": true, "privacy-proxy/internal/disclosurepolicy": true, "privacy-proxy/internal/identity": true, "privacy-proxy/internal/strictjson": true, "privacy-proxy/internal/networkidentity": true}
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/disclosuredata") {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("pure data imports application machinery %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("pure data imports persistence/VM %s", dep)
			}
		}
	}
}

func TestCurrentWalletDataSourceBoundary(t *testing.T) {
	allowed := map[string]bool{}
	for _, name := range []string{"disclosurewallet", "disclosuredata", "disclosurepolicy", "networkidentity", "walletops", "walletproof", "identity", "runtimepolicy", "policybundle", "policycore", "strictjson", "compliancepolicy", "compliance", "pricefeedpolicy", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/disclosurewallet") {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("current wallet data source imports application machinery %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("current wallet data source imports persistence/VM %s", dep)
			}
		}
	}
}

func TestApprovedSanctionsProjectionBoundary(t *testing.T) {
	allowed := map[string]bool{}
	// compliancepolicy already reuses compliance's pure numeric/settings
	// validation. Persistence and VM dependencies remain forbidden below.
	for _, name := range []string{"disclosuresanctions", "disclosuredata", "disclosurepolicy", "networkidentity", "identity", "policybundle", "policycore", "strictjson", "compliancepolicy", "compliance", "pricefeedpolicy", "brokerpolicy"} {
		allowed["privacy-proxy/internal/"+name] = true
	}
	for dep := range transitiveDeps(t, moduleRoot(t), "privacy-proxy/internal/disclosuresanctions") {
		if strings.HasPrefix(dep, "privacy-proxy/") && !allowed[dep] {
			t.Errorf("approved sanctions projection imports application machinery %s", dep)
		}
		for _, prefix := range []string{"github.com/jackc/", "github.com/redis/", "github.com/ethereum/go-ethereum/core/", "github.com/ethereum/go-ethereum/triedb"} {
			if strings.HasPrefix(dep, prefix) {
				t.Errorf("approved sanctions projection imports persistence/VM %s", dep)
			}
		}
	}
}
