package e2e

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// composeManifest is a loose schema covering only the fields the
// manifest tests need (ports + networks per service). Defined once and
// reused by every test in this file.
type composeManifest struct {
	Services map[string]struct {
		Ports    []any `yaml:"ports"`
		Networks any   `yaml:"networks"` // either []string (list form) or map[string]any (dict form)
	} `yaml:"services"`
}

func loadCompose(t *testing.T, repoRoot string) composeManifest {
	t.Helper()
	composePath := filepath.Join(repoRoot, "docker-compose.privacy.yml")
	b, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	var compose composeManifest
	if err := yaml.Unmarshal(b, &compose); err != nil {
		t.Fatalf("parse compose yaml: %v", err)
	}
	return compose
}

// networkSet normalizes the docker-compose `networks:` field — which can
// be either a list of strings or a map keyed by network name — into a
// set of network names attached to the service.
func networkSet(networks any) map[string]bool {
	out := map[string]bool{}
	switch v := networks.(type) {
	case []any:
		for _, n := range v {
			if s, ok := n.(string); ok {
				out[s] = true
			}
		}
	case map[string]any:
		for k := range v {
			out[k] = true
		}
	}
	return out
}

// TestPrivacyManifest_NoInternalPortsPublished is the fast, always-on
// static check that goes with the heavier runtime negative-network test
// in privacy_bypass_test.go.
//
// It parses docker-compose.privacy.yml directly (no Docker required) and
// asserts that every service listed in indexer_zone or bff_zone in
// deployments/privacy/trust-zone.yaml does not declare a `ports:` block.
// Catches the regression where someone adds `ports: ["50051:50051"]` to
// the indexer service — which would reopen the bypass — at the PR
// level, not later via the weekly runtime test.
//
// Runs as part of the regular `make test-e2e` and therefore the pre-push
// hook and CI.
func TestPrivacyManifest_NoInternalPortsPublished(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}
	internal := cfg.AllInternal()
	internalNames := map[string]bool{}
	for _, s := range internal {
		internalNames[s.Name] = true
	}

	compose := loadCompose(t, repoRoot)

	missingServices := []string{}
	for name := range internalNames {
		if _, ok := compose.Services[name]; !ok {
			missingServices = append(missingServices, name)
		}
	}
	sort.Strings(missingServices)
	if len(missingServices) > 0 {
		t.Fatalf("trust-zone.yaml lists internal services that are not in docker-compose.privacy.yml: %s. Either add them to the compose file or remove them from trust-zone.yaml.",
			strings.Join(missingServices, ", "))
	}

	for name, svc := range compose.Services {
		if !internalNames[name] {
			continue
		}
		if len(svc.Ports) > 0 {
			t.Errorf("service %q is in an internal zone but declares %d port mapping(s) in docker-compose.privacy.yml — this reopens the RD-855 bypass. Either remove the ports: block or remove %q from deployments/privacy/trust-zone.yaml.", name, len(svc.Ports), name)
		}
	}
}

// TestPrivacyManifest_PublicServicesArePublished is the positive
// counterpart: services listed under `public:` MUST declare a ports
// block. Catches the regression where someone removes port publishing
// from proxy-frontend, silently making the product unreachable.
func TestPrivacyManifest_PublicServicesArePublished(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}

	compose := loadCompose(t, repoRoot)

	for _, pub := range cfg.Public {
		svc, ok := compose.Services[pub.Name]
		if !ok {
			t.Errorf("public service %q missing from docker-compose.privacy.yml", pub.Name)
			continue
		}
		if len(svc.Ports) == 0 {
			t.Errorf("public service %q declares no ports in compose — users will not be able to reach it", pub.Name)
		}
	}
}

// TestPrivacyManifest_ZoneNetworkAttachments enforces the structural
// floor of the two-zone split (RD-876):
//
//  1. Every indexer_zone service attaches to docker network indexer-zone
//     and NOT to bff-zone.
//  2. Every bff_zone service attaches to docker network bff-zone and
//     NOT to indexer-zone.
//  3. proxy-backend (the BridgeService) attaches to BOTH internal zones
//     — it is the only legitimate path between them.
//  4. No other service attaches to both internal zones. A misbuilt BFF
//     should not be able to reach the indexer because the network
//     forbids it; this rule keeps the network as the structural floor
//     (independent of the BFF's compile-time/runtime defenses).
//
// Adding another cross-zone bridge requires updating BridgeService AND
// justifying the new cross-zone path in the PR description.
func TestPrivacyManifest_ZoneNetworkAttachments(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}

	compose := loadCompose(t, repoRoot)

	// (1) + (2): zone services must be on their own zone, not the other.
	for _, s := range cfg.IndexerZone {
		assertOnlyInZone(t, compose, s.Name, "indexer-zone", "bff-zone")
	}
	for _, s := range cfg.BffZone {
		assertOnlyInZone(t, compose, s.Name, "bff-zone", "indexer-zone")
	}

	// (3): the bridge attaches to both zones.
	bridge, ok := compose.Services[BridgeService]
	if !ok {
		t.Fatalf("bridge service %q missing from docker-compose.privacy.yml", BridgeService)
	}
	bridgeNets := networkSet(bridge.Networks)
	if !bridgeNets["indexer-zone"] {
		t.Errorf("bridge service %q must attach to indexer-zone but does not", BridgeService)
	}
	if !bridgeNets["bff-zone"] {
		t.Errorf("bridge service %q must attach to bff-zone but does not", BridgeService)
	}

	// (4): no service besides the bridge spans both zones.
	for name, svc := range compose.Services {
		if name == BridgeService {
			continue
		}
		nets := networkSet(svc.Networks)
		if nets["indexer-zone"] && nets["bff-zone"] {
			t.Errorf("service %q attaches to both indexer-zone and bff-zone — only %q (the BridgeService) is permitted to bridge them. Either remove one of the network attachments, or update e2e.BridgeService and the trust-zone.yaml description.", name, BridgeService)
		}
	}
}

// assertOnlyInZone verifies that a service attaches to wantZone and not
// to forbiddenZone. Used by the two-zone enforcement test.
func assertOnlyInZone(t *testing.T, compose composeManifest, name, wantZone, forbiddenZone string) {
	t.Helper()
	svc, ok := compose.Services[name]
	if !ok {
		t.Errorf("service %q listed in trust-zone.yaml is missing from docker-compose.privacy.yml", name)
		return
	}
	nets := networkSet(svc.Networks)
	if !nets[wantZone] {
		t.Errorf("service %q must attach to docker network %q but does not (attached to %v)", name, wantZone, sortedKeys(nets))
	}
	if nets[forbiddenZone] {
		t.Errorf("service %q must NOT attach to docker network %q (it is in the wrong zone) — %v", name, forbiddenZone, sortedKeys(nets))
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
