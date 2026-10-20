//go:build privacy_bypass
// +build privacy_bypass

// Negative-network tests for the privacy-mode deployment (RD-855 Phase 4b).
//
// Run with:
//
//	make e2e-privacy
//
// Each run uses a unique Compose project and Docker-assigned public ports by
// default. Set E2E_PRIVACY_PROJECT to give an external harness a stable project
// name. HOST_PORT_PROXY, HOST_PORT_UI, and HOST_PORT_EXPLORER remain available
// as explicit port overrides.
//
// The build tag keeps this out of the default test run (and the pre-push
// hook): the test brings up the full privacy-mode Compose stack and exercises
// the trust boundary from the outside. It takes 1-2 minutes in the happy case.
//
// The test asserts:
//
//  1. Internal-zone services (chain-indexer gRPC port, indexer postgres,
//     anvil RPC, Open Privacy Suite postgres, redis, BFF, BFF postgres) have
//     no host bindings owned by this Compose project. The list is loaded from
//     trust-zone.yaml dynamically.
//
//  2. The compose manifest itself does not publish ports on
//     internal-zone services (structural check via `docker compose
//     config`).
//
//  3. The block-explorer frontend in privacy mode:
//     - Responds to GET /
//     - Routes /api/* to Open Privacy Suite (NOT to a local api:8080 which
//     doesn't exist here)
//     - Returns 404 on /ws (subscriptions deferred per RD-855)
//
//  4. Cross-zone isolation (RD-876): a probe attached to bff-zone
//     cannot reach chain-indexer:50051. The two-zone split is the
//     structural floor that survives upstream build-pipeline
//     mistakes (a misbuilt BFF that lost its --target privacy tag or
//     had INDEXER_URL set still cannot reach the indexer because
//     they're on different docker networks).
//
// Together these prove the bypass described in RD-855 is closed and
// hardened per RD-876: there is no reachable path from a client to raw
// chain data except via Open Privacy Suite, which applies RedactionEngine
// on the way out.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// internalService identifies a project-owned internal container and the port
// it listens on inside the Compose network. It is loaded from trust-zone.yaml
// so the binding oracle stays in sync as services are added or removed.
type internalService struct {
	Service string
	Port    int
}

func loadInternalServices(t *testing.T, repoRoot string) []internalService {
	t.Helper()
	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}
	all := cfg.AllInternal()
	out := make([]internalService, 0, len(all))
	for _, s := range all {
		out = append(out, internalService{Service: s.Name, Port: s.DefaultInternalPort})
	}
	return out
}

// privacyComposeProject returns an explicit harness-supplied project name or a
// per-process unique default. COMPOSE_PROJECT_NAME is deliberately ignored:
// this stack must not accidentally join (and later tear down) another Compose
// stack whose name happens to be present in the caller's environment.
func privacyComposeProject() string {
	if project := strings.TrimSpace(os.Getenv("E2E_PRIVACY_PROJECT")); project != "" {
		return project
	}
	// Kept as a compatibility alias for callers that predate the all-E2E
	// harness. New callers should use E2E_PRIVACY_PROJECT.
	if project := strings.TrimSpace(os.Getenv("PRIVACY_BYPASS_COMPOSE_PROJECT")); project != "" {
		return project
	}
	return fmt.Sprintf("privacy-bypass-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// publicHostPort returns an explicit override or 0, which asks Docker to
// allocate a free ephemeral host port. The actual project-owned binding is
// discovered after Compose starts instead of assuming a machine-global port.
func publicHostPort(key string) string {
	if port := strings.TrimSpace(os.Getenv(key)); port != "" {
		return port
	}
	return "0"
}

var privacyProjectNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

const privacyOwnershipMarkerDir = "/tmp/privacy-proxy-e2e-project-locks"

type privacyProjectResources struct {
	Containers []string
	Networks   []string
	Volumes    []string
	Images     []string
}

func (r privacyProjectResources) empty() bool {
	return len(r.Containers) == 0 && len(r.Networks) == 0 && len(r.Volumes) == 0 && len(r.Images) == 0
}

func (r privacyProjectResources) String() string {
	return fmt.Sprintf("containers=%v networks=%v volumes=%v images=%v", r.Containers, r.Networks, r.Volumes, r.Images)
}

type privacyProjectOwnership struct {
	project           string
	markerDescription string
	verifyFn          func() error
	releaseFn         func() error
}

func (o *privacyProjectOwnership) verify() error {
	if o == nil || o.verifyFn == nil {
		return fmt.Errorf("privacy project ownership is unverified")
	}
	return o.verifyFn()
}

func (o *privacyProjectOwnership) release() error {
	if o == nil || o.releaseFn == nil {
		return fmt.Errorf("privacy project ownership cannot be released")
	}
	return o.releaseFn()
}

type privacyOwnershipDependencies struct {
	listResources    func(string) (privacyProjectResources, error)
	harnessOwnership func(string, string) (*privacyProjectOwnership, bool, error)
	directOwnership  func(string) (*privacyProjectOwnership, error)
}

func defaultPrivacyOwnershipDependencies() privacyOwnershipDependencies {
	return privacyOwnershipDependencies{
		listResources:    dockerPrivacyProjectResources,
		harnessOwnership: harnessPrivacyProjectOwnership,
		directOwnership:  createDirectPrivacyProjectOwnership,
	}
}

func validatePrivacyProjectName(project string) error {
	if len(project) == 0 || len(project) > 63 || !privacyProjectNamePattern.MatchString(project) {
		return fmt.Errorf("Compose project must start with a lowercase letter or digit, contain only a-z, 0-9, underscore, or hyphen, and be at most 63 characters (got %q)", project)
	}
	return nil
}

func dockerPrivacyProjectResources(project string) (privacyProjectResources, error) {
	containers, err := dockerResourceIDs("container", "ls", "-aq", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return privacyProjectResources{}, fmt.Errorf("inventory project containers: %w", err)
	}
	networks, err := dockerResourceIDs("network", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return privacyProjectResources{}, fmt.Errorf("inventory project networks: %w", err)
	}
	volumes, err := dockerResourceIDs("volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return privacyProjectResources{}, fmt.Errorf("inventory project volumes: %w", err)
	}
	imagesByLabel, err := dockerResourceIDs("image", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return privacyProjectResources{}, fmt.Errorf("inventory project images by label: %w", err)
	}
	imagesByReference, err := dockerResourceIDs("image", "ls", "-q", "--filter", "reference="+project+"-*")
	if err != nil {
		return privacyProjectResources{}, fmt.Errorf("inventory project images by reference: %w", err)
	}
	return privacyProjectResources{
		Containers: containers,
		Networks:   networks,
		Volumes:    volumes,
		Images:     uniqueStrings(append(imagesByLabel, imagesByReference...)),
	}, nil
}

func dockerResourceIDs(args ...string) ([]string, error) {
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return uniqueStrings(strings.Fields(string(out))), nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func acquirePrivacyProjectOwnership(repoRoot, project string, deps privacyOwnershipDependencies) (*privacyProjectOwnership, error) {
	if err := validatePrivacyProjectName(project); err != nil {
		return nil, err
	}
	resources, err := deps.listResources(project)
	if err != nil {
		return nil, err
	}
	harnessOwner, markerPresent, markerErr := deps.harnessOwnership(repoRoot, project)
	if markerPresent {
		if markerErr != nil {
			return nil, fmt.Errorf("invalid harness privacy-project ownership marker: %w", markerErr)
		}
		if harnessOwner == nil {
			return nil, fmt.Errorf("harness ownership marker was reported present without an owner")
		}
		if err := harnessOwner.verify(); err != nil {
			return nil, fmt.Errorf("verify harness privacy-project ownership: %w", err)
		}
		return harnessOwner, nil
	}
	if markerErr != nil {
		return nil, fmt.Errorf("inspect harness privacy-project ownership marker: %w", markerErr)
	}
	if !resources.empty() {
		return nil, fmt.Errorf("Compose project already has resources but no verified owner marker (%s)", resources)
	}

	directOwner, err := deps.directOwnership(project)
	if err != nil {
		return nil, fmt.Errorf("acquire direct privacy-project ownership: %w", err)
	}
	resources, err = deps.listResources(project)
	if err != nil {
		releaseErr := directOwner.release()
		return nil, fmt.Errorf("recheck project resources after ownership acquisition: %w (release marker: %v)", err, releaseErr)
	}
	if !resources.empty() {
		releaseErr := directOwner.release()
		return nil, fmt.Errorf("Compose project acquired resources during ownership check (%s); refusing to continue (release marker: %v)", resources, releaseErr)
	}
	return directOwner, nil
}

func claimPrivacyProjectForTest(t *testing.T, repoRoot, project string, cleanup func() error) (*privacyProjectOwnership, error) {
	return claimPrivacyProjectForTestWithDeps(t, repoRoot, project, defaultPrivacyOwnershipDependencies(), cleanup)
}

func claimPrivacyProjectForTestWithDeps(t *testing.T, repoRoot, project string, deps privacyOwnershipDependencies, cleanup func() error) (*privacyProjectOwnership, error) {
	t.Helper()
	owner, err := acquirePrivacyProjectOwnership(repoRoot, project, deps)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		// This check is deliberately adjacent to the destructive callback. A
		// marker that disappeared or changed after startup turns cleanup into a
		// fail-closed leak, never a down against an unverified project.
		if err := owner.verify(); err != nil {
			t.Errorf("refusing destructive cleanup for unverified Compose project %q: %v", project, err)
			return
		}
		if err := cleanup(); err != nil {
			t.Errorf("cleanup verified Compose project %q: %v", project, err)
			return
		}
		if err := owner.release(); err != nil {
			t.Errorf("release Compose project %q ownership marker: %v", project, err)
		}
	})
	return owner, nil
}

func harnessPrivacyProjectOwnership(repoRoot, project string) (*privacyProjectOwnership, bool, error) {
	artifactDir := strings.TrimSpace(os.Getenv("E2E_ARTIFACT_DIR"))
	if artifactDir == "" {
		return nil, false, nil
	}
	if !filepath.IsAbs(artifactDir) {
		artifactDir = filepath.Join(repoRoot, artifactDir)
	}
	artifactDir = filepath.Clean(artifactDir)
	roots := []string{artifactDir}
	if filepath.Base(artifactDir) == "privacy" {
		roots = append(roots, filepath.Dir(artifactDir))
	}

	markerNames := []string{".harness-owner", "run.env", ".privacy-project-owner"}
	var candidates []string
	for _, root := range roots {
		found := false
		for _, name := range markerNames {
			_, err := os.Lstat(filepath.Join(root, name))
			if err == nil {
				found = true
				continue
			}
			if !os.IsNotExist(err) {
				return nil, true, fmt.Errorf("inspect ownership marker %s: %w", filepath.Join(root, name), err)
			}
		}
		if found {
			candidates = append(candidates, root)
		}
	}
	if len(candidates) == 0 {
		return nil, false, nil
	}
	if len(candidates) != 1 {
		return nil, true, fmt.Errorf("ambiguous harness ownership roots: %v", candidates)
	}

	expectedRunID := strings.TrimSpace(os.Getenv("E2E_RUN_ID"))
	expectedBaseProject := strings.TrimSpace(os.Getenv("E2E_PROJECT"))
	if expectedRunID == "" || expectedBaseProject == "" {
		return nil, true, fmt.Errorf("harness markers require non-empty E2E_RUN_ID and E2E_PROJECT")
	}
	expected := map[string]string{
		"run_id":          expectedRunID,
		"project":         expectedBaseProject,
		"privacy_project": project,
	}
	snapshots := make(map[string][]byte, len(markerNames))
	metadata := make(map[string]map[string]string, len(markerNames))
	for _, name := range markerNames {
		path := filepath.Join(candidates[0], name)
		data, err := readRegularOwnershipFile(path)
		if err != nil {
			return nil, true, err
		}
		parsed, err := parseOwnershipMetadata(path, data)
		if err != nil {
			return nil, true, err
		}
		for key, want := range expected {
			if got := parsed[key]; got != want {
				return nil, true, fmt.Errorf("ownership marker %s has %s=%q, want %q", path, key, got, want)
			}
		}
		snapshots[path] = append([]byte(nil), data...)
		metadata[name] = parsed
	}
	if got := metadata[".privacy-project-owner"]["kind"]; got != "privacy" {
		return nil, true, fmt.Errorf("privacy-project marker kind=%q, want privacy", got)
	}

	verify := func() error {
		for path, want := range snapshots {
			got, err := readRegularOwnershipFile(path)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("ownership marker changed after acquisition: %s", path)
			}
		}
		return nil
	}
	owner := &privacyProjectOwnership{
		project:           project,
		markerDescription: "verified harness marker " + filepath.Join(candidates[0], ".privacy-project-owner"),
		verifyFn:          verify,
		releaseFn:         func() error { return nil },
	}
	return owner, true, nil
}

func readRegularOwnershipFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect ownership marker %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("ownership marker is not a regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ownership marker %s: %w", path, err)
	}
	return data, nil
}

func parseOwnershipMetadata(path string, data []byte) (map[string]string, error) {
	metadata := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid ownership metadata line in %s: %q", path, line)
		}
		if _, duplicate := metadata[key]; duplicate {
			return nil, fmt.Errorf("duplicate ownership metadata key %q in %s", key, path)
		}
		metadata[key] = value
	}
	return metadata, nil
}

func createDirectPrivacyProjectOwnership(project string) (*privacyProjectOwnership, error) {
	if err := validatePrivacyProjectName(project); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(privacyOwnershipMarkerDir, 0o700); err != nil {
		return nil, fmt.Errorf("create ownership marker directory: %w", err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate ownership nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	markerPath := filepath.Join(privacyOwnershipMarkerDir, project+".go-owner")
	markerBody := []byte(fmt.Sprintf("version=1\nproject=%s\nnonce=%s\n", project, nonce))
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create exclusive ownership marker %s: %w", markerPath, err)
	}
	removeCreatedMarker := func() {
		_ = marker.Close()
		_ = os.Remove(markerPath)
	}
	if _, err := marker.Write(markerBody); err != nil {
		removeCreatedMarker()
		return nil, fmt.Errorf("write ownership marker %s: %w", markerPath, err)
	}
	if err := marker.Sync(); err != nil {
		removeCreatedMarker()
		return nil, fmt.Errorf("sync ownership marker %s: %w", markerPath, err)
	}
	if err := marker.Close(); err != nil {
		_ = os.Remove(markerPath)
		return nil, fmt.Errorf("close ownership marker %s: %w", markerPath, err)
	}

	verify := func() error {
		got, err := readRegularOwnershipFile(markerPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, markerBody) {
			return fmt.Errorf("direct ownership nonce changed for project %s", project)
		}
		return nil
	}
	owner := &privacyProjectOwnership{
		project:           project,
		markerDescription: "direct nonce marker " + markerPath,
		verifyFn:          verify,
	}
	owner.releaseFn = func() error {
		if err := verify(); err != nil {
			return err
		}
		if err := os.Remove(markerPath); err != nil {
			return fmt.Errorf("remove owned marker %s: %w", markerPath, err)
		}
		return nil
	}
	if err := owner.verify(); err != nil {
		return nil, fmt.Errorf("verify new ownership marker: %w", err)
	}
	return owner, nil
}

func TestPrivacyModeBypassClosure(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	// The compose file lives at the repo root; locate it relative to this file.
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	composeFile := filepath.Join(repoRoot, "docker-compose.privacy.yml")
	if _, err := os.Stat(composeFile); err != nil {
		t.Fatalf("compose file not found at %s: %v", composeFile, err)
	}

	if override := privacyComposeOverride(repoRoot); override != "" {
		if _, err := os.Stat(override); err != nil {
			t.Fatalf("privacy Compose override not found at %s: %v", override, err)
		}
		t.Logf("using privacy Compose image-provenance override %s", override)
	}

	project := privacyComposeProject()
	env := []string{
		"JWT_SECRET=test-jwt-secret-do-not-use-in-production-1234567890",
		"JWT_REFRESH_SECRET=test-refresh-secret-do-not-use-in-production-0987654321",
		"ADMIN_API_TOKEN=test-admin-token",
		"PRIVACY_POSTGRES_PASSWORD=test-privacy-pg-password",
		"AUDIT_APP_PASSWORD=test-audit-app-password",
		"INDEXER_POSTGRES_PASSWORD=test-indexer-pg-password",
		"REDIS_PASSWORD=test-redis-password",
		"BLOCK_EXPLORER_POSTGRES_PASSWORD=test-bff-pg-password",
		"CORS_ALLOWED_ORIGINS=https://explorer.e2e.invalid,https://frontend.e2e.invalid",
		// Loopback-only, Docker-assigned ports prevent this test from
		// colliding with unrelated services on a shared host. Supplying a
		// HOST_PORT_* variable is an explicit request for a fixed port.
		"HOST_BIND=127.0.0.1",
		"HOST_PORT_PROXY=" + publicHostPort("HOST_PORT_PROXY"),
		"HOST_PORT_UI=" + publicHostPort("HOST_PORT_UI"),
		"HOST_PORT_EXPLORER=" + publicHostPort("HOST_PORT_EXPLORER"),
		// Dynamic published ports are not known until Docker starts. Use
		// valid HTTPS placeholders for browser-facing URL settings in this
		// network-boundary-only topology, rather than localhost:0. This test
		// does not exercise browser callbacks; Playwright owns that lane.
		"BASE_URL=https://proxy.e2e.invalid",
		"FRONTEND_URL=https://frontend.e2e.invalid",
		"VITE_BLOCK_EXPLORER_URL=https://explorer.e2e.invalid",
		"PRIVACY_PROXY_PUBLIC_URL=https://proxy.e2e.invalid",
		"SSO_REDIRECT_URI=https://explorer.e2e.invalid/api/auth/callback",
	}

	ownership, err := claimPrivacyProjectForTest(t, repoRoot, project, func() error {
		capturePrivacyComposeArtifacts(t, composeFile, env, repoRoot, project)
		down := dockerCompose(composeFile, env, repoRoot, project, "down", "-v", "--remove-orphans", "--rmi", "local")
		if out, err := down.CombinedOutput(); err != nil {
			return fmt.Errorf("compose down failed (project %s may have leaked resources): %w\n%s", project, err, string(out))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("refusing to use Compose project %q: %v", project, err)
	}
	t.Logf("using isolated Compose project %q (%s)", project, ownership.markerDescription)

	internalServices := loadInternalServices(t, repoRoot)

	t.Run("compose config does not publish internal-zone ports", func(t *testing.T) {
		assertNoPublishedInternalPortsInConfig(t, composeFile, env, repoRoot, project, internalServices)
	})

	t.Logf("starting privacy-mode compose stack (this may take 1-2 minutes)")
	up := dockerCompose(composeFile, env, repoRoot, project, "up", "-d", "--wait")
	out, err := up.CombinedOutput()
	if err != nil {
		t.Logf("compose up output:\n%s", string(out))
		t.Fatalf("compose up: %v", err)
	}

	// Resolve the ports from this project's containers. This both handles
	// Docker-assigned ports and prevents a successful probe from being
	// accidentally attributed to an unrelated listener on the machine.
	proxyPort := composePublishedPort(t, composeFile, env, repoRoot, project, "proxy-backend", 8080)
	uiPort := composePublishedPort(t, composeFile, env, repoRoot, project, "proxy-frontend", 80)
	explorerPort := composePublishedPort(t, composeFile, env, repoRoot, project, "block-explorer-frontend", 80)

	t.Run("internal-zone services have no project-owned host bindings", func(t *testing.T) {
		for _, svc := range internalServices {
			t.Run(svc.Service, func(t *testing.T) {
				assertNoPublishedPortsOnProjectService(t, composeFile, env, repoRoot, project, svc)
			})
		}
	})

	// RD-876: cross-zone isolation. Even if a future change drops the
	// BFF's `--target privacy` build tag or sets INDEXER_URL, the BFF
	// still cannot reach the indexer because they're on different
	// docker networks. Probe with throwaway alpine containers attached
	// to one zone at a time.
	t.Run("BFF cannot reach indexer across zones", func(t *testing.T) {
		assertCrossZoneIsolation(t, project)
	})

	t.Run("proxy-backend reachable on host", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", proxyPort)
		assertHTTP200(t, fmt.Sprintf("http://127.0.0.1:%d/health", proxyPort))
	})

	t.Run("proxy-frontend reachable on host", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", uiPort)
	})

	t.Run("block-explorer frontend reachable", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", explorerPort)
	})

	t.Run("block-explorer /ws returns 404 in privacy mode", func(t *testing.T) {
		// Privacy-mode nginx config explicitly returns 404 on /ws —
		// subscriptions are deferred. The legacy standalone config
		// would have proxied /ws to a local api:8080 which doesn't
		// exist here; a successful upgrade or a 502 would indicate
		// the wrong nginx config got mounted.
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/ws", explorerPort))
		if err != nil {
			t.Fatalf("GET /ws: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 404 on /ws, got %d\nbody: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("block-explorer privacy API returns exact Open Privacy Suite response", func(t *testing.T) {
		// This is a controlled OPS-specific oracle, not merely "not 502".
		// The privacy BFF requires a display identity, then forwards this grant
		// request to OPS and passes its status/body through byte-for-byte. The
		// fixed UUID is deliberately absent, so OPS's getGrantTransactions
		// handler returns its exact JSON 404. Local BFF/static fallbacks use
		// different status, content type, or body shapes.
		const (
			missingGrantID = "00000000-0000-0000-0000-000000000000"
			addressID      = "11111111-1111-1111-1111-111111111111"
		)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		url := fmt.Sprintf("http://127.0.0.1:%d/api/privacy/grant/%s/%s/transactions", explorerPort, missingGrantID, addressID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build controlled OPS oracle request: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: "explorer_auth", Value: explorerDisplayOnlyJWT()})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET controlled OPS oracle: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read controlled OPS oracle response: %v", err)
		}
		const wantBody = `{"error":"grant not found"}`
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" || string(body) != wantBody {
			t.Fatalf("controlled OPS oracle mismatch: status=%d content-type=%q body=%q; want status=404 content-type=application/json body=%s", resp.StatusCode, resp.Header.Get("Content-Type"), string(body), wantBody)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("controlled OPS oracle returned invalid JSON: %v", err)
		}
		if len(payload) != 1 {
			t.Fatalf("controlled OPS oracle schema has keys %v; want only error", payload)
		}
	})
}

func explorerDisplayOnlyJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"sub":"did:e2e:privacy-routing-oracle","exp":%d}`, time.Now().Add(time.Hour).Unix())
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	return header + "." + payload + ".unsigned"
}

func TestPrivacyProjectCollisionFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		resources privacyProjectResources
	}{
		{name: "container", resources: privacyProjectResources{Containers: []string{"unrelated-container"}}},
		{name: "network", resources: privacyProjectResources{Networks: []string{"unrelated-network"}}},
		{name: "volume", resources: privacyProjectResources{Volumes: []string{"unrelated-volume"}}},
		{name: "image", resources: privacyProjectResources{Images: []string{"unrelated-image"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := []byte("unrelated sentinel data must survive\n")
			sentinelPath := filepath.Join(t.TempDir(), "unrelated-sentinel")
			if err := os.WriteFile(sentinelPath, original, 0o600); err != nil {
				t.Fatalf("write sentinel: %v", err)
			}
			downCalls := 0
			markerCreated := false
			assertUntouched := func() {
				t.Helper()
				got, err := os.ReadFile(sentinelPath)
				if err != nil {
					t.Errorf("unrelated sentinel was removed: %v", err)
					return
				}
				if !bytes.Equal(got, original) {
					t.Errorf("unrelated sentinel changed: got %q, want %q", got, original)
				}
				if downCalls != 0 {
					t.Errorf("destructive cleanup ran %d times after ownership collision", downCalls)
				}
				if markerCreated {
					t.Error("direct ownership marker was created despite a pre-existing project resource")
				}
			}
			// Registered first so it runs after any cleanup the claim helper might
			// accidentally register (testing cleanups are LIFO).
			t.Cleanup(assertUntouched)

			deps := privacyOwnershipDependencies{
				listResources: func(string) (privacyProjectResources, error) {
					return tc.resources, nil
				},
				harnessOwnership: func(string, string) (*privacyProjectOwnership, bool, error) {
					return nil, false, nil
				},
				directOwnership: func(string) (*privacyProjectOwnership, error) {
					markerCreated = true
					return nil, fmt.Errorf("must not create a marker for a colliding project")
				},
			}
			owner, err := claimPrivacyProjectForTestWithDeps(t, "unused", "privacy-collision-test", deps, func() error {
				downCalls++
				return os.Remove(sentinelPath)
			})
			if err == nil {
				t.Fatal("expected project ownership collision to fail closed")
			}
			if owner != nil {
				t.Fatalf("collision returned unexpected owner: %+v", owner)
			}
			assertUntouched()
		})
	}
}

// ----- helpers -----

// privacyComposeOverride returns the optional harness-provided image
// provenance overlay. Relative paths are rooted at the repository so every
// Compose invocation resolves the same file regardless of the caller's cwd.
func privacyComposeOverride(repoRoot string) string {
	override := strings.TrimSpace(os.Getenv("E2E_PRIVACY_COMPOSE_OVERRIDE"))
	if override == "" {
		return ""
	}
	if !filepath.IsAbs(override) {
		override = filepath.Join(repoRoot, override)
	}
	return filepath.Clean(override)
}

// dockerCompose constructs a project-scoped docker compose command rooted at
// repoRoot, using the production manifest plus an optional image-provenance
// overlay, with env vars injected.
func dockerCompose(composeFile string, env []string, repoRoot, project string, args ...string) *exec.Cmd {
	full := []string{"compose", "-f", composeFile}
	if override := privacyComposeOverride(repoRoot); override != "" {
		full = append(full, "-f", override)
	}
	full = append(full, "-p", project)
	full = append(full, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = repoRoot
	cmd.Env = mergedEnv(os.Environ(), env)
	return cmd
}

// capturePrivacyComposeArtifacts preserves project state immediately before
// teardown when the harness supplied an artifact directory. Captures are
// best-effort diagnostics: a logging failure must not prevent Compose cleanup.
func capturePrivacyComposeArtifacts(t *testing.T, composeFile string, env []string, repoRoot, project string) {
	t.Helper()
	artifactDir := strings.TrimSpace(os.Getenv("E2E_ARTIFACT_DIR"))
	if artifactDir == "" {
		return
	}
	if !filepath.IsAbs(artifactDir) {
		artifactDir = filepath.Join(repoRoot, artifactDir)
	}
	artifactDir = filepath.Clean(artifactDir)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Logf("create privacy artifact directory %s: %v", artifactDir, err)
		return
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	captures := []struct {
		name string
		args []string
	}{
		{name: "ps", args: []string{"ps", "--all"}},
		{name: "logs", args: []string{"logs", "--no-color"}},
	}
	for _, capture := range captures {
		path := filepath.Join(artifactDir, fmt.Sprintf("privacy-compose-pre-down-%s-%s.log", stamp, capture.name))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Logf("create privacy Compose artifact %s: %v", path, err)
			continue
		}
		cmd := dockerCompose(composeFile, env, repoRoot, project, capture.args...)
		cmd.Stdout = file
		cmd.Stderr = file
		runErr := cmd.Run()
		closeErr := file.Close()
		if runErr != nil {
			t.Logf("capture privacy Compose %s to %s: %v", capture.name, path, runErr)
		}
		if closeErr != nil {
			t.Logf("close privacy Compose artifact %s: %v", path, closeErr)
		}
	}
}

// mergedEnv gives explicit test values precedence even when the caller has the
// same variables set. Passing duplicate keys to a child process is ambiguous
// across platforms and can otherwise defeat isolation settings such as the
// loopback bind and dynamic host ports.
func mergedEnv(base, overrides []string) []string {
	overridden := make(map[string]bool, len(overrides))
	for _, entry := range overrides {
		if key, _, ok := strings.Cut(entry, "="); ok {
			overridden[key] = true
		}
	}

	out := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok && overridden[key] {
			continue
		}
		out = append(out, entry)
	}
	return append(out, overrides...)
}

// composePublishedPort discovers a public binding through the exact Compose
// project started by this test. Docker chooses the port when HOST_PORT_*=0, so
// no machine-global default or unrelated listener is trusted as the oracle.
func composePublishedPort(t *testing.T, composeFile string, env []string, repoRoot, project, service string, containerPort int) int {
	t.Helper()
	cmd := dockerCompose(composeFile, env, repoRoot, project, "port", service, strconv.Itoa(containerPort))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve %s port %d for project %s: %v\n%s", service, containerPort, project, err, string(out))
	}

	bindings := strings.Fields(string(out))
	if len(bindings) != 1 {
		t.Fatalf("expected exactly one project-owned binding for %s:%d, got %q", service, containerPort, strings.TrimSpace(string(out)))
	}
	host, portText, err := net.SplitHostPort(bindings[0])
	if err != nil {
		t.Fatalf("parse project-owned binding %q for %s:%d: %v", bindings[0], service, containerPort, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("project %s published %s:%d on non-loopback host %q", project, service, containerPort, host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		t.Fatalf("parse project-owned host port %q for %s:%d", portText, service, containerPort)
	}

	containers := inspectProjectService(t, composeFile, env, repoRoot, project, service)
	if len(containers) != 1 {
		t.Fatalf("expected one container to own public binding %s:%d, got %d", service, containerPort, len(containers))
	}
	containerPortKey := fmt.Sprintf("%d/tcp", containerPort)
	owned := false
	for _, binding := range containers[0].NetworkSettings.Ports[containerPortKey] {
		if binding.HostPort == portText && binding.HostIP == host {
			owned = true
			break
		}
	}
	if !owned {
		t.Fatalf("binding %s for %s:%d is not attributed to project %s container %s", bindings[0], service, containerPort, project, containers[0].Name)
	}
	return port
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type dockerContainerInspection struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]dockerPortBinding `json:"Ports"`
	} `json:"NetworkSettings"`
}

// inspectProjectService resolves containers through Compose and then verifies
// the ownership labels before returning any runtime state to an assertion.
func inspectProjectService(t *testing.T, composeFile string, env []string, repoRoot, project, service string) []dockerContainerInspection {
	t.Helper()
	ps := dockerCompose(composeFile, env, repoRoot, project, "ps", "--all", "--quiet", service)
	out, err := ps.CombinedOutput()
	if err != nil {
		t.Fatalf("list containers for project %s service %s: %v\n%s", project, service, err, string(out))
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		t.Fatalf("project %s has no container for service %s", project, service)
	}

	inspect := exec.Command("docker", append([]string{"inspect"}, ids...)...)
	inspect.Dir = repoRoot
	inspectOut, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect project %s service %s: %v\n%s", project, service, err, string(inspectOut))
	}
	var containers []dockerContainerInspection
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		t.Fatalf("parse docker inspect for project %s service %s: %v", project, service, err)
	}
	if len(containers) != len(ids) {
		t.Fatalf("inspect returned %d containers for %d project-owned IDs (%s/%s)", len(containers), len(ids), project, service)
	}
	for _, container := range containers {
		if got := container.Config.Labels["com.docker.compose.project"]; got != project {
			t.Fatalf("container %s resolved for %s/%s has Compose project label %q", container.Name, project, service, got)
		}
		if got := container.Config.Labels["com.docker.compose.service"]; got != service {
			t.Fatalf("container %s resolved for %s/%s has Compose service label %q", container.Name, project, service, got)
		}
	}
	return containers
}

func assertNoPublishedPortsOnProjectService(t *testing.T, composeFile string, env []string, repoRoot, project string, service internalService) {
	t.Helper()
	containers := inspectProjectService(t, composeFile, env, repoRoot, project, service.Service)
	for _, container := range containers {
		for containerPort, bindings := range container.NetworkSettings.Ports {
			if len(bindings) == 0 {
				continue
			}
			t.Errorf("project %s internal service %s container %s publishes %s via %+v; expected internal port %d and every other port to remain project-internal", project, service.Service, container.Name, containerPort, bindings, service.Port)
		}
	}
}

// assertNoPublishedInternalPortsInConfig parses `docker compose config
// --format json` and fails the test if any internal-zone service
// (indexer-zone or bff-zone) declares a host port mapping.
func assertNoPublishedInternalPortsInConfig(t *testing.T, composeFile string, env []string, repoRoot, project string, internal []internalService) {
	t.Helper()
	cmd := dockerCompose(composeFile, env, repoRoot, project, "config", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	var cfg struct {
		Services map[string]struct {
			Ports []struct {
				Target    int    `json:"target"`
				Published string `json:"published"`
			} `json:"ports"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("parse compose config json: %v", err)
	}
	bannedServices := map[string]bool{}
	for _, s := range internal {
		bannedServices[s.Service] = true
	}
	for name, svc := range cfg.Services {
		if !bannedServices[name] {
			continue
		}
		if len(svc.Ports) > 0 {
			for _, p := range svc.Ports {
				t.Errorf("internal-zone service %q publishes port: target=%d published=%q — privacy-mode compose must not publish internal-zone services", name, p.Target, p.Published)
			}
		}
	}
}

// assertCrossZoneIsolation verifies the structural floor of the
// two-zone trust split:
//
//  1. From indexer-zone, chain-indexer:50051 IS reachable. This positive
//     control gates the negative assertion so a broken probe or target cannot
//     produce a vacuous pass.
//  2. From bff-zone, chain-indexer:50051 must NOT be reachable. This is
//     the load-bearing assertion — a misbuilt BFF that lost its
//     `--target privacy` tag or had INDEXER_URL set must still fail to
//     reach the indexer because the network forbids it.
//
// Probes use a throwaway alpine container attached to one zone at a
// time. busybox `nc -z -w 3` exits 0 on a successful TCP connect.
func assertCrossZoneIsolation(t *testing.T, project string) {
	t.Helper()

	probe := func(network string) ([]byte, error) {
		cmd := exec.Command("docker", "run", "--rm",
			"--network", network,
			"alpine:latest",
			"nc", "-z", "-w", "3", "chain-indexer", "50051")
		return cmd.CombinedOutput()
	}

	bffNet := project + "_bff-zone"
	indexerNet := project + "_indexer-zone"

	// A failing positive control invalidates the negative oracle. Retry because
	// chain-indexer has no Compose healthcheck and may only just have started.
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := probe(indexerNet)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("positive control failed: from %s, chain-indexer:50051 should be reachable: %v\n%s", indexerNet, err, string(out))
		}
		time.Sleep(time.Second)
	}

	// Negative case — load-bearing assertion, now gated by the control above.
	if _, err := probe(bffNet); err == nil {
		t.Fatalf("from %s, chain-indexer:50051 IS reachable — the two-zone trust split is broken. The block-explorer BFF could now bypass Open Privacy Suite at the network layer. Check the compose file: chain-indexer must be on indexer-zone only, the BFF must be on bff-zone only, and proxy-backend (the BridgeService) must be the only service on both.", bffNet)
	}
}

// assertReachable tries to open a TCP connection to host:port. Fails if
// the connect doesn't succeed within a short timeout.
func assertReachable(t *testing.T, host string, port int) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s should be reachable but isn't: %v", addr, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// assertHTTP200 does a GET and fails if the status isn't 200 or the
// request errors. Useful for healthcheck-style probes.
func assertHTTP200(t *testing.T, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d, body: %s", url, resp.StatusCode, string(body))
	}
}
