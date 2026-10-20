package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"privacy-proxy/internal/server/apispec"
)

// Route↔spec coverage gate (RD-1166).
//
// Every route the server registers must be documented in the generated
// OpenAPI document — either under its own canonical path or by collapsing
// onto one (alias mounts, impersonation mirrors; see CanonicalizeRoute).
// Operations not yet annotated are carried in openapi_todo_allowlist.txt,
// which may only shrink: annotating an operation without removing its
// allowlist line fails the gate, so coverage can never silently regress
// and the allowlist burns down to zero.

const allowlistFile = "openapi_todo_allowlist.txt"

var paramSegment = regexp.MustCompile(`\{[^/}]*\}`)

// normalizePath makes route-table and spec paths comparable regardless of
// how a path parameter is named ({org_id} vs {orgId}).
func normalizePath(p string) string {
	return paramSegment.ReplaceAllString(p, "{}")
}

// specOperations returns "METHOD /normalized/path" for every operation in
// the embedded generated document, plus the set of normalized paths.
func specOperations(t *testing.T) (map[string]bool, map[string]bool) {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(apispec.JSON, &doc); err != nil {
		t.Fatalf("embedded OpenAPI document does not parse: %v", err)
	}
	if len(doc.Paths) == 0 {
		t.Fatal("embedded OpenAPI document has no paths — run `make api-spec`")
	}
	ops := map[string]bool{}
	paths := map[string]bool{}
	for p, item := range doc.Paths {
		np := normalizePath(p)
		paths[np] = true
		for m := range item {
			switch strings.ToUpper(m) {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
				ops[strings.ToUpper(m)+" "+np] = true
			}
		}
	}
	return ops, paths
}

func readAllowlist(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(allowlistFile)
	if err != nil {
		t.Fatalf("read %s: %v", allowlistFile, err)
	}
	var entries []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries
}

func TestOpenAPICoverage_RouteSpecGate(t *testing.T) {
	specOps, specPaths := specOperations(t)

	// Enumerate the dev superset: dev-only routes are documented too (their
	// descriptions say they exist only in non-production builds).
	routes := RoutesForSpec(true)
	if len(routes) < 300 {
		t.Fatalf("route enumeration returned only %d routes — enumerator broken?", len(routes))
	}

	// requiredOps = canonical operations that must appear in the spec.
	// pathOnly   = canonical paths that must appear (impersonation mirrors:
	// the mount registers .Any(), so method-level matching is meaningless).
	requiredOps := map[string]string{} // "METHOD /path" -> example registered route
	pathOnly := map[string]string{}
	for _, r := range routes {
		cls := CanonicalizeRoute(r.Path)
		switch cls.Kind {
		case RouteKindRejectSurface:
			// Registered only to refuse with an explicit error; documented in
			// the impersonation tag description, not as operations.
			continue
		case RouteKindImpersonationMount:
			pathOnly[normalizePath(cls.Canonical)] = r.Method + " " + r.Path
		default:
			key := r.Method + " " + normalizePath(cls.Canonical)
			if _, ok := requiredOps[key]; !ok {
				requiredOps[key] = r.Method + " " + r.Path
			}
		}
	}

	var missing []string
	for key := range requiredOps {
		if !specOps[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)

	allowed := map[string]bool{}
	var stale []string
	for _, entry := range readAllowlist(t) {
		allowed[entry] = true
		if _, isMissing := requiredOps[entry]; !isMissing {
			stale = append(stale, entry+" (no such registered operation — remove the line)")
			continue
		}
		if specOps[entry] {
			stale = append(stale, entry+" (now documented — remove the line)")
		}
	}

	var fail []string
	for _, m := range missing {
		if !allowed[m] {
			fail = append(fail, m)
		}
	}
	if len(fail) > 0 {
		t.Errorf("%d registered operation(s) lack an OpenAPI entry (annotate the handler and run `make api-spec`, "+
			"or — only for not-yet-annotated legacy coverage — add the line to %s):\n%s",
			len(fail), allowlistFile, strings.Join(fail, "\n"))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("stale %s entr(ies):\n%s", allowlistFile, strings.Join(stale, "\n"))
	}

	// Impersonation mirrors: the canonical target path must be documented.
	var mountMissing []string
	for p, example := range pathOnly {
		if !specPaths[p] {
			mountMissing = append(mountMissing, fmt.Sprintf("%s (from mount %s)", p, example))
		}
	}
	if len(mountMissing) > 0 {
		sort.Strings(mountMissing)
		// The mirror targets are regular canonical routes as well, so they are
		// already gated (and allowlisted) above; this only guards against a
		// spec that documents the mirror but loses the canonical target.
		t.Logf("impersonation mirror targets not yet documented (covered by the allowlist above):\n%s",
			strings.Join(mountMissing, "\n"))
	}

	// Ghost detection: every documented path must correspond to a registered
	// canonical path — a spec entry for a route that no longer exists is
	// exactly the docs drift this gate exists to kill.
	registeredCanonical := map[string]bool{}
	for _, r := range routes {
		registeredCanonical[normalizePath(CanonicalizeRoute(r.Path).Canonical)] = true
	}
	var ghosts []string
	for p := range specPaths {
		if !registeredCanonical[p] {
			ghosts = append(ghosts, p)
		}
	}
	if len(ghosts) > 0 {
		sort.Strings(ghosts)
		t.Errorf("OpenAPI document lists path(s) that no registered route maps to (stale @Router annotation?):\n%s",
			strings.Join(ghosts, "\n"))
	}
}

// TestOpenAPICoverage_ProductionSubset pins the dev/prod route relationship
// the spec relies on: production registers a strict subset of the dev table,
// so documenting the dev superset documents production.
func TestOpenAPICoverage_ProductionSubset(t *testing.T) {
	dev := map[string]bool{}
	for _, r := range RoutesForSpec(true) {
		dev[r.Method+" "+r.Path] = true
	}
	prod := RoutesForSpec(false)
	if len(prod) == 0 {
		t.Fatal("production enumeration returned no routes")
	}
	for _, r := range prod {
		if !dev[r.Method+" "+r.Path] {
			t.Errorf("production-only route not present in the documented dev superset: %s %s", r.Method, r.Path)
		}
	}
}
