package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"privacy-proxy/internal/server/apispec"
)

// TestOpenAPIAuthz_AnonymousDenied is the fail-closed half of the per-endpoint
// authz matrix (RD-1166; the full matrix with real principals — wrong role,
// cross-org, right-principal-2xx — is RD-1168 and needs a provisioned DB):
//
// every operation the generated spec documents as secured (BearerAuth or
// AdminToken), plus the private-network-only surfaces (/api/v1/explorer,
// /metrics), must reject an UNAUTHENTICATED request from a non-private
// address at the middleware layer — 401/403 (or an oracle-avoiding 404) —
// and must never answer 2xx.
//
// The probe runs on the real router built by specRouter with every
// dependency behind the middleware nil'd: if a request gets past the gate,
// the handler panics on a nil dependency and gin's recovery turns it into a
// 500 — so BOTH a 2xx and a 5xx here mean a documented-protected operation
// lost its middleware gate. That is exactly the fail-open regression this
// test exists to catch, driven from the spec so new endpoints are in scope
// the moment they are documented.
func TestOpenAPIAuthz_AnonymousDenied(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(apispec.JSON, &doc); err != nil {
		t.Fatalf("embedded OpenAPI document does not parse: %v", err)
	}
	if len(doc.Paths) == 0 {
		t.Fatal("embedded OpenAPI document has no paths — run `make api-spec`")
	}

	router, stop := specRouter(true)
	defer stop()

	type probe struct{ method, specPath, url string }
	var probes []probe
	for p, item := range doc.Paths {
		for m, op := range item {
			method := strings.ToUpper(m)
			switch method {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
			default:
				continue
			}
			// The JSON-RPC mount documents BearerAuth but the token is
			// optional BY DESIGN (anonymous callers get the anonymous method
			// allowlist; denial is per-method RBAC downstream, not a
			// middleware gate). Its anonymous behavior is covered by the
			// RPC e2e suites, and with nil upstream deps it cannot be
			// probed here.
			if p == "/rpc" || strings.HasPrefix(p, "/rpc/") {
				continue
			}
			secured := len(op.Security) > 0
			privateOnly := strings.HasPrefix(p, "/api/v1/explorer") || p == "/metrics"
			if !secured && !privateOnly {
				continue // public by design (auth, oauth, health, openapi.json, dev identities)
			}
			url := concretePath(p)
			probes = append(probes, probe{method, p, url})
		}
	}
	sort.Slice(probes, func(i, j int) bool {
		if probes[i].specPath != probes[j].specPath {
			return probes[i].specPath < probes[j].specPath
		}
		return probes[i].method < probes[j].method
	})

	// Sanity floor: the admin + explorer + user surfaces alone are >100
	// operations. A collapse here means the spec parse or the filter broke,
	// not that the API got smaller.
	if len(probes) < 100 {
		t.Fatalf("only %d secured operations found in the spec — filter or spec broken", len(probes))
	}

	denied := map[int]bool{
		http.StatusUnauthorized: true,
		http.StatusForbidden:    true,
		// Oracle-avoiding gates may deny with 404; still a denial.
		http.StatusNotFound: true,
	}

	for _, pr := range probes {
		w := httptest.NewRecorder()
		// httptest.NewRequest's default RemoteAddr (192.0.2.1) is a public
		// TEST-NET address, so the private-network gates must also deny.
		req := httptest.NewRequest(pr.method, pr.url, nil)
		router.ServeHTTP(w, req)

		if !denied[w.Code] {
			t.Errorf("%s %s: anonymous request got %d, want a denial (401/403/404) — "+
				"2xx means the auth gate is gone, 5xx means the handler was reached",
				pr.method, pr.specPath, w.Code)
			continue
		}
		// A denial body, when JSON, must be the opaque error envelope —
		// no data fields, no internals (RD-934 discipline holds at the gates).
		body := w.Body.Bytes()
		if len(body) > 0 && body[0] == '{' {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(body, &m); err != nil {
				t.Errorf("%s %s: denial body is not valid JSON: %s", pr.method, pr.specPath, body)
				continue
			}
			for k := range m {
				if k != "error" {
					t.Errorf("%s %s: denial body carries %q — denials must be the opaque {\"error\"} envelope, got %s",
						pr.method, pr.specPath, k, body)
				}
			}
		}
	}
	t.Logf("probed %d secured operations from the spec", len(probes))
}

// concretePath substitutes benign literal values for {param} segments. The
// values never matter for this test — denial must happen at the middleware
// layer, before any parameter is interpreted.
func concretePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			name := strings.Trim(s, "{}")
			switch {
			case strings.Contains(name, "address") || strings.Contains(name, "hash"):
				segs[i] = "0x0000000000000000000000000000000000000001"
			case strings.Contains(name, "number"):
				segs[i] = "1"
			default:
				segs[i] = "probe"
			}
		}
	}
	return strings.Join(segs, "/")
}
