package selfhttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	f "privacy-proxy/internal/disclosuretest"
)

func TestDiagnosticsActualTLSOwnRoleClosedIngressAndSafeBuild(t *testing.T) {
	snapshot := f.Snapshot(t, nil)
	now := time.Unix(f.Now, 123456789).UTC()
	var calls atomic.Int32
	h, err := NewDiagnostics(DiagnosticsConfig{Config: Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: func() time.Time { return now }}, Build: BuildIdentity{Version: "v2.0.0", Commit: "abcdef012345", BuiltAt: "2026-11-20T12:00:00Z"}, Sample: func(ctx context.Context, org string) DiagnosticsSample {
		calls.Add(1)
		if org != f.Org {
			t.Error("foreign organization sampled", org)
		}
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > 3*time.Second {
			t.Error("unbounded sample")
		}
		return DiagnosticsSample{Readiness: Observation{State: "unavailable", SampledAt: &now}, Node: Observation{State: "connected", SampledAt: &now}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	for _, row := range []struct {
		name, method, path, body, origin, host, role string
		want                                         int
	}{
		{name: "full", role: "Admin", want: 200}, {name: "readonly", role: "Readonly", want: 200},
		{name: "no bearer cookie is no authority", role: "no-bearer", want: 401}, {name: "forged bearer", role: "forged-bearer", want: 401},
		{name: "unconfigured organization has no anonymous existence oracle", path: "/api/v2/orgs/ffffffff-ffff-ffff-ffff-ffffffffffff/diagnostics", role: "no-bearer", want: 401},
		{name: "member", role: "Auditor", want: 403}, {name: "unmapped", want: 403}, {name: "foreign", role: "Foreign", want: 403},
		{name: "foreign organization", path: "/api/v2/orgs/" + f.OtherOrg + "/diagnostics", role: "Admin", want: 403},
		{name: "post", method: "POST", role: "Admin", want: 405}, {name: "head", method: "HEAD", role: "Admin", want: 405}, {name: "options", method: "OPTIONS", role: "Admin", want: 405},
		{name: "query target", path: "/api/v2/orgs/" + f.Org + "/diagnostics?url=https://secret.node", role: "Admin", want: 400},
		{name: "empty query", path: "/api/v2/orgs/" + f.Org + "/diagnostics?", role: "Admin", want: 400},
		{name: "body", body: "x", role: "Admin", want: 400}, {name: "foreign origin", origin: "https://evil.test", role: "Admin", want: 403}, {name: "foreign host", host: "evil.test", role: "Admin", want: 403},
	} {
		t.Run(row.name, func(t *testing.T) {
			method := row.method
			if method == "" {
				method = "GET"
			}
			path := row.path
			if path == "" {
				path = "/api/v2/orgs/" + f.Org + "/diagnostics"
			}
			r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(row.body))
			r.Host = "ops.test"
			if row.host != "" {
				r.Host = row.host
			}
			if row.origin != "" {
				r.Header.Set("Origin", row.origin)
			}
			roles := []string{}
			if row.role != "" {
				roles = append(roles, row.role)
			}
			r.Header.Set("Cookie", "forged-user=admin")
			if row.role != "no-bearer" {
				if row.role == "forged-bearer" {
					r.Header.Set("Authorization", "Bearer forged")
				} else {
					r.Header.Set("Authorization", "Bearer "+f.Token(t, snapshot, f.AdminSubject, roles...))
				}
			}
			before := calls.Load()
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, _ := io.ReadAll(response.Body)
			if response.StatusCode != row.want {
				t.Fatalf("%d: %s", response.StatusCode, raw)
			}
			if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("cache/origin boundary")
			}
			if row.want != 200 && calls.Load() != before {
				t.Fatal("denied caller triggered node sampling")
			}
			if row.want == 200 {
				var dto DiagnosticsResponse
				if json.Unmarshal(raw, &dto) != nil || dto.Build.Commit != "abcdef012345" || dto.Readiness.State != "unavailable" || dto.Node.State != "connected" {
					t.Fatalf("readiness falsely implied node health: %s", raw)
				}
				if !strings.Contains(string(raw), ".123456789Z") {
					t.Fatalf("actual Go RFC3339Nano timestamp missing: %s", raw)
				}
			}
			for _, secret := range []string{"https://secret.node", "Authorization", "credential", "rawError", "rpcUrl"} {
				if strings.Contains(string(raw), secret) {
					t.Fatal("secret/target field escaped", secret)
				}
			}
		})
	}
}

func TestDiagnosticsExpiryPublicationAndMalformedObservationAreClosed(t *testing.T) {
	for _, mode := range []string{"expired-after-sample", "expired-before-publication", "raw-state", "cancelled", "unsafe-build"} {
		t.Run(mode, func(t *testing.T) {
			snapshot := f.Snapshot(t, nil)
			base := time.Unix(f.Now, 0).UTC()
			var finished atomic.Bool
			var reads atomic.Int32
			clock := func() time.Time {
				if finished.Load() {
					n := reads.Add(1)
					if mode == "expired-after-sample" || mode == "expired-before-publication" && n >= 3 {
						return base.Add(301 * time.Second)
					}
				}
				return base
			}
			h, err := NewDiagnostics(DiagnosticsConfig{Config: Config{Snapshot: snapshot, Origin: "https://ops.test", Clock: clock}, Build: BuildIdentity{Version: "https://secret.node/private", Commit: "Bearer SECRET", BuiltAt: "/private/key"}, Sample: func(ctx context.Context, _ string) DiagnosticsSample {
				finished.Store(true)
				if mode == "cancelled" {
					<-ctx.Done()
				}
				sample := DiagnosticsSample{Readiness: Observation{State: "unknown"}, Node: Observation{State: "unknown"}}
				if mode == "raw-state" {
					sample.Node.State = "https://secret.node/private credential failure"
				}
				return sample
			}})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(h)
			defer server.Close()
			r, _ := http.NewRequest("GET", server.URL+"/api/v2/orgs/"+f.Org+"/diagnostics", nil)
			r.Host = "ops.test"
			r.Header.Set("Authorization", "Bearer "+f.Token(t, snapshot, f.AdminSubject, "Admin"))
			if mode == "cancelled" {
				ctx, cancel := context.WithTimeout(r.Context(), 20*time.Millisecond)
				defer cancel()
				r = r.WithContext(ctx)
			}
			response, err := server.Client().Do(r)
			if mode == "cancelled" {
				if err == nil {
					response.Body.Close()
					t.Fatal("caller deadline escaped")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, _ := io.ReadAll(response.Body)
			want := 401
			if mode == "raw-state" {
				want = 503
			}
			if mode == "unsafe-build" {
				want = 200
			}
			if response.StatusCode != want {
				t.Fatalf("%s %d %s", mode, response.StatusCode, raw)
			}
			if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "secret.node") || strings.Contains(string(raw), "/private/key") {
				t.Fatal("unsafe detail escaped")
			}
			if want == 401 && strings.Contains(string(raw), "build") {
				t.Fatal("expired prepared response published")
			}
		})
	}
}
