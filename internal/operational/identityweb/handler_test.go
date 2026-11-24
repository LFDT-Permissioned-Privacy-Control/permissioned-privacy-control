package identityweb

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
)

func buildFS() fstest.MapFS {
	return fstest.MapFS{"index-v2.html": {Data: []byte(`<!doctype html><script type="module" src="/assets-v2/app.js"></script>`)}, "assets-v2/app.js": {Data: []byte(`document.title="OPS"`)}, "assets-v2/app.css": {Data: []byte(`body{color:black}`)}}
}
func TestSelectedBuildPagesAssetsAndNoLegacyFallback(t *testing.T) {
	snapshot := f.MultiSnapshot(t, func(_ *identity.SourceCatalog, s *brokerpolicy.SourceV2) {
		s.CompletionURI = "https://ops.test/auth/selected-complete"
	})
	files := buildFS()
	h, e := New(Config{snapshot, files})
	if e != nil {
		t.Fatal(e)
	}
	files["assets-v2/app.js"].Data = []byte("mutated after startup")
	server := httptest.NewTLSServer(h)
	defer server.Close()
	for _, tc := range []struct {
		path, method, host string
		want               int
		contains           string
	}{
		{"/login", "GET", "", 200, "<!doctype html>"}, {"/auth/sso?flow=owned", "GET", "", 200, "<!doctype html>"}, {"/auth/azure/callback?code=owned", "GET", "", 200, "<!doctype html>"}, {"/auth/selected-complete", "GET", "", 200, "<!doctype html>"},
		{"/account", "GET", "", 200, "<!doctype html>"}, {"/account?org=11111111-1111-4111-8111-111111111111", "GET", "", 400, ""}, {"/admin", "GET", "", 200, "<!doctype html>"}, {"/admin/rbac", "GET", "", 200, "<!doctype html>"}, {"/admin/rbac/organizations", "GET", "", 200, "<!doctype html>"}, {"/admin/rbac/groups", "GET", "", 200, "<!doctype html>"}, {"/admin/account", "GET", "", 200, "<!doctype html>"},
		{"/admin/rbac?org=11111111-1111-4111-8111-111111111111", "GET", "", 200, "<!doctype html>"}, {"/admin/rbac/groups?org=11111111-1111-4111-8111-111111111111", "GET", "", 200, "<!doctype html>"}, {"/admin/rbac/organizations?org=11111111-1111-4111-8111-111111111111", "GET", "", 200, "<!doctype html>"},
		{"/admin/rbac/groups?org=00000000-0000-0000-0000-000000000000", "GET", "", 400, ""}, {"/admin/rbac/groups?org=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "GET", "", 400, ""}, {"/admin/rbac/groups?org=11111111-1111-4111-8111-111111111111&org=11111111-1111-4111-8111-111111111111", "GET", "", 400, ""},
		{"/admin/rbac/groups?%6frg=11111111-1111-4111-8111-111111111111", "GET", "", 400, ""}, {"/admin/rbac/groups?flow=owned", "GET", "", 400, ""}, {"/admin/rbac/groups?", "GET", "", 400, ""}, {"/admin?org=11111111-1111-4111-8111-111111111111", "GET", "", 400, ""}, {"/admin/account?org=11111111-1111-4111-8111-111111111111", "GET", "", 400, ""},
		{"/admin/rbac/users", "GET", "", 404, ""}, {"/admin/rbac/groups/deeper", "GET", "", 404, ""}, {"/api/v2/unknown", "GET", "", 404, ""}, {"/admin/rbac/groups", "POST", "", 405, ""},
		{"/assets-v2/app.js", "GET", "", 200, "document.title"}, {"/api/v1/me", "GET", "", 404, ""}, {"/auth/complete", "GET", "", 404, ""}, {"/assets-v2/app.js?x=1", "GET", "", 404, ""}, {"/assets-v2/../index-v2.html", "GET", "", 404, ""}, {"/login", "HEAD", "", 405, ""}, {"/login", "GET", "evil.test", 403, ""},
	} {
		t.Run(tc.path+tc.method+tc.host, func(t *testing.T) {
			r, _ := http.NewRequest(tc.method, server.URL+tc.path, nil)
			r.Host = "ops.test"
			if tc.host != "" {
				r.Host = tc.host
			}
			res, e := server.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			if res.StatusCode != tc.want || tc.contains != "" && !strings.Contains(string(raw), tc.contains) {
				t.Fatal("wrong selected page/asset", res.StatusCode)
			}
			if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
				t.Fatal("unsafe browser headers")
			}
		})
	}
}

func TestAdminPageCannotBeSelectedAuthenticationCompletion(t *testing.T) {
	for _, selected := range adminPages {
		t.Run(selected, func(t *testing.T) {
			snapshot := f.MultiSnapshot(t, func(_ *identity.SourceCatalog, s *brokerpolicy.SourceV2) {
				s.CompletionURI = "https://ops.test" + selected
			})
			if _, err := New(Config{snapshot, buildFS()}); err == nil {
				t.Fatal("authentication completion overlaps an Admin route")
			}
		})
	}
}
func TestBuildRejectsUnexpectedFilesSymlinksAndCaps(t *testing.T) {
	snapshot := f.MultiSnapshot(t, nil)
	for _, change := range []func(fstest.MapFS){
		func(m fstest.MapFS) { delete(m, "index-v2.html") },
		func(m fstest.MapFS) { m["secret.env"] = &fstest.MapFile{Data: []byte("secret")} },
		func(m fstest.MapFS) { m["assets-v2/source.map"] = &fstest.MapFile{Data: []byte("source")} },
		func(m fstest.MapFS) { m["assets-v2/app.js"].Mode = fs.ModeSymlink },
		func(m fstest.MapFS) { m["assets-v2/app.js"].Data = []byte(strings.Repeat("x", (2<<20)+1)) },
	} {
		m := buildFS()
		change(m)
		if _, e := New(Config{snapshot, m}); e == nil {
			t.Fatal("unsafe build accepted")
		}
	}
}

func TestRegroupedAdminSourcePagesUseExactRoutesAndCanonicalOrganizationQuery(t *testing.T) {
	h, err := New(Config{f.MultiSnapshot(t, nil), buildFS()})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	pages := []string{
		"/admin/identity/profiles", "/admin/identity/claim-mappings", "/admin/settings",
		"/admin/disclosure/rules", "/admin/compliance/policy", "/admin/configuration",
	}
	for _, page := range pages {
		for _, query := range []struct {
			suffix string
			status int
		}{
			{"", http.StatusOK}, {"?org=11111111-1111-4111-8111-111111111111", http.StatusOK},
			{"?", http.StatusBadRequest}, {"?org=", http.StatusBadRequest}, {"?org=00000000-0000-0000-0000-000000000000", http.StatusBadRequest},
			{"?org=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", http.StatusBadRequest},
			{"?org=11111111-1111-4111-8111-111111111111&org=11111111-1111-4111-8111-111111111111", http.StatusBadRequest},
			{"?%6frg=11111111-1111-4111-8111-111111111111", http.StatusBadRequest},
			{"?org=%311111111-1111-4111-8111-111111111111", http.StatusBadRequest},
			{"?org=11111111-1111-4111-8111-111111111111&return=/admin", http.StatusBadRequest}, {"?return=/admin", http.StatusBadRequest},
		} {
			t.Run(page+query.suffix, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, server.URL+page+query.suffix, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "ops.test"
				res, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				if res.StatusCode != query.status || strings.Contains(string(body), "<!doctype html>") != (query.status == http.StatusOK) {
					t.Fatalf("wrong static source page/query boundary: %d", res.StatusCode)
				}
				if res.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("source response may be cached")
				}
			})
		}
	}
	for _, page := range []string{
		"/admin/rbac/contracts", "/admin/rbac/execution-policy", "/admin/rbac/configuration", "/admin/rbac/identity-profiles", "/admin/rbac/claim-mappings", "/admin/rbac/azure-tenants", "/admin/rbac/platform-configuration", "/admin/rbac/disclosure-source", "/admin/rbac/compliance-source",
	} {
		t.Run("compatibility"+page, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, server.URL+page, nil)
			req.Host = "ops.test"
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("existing exact source alias unavailable: %d", res.StatusCode)
			}
		})
	}
	for _, page := range []string{"/admin/identity", "/admin/identity/azure-tenants", "/admin/identity/profiles/", "/admin/identity/profiles/deeper", "/admin/settings/runtime", "/admin/configuration/groups", "/admin/disclosure/rules/", "/admin/compliance/policy/deeper"} {
		t.Run("unknown"+page, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, server.URL+page, nil)
			req.Host = "ops.test"
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusNotFound || strings.Contains(string(body), "<!doctype html>") {
				t.Fatal("unknown Admin prefix became a static page", res.StatusCode)
			}
		})
	}
}

func TestAdminStaticHandlerRejectsFragmentsAndEncodedPathAliases(t *testing.T) {
	h, err := New(Config{f.MultiSnapshot(t, nil), buildFS()})
	if err != nil {
		t.Fatal(err)
	}
	// Browsers do not transmit fragments over HTTP. Still reject a fragment if
	// an adapter supplies one directly; the browser route gate also rejects '#'.
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.URL.Fragment = "ignored" },
		func(r *http.Request) { r.URL.RawFragment = "ignored" },
		func(r *http.Request) { r.URL.RawPath = "/admin/%73ettings" },
	} {
		req := httptest.NewRequest(http.MethodGet, "https://ops.test/admin/settings", nil)
		change(req)
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), "<!doctype html>") {
			t.Fatal("unexpected fragment or encoded path reached the static entry", recorder.Code)
		}
	}
}
