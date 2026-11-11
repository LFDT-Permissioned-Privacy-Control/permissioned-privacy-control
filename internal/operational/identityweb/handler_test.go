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
