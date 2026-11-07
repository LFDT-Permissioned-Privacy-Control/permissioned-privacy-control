package identitysql_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identityhttp"
)

// This opt-in qualification uses installed pinned JS dependencies and an actual
// owned Chromium process, plus the normal RSA/JWKS/TLS/SQL fixture. No fake
// LockManager, provider verifier, Core identity verifier or SQL store is used.
func TestActualAzureTwoTabBrowser(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" {
		t.Skip("set OPS_BROWSER_INTEGRATION=1 for real Chromium qualification")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "auth-harness.js")
	build := exec.CommandContext(t.Context(), filepath.Join(root, "frontend/node_modules/.bin/esbuild"), filepath.Join(root, "e2e/playwright/v2-auth-harness.ts"), "--bundle", "--format=esm", "--target=es2020", "--outfile="+bundle)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("owned browser helper bundle: %v %s", err, output)
	}
	source, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var fault atomic.Int64 // 1=logout unavailable;2=renew COMMIT response lost;3=start unavailable
	var lostCommit atomic.Bool
	var protected atomic.Int64
	x := newBrowserFixtureSetup(t, nil, func(x *browserFixture) {
		verifierCatalog, _ := x.db.snapshot.Identity()
		verifier, err := identity.NewVerifier(verifierCatalog, x.db.clock)
		if err != nil {
			t.Fatal(err)
		}
		for i, mux := range x.muxes {
			mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				_, _ = fmt.Fprint(w, `<!doctype html><title>Owned V2 auth fixture</title><script type="module" src="/__test/auth-harness.js"></script>`)
			})
			mux.HandleFunc("/__test/auth-harness.js", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/javascript")
				_, _ = w.Write(source)
			})
			mux.HandleFunc("/__test/control", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
					w.WriteHeader(403)
					return
				}
				var command struct {
					AuthorizationURL string `json:"authorizationUrl"`
					Subject          string `json:"subject"`
					Fault            int64  `json:"fault"`
				}
				if json.NewDecoder(http.MaxBytesReader(w, r.Body, 20<<10)).Decode(&command) != nil {
					w.WriteHeader(400)
					return
				}
				if command.AuthorizationURL != "" {
					u, err := url.Parse(command.AuthorizationURL)
					if err != nil || u.Host != "login.microsoftonline.com" || u.Query().Get("nonce") == "" {
						w.WriteHeader(400)
						return
					}
					x.db.entra.SetNonce(u.Query().Get("nonce"))
					if command.Subject != "" && command.Subject != d.Subject && command.Subject != d.AdminSubject {
						w.WriteHeader(400)
						return
					}
					if command.Subject == "" {
						command.Subject = d.Subject
					}
					x.db.entra.SetSubject(command.Subject)
				}
				fault.Store(command.Fault)
				w.WriteHeader(204)
			})
			mux.HandleFunc("/__test/protected", func(w http.ResponseWriter, r *http.Request) {
				p, err := verifier.VerifyAccess(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				if err != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					w.WriteHeader(401)
					return
				}
				protected.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"actorId": p.ActorID()})
			})
			server := x.first
			if i == 1 {
				server = x.second
			}
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == identityhttp.Prefix+"azure/start" && fault.CompareAndSwap(3, 0) {
					fixtureUnavailable(w)
					return
				}
				if r.URL.Path == identityhttp.Prefix+"logout" && fault.CompareAndSwap(1, 0) {
					fixtureUnavailable(w)
					return
				}
				if r.URL.Path == identityhttp.Prefix+"renew" && fault.CompareAndSwap(2, 0) {
					recorder := httptest.NewRecorder()
					mux.ServeHTTP(recorder, r)
					if recorder.Code == 200 && len(recorder.Header().Values("Set-Cookie")) == 2 {
						lostCommit.Store(true)
					}
					// Discard committed response/cookies at the transport boundary. The
					// helper cannot recover/replay the consumed opaque predecessor.
					fixtureUnavailable(w)
					return
				}
				mux.ServeHTTP(w, r)
			})
		}
	})
	command := exec.CommandContext(t.Context(), "node", filepath.Join(root, "e2e/playwright/v2-auth-browser.mjs"), x.origin, strconv.FormatInt(x.db.entra.Clock.Load(), 10))
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("actual two-tab qualification: %v\n%s", err, output)
	}
	if !lostCommit.Load() || protected.Load() < 3 || x.db.entra.Grants.Load() < 8 {
		t.Fatal("browser qualification did not reach actual grants, protected requests and committed-response uncertainty")
	}
	t.Log(strings.TrimSpace(string(output)))
	t.Logf("actual provider grants=%d actual Core-authenticated requests=%d", x.db.entra.Grants.Load(), protected.Load())
}

func fixtureUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(503)
	_, _ = w.Write([]byte(`{"error":"authentication_unavailable"}`))
}
