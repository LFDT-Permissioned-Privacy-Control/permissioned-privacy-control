package identitysql_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identityhttp"
)

// This finite qualification reaches actual Chromium Web Locks, the real SDK
// client/prover, two service pools, TLS, PostgreSQL and Core verification.
func TestActualPrivadoTwoTabBrowser(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" || os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("set both browser and wallet integration flags for actual local qualification")
	}
	root, e := filepath.Abs("../../..")
	if e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(t.TempDir(), "privado-harness.js")
	command := exec.CommandContext(t.Context(), filepath.Join(root, "frontend/node_modules/.bin/esbuild"), filepath.Join(root, "e2e/playwright/v2-privado-auth-harness.ts"), "--bundle", "--format=esm", "--target=es2020", "--outfile="+bundle)
	if output, e := command.CombinedOutput(); e != nil {
		t.Fatalf("owned multi helper bundle: %v %s", e, output)
	}
	source, e := os.ReadFile(bundle)
	if e != nil {
		t.Fatal(e)
	}
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	var fault, lost, protected, proofs atomic.Int64
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) {
		configureWalletFixture(t, x, wallet, rpc)
		ids, _ := x.db.snapshot.Identity()
		verifier, e := identity.NewVerifier(ids, x.db.clock)
		if e != nil {
			t.Fatal(e)
		}
		for i, mux := range x.muxes {
			mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				_, _ = fmt.Fprint(w, `<!doctype html><title>Owned Privado identity fixture</title><script type="module" src="/__test/privado-harness.js"></script>`)
			})
			mux.HandleFunc("/__test/wallet", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = fmt.Fprint(w, `<!doctype html><title>Owned separate-origin wallet transport fixture</title>`)
			})
			mux.HandleFunc("/__test/privado-harness.js", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/javascript")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(source)
			})
			mux.HandleFunc("/__test/config", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"profileId": f.PrivadoRoleProfile, "holderA": wallet.ready.HolderA, "holderB": wallet.ready.HolderB})
			})
			mux.HandleFunc("/__test/control", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
					w.WriteHeader(403)
					return
				}
				var input struct{ Action, RequestID, Holder, Kind string }
				if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10)).Decode(&input) != nil {
					w.WriteHeader(400)
					return
				}
				switch input.Action {
				case "proof":
					request, e := x.serviceOne.PublicPrivadoRequest(r.Context(), input.RequestID)
					if e != nil {
						w.WriteHeader(400)
						return
					}
					_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(70 * time.Second))
					ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
					defer cancel()
					proof, e := wallet.prove(ctx, request, input.Holder, "")
					if e != nil || proof.Diagnostics.RoleGenerations != 1 || proof.Diagnostics.OuterGenerations != 1 || !proof.Diagnostics.BypassProofsCache || !proof.Diagnostics.StateCacheDisabled {
						w.WriteHeader(500)
						return
					}
					proofs.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"compact": proof.Compact})
				case "fault":
					if input.Kind != "lost-complete" {
						w.WriteHeader(400)
						return
					}
					fault.Store(1)
					w.WriteHeader(204)
				case "stats":
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]int64{"proofs": proofs.Load(), "protected": protected.Load(), "lostComplete": lost.Load(), "providerRPC": rpc.hits.Load()})
				default:
					w.WriteHeader(400)
				}
			})
			mux.HandleFunc("/__test/protected", func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					w.WriteHeader(401)
					return
				}
				principal, e := verifier.VerifyAccess(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				if e != nil {
					w.WriteHeader(401)
					return
				}
				protected.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"actorId": principal.ActorID()})
			})
			server := x.first
			if i == 1 {
				server = x.second
			}
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == identityhttp.Prefix+"privado/complete" && fault.CompareAndSwap(1, 0) {
					capture := &captureAuthResponse{ResponseRecorder: httptest.NewRecorder(), actual: w}
					mux.ServeHTTP(capture, r)
					if capture.Code == 200 && len(capture.Header().Values("Set-Cookie")) == 2 {
						lost.Add(1)
					}
					fixtureUnavailable(w)
					return
				}
				mux.ServeHTTP(w, r)
			})
		}
	})
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	command = exec.CommandContext(t.Context(), node, filepath.Join(root, "e2e/playwright/v2-privado-auth-browser.mjs"), x.origin, strconv.FormatInt(x.db.clock().Unix(), 10))
	command.Dir = root
	output, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("actual multi-browser qualification: %v\n%s", e, output)
	}
	if lost.Load() != 1 || proofs.Load() < 7 || protected.Load() < 3 || rpc.hits.Load() < 40 {
		t.Fatal("browser did not reach actual proof/currentstate/commit/Core boundaries", lost.Load(), proofs.Load(), protected.Load(), rpc.hits.Load())
	}
	t.Log(strings.TrimSpace(string(output)))
	t.Logf("actual client roleproofs=%d Core requests=%d providerRPC=%d knownlostcompletion=%d", proofs.Load(), protected.Load(), rpc.hits.Load(), lost.Load())
}
