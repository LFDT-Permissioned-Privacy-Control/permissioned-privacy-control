package identitysql_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/identityweb"
	"privacy-proxy/internal/selfhttp"
)

func centralBuild(t *testing.T) (string, string) {
	t.Helper()
	root, e := filepath.Abs("../../..")
	if e != nil {
		t.Fatal(e)
	}
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	out := t.TempDir()
	cmd := exec.CommandContext(t.Context(), node, filepath.Join(root, "frontend/node_modules/vite/bin/vite.js"), "build", "--config", "vite.v2.config.ts", "--outDir", out)
	cmd.Dir = filepath.Join(root, "frontend")
	if raw, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("actual V2 production build: %v %s", e, raw)
	}
	return root, out
}
func centralMount(t *testing.T, x *browserFixture, build string) {
	t.Helper()
	for _, mux := range x.muxes {
		web, e := identityweb.New(identityweb.Config{Snapshot: x.db.snapshot, Files: os.DirFS(build)})
		if e != nil {
			t.Fatal(e)
		}
		web.Register(mux)
		self, e := selfhttp.New(selfhttp.Config{Snapshot: x.db.snapshot, Origin: x.origin, Clock: x.db.clock})
		if e != nil {
			t.Fatal(e)
		}
		self.Register(mux)
	}
}
func centralDriver(t *testing.T, root, origin, kind string, clock int64) {
	t.Helper()
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	cmd := exec.CommandContext(t.Context(), node, filepath.Join(root, "e2e/playwright/v2-central-web-browser.mjs"), origin, kind, time.Unix(clock, 0).UTC().Format(time.RFC3339))
	cmd.Dir = root
	raw, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("actual built central browser: %v\n%s", e, raw)
	}
	t.Log(strings.TrimSpace(string(raw)))
}

func TestActualBuiltCentralAzureBrowser(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" {
		t.Skip("set OPS_BROWSER_INTEGRATION=1 for actual built browser qualification")
	}
	root, build := centralBuild(t)
	x := newSSOAzureFixture(t, true)
	_ = attachSSO(t, x, []string{d.Org, d.OtherOrg}, false)
	centralMount(t, x, build)
	for _, mux := range x.muxes {
		mux.HandleFunc("/__test/control", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
				w.WriteHeader(403)
				return
			}
			var in struct{ AuthorizationURL, Subject string }
			// The browser driver's lifecycle control advances the owned provider
			// clock only after navigating away, beyond the original access expiry.
			var command struct {
				AuthorizationURL, Subject string
				AdvanceSeconds            int64
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 20<<10)).Decode(&command) != nil {
				w.WriteHeader(400)
				return
			}
			if command.AdvanceSeconds == 301 && command.AuthorizationURL == "" && command.Subject == "" {
				x.db.entra.Clock.Add(301)
				w.WriteHeader(204)
				return
			}
			if command.AdvanceSeconds != 0 {
				w.WriteHeader(400)
				return
			}
			in.AuthorizationURL, in.Subject = command.AuthorizationURL, command.Subject
			u, e := url.Parse(in.AuthorizationURL)
			if e != nil || u.Host != "login.microsoftonline.com" || u.Query().Get("nonce") == "" || (in.Subject != d.Subject && in.Subject != d.AdminSubject) {
				w.WriteHeader(400)
				return
			}
			x.db.entra.SetNonce(u.Query().Get("nonce"))
			x.db.entra.SetSubject(in.Subject)
			w.WriteHeader(204)
		})
	}
	centralDriver(t, root, x.origin, "azure", x.db.clock().Unix())
	if x.db.entra.Grants.Load() < 5 {
		t.Fatal("browser missed actual signed provider exchange/refresh", x.db.entra.Grants.Load())
	}
}

func TestActualBuiltCentralPrivadoBrowser(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" || os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" {
		t.Skip("set browser+wallet flags for actual built Privado qualification")
	}
	root, build := centralBuild(t)
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) { configureWalletFixture(t, x, wallet, rpc) })
	centralMount(t, x.browserFixture, build)
	var proofs atomic.Int64
	for _, mux := range x.muxes {
		mux.HandleFunc("/__test/wallet", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><title>Owned separate wallet</title>"))
		})
		mux.HandleFunc("/__test/config", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"holderA": wallet.ready.HolderA, "holderB": wallet.ready.HolderB, "profile": "privado-role"})
		})
		mux.HandleFunc("/__test/proof", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
				w.WriteHeader(403)
				return
			}
			var in struct{ RequestID, Holder string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&in) != nil || (in.Holder != "a" && in.Holder != "b") {
				w.WriteHeader(400)
				return
			}
			request, e := x.serviceOne.PublicPrivadoRequest(r.Context(), in.RequestID)
			if e != nil {
				w.WriteHeader(400)
				return
			}
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(70 * time.Second))
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()
			proof, e := wallet.prove(ctx, request, in.Holder, "")
			if e != nil || proof.Diagnostics.RoleGenerations != 1 || proof.Diagnostics.OuterGenerations != 1 || !proof.Diagnostics.BypassProofsCache || !proof.Diagnostics.StateCacheDisabled {
				w.WriteHeader(500)
				return
			}
			proofs.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"compact": proof.Compact})
		})
	}
	centralDriver(t, root, x.origin, "privado", x.db.clock().Unix())
	if proofs.Load() < 3 || rpc.hits.Load() < 15 {
		t.Fatal("built browser missed actual fresh proof/live-state verifier", proofs.Load(), rpc.hits.Load())
	}
}
