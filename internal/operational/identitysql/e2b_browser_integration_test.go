package identitysql_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func e2bApp(t *testing.T, x *browserFixture, build, app string, sso *ssoFixture) (string, func()) {
	t.Helper()
	explorer := os.Getenv("OPS_E2B_EXPLORER_ROOT")
	if explorer == "" {
		t.Fatal("owned Explorer worktree required")
	}
	binary := filepath.Join(t.TempDir(), "e2b-app.test")
	compile := exec.CommandContext(t.Context(), "go", "test", "-c", "-tags", "privacy", "-o", binary, "./internal/api")
	compile.Dir = filepath.Join(explorer, "backend")
	if raw, e := compile.CombinedOutput(); e != nil {
		t.Fatalf("owned actual BFF compile failed: %s", raw)
	}
	ids, _ := x.db.snapshot.Identity()
	var profiles []map[string]string
	for _, id := range []string{f.HumanProfile, f.PrivadoRoleProfile} {
		if digest, ok := ids.ProfileDigest(id); ok {
			profiles = append(profiles, map[string]string{"id": id, "digest": digest})
		}
	}
	source := map[string]any{"apiVersion": "ops.explorer-sso/v2", "kind": "ExplorerSSO", "appOrigin": app, "opsOrigin": x.origin, "callbackURI": app + "/api/auth/callback", "clientId": "app-a", "clientSecret": map[string]string{"fromEnv": "E2B_CLIENT"}, "issuer": "https://ops.test", "audience": "core", "keys": []map[string]string{{"id": "test", "x": base64.RawURLEncoding.EncodeToString(f.SigningKey().Public().(ed25519.PublicKey))}}, "profiles": profiles, "stateKey": map[string]string{"id": "state", "fromEnv": "E2B_STATE"}, "tokenKey": map[string]string{"id": "token", "fromEnv": "E2B_TOKEN"}, "recoveryEpoch": uuid.NewString(), "limits": map[string]int64{"maxContexts": 200000, "maxCipherBytes": 1 << 30, "maxMetadataBytes": 512 << 20}, "network": map[string]string{"chainId": "1", "genesisHash": "0x" + strings.Repeat("1", 64)}, "retention": map[string]any{"enabled": false, "batchSize": 100, "intervalMillis": 1000}}
	raw, _ := json.Marshal(source)
	sum := sha256.Sum256(raw)
	if _, e := x.db.owner.Exec(t.Context(), `CREATE ROLE explorer_sso_app LOGIN NOINHERIT PASSWORD 'owned-app-fixture'`); e != nil {
		t.Fatal(e)
	}
	dsn, _ := url.Parse(x.db.ownerDSN)
	dsn.User = url.UserPassword("explorer_sso_app", "owned-app-fixture")
	appURL, _ := url.Parse(app)
	config := map[string]any{"Source": json.RawMessage(raw), "SHA256": hex.EncodeToString(sum[:]), "OwnerDSN": x.db.ownerDSN, "AppDSN": dsn.String(), "Listen": "127.0.0.1:" + appURL.Port(), "OPSAddress": strings.TrimPrefix(x.origin, "https://"), "OPSCertificate": base64.RawStdEncoding.EncodeToString(x.first.Certificate().Raw), "Build": build, "Now": x.db.clock().Unix(), "WallClock": x.db.wallClock.Load(), "ClientSecret": sso.secretA}
	file := filepath.Join(t.TempDir(), "owned-app.json")
	configRaw, _ := json.Marshal(config)
	if e := os.WriteFile(file, configRaw, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestOwnedE2BBrowserApp$", "-test.timeout=250s")
	cmd.Env = append(os.Environ(), "E2B_OWNED_APP_CONFIG="+file)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	scanner := bufio.NewScanner(stdout)
	ready := make(chan bool, 1)
	go func() {
		found := false
		for scanner.Scan() {
			if scanner.Text() == "E2B_APP_READY" && !found {
				found = true
				ready <- true
			}
		}
		if !found {
			ready <- false
		}
	}()
	select {
	case ok := <-ready:
		if !ok {
			_ = cmd.Wait()
			t.Fatal("owned actual BFF startup failed", diagnostics.String())
		}
	case <-time.After(35 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("owned actual BFF readiness timeout")
	}
	stop := func() {
		_ = cmd.Process.Signal(os.Interrupt)
		if e := cmd.Wait(); e != nil {
			t.Error("owned actual BFF teardown failed")
		}
	}
	return app, stop
}
func e2bBuild(t *testing.T) (string, string, string) {
	t.Helper()
	root, opsBuild := centralBuild(t)
	explorer := os.Getenv("OPS_E2B_EXPLORER_ROOT")
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	out := t.TempDir()
	cmd := exec.CommandContext(t.Context(), node, filepath.Join(explorer, "frontend/node_modules/vite/bin/vite.js"), "build", "--config", "vite.v2.config.ts", "--outDir", out)
	cmd.Dir = filepath.Join(explorer, "frontend")
	if raw, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("actual V2 Explorer build failed: %s", raw)
	}
	return root, opsBuild, out
}
func reserveAppOrigin(t *testing.T) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return fmt.Sprintf("https://app.test:%d", port)
}
func e2bDriver(t *testing.T, root, ops, app, kind string, now int64) {
	t.Helper()
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	cmd := exec.CommandContext(t.Context(), node, filepath.Join(root, "e2e/playwright/v2-enterprise-app-browser.mjs"), ops, app, kind, time.Unix(now, 0).UTC().Format(time.RFC3339))
	cmd.Dir = root
	raw, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("actual cross-origin browser failed: %s", raw)
	}
	t.Log(strings.TrimSpace(string(raw)))
}

func TestActualBuiltEnterpriseAzureApp(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" || os.Getenv("OPS_E2B_EXPLORER_ROOT") == "" {
		t.Skip("owned actual cross-repository browser flags required")
	}
	root, opsBuild, appBuild := e2bBuild(t)
	x := newSSOAzureFixture(t, true)
	app := reserveAppOrigin(t)
	sso := attachSSOAt(t, x, []string{d.Org, d.OtherOrg}, false, app+"/api/auth/callback")
	centralMount(t, x, opsBuild)
	for _, mux := range x.muxes {
		mux.HandleFunc("/__test/control", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
				w.WriteHeader(403)
				return
			}
			var command struct {
				AuthorizationURL, Subject string
				AdvanceSeconds            int64
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 20<<10)).Decode(&command) != nil {
				w.WriteHeader(400)
				return
			}
			if command.AdvanceSeconds > 0 && command.AdvanceSeconds <= 301 && command.AuthorizationURL == "" {
				x.db.entra.Clock.Add(command.AdvanceSeconds)
				w.WriteHeader(204)
				return
			}
			u, e := url.Parse(command.AuthorizationURL)
			if e != nil || u.Host != "login.microsoftonline.com" || u.Query().Get("nonce") == "" || command.Subject != d.Subject && command.Subject != d.AdminSubject {
				w.WriteHeader(400)
				return
			}
			x.db.entra.SetNonce(u.Query().Get("nonce"))
			x.db.entra.SetSubject(command.Subject)
			w.WriteHeader(204)
		})
	}
	_, stop := e2bApp(t, x, appBuild, app, sso)
	defer stop()
	e2bDriver(t, root, x.origin, app, "azure", x.db.clock().Unix())
	if x.db.entra.Grants.Load() < 2 {
		t.Fatal("browser did not perform genuine signed Azure refresh")
	}
}

func TestActualBuiltEnterprisePrivadoApp(t *testing.T) {
	if os.Getenv("OPS_BROWSER_INTEGRATION") != "1" || os.Getenv("OPS_PRIVADO_WALLET_INTEGRATION") != "1" || os.Getenv("OPS_E2B_EXPLORER_ROOT") == "" {
		t.Skip("owned actual browser + fresh-wallet flags required")
	}
	root, opsBuild, appBuild := e2bBuild(t)
	wallet := startWalletProcess(t)
	rpc := newWalletRPC(t, wallet)
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) { configureWalletFixture(t, x, wallet, rpc) })
	app := reserveAppOrigin(t)
	sso := attachSSOAt(t, x.browserFixture, []string{d.Org}, false, app+"/api/auth/callback")
	centralMount(t, x.browserFixture, opsBuild)
	var proofs atomic.Int64
	for _, mux := range x.muxes {
		mux.HandleFunc("/__test/wallet", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<!doctype html><title>Owned separate wallet</title>"))
		})
		mux.HandleFunc("/__test/proof", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Header.Get("Origin") != x.origin {
				w.WriteHeader(403)
				return
			}
			var input struct{ RequestID, Holder string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&input) != nil || input.Holder != "a" && input.Holder != "b" {
				w.WriteHeader(400)
				return
			}
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
		})
	}
	_, stop := e2bApp(t, x.browserFixture, appBuild, app, sso)
	defer stop()
	e2bDriver(t, root, x.origin, app, "privado", x.db.clock().Unix())
	if proofs.Load() != 2 || rpc.hits.Load() < 10 {
		t.Fatal("actual app missed two genuine fresh proof/live-state checks", proofs.Load(), rpc.hits.Load())
	}
}
