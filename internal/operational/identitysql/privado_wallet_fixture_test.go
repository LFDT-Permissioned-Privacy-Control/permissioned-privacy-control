package identitysql_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identityhttp"
)

type walletReady struct {
	Type, TestOnly, SDKVersion, HolderA, HolderB, IssuerDID, VerifierDID, ContextURL, Network, ChainID, StateContract, RPCURL string
	Context                                                                                                                   json.RawMessage
}
type walletProof struct {
	ID, Compact, Error string
	ClaimsAsOf         int64
	Diagnostics        struct {
		BypassProofsCache, StateCacheDisabled, HadCache bool
		RoleGenerations, OuterGenerations               int
		InnerProofDigests                               []string
	}
}
type walletProcess struct {
	ready  walletReady
	input  io.WriteCloser
	lines  chan []byte
	done   chan error
	cmd    *exec.Cmd
	mu     sync.Mutex
	stderr bytes.Buffer
}

func startWalletProcess(t *testing.T) *walletProcess {
	t.Helper()
	root, e := filepath.Abs("../../..")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	w := &walletProcess{lines: make(chan []byte, 1), done: make(chan error, 1)}
	node := os.Getenv("OPS_TEST_NODE")
	if node == "" {
		node = "node"
	}
	w.cmd = exec.CommandContext(ctx, node, "--max-old-space-size=1024", filepath.Join(root, "e2e/playwright/v2-privado-wallet-fixture.mjs"))
	w.cmd.Env = append(os.Environ(), "OPS_PRIVADO_WALLET_DEMO=0")
	w.cmd.Dir = root
	w.cmd.Stderr = &w.stderr
	stdout, e := w.cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	w.input, e = w.cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = w.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 2<<20)
		for scanner.Scan() {
			data := bytes.Clone(scanner.Bytes())
			select {
			case w.lines <- data:
			case <-ctx.Done():
				return
			}
		}
		close(w.lines)
	}()
	go func() { w.done <- w.cmd.Wait() }()
	t.Cleanup(func() {
		_ = w.input.Close()
		select {
		case <-w.done:
		case <-time.After(3 * time.Second):
			cancel()
			<-w.done
		}
		cancel()
	})
	select {
	case raw, ok := <-w.lines:
		if !ok || json.Unmarshal(raw, &w.ready) != nil || w.ready.Type != "ready" || w.ready.SDKVersion != "1.43.0" || !strings.HasPrefix(w.ready.TestOnly, "NEW PUBLIC") {
			t.Fatal("actual wallet initialization failed")
		}
	case <-time.After(45 * time.Second):
		cancel()
		t.Fatal("actual wallet initialization deadline")
	}
	for _, did := range []string{w.ready.HolderA, w.ready.HolderB, w.ready.IssuerDID, w.ready.VerifierDID} {
		if !strings.HasPrefix(did, "did:iden3:polygon:mumbai:") {
			t.Fatal("unexpected public fixture network")
		}
	}
	u, e := url.Parse(w.ready.RPCURL)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("fixture RPC is not ownedloopback")
	}
	return w
}
func (w *walletProcess) prove(ctx context.Context, request []byte, holder, cacheMode string) (walletProof, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := fmt.Sprintf("proof-%d", time.Now().UnixNano())
	var raw json.RawMessage = bytes.Clone(request)
	command := struct {
		ID        string          `json:"id"`
		Request   json.RawMessage `json:"request"`
		Holder    string          `json:"holder"`
		CacheMode string          `json:"cacheMode"`
	}{id, raw, holder, cacheMode}
	if e := json.NewEncoder(w.input).Encode(command); e != nil {
		return walletProof{}, e
	}
	select {
	case line, ok := <-w.lines:
		var out walletProof
		if !ok || json.Unmarshal(line, &out) != nil || out.ID != id || out.Error != "" || out.Compact == "" || len(out.Compact) > 1<<20 {
			return walletProof{}, fmt.Errorf("actual SDK proof failed: %s", out.Error)
		}
		return out, nil
	case <-ctx.Done():
		return walletProof{}, ctx.Err()
	}
}

func (w *walletProcess) advanceGIST(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := fmt.Sprintf("gist-%d", time.Now().UnixNano())
	if e := json.NewEncoder(w.input).Encode(map[string]string{"id": id, "action": "advance-gist"}); e != nil {
		return e
	}
	select {
	case line, ok := <-w.lines:
		var out struct{ ID, Root, PreviousRoot, Error string }
		if !ok || json.Unmarshal(line, &out) != nil || out.ID != id || out.Error != "" || out.Root == "" || out.Root == out.PreviousRoot {
			return fmt.Errorf("actual GIST update failed: %s", out.Error)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type walletRPC struct {
	server *httptest.Server
	hits   atomic.Int64
	fail   atomic.Bool
}

func newWalletRPC(t *testing.T, wallet *walletProcess) *walletRPC {
	t.Helper()
	r := &walletRPC{}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		r.hits.Add(1)
		raw, e := readBounded(request.Body, 16<<10)
		if e != nil {
			w.WriteHeader(400)
			return
		}
		if r.fail.Load() {
			var q struct {
				ID json.RawMessage `json:"id"`
			}
			if json.Unmarshal(raw, &q) != nil {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32005, "message": "owned fixture capacity"}})
			return
		}
		forward, e := http.NewRequestWithContext(request.Context(), "POST", wallet.ready.RPCURL, bytes.NewReader(raw))
		if e != nil {
			w.WriteHeader(500)
			return
		}
		forward.Header.Set("Content-Type", "application/json")
		response, e := client.Do(forward)
		if e != nil {
			w.WriteHeader(503)
			return
		}
		defer response.Body.Close()
		data, e := readBounded(response.Body, 64<<10)
		if e != nil {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(data)
	}))
	t.Cleanup(r.server.Close)
	return r
}

type walletRPCTransport struct{ rpc *walletRPC }

func (t walletRPCTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.String() != "https://state.test/rpc" {
		return nil, http.ErrNotSupported
	}
	copy := request.Clone(request.Context())
	u, _ := url.Parse(t.rpc.server.URL)
	copy.URL.Scheme = u.Scheme
	copy.URL.Host = u.Host
	copy.Host = request.Host
	return t.rpc.server.Client().Transport.RoundTrip(copy)
}
func configureWalletFixture(t *testing.T, x *multiHTTPFixture, w *walletProcess, rpc *walletRPC) {
	t.Helper()
	x.db.wallClock.Store(true)
	ids := f.MultiIdentitySource(t)
	broker := f.MultiBrokerSource()
	broker.WebOrigin = x.origin
	broker.CompletionURI = x.origin + "/auth/complete"
	broker.AzureProfiles = []brokerpolicy.AzureBinding{}
	broker.PrivadoProfiles = []brokerpolicy.PrivadoBinding{{ProfileID: f.PrivadoRoleProfile}}
	broker.PrivadoNetworks[0].Network = w.ready.Network
	broker.PrivadoNetworks[0].ChainID = w.ready.ChainID
	broker.PrivadoNetworks[0].StateContract = w.ready.StateContract
	sum := sha256.Sum256(w.ready.Context)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	broker.PinnedDocuments = []brokerpolicy.PinnedDocumentRef{{URL: w.ready.ContextURL, Path: "role-context.json", SHA256: digest}}
	for i := range ids.Profiles {
		p := &ids.Profiles[i]
		if p.ID == f.PrivadoRoleProfile {
			p.VerifierID = w.ready.VerifierDID
			p.AllowedCredentialIssuers = []string{w.ready.IssuerDID}
			p.Context = w.ready.ContextURL
			p.ContextDigest = digest
			p.Network = w.ready.Network
			p.IdentityStateContract = w.ready.StateContract
		}
	}
	ids.Mappings = append(ids.Mappings, identity.Mapping{ID: "privado-reader", ProfileID: f.PrivadoRoleProfile, OrganizationID: d.Org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "privado.predicate", Value: "reader"}, GroupIDs: []string{d.AuditorGroup}})
	x.db.snapshot = f.MultiSnapshotSources(t, ids, broker, map[string][]byte{"role-context.json": w.ready.Context})
	x.privadoTransport = walletRPCTransport{rpc}
}
func (x *multiHTTPFixture) walletProof(t *testing.T, w *walletProcess, start privadoStartDTO, holder, cacheMode string) walletProof {
	t.Helper()
	status, _, request := x.request(t, x.newClient(t, false), "GET", identityhttp.Prefix+"privado/requests/"+start.RequestID, nil, nil)
	if status != 200 {
		t.Fatal("actual wallet request", status)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	proof, e := w.prove(ctx, request, holder, cacheMode)
	if e != nil {
		t.Fatal(e)
	}
	return proof
}
func (x *multiHTTPFixture) postWalletProof(t *testing.T, id string, p walletProof) (int, http.Header, []byte) {
	t.Helper()
	return x.request(t, x.newClient(t, false), "POST", identityhttp.Prefix+"privado/proofs/"+id, p.Compact, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
		r.Header.Del("Origin")
	})
}
