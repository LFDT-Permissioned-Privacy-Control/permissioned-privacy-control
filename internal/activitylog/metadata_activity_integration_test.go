package activitylog_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/networkidentity"
	s "privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
)

// Every successful assertion below crosses actual Recorder.Complete and the
// actual Pebble sync. SQL proves exactly one completion was subsequently sealed;
// it is not used as a substitute for the pre-response local receipt.
func metadataSealedOne(t *testing.T, x *database, before int64) a.Envelope {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for {
		var rows int64
		err := x.owner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, x.scope.NetworkKey[:]).Scan(&rows)
		if err != nil {
			t.Fatal(err)
		}
		if rows == before+1 {
			var raw []byte
			if err = x.owner.QueryRow(t.Context(), `SELECT l.request_params FROM ops_activity_v1.qualified_logs l JOIN ops_activity_v1.sources s ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, x.scope.NetworkKey[:]).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var e a.Envelope
			if json.Unmarshal(raw, &e) != nil || len(raw) > a.MaxEncodedBytes {
				t.Fatal("invalid actual sealed completion")
			}
			return e
		}
		if rows > before+1 || time.Now().After(deadline) {
			t.Fatal("expected exactly one actual sealed completion", before, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func metadataRows(t *testing.T, x *database) int64 {
	t.Helper()
	var rows int64
	if err := x.owner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, x.scope.NetworkKey[:]).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestMetadataActivityAllWireGoldensActualAppend(t *testing.T) {
	n := newMetadataNode(t)
	f := metadataFixture()
	snapshot := f.load(t)
	var clock atomic.Int64
	clock.Store(now)
	e := metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{"eth_chainId", "web3_clientVersion"}))
	x := setupActivityDatabase(t, n.network())
	var vectors []struct {
		Name          string `json:"name"`
		Request       string `json:"request_utf8"`
		Authorization string `json:"authorization"`
		Status        int    `json:"http_status"`
		Response      string `json:"response_utf8"`
		RPCs          *int   `json:"physical_rpcs"`
		Method        string `json:"audit_method"`
		Class         string `json:"audit_class"`
	}
	raw, err := os.ReadFile("testdata/metadata-wire-v1.json")
	if err != nil || json.Unmarshal(raw, &vectors) != nil || len(vectors) != 29 {
		t.Fatal("complete public wire goldens", err, len(vectors))
	}
	var knownActor string
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			clock.Store(now)
			beforeRows, beforeRPC := metadataRows(t, x), n.count()
			var appended atomic.Int32
			recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error {
				appended.Add(1)
				if v.Name == "same-view-expiry-after-append" {
					clock.Store(now + 300)
				}
				if v.Name == "audit-failure-notification" {
					return errors.New("owned actual Pebble beforeSet failure")
				}
				return nil
			}, e.OperationBinding().Methods...)
			service, err := rpcactivity.New(rpcactivity.Config{Metadata: e, Recorder: recorder, Network: n.network()})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := service.Handler("")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(handler)
			t.Cleanup(server.Close)
			req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL, strings.NewReader(v.Request))
			switch {
			case strings.HasPrefix(v.Authorization, "absent"):
			case v.Authorization == "one EMPTY header value (present)":
				req.Header["Authorization"] = []string{""}
			case v.Authorization == "two header values":
				req.Header["Authorization"] = []string{"Bearer broken", "Bearer broken"}
			case v.Name == "local-keccak":
				req.Header.Set("Authorization", "Bearer "+token(t, snapshot, []string{reader}))
			case v.Authorization == "any":
				req.Header.Set("Authorization", "Bearer broken")
			default:
				req.Header.Set("Authorization", "Bearer "+token(t, snapshot, []string{}))
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != v.Status || string(body) != v.Response {
				t.Fatalf("exact metadata wire: status %d want %d\n%s\nwant %s\nerr %v", resp.StatusCode, v.Status, body, v.Response, err)
			}
			if appended.Load() != 1 {
				t.Fatal("operation did not cross exactly one actual Append", appended.Load())
			}
			if v.RPCs != nil && n.count()-beforeRPC != *v.RPCs {
				t.Fatal("physical metadata RPC budget", n.count()-beforeRPC, *v.RPCs)
			}
			if v.Name != "audit-failure-notification" {
				sealed := metadataSealedOne(t, x, beforeRows)
				if sealed.Policy != strings.TrimPrefix(string(e.OperationBinding().PolicyDigest), "sha256:") || sealed.HTTP != 200 {
					t.Fatal("selected policy/output metadata", sealed)
				}
				if v.Method != "" && sealed.Method != v.Method || v.Class != "" && sealed.Outcome != v.Class {
					t.Fatal("selected operation changed after delivery", sealed)
				}
				if sealed.DataOrg != "" && v.Name != "local-keccak" {
					t.Fatal("org-free/denied metadata fabricated org", sealed)
				}
				if v.Name == "null-id-response" && sealed.ActorID != "" {
					t.Fatal("anonymous actor fabricated", sealed)
				}
				if v.Name == "same-view-expiry-after-append" && (sealed.ActorID == "" || sealed.Outcome != "success") {
					t.Fatal("expiry rewrote selected success", sealed)
				}
				if v.Name == "ordinary" {
					knownActor = sealed.ActorID
				}
				if v.Name == "ordinary" || v.Name == "null-id-response" {
					// The least-privileged actual reader validates the new head
					// shape through the shared decoder, yet an empty DataOrg
					// cannot satisfy an organization's protected row predicate.
					reader, err := s.OpenReader(t.Context(), x.reader, x.scope)
					if err != nil {
						t.Fatal("org-free policy reader startup", err)
					}
					defer reader.Close()
					cut, err := reader.Open(t.Context(), "", now*1000000)
					if err != nil {
						t.Fatal("org-free policy actual reader head", err)
					}
					defer cut.Close()
					page, end, err := cut.ReadPage(t.Context(), s.ReadQuery{Organization: orgA, Actors: []string{knownActor}, FromMicros: now * 1000000, ThroughMicros: now * 1000000, Limit: 10}, nil)
					if err != nil || !end || len(page) != 0 || cut.Cut().HeadID == 0 {
						t.Fatal("policy digest invented protected org authority", page, end, err)
					}
				}
			}
			clock.Store(now)
		})
	}
}

func TestMetadataActivityActualAppendAndOutputLifetimeCap(t *testing.T) {
	n := newMetadataNode(t)
	f := metadataFixture()
	snapshot := f.load(t)
	var clock atomic.Int64
	clock.Store(now)
	e := metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{}))
	x := setupActivityDatabase(t, n.network())
	for _, scenario := range []string{"expiry-during-append", "slot-through-socket-write"} {
		t.Run(scenario, func(t *testing.T) {
			clock.Store(now)
			beforeRows := metadataRows(t, x)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error { close(entered); <-release; return nil }, e.OperationBinding().Methods...)
			service, err := rpcactivity.New(rpcactivity.Config{Metadata: e, Recorder: recorder, Network: n.network()})
			if err != nil {
				t.Fatal(err)
			}
			root, _ := service.Handler(orgA)
			alias, _ := service.Handler("")
			writeEntered, writeRelease := make(chan struct{}), make(chan struct{})
			var writeOnce sync.Once
			t.Cleanup(func() { writeOnce.Do(func() { close(writeRelease) }) })
			mux := http.NewServeMux()
			mux.Handle("/alias", alias)
			mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario == "slot-through-socket-write" {
					root.ServeHTTP(&blockedWriter{ResponseWriter: w, entered: writeEntered, release: writeRelease}, r)
				} else {
					root.ServeHTTP(w, r)
				}
			}))
			server := httptest.NewTLSServer(mux)
			t.Cleanup(server.Close)
			tok := token(t, snapshot, []string{reader})
			body := string(metadataRequest("eth_accounts", "[]"))
			done := requestAsync(t, server.Client(), server.URL, tok, body, t.Context())
			await(t, entered)
			if scenario == "expiry-during-append" {
				clock.Store(now + 300)
			}
			before := n.count()
			busy := bodyResult(t, requestAsync(t, server.Client(), server.URL+"/alias", tok, body, t.Context()))
			requireMetadataCode(t, busy, -32002)
			if n.count() != before {
				t.Fatal("shared alias reached node during blocked actual Append")
			}
			once.Do(func() { close(release) })
			if scenario == "slot-through-socket-write" {
				await(t, writeEntered)
				before = n.count()
				busy = bodyResult(t, requestAsync(t, server.Client(), server.URL+"/alias", tok, body, t.Context()))
				requireMetadataCode(t, busy, -32002)
				if n.count() != before {
					t.Fatal("HTTP N slot released after Complete before actual write")
				}
				writeOnce.Do(func() { close(writeRelease) })
			}
			wire := bodyResult(t, done)
			if scenario == "expiry-during-append" {
				requireMetadataCode(t, wire, -32002)
				if bytes.Contains(wire, []byte(addressB)) {
					t.Fatal("expired observation escaped actual Append")
				}
			} else if !bytes.Contains(wire, []byte(addressB)) {
				t.Fatal(string(wire))
			}
			sealed := metadataSealedOne(t, x, beforeRows)
			if sealed.ActorID == "" || sealed.DataOrg != orgA || sealed.Method != "eth_accounts" || sealed.Outcome != "success" {
				t.Fatal("actual selected query outcome changed", sealed)
			}
			clock.Store(now)
		})
	}
}

func TestMetadataActivityCombinedSnapshotAndSharedNativeGate(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	f := metadataFixture()
	var clock atomic.Int64
	clock.Store(now)
	f.clock = &clock
	var directory string
	f.loadedDirectory = &directory
	n := &node{}
	native, tok, financial, snapshot := mountedRawEngine(t, f, n, d, false)
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	metaNode := newMetadataNode(t)
	metaNode.mu.Lock()
	metaNode.genesis = n.genesisHeader
	metaNode.mu.Unlock()
	config := metadataConfig(t, metaNode, snapshot, &clock, []string{})
	config.Network = network
	// Strong-network metadata is pinned into each concrete client, not replaced
	// only on the outer configuration.
	config.Default = metadataClientForNetwork(t, metaNode, network, "default", "default-only", config.QueryLimits)
	for binding := range config.Clients {
		config.Clients[binding] = metadataClientForNetwork(t, metaNode, network, binding.CredentialRef, "selected-only", config.QueryLimits)
	}
	metadata := metadataEngine(t, config)
	x := setupActivityDatabase(t, network)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var appendCount atomic.Int32
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error {
		if appendCount.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}, metadata.OperationBinding().Methods...)
	service, err := rpcactivity.New(rpcactivity.Config{Engine: native, Metadata: metadata, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	// Re-read EXACTLY the same approved file bytes, while the trusted external
	// method map changes under the same version text. Only pointer identity
	// binds both concrete engines to the same selected method authority.
	otherMethods := *f.methodCatalog
	otherMethods.Aliases = map[string]string{}
	for name, target := range f.methodCatalog.Aliases {
		otherMethods.Aliases[name] = target
	}
	otherMethods.Aliases["bank_accounts"] = "net_peerCount"
	copySnapshot, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: directory, ExpectedManifestDigest: snapshot.Metadata().ManifestDigest, ExpectedEnvironment: "test", ExpectedChainID: "1"}, policybundle.Options{Limits: policybundle.DefaultLimits(), Profile: policybundle.RuntimeCreationObservedProfile("rpc/v1"), Methods: otherMethods, IdentityLimits: identity.DefaultLimits(), ComplianceLimits: compliancepolicy.DefaultLimits()})
	if err != nil || copySnapshot.Metadata().ManifestDigest != snapshot.Metadata().ManifestDigest {
		t.Fatal("same approved files re-read", err)
	}
	foreignConfig := config
	foreignConfig.Snapshot = copySnapshot
	foreignMetadata := metadataEngine(t, foreignConfig)
	if foreignMetadata.OperationBinding().PolicyDigest == metadata.OperationBinding().PolicyDigest {
		t.Fatal("actual same-version method change lost from digest")
	}
	if _, err := rpcactivity.New(rpcactivity.Config{Engine: native, Metadata: foreignMetadata, Recorder: recorder, Network: network}); err == nil {
		t.Fatal("equal-looking separate snapshot accepted")
	}
	handler, _ := service.Handler(orgA)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	done := requestAsync(t, server.Client(), server.URL, tok, string(metadataRequest("eth_accounts", "[]")), t.Context())
	await(t, entered)
	before, _ := n.counts()
	call := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + addressA + `","data":"0x0102"}]}`
	busy := bodyResult(t, requestAsync(t, server.Client(), server.URL, tok, call, t.Context()))
	requireMetadataCode(t, busy, -32002)
	after, _ := n.counts()
	if len(after) != len(before) {
		t.Fatal("native alias bypassed shared metadata Append slot")
	}
	once.Do(func() { close(release) })
	if wire := bodyResult(t, done); !bytes.Contains(wire, []byte(addressB)) {
		t.Fatal(string(wire))
	}
	metadataSealedOne(t, x, 0)
	beforeRows := metadataRows(t, x)
	wire := bodyResult(t, requestAsync(t, server.Client(), server.URL, tok, call, t.Context()))
	if !bytes.Contains(wire, []byte("0xfeed")) {
		t.Fatal("native path regressed after metadata", string(wire))
	}
	sealed := metadataSealedOne(t, x, beforeRows)
	if sealed.Method != "eth_call" || sealed.Outcome != "success" {
		t.Fatal(sealed)
	}
}
