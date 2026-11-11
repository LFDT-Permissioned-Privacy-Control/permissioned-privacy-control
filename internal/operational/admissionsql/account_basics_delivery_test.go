package admissionsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	log "privacy-proxy/internal/activitylog"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcstatepolicy"
)

func TestAccountBasicsActualWalletSQLBeforeFinalCanonicalSample(t *testing.T) {
	d := setupObserver(t)
	node, _, _, snap, included := newObservedWork(t, d)
	binding := f.AddressReadBinding{Network: included.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	reader, err := admissionsql.NewAddressReader(d.facts, binding)
	if err != nil {
		t.Fatal(err)
	}
	network := networkidentity.Binding{Environment: binding.Network.Environment, ChainID: binding.Network.ChainID, GenesisHash: binding.Network.Genesis.Hex(), DeploymentID: binding.Network.Deployment}
	snapshot := df.StateSnapshot(t, df.DefaultStateFixture(t))
	var clock atomic.Int64
	clock.Store(df.Now)
	wallet := df.ActualWalletFixture(t, t.Context(), d.db.ownerDSN, snapshot, network, func() time.Time { return time.Unix(clock.Load(), 0) })
	token := df.Token(t, snapshot, df.Subject, "Auditor")
	key, _ := crypto.HexToECDSA(strings.Repeat("3", 64))
	target := wallet.Link(t, t.Context(), token, key)
	type queryHold struct{ entered, release chan struct{} }
	var phaseMu sync.Mutex
	var hold *queryHold
	var finalHeaders atomic.Int32
	var balanceCalls atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") == false {
			t.Error("non-json typed state request")
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var q struct {
			ID     json.RawMessage
			Method string
			Params []json.RawMessage
		}
		if json.Unmarshal(raw, &q) != nil {
			t.Error("owned state request")
			return
		}
		if q.Method == "eth_getBalance" {
			balanceCalls.Add(1)
			phaseMu.Lock()
			current := hold
			phaseMu.Unlock()
			if current != nil {
				close(current.entered)
				<-current.release
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": "0x55"})
			return
		}
		if q.Method == "eth_getHeaderByNumber" && len(q.Params) == 1 && string(q.Params[0]) == `"0x1"` {
			finalHeaders.Add(1)
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		node.serve(w, r)
	}))
	defer backend.Close()
	client, err := rpcexecution.NewStateClient(backend.Client().Transport, rpcexecution.StateSource{Network: network, URL: backend.URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}, LinkedWalletBasics: true})
	definition, err := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: definition, Network: network, Default: client, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: df.Org}: client, {OrganizationID: df.OtherOrg}: client}, Associations: reader, AssociationBinding: binding, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: func() time.Time { return time.Unix(clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	// The real pre-effect writer has retained a creation plan but no birth has
	// been published. Even a zero-code node observation cannot make its address
	// public; the caller has proved a DIFFERENT EOA key only.
	var plans int
	if err := d.db.owner.QueryRow(t.Context(), `SELECT count(*) FROM ops_admission_v2.creation_plans WHERE network_key=$1`, binding.Network.Key[:]).Scan(&plans); err != nil || plans != 1 {
		t.Fatal("actual pre-effect plan missing", err, plans)
	}
	node.mu.Lock()
	node.code = "0x"
	node.mu.Unlock()
	private := engine.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), df.Org, []byte(`{"id":9,"method":"eth_getBalance","params":["`+node.child.Hex()+`","pending"]}`))
	metadata, err := private.MetadataFor(engine)
	if err != nil || metadata.Class != rpcengine.DeniedCompletion || balanceCalls.Load() != 0 {
		t.Fatal("unobserved zero-code planned address became public", metadata, err)
	}
	node.mu.Lock()
	node.code = "0x6000"
	node.mu.Unlock()
	_, qualified := acquireObserved(t, d, snap, included)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal(err)
	}
	recorder, scope, activityOwner := currentAddressActualRecorder(t, d, network, &clock, engine.OperationBinding().Methods)
	service, err := rpcactivity.New(rpcactivity.Config{State: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(df.Org)
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	original := types.CopyHeader(node.header)
	for _, mode := range []string{"positive", "node-reorg-during-successful-wallet-reload", "expiry-during-successful-wallet-reload"} {
		t.Run(mode, func(t *testing.T) {
			clock.Store(df.Now)
			node.mu.Lock()
			node.header = types.CopyHeader(original)
			node.mu.Unlock()
			phase := &queryHold{make(chan struct{}), make(chan struct{})}
			phaseMu.Lock()
			hold = phase
			phaseMu.Unlock()
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(phase.release) })
			var oldRows int64
			if err := activityOwner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, scope.NetworkKey[:]).Scan(&oldRows); err != nil {
				t.Fatal(err)
			}
			headers := finalHeaders.Load()
			done := make(chan []byte, 1)
			go func() {
				request, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["`+target.Hex()+`","pending"]}`))
				request.Header.Set("Authorization", "Bearer "+token)
				response, err := front.Client().Do(request)
				if err != nil {
					done <- nil
					return
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				done <- body
			}()
			select {
			case <-phase.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("positive initial wallet proof never reached state query")
			}
			lock, err := wallet.Owner.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(context.Background())
			if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_wallet_v2.wallet_links IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			releaseOnce.Do(func() { close(phase.release) })
			deadline := time.Now().Add(500 * time.Millisecond)
			for {
				var waiting bool
				if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='state_wallet_reader' AND wait_event_type='Lock' AND query LIKE '%wallet_links%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("actual final wallet reload did not block after real Append/A3 SQL")
				}
				time.Sleep(time.Millisecond)
			}
			if finalHeaders.Load() != headers {
				t.Fatal("canonicality sampled BEFORE blocking final wallet SQL")
			}
			if mode == "node-reorg-during-successful-wallet-reload" {
				node.mu.Lock()
				node.header = types.CopyHeader(original)
				node.header.Extra = []byte("backend-reorg-while-wallet-SQL-waits")
				node.mu.Unlock()
			}
			if mode == "expiry-during-successful-wallet-reload" {
				clock.Store(df.Now + 300)
			}
			if err := lock.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			var body []byte
			select {
			case body = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("actual state delivery did not settle")
			}
			if finalHeaders.Load() != headers+1 {
				t.Fatal("successful final wallet query not followed by exactly one original-number node sample")
			}
			if mode == "positive" {
				if !strings.Contains(string(body), "0x55") {
					t.Fatal("actual linked-wallet positive denied", string(body))
				}
			} else if !strings.Contains(string(body), `"code":-32002`) || strings.Contains(string(body), "0x55") {
				t.Fatal("late source change leaked protected result", mode, string(body))
			}
			deadline = time.Now().Add(4 * time.Second)
			for {
				var rows int64
				var encoded []byte
				if err := activityOwner.QueryRow(t.Context(), `SELECT s.row_count,l.request_params FROM ops_activity_v1.sources s LEFT JOIN ops_activity_v1.qualified_logs l ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, scope.NetworkKey[:]).Scan(&rows, &encoded); err != nil {
					t.Fatal(err)
				}
				if rows == oldRows+1 {
					var selected log.Envelope
					if json.Unmarshal(encoded, &selected) != nil || selected.Outcome != "success" || selected.ActorID != df.Actor(df.Subject) {
						t.Fatal("late source check replaced original selected completion", string(encoded))
					}
					break
				}
				if rows > oldRows+1 || time.Now().After(deadline) {
					t.Fatal("actual completion did not seal once", rows)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
