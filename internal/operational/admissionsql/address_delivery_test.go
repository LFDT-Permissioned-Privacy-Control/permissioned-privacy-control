package admissionsql_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	log "privacy-proxy/internal/activitylog"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcstatepolicy"
)

// This bridge uses the SAME actual published A2 facts-role reader as the
// surrounding PostgreSQL test, a real TLS StateClient, actual Recorder/Pebble,
// real SQL sealing and a real HTTP delivery gate. No ownership answer is stubbed.
func currentAddressCanonicalDelivery(t *testing.T, d *observerDatabase, reader *admissionsql.AddressReader, binding f.AddressReadBinding, node *observedNode, before f.ObserverSnapshot) {
	t.Helper()
	var clock atomic.Int64
	clock.Store(df.Now)
	var reorgAfterQuery, expireDuringHeader atomic.Bool
	var mu sync.Mutex
	original := types.CopyHeader(node.header)
	canonical := map[uint64]*types.Header{0: types.CopyHeader(node.genesis), 1: original}
	var numberChecks atomic.Int32
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		var q struct {
			ID     json.RawMessage
			Method string
			Params []json.RawMessage
		}
		if json.Unmarshal(raw, &q) != nil {
			t.Error("backend request")
			return
		}
		if q.Method == "eth_getHeaderByNumber" {
			var selector string
			_ = json.Unmarshal(q.Params[0], &selector)
			var number uint64
			if selector == "0x0" {
				number = 0
			} else if selector == "0x1" {
				number = 1
				numberChecks.Add(1)
			} else {
				t.Error("non-original numeric header selector", selector)
			}
			mu.Lock()
			header := canonical[number]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": header})
			if number == 1 && expireDuringHeader.Load() {
				clock.Store(df.Now + 300)
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		node.serve(w, r)
		if q.Method == "eth_getCode" && reorgAfterQuery.Load() {
			fork := types.CopyHeader(original)
			fork.Extra = []byte("honest-new-canonical-branch")
			mu.Lock()
			canonical[1] = fork
			mu.Unlock()
		}
	}))
	defer backend.Close()
	network := networkidentity.Binding{Environment: binding.Network.Environment, ChainID: binding.Network.ChainID, GenesisHash: binding.Network.Genesis.Hex(), DeploymentID: binding.Network.Deployment}
	client, err := rpcexecution.NewStateClient(backend.Client().Transport, rpcexecution.StateSource{Network: network, URL: backend.URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := df.StateSnapshot(t, df.DefaultStateFixture(t))
	raw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}})
	policy, err := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	observed := &observedAddressReader{reader: reader, rechecked: make(chan error, 16)}
	engine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: policy, Network: network, Default: client, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: df.Org}: client, {OrganizationID: df.OtherOrg}: client}, Associations: observed, AssociationBinding: binding, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: func() time.Time { return time.Unix(clock.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	recorder, scope, activityOwner := currentAddressActualRecorder(t, d, network, &clock, engine.OperationBinding().Methods)
	service, err := rpcactivity.New(rpcactivity.Config{State: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Handler(df.Org)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	token := df.Token(t, snapshot, df.Subject, "Auditor")
	for _, mode := range []string{"original-positive", "stale-sql-node-reorg", "restored-positive", "expiry-during-final-header"} {
		t.Run(mode, func(t *testing.T) {
			clock.Store(df.Now)
			mu.Lock()
			canonical[1] = original
			mu.Unlock()
			reorgAfterQuery.Store(mode == "stale-sql-node-reorg")
			expireDuringHeader.Store(mode == "expiry-during-final-header")
			beforeChecks := numberChecks.Load()
			var oldRows int64
			if err := activityOwner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, scope.NetworkKey[:]).Scan(&oldRows); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["`+node.child.Hex()+`","latest"]}`))
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := front.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if err := <-observed.rechecked; err != nil {
				t.Fatal("actual unchanged SQL Recheck failed instead of reaching live-node gate", err)
			}
			if numberChecks.Load() != beforeChecks+1 {
				t.Fatal("not exactly one original-number final node call")
			}
			denied := mode == "stale-sql-node-reorg" || mode == "expiry-during-final-header"
			if denied {
				if !strings.Contains(string(body), `"code":-32002`) || strings.Contains(string(body), "0x6000") {
					t.Fatal("late gate leaked protected result", string(body))
				}
			} else if !strings.Contains(string(body), "0x6000") {
				t.Fatal("valid canonical path rejected", string(body))
			}
			deadline := time.Now().Add(4 * time.Second)
			for {
				var rows int64
				var encoded []byte
				err := activityOwner.QueryRow(t.Context(), `SELECT s.row_count,l.request_params FROM ops_activity_v1.sources s LEFT JOIN ops_activity_v1.qualified_logs l ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, scope.NetworkKey[:]).Scan(&rows, &encoded)
				if err != nil {
					t.Fatal(err)
				}
				if rows == oldRows+1 {
					var selected log.Envelope
					if json.Unmarshal(encoded, &selected) != nil || selected.Outcome != "success" || selected.ActorID != df.Actor(df.Subject) {
						t.Fatal("late gate replaced original selected completion", string(encoded))
					}
					break
				}
				if rows > oldRows+1 || time.Now().After(deadline) {
					t.Fatal("actual completion did not seal once", rows, oldRows)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	// Ordinary observer progress must not invalidate an unchanged target fact
	// digest or require that the freshly reread head equal the original head.
	clock.Store(df.Now)
	reorgAfterQuery.Store(false)
	expireDuringHeader.Store(false)
	mu.Lock()
	canonical[1] = original
	mu.Unlock()
	t.Run("association-change-after-actual-append", func(t *testing.T) {
		result := engine.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), df.Org, []byte(`{"jsonrpc":"2.0","id":2,"method":"eth_getCode","params":["`+node.child.Hex()+`","latest"]}`))
		metadata, err := result.MetadataFor(engine)
		if err != nil || metadata.Class != rpcengine.SuccessfulCompletion {
			t.Fatal("original positive A2 operation", err, metadata)
		}
		digest, err := log.ParseDigestHex(strings.TrimPrefix(string(metadata.PolicyDigest), "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		var oldRows int64
		if err := activityOwner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, scope.NetworkKey[:]).Scan(&oldRows); err != nil {
			t.Fatal(err)
		}
		slot, err := recorder.Reserve()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := slot.Complete(log.Completion{ActorID: metadata.ActorID, DataOrganizationID: metadata.OrganizationID, PolicyDigest: digest, Method: metadata.Method, HTTPStatus: 200, Outcome: log.Success}); err != nil {
			t.Fatal("actual synchronous append", err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `CREATE TEMP TABLE saved_delivery_associations AS SELECT * FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1`, binding.Network.Key[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1`, binding.Network.Key[:]); err != nil {
			t.Fatal(err)
		}
		checks := numberChecks.Load()
		if result.RequireDeliverable(t.Context(), engine) == nil {
			t.Fatal("changed actual SQL association delivered after real Append")
		}
		if err := <-observed.rechecked; err == nil {
			t.Fatal("actual post-Append orphan was accepted")
		}
		if numberChecks.Load() != checks {
			t.Fatal("failed SQL evidence proceeded to node final check")
		}
		if _, err := d.db.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.creation_authority_associations SELECT * FROM saved_delivery_associations`); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(4 * time.Second)
		for {
			var rows int64
			var raw []byte
			if err := activityOwner.QueryRow(t.Context(), `SELECT s.row_count,l.request_params FROM ops_activity_v1.sources s JOIN ops_activity_v1.qualified_logs l ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, scope.NetworkKey[:]).Scan(&rows, &raw); err != nil {
				t.Fatal(err)
			}
			if rows == oldRows+1 {
				var selected log.Envelope
				if json.Unmarshal(raw, &selected) != nil || selected.Outcome != "success" || selected.ActorID != metadata.ActorID {
					t.Fatal("actual association change rewrote original selected completion")
				}
				break
			}
			if rows > oldRows+1 || time.Now().After(deadline) {
				t.Fatal("post-Append change did not seal once", rows)
			}
			time.Sleep(time.Millisecond)
		}
	})
	pass, err := reader.ReadAddressAssociations(t.Context(), node.child)
	if err != nil || pass.ObserverHead().Number != 1 || pass.ObserverHead().Hash != original.Hash() {
		t.Fatal("same-read original observer head", err)
	}
	latest, err := d.observer.ReadObserver(t.Context(), before.Lease)
	if err != nil {
		t.Fatal(err)
	}
	next := &types.Header{Number: big.NewInt(2), ParentHash: original.Hash(), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: original.Time + 1}
	newHead := f.Header{Number: 2, Hash: next.Hash(), Parent: next.ParentHash, Timestamp: next.Time}
	_, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: latest, Common: latest.State.Head, Headers: []f.Header{newHead}, Tip: newHead})
	if err != nil {
		t.Fatal("actual append-only observer advance", err)
	}
	fresh, err := reader.ReadAddressAssociations(t.Context(), node.child)
	if err != nil || fresh.ObserverHead().Number != 2 || !pass.SameCurrent(fresh) {
		t.Fatal("normal SQL head progress changed target currentness", err)
	}
	if reader.RecheckAddressAssociations(t.Context(), pass) != nil || client.RequireCanonicalHeader(t.Context(), pass.ObserverHead()) != nil {
		t.Fatal("original canonical ancestor rejected after actual SQL observer progress")
	}
}

func currentAddressActualRecorder(t *testing.T, d *observerDatabase, network networkidentity.Binding, clock *atomic.Int64, methods []string) (*log.Recorder, activitysql.Scope, *pgx.Conn) {
	t.Helper()
	ctx := t.Context()
	// Activity005 deliberately refuses a database containing admission or user
	// tables. Keep the actual separate lean database boundary in this bridge.
	if _, err := d.db.owner.Exec(ctx, `CREATE DATABASE state_activity_test`); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(d.db.ownerDSN)
	u.Path = "/state_activity_test"
	ownerDSN := u.String()
	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	for _, role := range []string{"state_b1_writer", "state_b1_reader", "state_b1_retention"} {
		if _, err := d.db.owner.Exec(ctx, `CREATE ROLE `+role+` LOGIN NOINHERIT PASSWORD 'state-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := filepath.Glob("../../db/migrations_audit/00[1-4]_*.sql")
	if err != nil || len(paths) != 4 {
		t.Fatal("baseline audit migration paths", paths, err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = owner.Exec(ctx, "BEGIN;"+string(raw)+";COMMIT"); err != nil {
			t.Fatal(err)
		}
	}
	roles := activitysql.RoleNames{Writer: "state_b1_writer", Reader: "state_b1_reader", Retention: "state_b1_retention"}
	if err := activitysql.Migrate(ctx, ownerDSN, roles.Writer, roles.Reader, roles.Retention, true); err != nil {
		t.Fatal(err)
	}
	registration := activitysql.Registration{Network: network, SourceID: uuid.NewString(), Configuration: [32]byte{1}, Limits: activitysql.DefaultStorageLimits(), Roles: roles}
	if err := activitysql.Initialize(ctx, ownerDSN, registration, true); err != nil {
		t.Fatal(err)
	}
	key, _ := network.Key()
	status, err := activitysql.Status(ctx, ownerDSN, key, registration.SourceID)
	if err != nil {
		t.Fatal(err)
	}
	scope := activitysql.Scope{NetworkKey: key, SourceID: registration.SourceID, ExpectedGeneration: status.Metadata.Generation}
	u.User = url.UserPassword(roles.Writer, "state-test-only")
	writer, err := activitysql.OpenWriter(ctx, u.String(), scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	labels := append([]string{"rpc.invalid_request", "rpc.invalid_transport"}, methods...)
	slices.Sort(labels)
	labels = slices.Compact(labels)
	recorder, err := log.New(ctx, log.Config{Network: network, SourceID: scope.SourceID, ProducerID: uuid.NewString(), ExpectedGeneration: scope.ExpectedGeneration, Configuration: log.Digest(registration.Configuration), Methods: labels, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }, BufferDirectory: t.TempDir(), Limits: log.Limits{InFlight: 1, BufferedEntries: 64, BufferedBytes: 64 * log.MaxEncodedBytes, SealBatch: 16}}, writer)
	if err != nil {
		t.Fatal(err)
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- recorder.Run(run) }()
	t.Cleanup(func() {
		cancel()
		ctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if err := recorder.Close(ctx); err != nil {
			t.Error(err)
		}
		<-done
	})
	return recorder, scope, owner
}
