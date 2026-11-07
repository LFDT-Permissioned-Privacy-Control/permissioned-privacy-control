package admissionsql_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

type observerDatabase struct {
	db                    *database
	app, observer, facts  *admissionsql.Store
	observerDSN, factsDSN string
}

func setupObserver(t *testing.T) *observerDatabase {
	t.Helper()
	d := setup(t)
	d.one.Close()
	d.two.Close()
	for _, role := range []string{"creation_observer", "creation_facts"} {
		if _, err := d.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'admission-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := admissionsql.MigrateCreationObserver(t.Context(), d.ownerDSN, "admission_app", "admission_reader", "admission_retention", "creation_observer", "creation_facts"); err != nil {
		t.Fatal("offline schema3", err)
	}
	u, _ := url.Parse(d.ownerDSN)
	u.User = url.UserPassword("creation_observer", "admission-test-only")
	observerDSN := u.String()
	u.User = url.UserPassword("creation_facts", "admission-test-only")
	factsDSN := u.String()
	app, err := admissionsql.OpenCreationObserved(t.Context(), d.appDSN, a.DefaultCreationLimits())
	if err != nil {
		t.Fatal("schema3 app startup", err)
	}
	t.Cleanup(app.Close)
	observer, err := admissionsql.OpenObserver(t.Context(), observerDSN)
	if err != nil {
		t.Fatal("schema3 observer startup", err)
	}
	t.Cleanup(observer.Close)
	facts, err := admissionsql.OpenCreationFacts(t.Context(), factsDSN)
	if err != nil {
		t.Fatal("schema3 facts startup", err)
	}
	t.Cleanup(facts.Close)
	return &observerDatabase{d, app, observer, facts, observerDSN, factsDSN}
}
func observerScope(t *testing.T, d *observerDatabase) (a.NetworkBinding, a.Scope, creationcapture.Metadata, f.Source, f.Header) {
	t.Helper()
	binding, scope := creationScope(t, d.db)
	network := f.Network{Key: f.Digest(scope.Network), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: common.HexToHash(binding.GenesisHash), Deployment: binding.DeploymentID}
	state := f.State{Generation: scope.State.Generation, Coverage: f.Digest(scope.State.Coverage)}
	ref := f.Source{Network: network, URL: "https://node.invalid/rpc", Profile: "reth-prague-included-creations/v1", PragueStart: 1, PragueEnd: 1 << 63}
	ingress := ref
	ingress.Organization = scope.Organization
	ingress.Profile = "geth-prague-lifecycle-signed/v1"
	set, err := f.SourceSet([]f.Source{ingress})
	if err != nil {
		t.Fatal(err)
	}
	metadata := creationcapture.Metadata{Network: network, State: state, Reference: ref.Digest(), SourceSet: set}
	floor := f.Header{Number: 10, Hash: common.HexToHash("0x1234"), Parent: common.HexToHash("0x1233"), Timestamp: 1700000000}
	if err := admissionsql.BootstrapCreationObserver(t.Context(), d.db.ownerDSN, binding, scope.State, metadata, floor); err != nil {
		t.Fatal("fresh observer bootstrap", err)
	}
	return binding, scope, metadata, ref, floor
}
func activeObserver(t *testing.T, d *observerDatabase, m creationcapture.Metadata, floor f.Header) f.ObserverSnapshot {
	t.Helper()
	snap, err := d.observer.AcquireObserverLease(t.Context(), m.Network.Key, m.State, uuid.NewString(), m.SourceSet, m.Reference)
	if err != nil {
		t.Fatal("lease", err)
	}
	snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: floor, Tip: floor})
	if err != nil || !snap.State.Ready || !snap.State.CaptureReady {
		t.Fatal("exclusive awaiting activation", snap, err)
	}
	return snap
}
func capturedIntent(t *testing.T, scope a.Scope) a.CreationIntent {
	i := creationIntent(t, scope)
	p, err := i.PlanData()
	if err != nil {
		t.Fatal(err)
	}
	p.Version = nativeadmission.CapturedCreationPlanVersion
	p.CaptureProfile = f.CaptureProfile
	i.Plan, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	i.PlanDigest = a.Digest(nativeadmission.CapturedCreationPlanDigest(i.Plan))
	return i
}
func coverageRecord(m creationcapture.Metadata, s f.ObserverSnapshot, anchor f.Header) f.CoverageRecord {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return f.CoverageRecord{Version: 1, Policy: f.CaptureProfile, Network: m.Network.Key, State: m.State, ObserverEpoch: s.Lease.ObserverEpoch, CaptureEpoch: s.Lease.CaptureEpoch, SourceSet: m.SourceSet, Reference: m.Reference, Ingress: f.Hash("test-ingress", nil), HighWater: anchor, Latest: anchor, HeaderVersion: s.State.HeaderVersion, LeaseFence: s.Lease.Fence, ProbeStarted: now, ProbeFinished: now.Add(time.Millisecond), ValidUntil: now.Add(time.Second)}
}
func commitCovered(ctx context.Context, store *admissionsql.Store, scope a.Scope, i a.CreationIntent, r f.CoverageRecord) error {
	_, err := store.WithCoveredRawTransaction(ctx, scope, a.CaptureCommitBinding{ObserverEpoch: r.ObserverEpoch, CaptureEpoch: r.CaptureEpoch, SourceSet: r.SourceSet}, func(raw a.RawTx) (a.CommitKind, error) {
		_, err := raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(i, r)
		return a.CommitAllow, err
	})
	return err
}
func TestCreationObservedActualPostgresCoverageRecoveryAndFences(t *testing.T) {
	d := setupObserver(t)
	t.Run("lower-only observer caps reject complete over-cap publication", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		limits := f.DefaultLimits()
		limits.Headers = 2
		limited, err := admissionsql.OpenObserver(t.Context(), d.observerDSN, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer limited.Close()
		for _, bad := range []f.Limits{func() f.Limits { b := limits; b.Headers = 0; return b }(), func() f.Limits { b := limits; b.Headers = f.DefaultLimits().Headers + 1; return b }()} {
			if s, err := admissionsql.OpenObserver(t.Context(), d.observerDSN, bad); !errors.Is(err, a.ErrInvalid) || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("invalid/lifted limits opened", err)
			}
		}
		if s, err := admissionsql.OpenObserver(t.Context(), d.observerDSN, limits, limits); !errors.Is(err, a.ErrInvalid) || s != nil {
			t.Fatal("multiple observer limit sets accepted", err)
		}
		child := f.Header{Number: 11, Hash: common.HexToHash("0x7777"), Parent: floor.Hash, Timestamp: floor.Timestamp + 1}
		snap, err = limited.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: floor, Headers: []f.Header{child}, Tip: child})
		if err != nil {
			t.Fatal("allowed lower-cap publication", err)
		}
		extra := f.Header{Number: 12, Hash: common.HexToHash("0x8888"), Parent: child.Hash, Timestamp: child.Timestamp + 1}
		if _, err := limited.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: child, Headers: []f.Header{extra}, Tip: extra}); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("over-cap prefix published", err)
		}
		var head, count int64
		if d.db.owner.QueryRow(t.Context(), `SELECT o.head_number,c.header_count FROM ops_admission_v2.creation_observer_state o JOIN ops_admission_v2.creation_capacity c USING(network_key)WHERE o.network_key=$1`, scope.Network[:]).Scan(&head, &count) != nil || head != 11 || count != 2 {
			t.Fatal("partial capped suffix/counter", head, count)
		}
	})
	t.Run("unchanged heartbeat preserves prefix version and avoids financial capacity lock", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		blocker, err := d.db.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(t.Context())
		if _, err := blocker.Exec(t.Context(), `SELECT header_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1 FOR UPDATE`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		pulse, err := d.observer.PublishObserverHeaders(ctx, f.HeaderUpdate{Before: snap, Common: floor, Tip: floor})
		if err != nil || pulse.State.HeaderVersion != snap.State.HeaderVersion || pulse.Lease.CaptureEpoch != snap.Lease.CaptureEpoch || !pulse.State.CaptureReady {
			t.Fatal("heartbeat changed prefix or waited unrelated capacity", pulse, err)
		}
		if err := blocker.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("atomic first coverage and timing-free duplicate", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		i := capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		r := coverageRecord(m, snap, floor)
		if err := commitCovered(t.Context(), d.app, scope, i, r); err != nil {
			t.Fatal("covered factory intent", err)
		}
		var count, bytes, generation int64
		var original []byte
		if d.db.owner.QueryRow(t.Context(), `SELECT c.capture_coverage_count,c.capture_coverage_bytes,w.generation,v.record_digest FROM ops_admission_v2.creation_capacity c JOIN ops_admission_v2.creation_work w USING(network_key)JOIN ops_admission_v2.creation_capture_coverage v USING(network_key,tx_hash)WHERE c.network_key=$1`, scope.Network[:]).Scan(&count, &bytes, &generation, &original) != nil || count != 1 || generation != 1 {
			t.Fatal("atomic usage", count, bytes, generation)
		}
		r.ProbeStarted = r.ProbeStarted.Add(time.Second)
		r.ProbeFinished = r.ProbeFinished.Add(time.Second)
		r.ValidUntil = r.ValidUntil.Add(time.Second)
		if err := commitCovered(t.Context(), d.app, scope, i, r); err != nil {
			t.Fatal("duplicate changed only clocks", err)
		}
		var unchanged bool
		if err := d.db.owner.QueryRow(t.Context(), `SELECT c.capture_coverage_count=$2 AND c.capture_coverage_bytes=$3 AND w.generation=$4 AND v.record_digest=$5 FROM ops_admission_v2.creation_capacity c JOIN ops_admission_v2.creation_work w USING(network_key)JOIN ops_admission_v2.creation_capture_coverage v USING(network_key,tx_hash)WHERE c.network_key=$1`, scope.Network[:], count, bytes, generation, original).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("duplicate rewrote original coverage", err)
		}
	})
	t.Run("transient liveness does not invalidate ticket; takeover does", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		r := coverageRecord(m, snap, floor)
		if err := d.observer.MarkObserverTip(t.Context(), snap, f.Header{Number: 11, Hash: common.HexToHash("0x1235"), Parent: floor.Hash, Timestamp: floor.Timestamp + 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.app.ReadCheckpoint(t.Context(), m.Network.Key, m.State, m.SourceSet); err == nil {
			t.Fatal("unready live gate allowed")
		}
		i := capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		if err := commitCovered(t.Context(), d.app, scope, i, r); err != nil {
			t.Fatal("late valid ticket rejected transient tip", err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET lease_expires=clock_timestamp()-interval'1 second' WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.observer.AcquireObserverLease(t.Context(), m.Network.Key, m.State, uuid.NewString(), m.SourceSet, m.Reference); err != nil {
			t.Fatal(err)
		}
		scope.Hash = common.HexToHash("0x9999")
		i = capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		if err := commitCovered(t.Context(), d.app, scope, i, r); !errors.Is(err, a.ErrUnavailable) {
			t.Fatal("old ticket crossed capture epoch", err)
		}
	})
	t.Run("sticky trust revocation survives explicit recovery and blocks original duplicate", func(t *testing.T) {
		binding, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		i := capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		r := coverageRecord(m, snap, floor)
		if err := commitCovered(t.Context(), d.app, scope, i, r); err != nil {
			t.Fatal(err)
		}
		if err := d.observer.QuarantineObserver(t.Context(), snap, "uncertain-capture-trust"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.observer.AcquireObserverLease(t.Context(), m.Network.Key, m.State, uuid.NewString(), m.SourceSet, m.Reference); err == nil {
			t.Fatal("online worker cleared sticky quarantine")
		}
		generation := uuid.NewString()
		if err := admissionsql.BeginRecovery(t.Context(), d.db.ownerDSN, binding, generation); err != nil {
			t.Fatal(err)
		}
		expected := a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}
		var observerEpoch string
		if d.db.owner.QueryRow(t.Context(), `SELECT observer_epoch::text FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, scope.Network[:]).Scan(&observerEpoch) != nil {
			t.Fatal("observer epoch")
		}
		if err := admissionsql.RevokeCaptureEpochs(t.Context(), d.db.ownerDSN, binding, generation, observerEpoch, "freshness-unproven", []string{r.CaptureEpoch, uuid.NewString()}, true); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("unknown epoch partially revoked", err)
		}
		for j := 0; j < 2; j++ {
			if err := admissionsql.RevokeCaptureEpochs(t.Context(), d.db.ownerDSN, binding, generation, observerEpoch, "freshness-unproven", []string{r.CaptureEpoch}, true); err != nil {
				t.Fatal(err)
			}
		}
		var count int
		if d.db.owner.QueryRow(t.Context(), `SELECT revoked_epoch_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, scope.Network[:]).Scan(&count) != nil || count != 1 {
			t.Fatal("revocation idempotency", count)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, expected, true); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("legacy finalize cleared sticky trust", err)
		}
		for _, ack := range [][2]bool{{false, true}, {true, false}} {
			if err := admissionsql.FinalizeCreationObserverRecovery(t.Context(), d.db.ownerDSN, binding, expected, observerEpoch, ack[0], ack[1], time.Minute); !errors.Is(err, a.ErrInvalid) {
				t.Fatal("missing explicit trust/completeness acknowledgement", ack, err)
			}
		}
		if err := admissionsql.FinalizeCreationObserverRecovery(t.Context(), d.db.ownerDSN, binding, expected, uuid.NewString(), true, true, time.Minute); !errors.Is(err, a.ErrConflict) {
			t.Fatal("stale epoch finalized", err)
		}
		if err := admissionsql.FinalizeCreationObserverRecovery(t.Context(), d.db.ownerDSN, binding, expected, observerEpoch, true, true, time.Minute); err != nil {
			t.Fatal("explicit preserved-deny recovery", err)
		}
		var ready, capture bool
		var quarantine string
		if d.db.owner.QueryRow(t.Context(), `SELECT ready,capture_ready,quarantine FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, scope.Network[:]).Scan(&ready, &capture, &quarantine) != nil || ready || capture || quarantine != "awaiting-canonical" {
			t.Fatal("offline recovery became serving-ready", ready, capture, quarantine)
		}
		scope.State = expected
		m.State = f.State{Generation: generation, Coverage: f.Digest(expected.Coverage)}
		snap = activeObserver(t, d, m, floor)
		r = coverageRecord(m, snap, floor)
		if err := commitCovered(t.Context(), d.app, scope, i, r); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("fresh ticket rewrote revoked original coverage", err)
		}
	})
	t.Run("missing v2 coverage is corruption rather than fresh bootstrap", func(t *testing.T) {
		binding, scope, m, _, floor := observerScope(t, d)
		snap := activeObserver(t, d, m, floor)
		i := capturedIntent(t, scope)
		i.Anchor.Timestamp = floor.Timestamp
		r := coverageRecord(m, snap, floor)
		if err := commitCovered(t.Context(), d.app, scope, i, r); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := commitCovered(t.Context(), d.app, scope, i, r); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("duplicate repaired missing original coverage", err)
		}
		generation := uuid.NewString()
		if err := admissionsql.BeginRecovery(t.Context(), d.db.ownerDSN, binding, generation); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, a.ExpectedState{Generation: generation, Coverage: admissionsql.EmptyCoverage()}, true); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("restore accepted missing atomic coverage", err)
		}
	})
	t.Run("effective role boundaries and live TTL checked before conversion", func(t *testing.T) {
		_, scope, m, _, floor := observerScope(t, d)
		_ = activeObserver(t, d, m, floor)
		app, err := pgx.Connect(t.Context(), d.db.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(t.Context())
		for _, sql := range []string{`UPDATE ops_admission_v2.creation_observer_state SET capture_ready=false WHERE network_key=$1`, `SELECT * FROM ops_admission_v2.creation_observer_state WHERE network_key=$1 FOR SHARE`, `DELETE FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1`, `DELETE FROM ops_admission_v2.revoked_creation_capture_epochs WHERE network_key=$1`} {
			if _, err := app.Exec(t.Context(), sql, scope.Network[:]); err == nil {
				t.Fatal("app gained forbidden observer/immutable mutation", sql)
			}
		}
		observer, err := pgx.Connect(t.Context(), d.observerDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(t.Context())
		for _, sql := range []string{`SELECT * FROM ops_admission_v2.travel_records`, `DELETE FROM ops_admission_v2.creation_authority_refs`, `UPDATE ops_admission_v2.creation_capacity SET revoked_epoch_count=0`, `DELETE FROM ops_admission_v2.revoked_creation_capture_epochs`} {
			if _, err := observer.Exec(t.Context(), sql); err == nil {
				t.Fatal("worker gained forbidden scope", sql)
			}
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET capture_heartbeat_until='9999-01-01 UTC' WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.app.ReadCheckpoint(t.Context(), m.Network.Key, m.State, m.SourceSet); err == nil {
			t.Fatal("huge live TTL became valid duration")
		}
	})
}

func TestCreationObservedActualHeaderWorkerPostgres(t *testing.T) {
	d := setupObserver(t)
	headers := make([]*types.Header, 150)
	for i := range headers {
		parent := common.Hash{}
		if i > 0 {
			parent = headers[i-1].Hash()
		}
		headers[i] = &types.Header{ParentHash: parent, Number: big.NewInt(int64(i)), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1700000000 + uint64(i), BaseFee: big.NewInt(1)}
	}
	var mu sync.Mutex
	head := 140
	calls := 0
	syncing := false
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		var q struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("invalid node request")
			return
		}
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
			if syncing {
				result = map[string]any{"startingBlock": "0x0", "currentBlock": "0x89", "highestBlock": "0x8c"}
			}
		case "eth_getHeaderByNumber":
			var selector string
			_ = json.Unmarshal(q.Params[0], &selector)
			n := uint64(head)
			if selector != "latest" {
				var err error
				n, err = strconv.ParseUint(selector[2:], 16, 64)
				if err != nil {
					t.Error(err)
					return
				}
			}
			if n <= uint64(head) {
				result = headers[n]
			}
		default:
			t.Error("unexpected RPC", q.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	defer node.Close()
	binding := a.NetworkBinding{Environment: "worker-test", ChainID: "1", GenesisHash: headers[0].Hash().Hex(), DeploymentID: uuid.NewString()}
	key, _ := binding.Key()
	expected := a.ExpectedState{Generation: uuid.NewString(), Coverage: admissionsql.EmptyCoverage()}
	if err := admissionsql.BootstrapEmpty(t.Context(), d.db.ownerDSN, binding, expected.Generation); err != nil {
		t.Fatal(err)
	}
	network := f.Network{Key: f.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: headers[0].Hash(), Deployment: binding.DeploymentID}
	ref := f.Source{Network: network, URL: node.URL, Profile: "reth-prague-included-creations/v1", PragueStart: 1, PragueEnd: 1 << 63}
	set, _ := f.SourceSet(nil)
	metadata := creationcapture.Metadata{Network: network, State: f.State{Generation: expected.Generation, Coverage: f.Digest(expected.Coverage)}, SourceSet: set, Reference: ref.Digest()}
	h := headers[10]
	floor := f.Header{Number: 10, Hash: h.Hash(), Parent: h.ParentHash, Timestamp: h.Time}
	if err := admissionsql.BootstrapCreationObserver(t.Context(), d.db.ownerDSN, binding, expected, metadata, floor); err != nil {
		t.Fatal(err)
	}
	client, err := rpcexecution.NewHeaderClient(node.Client().Transport, ref, rpcexecution.Credential{}, rpcexecution.DefaultHeaderLimits())
	if err != nil {
		t.Fatal(err)
	}
	worker, err := creationobserver.NewHeaderWorker(creationobserver.HeaderOptions{Network: network, State: metadata.State, Owner: uuid.NewString(), SourceSet: set, Reference: ref, CaughtUpAssertion: f.CaughtUpAssertion, Client: client, Store: d.observer})
	if err != nil {
		t.Fatal(err)
	}
	step := func() {
		t.Helper()
		mu.Lock()
		calls = 0
		mu.Unlock()
		if err := worker.Step(t.Context()); err != nil {
			t.Fatal("real header step", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if calls > 143 {
			t.Fatal("composed physical budget", calls)
		}
	}
	step()
	var n int64
	var ready, capture bool
	if err := d.db.owner.QueryRow(t.Context(), `SELECT head_number,ready,capture_ready FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, key[:]).Scan(&n, &ready, &capture); err != nil || n != 137 || ready || capture {
		t.Fatal("partial prefix became ready", n, ready, capture, err)
	}
	mu.Lock()
	head = 138
	mu.Unlock()
	if err := worker.Step(t.Context()); !errors.Is(err, creationobserver.ErrUnavailable) {
		t.Fatal("partial catchup forgot known higher tip", err)
	}
	var known int64
	if d.db.owner.QueryRow(t.Context(), `SELECT head_number,capture_ready,known_tip_number FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, key[:]).Scan(&n, &capture, &known) != nil || n != 137 || capture || known != 140 {
		t.Fatal("known high water regressed", n, capture, known)
	}
	// A future suffix not yet in the prefix may change at the same height.
	// Its diagnostic hash is not immutable authority; the actual appended
	// canonical suffix and final tip still have to match exactly.
	mu.Lock()
	head = 140
	headers[140] = types.CopyHeader(headers[140])
	headers[140].Extra = []byte("unpublished-future-tip")
	for i := 141; i < len(headers); i++ {
		headers[i].ParentHash = headers[i-1].Hash()
	}
	mu.Unlock()
	step()
	cp, err := d.app.ReadCheckpoint(t.Context(), network.Key, metadata.State, set)
	if err != nil || cp.HighWater.Number != 140 {
		t.Fatal("coherent actual worker checkpoint", cp, err)
	}
	epoch := cp.CaptureEpoch
	mu.Lock()
	syncing = true
	mu.Unlock()
	if err := worker.Step(t.Context()); !errors.Is(err, creationobserver.ErrUnavailable) {
		t.Fatal("nonfalse sync at unchanged tip", err)
	}
	if _, err := d.app.ReadCheckpoint(t.Context(), network.Key, metadata.State, set); err == nil {
		t.Fatal("known syncing left live capture heartbeat")
	}
	mu.Lock()
	syncing = false
	mu.Unlock()
	step()
	mu.Lock()
	head = 139
	mu.Unlock()
	if err := worker.Step(t.Context()); !errors.Is(err, creationobserver.ErrUnavailable) {
		t.Fatal("lagging node accepted", err)
	}
	if d.db.owner.QueryRow(t.Context(), `SELECT head_number,ready,capture_ready FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, key[:]).Scan(&n, &ready, &capture) != nil || n != 140 || !ready || capture {
		t.Fatal("ordinary lag became reorg/durable trust failure", n, ready, capture)
	}
	mu.Lock()
	head = 140
	mu.Unlock()
	step()
	mu.Lock()
	for i := 139; i < len(headers); i++ {
		headers[i] = types.CopyHeader(headers[i])
		headers[i].ParentHash = headers[i-1].Hash()
		headers[i].Extra = []byte("new-branch")
	}
	head = 142
	mu.Unlock()
	step()
	if d.db.owner.QueryRow(t.Context(), `SELECT head_number,ready,capture_ready FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, key[:]).Scan(&n, &ready, &capture) != nil || n != 138 || !ready || capture {
		t.Fatal("rollback-only Step", n, ready, capture)
	}
	step()
	cp, err = d.app.ReadCheckpoint(t.Context(), network.Key, metadata.State, set)
	if err != nil || cp.HighWater.Number != 142 || cp.CaptureEpoch == epoch {
		t.Fatal("reorg epoch/catchup", cp, err)
	}
	t.Log(fmt.Sprintf("actual HTTP header client + PG: prefix137->140, ordinary lag139, rollback138->142; max143 calls/step"))
}
