package admissionsql_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/creationobserver"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/rpcexecution"
)

func observedObject(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("fixture JSON")
	}
	return out
}

type observedNode struct {
	mu                     sync.Mutex
	genesis, header        *types.Header
	tx                     *types.Transaction
	signer, creator, child common.Address
	children               []common.Address
	code                   string
	traceCount             int
	index                  uint32
}

func (n *observedNode) serve(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var q struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		http.Error(w, "JSON", 400)
		return
	}
	object := func(v any) map[string]any {
		b, _ := json.Marshal(v)
		out := map[string]any{}
		_ = json.Unmarshal(b, &out)
		return out
	}
	header := object(n.header)
	var result any
	switch q.Method {
	case "eth_chainId":
		result = "0x1"
	case "eth_syncing":
		result = false
	case "eth_getHeaderByNumber", "eth_getHeaderByHash":
		result = header
		if len(q.Params) > 0 && string(q.Params[0]) == `"0x0"` {
			result = object(n.genesis)
		}
	case "eth_getTransactionByHash":
		v := object(n.tx)
		v["from"] = n.signer.Hex()
		v["blockHash"] = n.header.Hash().Hex()
		v["blockNumber"] = "0x1"
		v["transactionIndex"] = "0x" + strconv.FormatUint(uint64(n.index), 16)
		result = v
	case "eth_getTransactionReceipt":
		result = map[string]any{"transactionHash": n.tx.Hash().Hex(), "from": n.signer.Hex(), "to": n.creator.Hex(), "blockHash": n.header.Hash().Hex(), "blockNumber": "0x1", "transactionIndex": "0x0", "status": "0x1", "contractAddress": nil, "type": "0x2", "gasUsed": "0x20", "cumulativeGasUsed": "0x20", "effectiveGasPrice": "0x1", "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
		result.(map[string]any)["transactionIndex"] = "0x" + strconv.FormatUint(uint64(n.index), 16)
		result.(map[string]any)["cumulativeGasUsed"] = "0x" + strconv.FormatUint(32*(uint64(n.index)+1), 16)
	case "eth_getBlockByHash", "eth_getBlockByNumber":
		header["transactions"] = []any{n.tx.Hash().Hex()}
		if n.index == 1 {
			header["transactions"] = []any{common.Hash{99}.Hex(), n.tx.Hash().Hex()}
		}
		header["uncles"] = []any{}
		header["withdrawals"] = []any{}
		result = header
	case "debug_traceTransaction":
		n.traceCount++
		children := n.children
		if children == nil {
			children = []common.Address{n.child}
		}
		calls := make([]any, 0, len(children))
		for _, child := range children {
			calls = append(calls, map[string]any{"type": "CREATE", "from": n.creator.Hex(), "to": child.Hex(), "input": "0x6001", "output": n.code, "value": "0x0", "gas": "0x1000", "gasUsed": "0x10"})
		}
		result = map[string]any{"callTracer": map[string]any{"type": "CALL", "from": n.signer.Hex(), "to": n.creator.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x10000", "gasUsed": "0x20", "output": "0x", "calls": calls}, "prestateTracer": map[string]any{}}
	case "eth_getCode":
		result = n.code
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "fixture method unavailable"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
}
func newObservedWork(t *testing.T, d *observerDatabase, configure ...func(*observedNode)) (*observedNode, a.Scope, a.CreationIntent, f.ObserverSnapshot, *rpcexecution.IncludedClient) {
	t.Helper()
	binding, scope := creationScope(t, d.db)
	key, _ := crypto.HexToECDSA(strings.Repeat("11", 32))
	creator := common.HexToAddress("0x1111111111111111111111111111111111111111")
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(1)), &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 7, To: &creator, Gas: 500000, GasFeeCap: big.NewInt(3), GasTipCap: big.NewInt(1), Value: big.NewInt(0), Data: []byte{0x60, 1}})
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), Time: 1700000000, GasLimit: 30000000, BaseFee: big.NewInt(1)}
	header := &types.Header{Number: big.NewInt(1), ParentHash: genesis.Hash(), Difficulty: big.NewInt(0), Time: genesis.Time + 1, GasLimit: 30000000, BaseFee: big.NewInt(1)}
	node := &observedNode{genesis: genesis, header: header, tx: tx, signer: crypto.PubkeyToAddress(key.PublicKey), creator: creator, child: common.HexToAddress("0x2222222222222222222222222222222222222222"), code: "0x6000"}
	for _, apply := range configure {
		apply(node)
	}
	server := httptest.NewServer(http.HandlerFunc(node.serve))
	t.Cleanup(server.Close)
	binding.GenesisHash = genesis.Hash().Hex()
	scope.Network, _ = binding.Key()
	scope.Hash = tx.Hash()
	if err := admissionsql.BootstrapEmpty(t.Context(), d.db.ownerDSN, binding, scope.State.Generation); err != nil {
		t.Fatal(err)
	}
	network := f.Network{Key: f.Digest(scope.Network), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: genesis.Hash(), Deployment: binding.DeploymentID}
	source := f.Source{Network: network, URL: server.URL, Profile: rpcexecution.IncludedProfileID, PragueStart: 1, PragueEnd: 1 << 63}
	ingress := source
	ingress.Organization = scope.Organization
	ingress.Profile = rpcexecution.LifecycleSignedProfileID
	set, _ := f.SourceSet([]f.Source{ingress})
	metadata := creationcapture.Metadata{Network: network, State: f.State{Generation: scope.State.Generation, Coverage: f.Digest(scope.State.Coverage)}, SourceSet: set, Reference: source.Digest()}
	floor := f.Header{Number: 0, Hash: genesis.Hash(), Parent: genesis.ParentHash, Timestamp: genesis.Time}
	if err := admissionsql.BootstrapCreationObserver(t.Context(), d.db.ownerDSN, binding, scope.State, metadata, floor); err != nil {
		t.Fatal(err)
	}
	snap := activeObserver(t, d, metadata, floor)
	i := capturedIntent(t, scope)
	i.Anchor.Hash = floor.Hash
	i.Anchor.Number = 0
	i.Anchor.Timestamp = floor.Timestamp
	if err := commitCovered(t.Context(), d.app, scope, i, coverageRecord(metadata, snap, floor)); err != nil {
		t.Fatal("covered source", err)
	}
	snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: floor, Headers: []f.Header{{Number: 1, Hash: header.Hash(), Parent: header.ParentHash, Timestamp: header.Time}}, Tip: f.Header{Number: 1, Hash: header.Hash(), Parent: header.ParentHash, Timestamp: header.Time}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := rpcexecution.NewIncludedClient(http.DefaultTransport, source, rpcexecution.Credential{}, rpcexecution.DefaultIncludedLimits())
	if err != nil {
		t.Fatal(err)
	}
	return node, scope, i, snap, client
}
func acquireObserved(t *testing.T, d *observerDatabase, snap f.ObserverSnapshot, client *rpcexecution.IncludedClient) (*creationobserver.WorkSnapshot, *creationobserver.QualifiedObservation) {
	t.Helper()
	work, found, err := d.observer.LoadNextCreationWork(t.Context(), client.Source().Network, snap)
	if err != nil || !found {
		t.Fatal("load work", found, err)
	}
	proof, err := client.AcquireIncluded(t.Context(), work.Hash())
	if err != nil {
		t.Fatal("included proof", err)
	}
	qualified, err := creationobserver.QualifyIncluded(work, proof)
	if err != nil {
		t.Fatal("unique match", err)
	}
	return work, qualified
}
func observedCounts(t *testing.T, d *observerDatabase, scope a.Scope) (int64, int64) {
	t.Helper()
	var births, associations int64
	if d.db.owner.QueryRow(t.Context(), `SELECT birth_count,association_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1`, scope.Network[:]).Scan(&births, &associations) != nil {
		t.Fatal("counts")
	}
	return births, associations
}

func TestCreationObserverActualPostgresIncludedPublication(t *testing.T) {
	d := setupObserver(t)
	t.Run("first immutable publication and exact duplicate", func(t *testing.T) {
		_, scope, _, snap, client := newObservedWork(t, d)
		work, q := acquireObserved(t, d, snap, client)
		if len(q.Data().Births) != 1 || len(q.Data().Associations) != 1 {
			t.Fatal("missing qualified factory", q.Data())
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("publish", err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("duplicate", err)
		}
		if births, as := observedCounts(t, d, scope); births != 1 || as != 1 {
			t.Fatal("duplicate changed counters", births, as)
		}
		if next, found, err := d.observer.LoadNextCreationWork(t.Context(), client.Source().Network, snap); err != nil || found || next != nil {
			t.Fatal("terminal generation remains due", found, err)
		}
		if work.Generation() != 1 {
			t.Fatal("wrong generation")
		}
	})
	t.Run("publication crosses bounded128 row batches atomically", func(t *testing.T) {
		node, scope, i, snap, client := newObservedWork(t, d)
		children := make([]common.Address, 129)
		for j := range children {
			children[j] = common.BigToAddress(big.NewInt(int64(1000 + j)))
		}
		node.mu.Lock()
		node.children = children
		node.mu.Unlock()
		original, _ := i.CapturedPlanData()
		for start := 0; start < len(children); start += 128 {
			p := original
			p.Entries = []nativeadmission.CreationEntry{}
			p.FactoryRoots = []nativeadmission.CreationFactoryRoot{}
			for j := start; j < min(start+128, len(children)); j++ {
				e := original.Entries[0]
				e.Address = children[j]
				e.Record = j + 1
				e.FactoryRoot = j - start
				p.Entries = append(p.Entries, e)
				p.FactoryRoots = append(p.FactoryRoots, nativeadmission.CreationFactoryRoot{Entry: j - start, Declaration: 0})
			}
			i.Plan, _ = json.Marshal(p)
			i.PlanDigest = a.Digest(nativeadmission.CapturedCreationPlanDigest(i.Plan))
			m := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
			if err := commitCovered(t.Context(), d.app, scope, i, coverageRecord(m, snap, snap.State.Floor)); err != nil {
				t.Fatal("bounded source", err)
			}
		}
		_, q := acquireObserved(t, d, snap, client)
		if len(q.Data().Births) != 129 || len(q.Data().Associations) != 129 {
			t.Fatal("bulk match incomplete")
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("batched publish", err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("batched duplicate", err)
		}
		if b, as := observedCounts(t, d, scope); b != 129 || as != 129 {
			t.Fatal("partial or duplicate bulk counters", b, as)
		}
	})
	t.Run("stale lease and canceled publication have no effects", func(t *testing.T) {
		_, scope, _, snap, client := newObservedWork(t, d)
		_, q := acquireObserved(t, d, snap, client)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if d.observer.PublishCreationObservation(ctx, q) == nil {
			t.Fatal("canceled publication succeeded")
		}
		if err := d.observer.QuarantineObserver(t.Context(), snap, "coverage-gap"); err != nil {
			t.Fatal(err)
		}
		if d.observer.PublishCreationObservation(t.Context(), q) == nil {
			t.Fatal("quarantined lease published")
		}
		if b, as := observedCounts(t, d, scope); b != 0 || as != 0 {
			t.Fatal("partial effects", b, as)
		}
	})
	t.Run("same-inclusion immutable contradiction quarantines without overwrite", func(t *testing.T) {
		_, scope, _, snap, client := newObservedWork(t, d)
		_, q := acquireObserved(t, d, snap, client)
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_births SET output_length=3 WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); !errors.Is(err, a.ErrConflict) {
			t.Fatal("contradictory immutable metadata accepted", err)
		}
		var length int
		var quarantine string
		if d.db.owner.QueryRow(t.Context(), `SELECT b.output_length,o.quarantine FROM ops_admission_v2.creation_births b JOIN ops_admission_v2.creation_observer_state o USING(network_key)WHERE b.network_key=$1`, scope.Network[:]).Scan(&length, &quarantine) != nil || length != 3 || quarantine != "coverage-gap" {
			t.Fatal("conflict overwritten or not quarantined", length, quarantine)
		}
		if b, as := observedCounts(t, d, scope); b != 1 || as != 1 {
			t.Fatal("conflict added facts", b, as)
		}
	})
	t.Run("atomic lower association cap", func(t *testing.T) {
		_, scope, i, snap, client := newObservedWork(t, d)
		// Append a second captured source with the same planned tuple but a
		// distinct immutable provenance; both associations exceed lower cap1.
		p, _ := i.CapturedPlanData()
		p.Manifest = a.HashParts("second-approved-source").String()
		i.Plan, _ = json.Marshal(p)
		i.PlanDigest = a.Digest(nativeadmission.CapturedCreationPlanDigest(i.Plan))
		m := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
		if err := commitCovered(t.Context(), d.app, scope, i, coverageRecord(m, snap, snap.State.Floor)); err != nil {
			t.Fatal(err)
		}
		_, q := acquireObserved(t, d, snap, client)
		limits := f.DefaultLimits()
		limits.Associations = 1
		limited, err := admissionsql.OpenObserver(t.Context(), d.observerDSN, limits)
		if err != nil {
			t.Fatal(err)
		}
		defer limited.Close()
		if err := limited.PublishCreationObservation(t.Context(), q); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("cap accepted partial publication", err)
		}
		if b, as := observedCounts(t, d, scope); b != 0 || as != 0 {
			t.Fatal("partial capped effects", b, as)
		}
	})
	t.Run("same signed transaction re-inclusion preserves orphan and qualifies only canonical birth", func(t *testing.T) {
		node, scope, _, snap, client := newObservedWork(t, d)
		_, q := acquireObserved(t, d, snap, client)
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		oldHash := q.Data().Inclusion.Hash
		node.mu.Lock()
		node.header.Extra = []byte{1}
		node.code = "0x6001"
		newTip := f.Header{Number: 1, Hash: node.header.Hash(), Parent: node.header.ParentHash, Timestamp: node.header.Time}
		node.mu.Unlock()
		var err error
		snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: snap.State.Floor, Tip: newTip})
		if err != nil {
			t.Fatal("rollback", err)
		}
		snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: snap.State.Floor, Headers: []f.Header{newTip}, Tip: newTip})
		if err != nil {
			t.Fatal("new branch", err)
		}
		if d.observer.PublishCreationObservation(t.Context(), q) == nil {
			t.Fatal("stale old proof accepted")
		}
		current, err := d.observer.ReadObserver(t.Context(), snap.Lease)
		if err != nil || current.State.Quarantine != "none" {
			t.Fatal("normal CAS movement quarantined source", err)
		}
		_, q2 := acquireObserved(t, d, snap, client)
		if q2.Data().Inclusion.Hash == oldHash || q2.Data().Births[0].OutputHash == q.Data().Births[0].OutputHash {
			t.Fatal("fixture did not change actual inclusion/output")
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q2); err != nil {
			t.Fatal("re-included signed hash conflicts", err)
		}
		if b, as := observedCounts(t, d, scope); b != 2 || as != 2 {
			t.Fatal("orphan overwritten or not retained in caps", b, as)
		}
		var canonical, retained int
		if d.db.owner.QueryRow(t.Context(), `SELECT count(*),count(*)FILTER(WHERE h.hash IS NOT NULL)FROM ops_admission_v2.creation_births b LEFT JOIN ops_admission_v2.creation_headers h ON h.network_key=b.network_key AND h.number=b.inclusion_number AND h.hash=b.inclusion_hash WHERE b.network_key=$1`, scope.Network[:]).Scan(&retained, &canonical) != nil || retained != 2 || canonical != 1 {
			t.Fatal("orphan supplied current authority", retained, canonical)
		}
		// A fork AFTER the inclusion changes the prefix epoch but not this
		// execution. Acknowledge it without another node trace.
		later := f.Header{Number: 2, Hash: common.HexToHash("0xaaaa"), Parent: newTip.Hash, Timestamp: newTip.Timestamp + 1}
		snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: newTip, Headers: []f.Header{later}, Tip: later})
		if err != nil {
			t.Fatal(err)
		}
		fork := later
		fork.Hash = common.HexToHash("0xbbbb")
		snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: newTip, Tip: fork})
		if err != nil {
			t.Fatal(err)
		}
		snap, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: newTip, Headers: []f.Header{fork}, Tip: fork})
		if err != nil {
			t.Fatal(err)
		}
		work, found, err := d.observer.LoadNextCreationWork(t.Context(), client.Source().Network, snap)
		if err != nil || !found {
			t.Fatal("stale reorg job not scheduled", err)
		}
		node.mu.Lock()
		traces := node.traceCount
		node.mu.Unlock()
		if ack, err := d.observer.AcknowledgeUnchangedInclusion(t.Context(), work); err != nil || !ack {
			t.Fatal("unchanged inclusion not acknowledged", ack, err)
		}
		node.mu.Lock()
		if node.traceCount != traces {
			t.Error("epoch acknowledgement retraced node")
		}
		node.mu.Unlock()
	})
	t.Run("late append remains due and appends independent wallet authority", func(t *testing.T) {
		_, scope, i, snap, client := newObservedWork(t, d)
		work, q := acquireObserved(t, d, snap, client)
		witness := creationWitness(i, "captured-user-proved-wallet")
		i.Wallet = &a.CreationWalletAuthority{Actor: scope.Actor, Organization: scope.Organization, Witness: witness.ID}
		m := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
		coverage := coverageRecord(m, snap, snap.State.Floor)
		_, err := d.app.WithCoveredRawTransaction(t.Context(), scope, a.CaptureCommitBinding{ObserverEpoch: coverage.ObserverEpoch, CaptureEpoch: coverage.CaptureEpoch, SourceSet: coverage.SourceSet}, func(raw a.RawTx) (a.CommitKind, error) {
			if _, err := raw.PutOrigin(a.Origin{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: scope.Organization, FirstAdmittedAt: i.CapturedAt, Primary: witness}); err != nil {
				return 0, err
			}
			_, err := raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(i, coverage)
			return a.CommitAllow, err
		})
		if err != nil {
			t.Fatal("late committed original capture", err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("new generation incorrectly invalidated captured subset", err)
		}
		next, found, err := d.observer.LoadNextCreationWork(t.Context(), client.Source().Network, snap)
		if err != nil || !found || next.Generation() <= work.Generation() {
			t.Fatal("late ref not due", found, err)
		}
		proof, err := client.AcquireIncluded(t.Context(), scope.Hash)
		if err != nil {
			t.Fatal(err)
		}
		q2, err := creationobserver.QualifyIncluded(next, proof)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q2); err != nil {
			t.Fatal(err)
		}
		if b, as := observedCounts(t, d, scope); b != 1 || as != 2 {
			t.Fatal("late wallet replaced factory or duplicated birth", b, as)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("old exact duplicate", err)
		}
		if err := d.observer.RecordCreationRetry(t.Context(), work, "uncovered"); err != nil {
			t.Fatal("old retry", err)
		}
		var processed int64
		if d.db.owner.QueryRow(t.Context(), `SELECT processed_generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, scope.Network[:], scope.Hash[:]).Scan(&processed) != nil || processed != next.Generation() {
			t.Fatal("old duplicate regressed newer processed generation", processed)
		}
	})
	t.Run("epoch revoked during node proof is filtered without minting or repairing coverage", func(t *testing.T) {
		_, scope, _, snap, client := newObservedWork(t, d)
		_, q := acquireObserved(t, d, snap, client)
		// Owner insertion models the immutable deny cohort becoming visible
		// before publication; the real exclusive-fence transition is separately
		// exercised by the checkpoint1 actual two-pool tests.
		seed := q.Work().Seeds()[0]
		if _, err := d.db.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.revoked_creation_capture_epochs(network_key,capture_epoch,witness_tx_hash,witness_seed_digest,reason,revoked_at)VALUES($1,$2::uuid,$3,$4,'freshness-unproven',clock_timestamp())`, scope.Network[:], snap.Lease.CaptureEpoch, scope.Hash[:], seed[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_capacity SET revoked_epoch_count=1 WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal("revoked ref should be individually filtered", err)
		}
		if b, as := observedCounts(t, d, scope); b != 0 || as != 0 {
			t.Fatal("revoked original capture supplied authority", b, as)
		}
	})
	t.Run("revoked cohort does not suppress another truthful capture epoch", func(t *testing.T) {
		_, scope, i, snap, client := newObservedWork(t, d)
		oldEpoch := snap.Lease.CaptureEpoch
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET lease_expires=clock_timestamp()-interval'1 second' WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		var err error
		snap, err = d.observer.AcquireObserverLease(t.Context(), snap.Lease.Network, snap.Lease.State, uuid.NewString(), snap.Lease.SourceSet, snap.Lease.Reference)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := i.CapturedPlanData()
		p.Manifest = a.HashParts("another-truthful-covered-epoch").String()
		i.Plan, _ = json.Marshal(p)
		i.PlanDigest = a.Digest(nativeadmission.CapturedCreationPlanDigest(i.Plan))
		m := creationcapture.Metadata{Network: client.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference}
		if err := commitCovered(t.Context(), d.app, scope, i, coverageRecord(m, snap, snap.State.Floor)); err != nil {
			t.Fatal(err)
		}
		_, q := acquireObserved(t, d, snap, client)
		if len(q.Data().Associations) != 2 {
			t.Fatal("fixture lacks independently covered references")
		}
		if _, err := d.db.owner.Exec(t.Context(), `INSERT INTO ops_admission_v2.revoked_creation_capture_epochs(network_key,capture_epoch,witness_tx_hash,witness_seed_digest,reason,revoked_at)SELECT network_key,capture_epoch,tx_hash,seed_digest,'freshness-unproven',clock_timestamp()FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND capture_epoch=$2::uuid`, scope.Network[:], oldEpoch); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_capacity SET revoked_epoch_count=1 WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		if b, as := observedCounts(t, d, scope); b != 1 || as != 1 {
			t.Fatal("unrevoked association suppressed or revoked one retained", b, as)
		}
	})
	t.Run("actual coordinator advances headers then acquires and publishes once", func(t *testing.T) {
		node, scope, _, snap, client := newObservedWork(t, d)
		headers, err := rpcexecution.NewHeaderClient(http.DefaultTransport, client.Source(), rpcexecution.Credential{}, rpcexecution.DefaultHeaderLimits())
		if err != nil {
			t.Fatal(err)
		}
		observer, err := creationobserver.New(creationobserver.Options{Network: client.Source().Network, State: snap.Lease.State, Owner: snap.Lease.Owner, SourceSet: snap.Lease.SourceSet, Reference: client.Source(), CaughtUpAssertion: f.CaughtUpAssertion, HeaderClient: headers, IncludedClient: client, Store: d.observer})
		if err != nil {
			t.Fatal(err)
		}
		if err := observer.Step(t.Context()); err != nil {
			t.Fatal("complete step", err)
		}
		if err := observer.Step(t.Context()); err != nil {
			t.Fatal("idle pulse", err)
		}
		if b, as := observedCounts(t, d, scope); b != 1 || as != 1 {
			t.Fatal("coordinator did not publish", b, as)
		}
		node.mu.Lock()
		if node.traceCount != 1 {
			t.Error("idle coordinator re-acquired terminal proof", node.traceCount)
		}
		node.mu.Unlock()
	})
	t.Run("restore validates retained tuple qualification and leaves serving unready", func(t *testing.T) {
		_, scope, _, snap, client := newObservedWork(t, d)
		_, q := acquireObserved(t, d, snap, client)
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		n := client.Source().Network
		binding := a.NetworkBinding{Environment: n.Environment, ChainID: n.ChainID, GenesisHash: n.Genesis.Hex(), DeploymentID: n.Deployment}
		expected := scope.State
		expected.Generation = uuid.NewString()
		if err := admissionsql.BeginRecovery(t.Context(), d.db.ownerDSN, binding, expected.Generation); err != nil {
			t.Fatal(err)
		}
		tampered := a.HashParts("tampered")
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_authority_associations SET qualification_digest=$2 WHERE network_key=$1`, scope.Network[:], tampered[:]); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, expected, true); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("restore accepted changed qualification", err)
		}
		qualification := q.Data().Associations[0].Qualification
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_authority_associations SET qualification_digest=$2 WHERE network_key=$1`, scope.Network[:], qualification[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_births SET inclusion_number=0 WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, expected, true); !errors.Is(err, a.ErrCoverage) {
			t.Fatal("restore accepted A>=C", err)
		}
		if _, err := d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_births SET inclusion_number=1 WHERE network_key=$1`, scope.Network[:]); err != nil {
			t.Fatal(err)
		}
		if err := admissionsql.FinalizeRecovery(t.Context(), d.db.ownerDSN, binding, expected, true); err != nil {
			t.Fatal("truthful observed rows failed present-row recovery", err)
		}
		var ready, capture bool
		var quarantine string
		if d.db.owner.QueryRow(t.Context(), `SELECT ready,capture_ready,quarantine FROM ops_admission_v2.creation_observer_state WHERE network_key=$1`, scope.Network[:]).Scan(&ready, &capture, &quarantine) != nil || ready || capture || quarantine != "awaiting-canonical" {
			t.Fatal("restore invented live readiness", ready, capture, quarantine)
		}
	})
}
