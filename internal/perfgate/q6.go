package perfgate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/jackc/pgx/v5/pgtype"
)

// Q6 measurement prototype (plan RD-1410 §4.10, §4.11, §6.1, §9.5): the request
// path's tracking-DB write on the rev 11 compact schema, either waited for
// before transport (variant a, the design) or written in the background
// (variant b, a diagnostic that permits shared-signer rebinding). It is a
// measurement prototype, not the P3 implementation: no signing, no RBAC, no
// audit append; the node is the gate-2 mock.

// Binding states (node_tx_binding.state).
const (
	statePending     = 1
	stateProvisional = 2
)

// Q6Schema is the rev 11 compact tracking schema used by the prototype.
const Q6Schema = `
CREATE TABLE IF NOT EXISTS tracking_meta (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
  chain_id BIGINT NOT NULL, deployment_id TEXT NOT NULL, incarnation UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS node_tx_binding (
  tx_hash BYTEA PRIMARY KEY, principal_id UUID NOT NULL, org_id UUID NOT NULL, signer BYTEA NOT NULL, nonce BIGINT NOT NULL,
  state SMALLINT NOT NULL, reason SMALLINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  generation INT NOT NULL, context_id UUID NOT NULL, envelope_hash BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL, min_version BIGINT NOT NULL,
  delivered_boot UUID, delivered_generation INT, claim_owner UUID, claim_boot UUID, claim_expires TIMESTAMPTZ,
  incarnation UUID NOT NULL, issued_contexts UUID[] NOT NULL, visible_to TEXT[] NOT NULL DEFAULT '{}'
) WITH (fillfactor = 80);
CREATE TABLE IF NOT EXISTS node_tx_payload (tx_hash BYTEA PRIMARY KEY, raw_tx BYTEA NOT NULL);
CREATE TABLE IF NOT EXISTS node_tx_status (
  tx_hash BYTEA NOT NULL, principal_id UUID NOT NULL, org_id UUID NOT NULL, state SMALLINT NOT NULL, reason SMALLINT NOT NULL,
  final_at TIMESTAMPTZ NOT NULL, block_number BIGINT) PARTITION BY RANGE (final_at);
CREATE INDEX IF NOT EXISTS node_tx_status_tx_hash ON node_tx_status (tx_hash);
CREATE TABLE IF NOT EXISTS node_tx_identities (
  tx_hash BYTEA NOT NULL, generation INT NOT NULL, context_id UUID NOT NULL, envelope_hash BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  min_version BIGINT NOT NULL, reason SMALLINT NOT NULL, actor SMALLINT NOT NULL, travel_rule_record UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), seq BIGSERIAL) PARTITION BY RANGE (created_at);
CREATE TABLE IF NOT EXISTS pending_quota (singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton), used BIGINT NOT NULL);
INSERT INTO pending_quota (used) VALUES (0) ON CONFLICT DO NOTHING;
`

// q6MainSchema is the main-DB side of the prototype: the unique compliance
// claim lookup (§4.8.5) plus a toy pool of travel-rule records to claim.
const q6MainSchema = `
CREATE TABLE IF NOT EXISTS q6_travel_records (id UUID PRIMARY KEY, used_tx_hash BYTEA);
CREATE INDEX IF NOT EXISTS q6_travel_records_unused ON q6_travel_records (id) WHERE used_tx_hash IS NULL;
CREATE TABLE IF NOT EXISTS node_tx_compliance_claims (chain_id BIGINT NOT NULL, deployment_id TEXT NOT NULL, tx_hash BYTEA NOT NULL,
  travel_rule_record_id UUID NOT NULL UNIQUE, claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (chain_id, deployment_id, tx_hash));
`

const q6AuditSchema = `CREATE TABLE IF NOT EXISTS q6_audit_synthetic (id BIGSERIAL PRIMARY KEY, buffer_seq BIGINT NOT NULL, external_id TEXT NOT NULL, method TEXT NOT NULL,
  status_code INT NOT NULL, org_id UUID, request_params JSONB, entry_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp());`

// Q6Config is one prototype case.
type Q6Config struct {
	Variant       string                     `json:"variant"` // a | b
	Instances     int                        `json:"instances"`
	Rate          int                        `json:"rate"`
	Warmup        time.Duration              `json:"warmup"`
	Window        time.Duration              `json:"window"`
	Drain         time.Duration              `json:"drain"`
	FinalityLag   time.Duration              `json:"finality_lag"`
	MaxBatch      int                        `json:"max_batch"`
	QueueCap      int                        `json:"queue_cap_b"`
	ClaimFraction float64                    `json:"claim_fraction"`
	RetryFraction float64                    `json:"retry_fraction"`
	ConflictFrac  float64                    `json:"conflict_fraction"`
	AuditRate     int                        `json:"synthetic_audit_records_per_second"`
	Senders       int                        `json:"senders"`
	ExecDSN       string                     `json:"-"`
	MainDSN       string                     `json:"-"`
	AuditDSN      string                     `json:"-"`
	NodeURL       string                     `json:"-"`
	NodeToken     string                     `json:"-"`
	DeploymentID  string                     `json:"deployment_id"`
	Index         func([]Tx, []string) error `json:"-"`
	NodeStats     func() (MockStats, error)  `json:"-"`
	ExecAdmin     *sql.DB                    `json:"-"`
	ExecContainer *Container                 `json:"-"`
	Layout        string                     `json:"layout"`
}

// Q6Report is the prototype's result.
type Q6Report struct {
	Config            Q6Config           `json:"config"`
	Window            WindowReport       `json:"request_window"`
	CommittedInWindow int64              `json:"rows_committed_in_window"`
	CommittedPerSec   float64            `json:"rows_committed_per_second"`
	CommitsInWindow   int64              `json:"intent_commits_in_window"`
	CommitsPerSec     float64            `json:"intent_commits_per_second"`
	BatchSizes        map[string]int64   `json:"intent_batch_size_histogram"`
	BatchSizeMean     float64            `json:"intent_batch_size_mean"`
	CommitWaitMS      MillisF            `json:"commit_wait_ms"`
	QuotaUpdateMS     MillisF            `json:"quota_update_ms"`
	BatchTxnMS        MillisF            `json:"batch_transaction_ms"`
	ClaimMS           MillisF            `json:"compliance_claim_ms"`
	Background        map[string]int64   `json:"background_commits_in_window"`
	Lifecycle         map[string]int64   `json:"lifecycle_transitions"`
	FinalizeLagMS     MillisF            `json:"node_final_to_tracking_final_ms"`
	ReconcileBacklog  []Sample           `json:"reconcile_backlog"`
	QueueBacklogEnd   int64              `json:"b_queue_backlog_at_window_end"`
	QueueDrainSec     float64            `json:"b_queue_drain_seconds"`
	QueueRejections   int64              `json:"b_queue_full_rejections"`
	ConflictRequests  int64              `json:"conflict_requests_injected"`
	ConflictsRefused  int64              `json:"conflicts_refused_before_transport"`
	ConflictsSent     int64              `json:"conflicts_sent_to_node_before_write"`
	ConflictsAfterTx  int64              `json:"conflicts_detected_after_transport"`
	InsertedInWindow  int64              `json:"new_rows_inserted_in_window"`
	ConflictInserted  int64              `json:"anomaly_conflicting_intent_inserted"`
	Deadlocks         int64              `json:"deadlock_or_serialization_retries"`
	BindingRowsAtEnd  int64              `json:"binding_rows_left_at_end"`
	StalledTxs        int                `json:"node_stalled_txs_at_end"`
	MissingAtFinal    int64              `json:"finality_rows_missing"`
	WriteFailures     int64              `json:"write_failures"`
	Cluster           ClusterDelta       `json:"tracking_instance_window"`
	PerTx             map[string]float64 `json:"per_tx"`
	Tables            []TableStats       `json:"tables_at_end"`
	RowBytes          map[string]float64 `json:"avg_row_bytes"`
	QuotaConsistent   bool               `json:"quota_equals_pending_rows_at_end"`
	WaitEvents        map[string]int     `json:"wait_event_samples_window"`
	Errors            []string           `json:"errors,omitempty"`
}

// MillisF is a latency distribution in fractional milliseconds.
type MillisF struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50"`
	P99   float64 `json:"p99"`
	Max   float64 `json:"max"`
}

func percentilesF(values []time.Duration) MillisF {
	if len(values) == 0 {
		return MillisF{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	at := func(q float64) float64 {
		i := int(float64(len(values))*q+0.5) - 1
		i = max(0, min(i, len(values)-1))
		return float64(values[i].Microseconds()) / 1e3
	}
	return MillisF{Count: len(values), P50: at(.5), P99: at(.99), Max: float64(values[len(values)-1].Microseconds()) / 1e3}
}

// q6Tx is one pre-built prototype transaction.
type q6Tx struct {
	hash, signer, raw []byte
	rawHex, hashHex   string
	nonce             uint64
	principal, org    [16]byte
	sender            int
}

func buildQ6Workload(senders int, total int, seed string) ([]q6Tx, []Tx, []string, error) {
	keys, err := NewSenders("q6-"+seed, senders, 1)
	if err != nil {
		return nil, nil, nil, err
	}
	principals := make([][16]byte, senders)
	for i := range principals {
		principals[i] = uuid16()
	}
	org := uuid16()
	chain := big.NewInt(31337)
	signer := types.LatestSignerForChainID(chain)
	to := common.HexToAddress("0x00000000000000000000000000000000000f2a7f")
	out := make([]q6Tx, total)
	index := make([]Tx, total)
	addresses := make([]string, senders)
	for i, k := range keys {
		addresses[i] = k.Address
	}
	var wg sync.WaitGroup
	workers := 8
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < total; i += workers {
				s := i % senders
				nonce := uint64(i / senders)
				tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: chain, Nonce: nonce, GasTipCap: big.NewInt(1_000_000), GasFeeCap: big.NewInt(3_000_000_000), Gas: 21_000, To: &to, Value: big.NewInt(1)}), signer, keys[s].Key)
				if err != nil {
					errs <- err
					return
				}
				raw, _ := tx.MarshalBinary()
				hash := tx.Hash()
				out[i] = q6Tx{hash: hash.Bytes(), signer: common.HexToAddress(keys[s].Address).Bytes(), raw: raw, rawHex: "0x" + hex.EncodeToString(raw), hashHex: strings.ToLower(hash.Hex()), nonce: nonce, principal: principals[s], org: org, sender: s}
				index[i] = Tx{Hash: strings.ToLower(hash.Hex()), Sender: s, Nonce: nonce}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, nil, nil, err
	}
	return out, index, addresses, nil
}

func q6Identity(deployment string, tx q6Tx, principal, context [16]byte) []byte {
	payload, _ := json.Marshal(map[string]any{"network": map[string]any{"chain_id": 31337, "deployment_id": deployment}, "issued_at": time.Now().Unix(), "expires_at": time.Now().Add(5 * time.Minute).Unix(),
		"scope": "transaction", "context_id": uuidString(context), "principal_id": uuidString(principal), "org_id": uuidString(tx.org), "signer": "0x" + hex.EncodeToString(tx.signer), "binding_hash": tx.hashHex, "min_snapshot_version": 7})
	envelope, _ := json.Marshal(map[string]any{"version": 1, "kind": "identity", "key_id": "q6", "payload": payload, "signature": make([]byte, 64)})
	return envelope
}

func nodeCall(ctx context.Context, client *http.Client, url, token, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "q6", "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var reply struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, err
	}
	if reply.Error != nil {
		return nil, reply.Error
	}
	return reply.Result, nil
}

// Q6Run is a prepared prototype case: schema, workload and node index ready.
type Q6Run struct {
	c           Q6Config
	report      *Q6Report
	execDB      *sql.DB
	mainDB      *sql.DB
	auditDB     *sql.DB
	txs         []q6Tx
	byHash      map[string]int
	plan        []q6Plan
	incarnation [16]byte
}

type q6Plan struct {
	conflictWith int // -1, or the earlier transaction re-presented by another principal
	retry, claim bool
}

// PrepareQ6 creates the schema, signs the workload and registers it with the
// mock node. Nothing here is timed.
func PrepareQ6(ctx context.Context, c Q6Config) (*Q6Run, error) {
	r := &Q6Run{c: c, report: &Q6Report{Config: c, Background: map[string]int64{}, Lifecycle: map[string]int64{}, PerTx: map[string]float64{}, RowBytes: map[string]float64{}, BatchSizes: map[string]int64{}, WaitEvents: map[string]int{}}}
	var err error
	if r.execDB, err = OpenDB(c.ExecDSN); err != nil {
		return nil, err
	}
	r.execDB.SetMaxOpenConns(16)
	if _, err := r.execDB.ExecContext(ctx, Q6Schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	for d := -1; d <= 2; d++ {
		from, to := day.AddDate(0, 0, d), day.AddDate(0, 0, d+1)
		for _, table := range []string{"node_tx_status", "node_tx_identities"} {
			stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s_%s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`, table, from.Format("20060102"), table, from.Format(time.RFC3339), to.Format(time.RFC3339))
			if _, err := r.execDB.ExecContext(ctx, stmt); err != nil {
				return nil, err
			}
		}
	}
	r.incarnation = uuid16()
	if _, err := r.execDB.ExecContext(ctx, `INSERT INTO tracking_meta (chain_id, deployment_id, incarnation) VALUES (31337, $1, $2) ON CONFLICT (singleton) DO UPDATE SET incarnation = EXCLUDED.incarnation`, c.DeploymentID, pgtype.UUID{Bytes: r.incarnation, Valid: true}); err != nil {
		return nil, err
	}
	if c.ClaimFraction > 0 {
		if r.mainDB, err = OpenDB(c.MainDSN); err != nil {
			return nil, err
		}
		r.mainDB.SetMaxOpenConns(16)
		if _, err := r.mainDB.ExecContext(ctx, q6MainSchema); err != nil {
			return nil, err
		}
		need := int(float64(c.Rate)*(c.Warmup+c.Window).Seconds()*c.ClaimFraction*1.3) + 100
		if _, err := r.mainDB.ExecContext(ctx, `INSERT INTO q6_travel_records (id) SELECT gen_random_uuid() FROM generate_series(1, $1)`, need); err != nil {
			return nil, err
		}
	}
	if c.AuditRate > 0 {
		if r.auditDB, err = OpenDB(c.AuditDSN); err != nil {
			return nil, err
		}
		if _, err := r.auditDB.ExecContext(ctx, q6AuditSchema); err != nil {
			return nil, err
		}
	}
	total := int(float64(c.Rate) * (c.Warmup + c.Window).Seconds())
	txs, index, addresses, err := buildQ6Workload(c.Senders, total, c.DeploymentID)
	if err != nil {
		return nil, err
	}
	if err := c.Index(index, addresses); err != nil {
		return nil, err
	}
	r.txs = txs
	r.byHash = make(map[string]int, len(txs))
	for i, tx := range txs {
		r.byHash[tx.hashHex] = i
	}
	rng := mrand.New(mrand.NewPCG(1, 2))
	r.plan = make([]q6Plan, total)
	for i := range r.plan {
		r.plan[i].conflictWith = -1
		p := rng.Float64()
		if i > c.Senders*4 {
			switch {
			case p < c.ConflictFrac:
				// ~150 ms earlier: still bound (not yet final) at any finality lag ≥ 1 s.
				r.plan[i].conflictWith = i - max(1, c.Rate*15/100)
			case p < c.ConflictFrac+c.RetryFraction:
				r.plan[i].retry = true
			}
		}
		r.plan[i].claim = rng.Float64() < c.ClaimFraction
	}
	return r, nil
}

// Close releases the run's connections.
func (r *Q6Run) Close() {
	for _, db := range []*sql.DB{r.execDB, r.mainDB, r.auditDB} {
		if db != nil {
			db.Close()
		}
	}
}

// q6Claim is the one-per-transaction compliance claim (§4.8.5) in the main DB.
func q6Claim(ctx context.Context, db *sql.DB, deployment string, hash []byte) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing pgtype.UUID
	err = tx.QueryRowContext(ctx, `SELECT travel_rule_record_id FROM node_tx_compliance_claims WHERE chain_id = 31337 AND deployment_id = $1 AND tx_hash = $2`, deployment, hash).Scan(&existing)
	if err == nil {
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var id pgtype.UUID
	if err := tx.QueryRowContext(ctx, `UPDATE q6_travel_records SET used_tx_hash = $1 WHERE id = (SELECT id FROM q6_travel_records WHERE used_tx_hash IS NULL LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id`, hash).Scan(&id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_compliance_claims (chain_id, deployment_id, tx_hash, travel_rule_record_id) VALUES (31337, $1, $2, $3) ON CONFLICT DO NOTHING`, deployment, hash, id); err != nil {
		return err
	}
	return tx.Commit()
}

// q6SyntheticAudit stands in for the rev 11 audit sealer's target load
// (≥ 10,500 records/s, §6.1): one multi-row INSERT per 100 ms tick.
func q6SyntheticAudit(ctx context.Context, db *sql.DB, rate int, rec *q6Recorder) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	perTick := rate / 10
	seq := int64(0)
	params := []byte(`{"tx_hash":"0x00","context_id":"00000000-0000-4000-8000-000000000000","generation":1,"actor":"system:identity-renewal"}`)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_, err := db.ExecContext(ctx, `INSERT INTO q6_audit_synthetic (buffer_seq, external_id, method, status_code, org_id, request_params, entry_hash)
 SELECT $1 + g, 'did:test:q6', CASE WHEN g % 2 = 0 THEN 'eth_sendRawTransaction' ELSE 'ops.system.finalized' END, 200, gen_random_uuid(), $2::jsonb, md5(g::text) FROM generate_series(1, $3) AS g`, seq, params, perTick)
		seq += int64(perTick)
		at := time.Now()
		if err == nil {
			rec.add(func() { rec.background["synthetic_audit"] = append(rec.background["synthetic_audit"], at) })
		}
	}
}

// q6Txn runs f in a transaction, retrying deadlock and serialization failures.
func q6Txn(ctx context.Context, db *sql.DB, f func(*sql.Tx) error) error {
	run := func() error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := f(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	err := run()
	for tries := 0; err != nil && retryable(err) && tries < 3; tries++ {
		err = run()
	}
	return err
}
