package perfgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// q6Intent is one binding write. Variant (a) waits on done; variant (b)
// learns its result only through onCommit.
type q6Intent struct {
	hash, signer   []byte
	hashHex        string
	principal, org [16]byte
	nonce          uint64
	context        [16]byte
	envelopeHash   []byte
	raw            []byte
	enqueued       time.Time
	onCommit       func(q6Result)
}

type q6Result struct {
	ok, conflict bool
	generation   int32
	committed    time.Time
	err          error
}

type timed struct {
	at time.Time
	d  time.Duration
}

// q6Recorder collects timestamped samples under one lock, so every
// distribution can be cut to the steady window afterwards.
type q6Recorder struct {
	mu                       sync.Mutex
	commitWait, quota, batch []timed
	claims                   []timed
	batchSizes               []struct {
		at   time.Time
		size int
	}
	commits, accepted, inserted []time.Time
	background                  map[string][]time.Time
	lifecycle                   map[string]int64
	finalAt                     map[string]time.Time
	missingAtFinal              int64
}

func (r *q6Recorder) add(f func()) { r.mu.Lock(); f(); r.mu.Unlock() }

type q6Instance struct {
	id        int
	db        *sql.DB
	queue     chan *q6Intent
	acks      chan q6Ack
	boot      [16]byte
	inc       [16]byte
	rec       *q6Recorder
	cfg       *Q6Config
	failures  *atomic.Int64
	deadlocks *atomic.Int64
	inFlight  atomic.Int32
}

// retryable reports a deadlock or serialization failure (retried, counted).
func retryable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "40P01" || pgErr.Code == "40001")
}

type q6Ack struct {
	hash       []byte
	generation int32
}

func uuid16() [16]byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return b
}

func uuidString(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func uuidArray(values [][16]byte) []pgtype.UUID {
	out := make([]pgtype.UUID, len(values))
	for i, v := range values {
		out[i] = pgtype.UUID{Bytes: v, Valid: true}
	}
	return out
}

func sortHashes(hashes [][]byte) {
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i], hashes[j]) < 0 })
}

// commitLoop is the no-timer group committer (V1-3): it takes whatever has
// queued, up to MaxBatch, and writes it in one transaction.
func (q *q6Instance) commitLoop(ctx context.Context) {
	for {
		var first *q6Intent
		select {
		case <-ctx.Done():
			return
		case first = <-q.queue:
		}
		batch := []*q6Intent{first}
	fill:
		for len(batch) < q.cfg.MaxBatch {
			select {
			case next := <-q.queue:
				batch = append(batch, next)
			default:
				break fill
			}
		}
		q.inFlight.Add(1)
		q.commitBatch(ctx, batch)
		q.inFlight.Add(-1)
	}
}

func (q *q6Instance) commitBatch(ctx context.Context, batch []*q6Intent) {
	// In-batch duplicates (plan §4.10): the first intent for a hash is
	// written; a later same-principal duplicate shares its result, a later
	// different-principal one is a conflict.
	first := map[string]*q6Intent{}
	var order, dups []*q6Intent
	for _, in := range batch {
		if prior, seen := first[in.hashHex]; seen {
			if prior.principal != in.principal {
				// Judge it against the bound row, not this batch: next batch.
				go trySend(ctx, q.queue, in)
				continue
			}
			dups = append(dups, in)
			continue
		}
		first[in.hashHex] = in
		order = append(order, in)
	}
	// Lock rows in one global order (hash) across every multi-row writer.
	sort.Slice(order, func(i, j int) bool { return bytes.Compare(order[i].hash, order[j].hash) < 0 })
	n := len(order)
	hashes, signers, raws, envs := make([][]byte, n), make([][]byte, n), make([][]byte, n), make([][]byte, n)
	principals, orgs, contexts := make([][16]byte, n), make([][16]byte, n), make([][16]byte, n)
	nonces := make([]int64, n)
	for i, in := range order {
		hashes[i], signers[i], raws[i], envs[i] = in.hash, in.signer, in.raw, in.envelopeHash
		principals[i], orgs[i], contexts[i], nonces[i] = in.principal, in.org, in.context, int64(in.nonce)
	}
	started := time.Now()
	var generations map[string]int32
	var newRows int
	var quotaTime time.Duration
	attempt := func() error {
		generations, newRows = map[string]int32{}, 0
		tx, err := q.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT incarnation = $1 FROM tracking_meta`, pgtype.UUID{Bytes: q.inc, Valid: true}).Scan(&ok); err != nil || !ok {
			return errors.Join(err, errors.New("incarnation changed"))
		}
		// The principal/org/signer guard makes a different principal's
		// re-presentation return no row (a conflict). A same-principal
		// upsert never changes pending-ness here (a provisional row stays
		// provisional), so Δ = is_pending(after) − is_pending(before) is
		// exactly the number of newly inserted pending rows (xmax = 0).
		rows, err := tx.QueryContext(ctx, `INSERT INTO node_tx_binding (tx_hash, principal_id, org_id, signer, nonce, state, generation, context_id, envelope_hash, expires_at, min_version, incarnation, issued_contexts,
    claim_owner, claim_boot, claim_expires)
  SELECT t.tx_hash, t.principal_id, t.org_id, t.signer, t.nonce, 1, 1, t.context_id, t.envelope_hash, clock_timestamp() + interval '300 seconds', 7, $8, ARRAY[t.context_id], $9, $9, clock_timestamp() + interval '20 seconds'
  FROM unnest($1::bytea[], $2::uuid[], $3::uuid[], $4::bytea[], $5::bigint[], $6::uuid[], $7::bytea[]) WITH ORDINALITY AS t(tx_hash, principal_id, org_id, signer, nonce, context_id, envelope_hash, ord) ORDER BY t.ord
  ON CONFLICT (tx_hash) DO UPDATE SET generation = node_tx_binding.generation + 1, context_id = EXCLUDED.context_id, envelope_hash = EXCLUDED.envelope_hash,
    expires_at = EXCLUDED.expires_at, state = CASE WHEN node_tx_binding.state = 2 THEN 2 ELSE 1 END, issued_contexts = node_tx_binding.issued_contexts || EXCLUDED.context_id,
    claim_owner = EXCLUDED.claim_owner, claim_boot = EXCLUDED.claim_boot, claim_expires = EXCLUDED.claim_expires
  WHERE node_tx_binding.principal_id = EXCLUDED.principal_id AND node_tx_binding.org_id = EXCLUDED.org_id AND node_tx_binding.signer = EXCLUDED.signer
  RETURNING tx_hash, generation, state, (xmax = 0) AS inserted`,
			hashes, uuidArray(principals), uuidArray(orgs), signers, nonces, uuidArray(contexts), envs,
			pgtype.UUID{Bytes: q.inc, Valid: true}, pgtype.UUID{Bytes: q.boot, Valid: true})
		if err != nil {
			return err
		}
		delta := int64(0)
		var history [][]byte
		for rows.Next() {
			var hash []byte
			var generation int32
			var state int16
			var inserted bool
			if err := rows.Scan(&hash, &generation, &state, &inserted); err != nil {
				rows.Close()
				return err
			}
			generations["0x"+hex.EncodeToString(hash)] = generation
			if inserted {
				newRows++
				if state == statePending {
					delta++
				}
			} else {
				history = append(history, hash)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var payloadHashes, payloadRaw [][]byte
		for i, hash := range hashes {
			if _, ok := generations["0x"+hex.EncodeToString(hash)]; ok {
				payloadHashes, payloadRaw = append(payloadHashes, hash), append(payloadRaw, raws[i])
			}
		}
		if len(payloadHashes) > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_payload (tx_hash, raw_tx) SELECT * FROM unnest($1::bytea[], $2::bytea[]) ON CONFLICT (tx_hash) DO NOTHING`, payloadHashes, payloadRaw); err != nil {
				return err
			}
		}
		if len(history) > 0 { // generations ≥ 2 (§4.8.6)
			if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_identities (tx_hash, generation, context_id, envelope_hash, expires_at, min_version, reason, actor)
 SELECT b.tx_hash, b.generation, b.context_id, b.envelope_hash, b.expires_at, b.min_version, 0, 1 FROM node_tx_binding b WHERE b.tx_hash = ANY($1)`, history); err != nil {
				return err
			}
		}
		// The shared quota row is updated last, so its lock is held only to commit.
		quotaStart := time.Now()
		if delta != 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE pending_quota SET used = used + $1`, delta); err != nil {
				return err
			}
		}
		quotaTime = time.Since(quotaStart)
		return tx.Commit()
	}
	err := attempt()
	for tries := 0; err != nil && retryable(err) && tries < 3; tries++ {
		q.deadlocks.Add(1)
		err = attempt()
	}
	committed := time.Now()
	q.rec.add(func() {
		if err == nil {
			q.rec.batch = append(q.rec.batch, timed{committed, committed.Sub(started)})
			q.rec.batchSizes = append(q.rec.batchSizes, struct {
				at   time.Time
				size int
			}{committed, len(batch)})
			q.rec.quota = append(q.rec.quota, timed{committed, quotaTime})
			q.rec.commits = append(q.rec.commits, committed)
			for range generations {
				q.rec.accepted = append(q.rec.accepted, committed)
			}
			for i := 0; i < newRows; i++ {
				q.rec.inserted = append(q.rec.inserted, committed)
			}
		}
	})
	if err != nil {
		q.failures.Add(1)
	}
	deliver := func(in *q6Intent, res q6Result) {
		if in.onCommit != nil {
			in.onCommit(res)
		}
	}
	results := map[string]q6Result{}
	for _, in := range order {
		res := q6Result{committed: committed, err: err}
		if err == nil {
			res.generation, res.ok = generations[in.hashHex]
			res.conflict = !res.ok
		}
		results[in.hashHex] = res
		deliver(in, res)
	}
	for _, in := range dups { // same principal as the written intent: same result
		deliver(in, results[in.hashHex])
	}
}

// ackLoop records delivery acknowledgements in one UPDATE per tick (HOT: no
// indexed column changes), in hash order like every other multi-row writer.
func (q *q6Instance) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	pending := map[string]q6Ack{}
	tries := map[string]int{}
	for {
		select {
		case <-ctx.Done():
			return
		case ack := <-q.acks:
			pending[string(ack.hash)] = ack
			tries[string(ack.hash)] = 0
			continue
		case <-ticker.C:
		}
		if len(pending) == 0 {
			continue
		}
		keys := make([][]byte, 0, len(pending))
		for _, a := range pending {
			keys = append(keys, a.hash)
		}
		sortHashes(keys)
		gens := make([]int32, len(keys))
		for i, k := range keys {
			gens[i] = pending[string(k)].generation
		}
		// Best effort: rows another writer holds are skipped and retried next tick,
		// so the acknowledgement can never deadlock with a batch or the reconciler.
		rows, err := q.db.QueryContext(ctx, `WITH v AS (SELECT * FROM unnest($1::bytea[], $2::int[]) AS v(h, g)),
 target AS (SELECT b.tx_hash, v.g FROM node_tx_binding b JOIN v ON b.tx_hash = v.h WHERE b.generation = v.g AND b.incarnation = $4 ORDER BY b.tx_hash FOR UPDATE OF b SKIP LOCKED)
 UPDATE node_tx_binding b SET delivered_boot = $3, delivered_generation = target.g, claim_owner = NULL, claim_boot = NULL, claim_expires = NULL FROM target WHERE b.tx_hash = target.tx_hash
 RETURNING b.tx_hash`, keys, gens, pgtype.UUID{Bytes: q.boot, Valid: true}, pgtype.UUID{Bytes: q.inc, Valid: true})
		at := time.Now()
		if err != nil {
			q.failures.Add(1)
			continue // retried next tick
		}
		for rows.Next() {
			var h []byte
			if rows.Scan(&h) == nil {
				delete(pending, string(h))
				delete(tries, string(h))
			}
		}
		rows.Close()
		// Skipped (locked) rows are retried; rows gone or superseded are dropped.
		for h := range pending {
			if tries[h]++; tries[h] >= 5 {
				delete(pending, h)
				delete(tries, h)
			}
		}
		q.rec.add(func() { q.rec.background["ack"] = append(q.rec.background["ack"], at) })
	}
}

// send is a cancellation-safe channel send.
func trySend[T any](ctx context.Context, ch chan T, v T) bool {
	select {
	case ch <- v:
		return true
	case <-ctx.Done():
		return false
	}
}

// Run offers the workload over phases and returns the report. stamps reads
// the mock node's per-hash finalization instants after the run.
func (r *Q6Run) Run(ctx context.Context, phases Phases, stamps func() (map[string]Stamp, error)) (*Q6Report, error) {
	c, report, txs := r.c, r.report, r.txs
	rec := &q6Recorder{background: map[string][]time.Time{}, lifecycle: map[string]int64{}, finalAt: map[string]time.Time{}}
	var failures, deadlocks atomic.Int64
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	instances := make([]*q6Instance, c.Instances)
	for i := range instances {
		db, err := OpenDB(c.ExecDSN)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		db.SetMaxOpenConns(8)
		instances[i] = &q6Instance{id: i, db: db, queue: make(chan *q6Intent, c.QueueCap), acks: make(chan q6Ack, 1<<16), boot: uuid16(), inc: r.incarnation, rec: rec, cfg: &c, failures: &failures, deadlocks: &deadlocks}
		go instances[i].commitLoop(runCtx)
		go instances[i].ackLoop(runCtx)
	}
	client := NewLoadClient(1024)
	var delivered sync.Map // hash hex -> workload index, only for committed, node-accepted rows
	reconcileCtx, stopReconcile := context.WithCancel(ctx)
	reconcileDone := make(chan struct{})
	go func() {
		defer close(reconcileDone)
		q6Reconcile(reconcileCtx, r.execDB, client, c, txs, &delivered, rec, report)
	}()
	if c.AuditRate > 0 {
		go q6SyntheticAudit(runCtx, r.auditDB, c.AuditRate, rec)
	}
	// Window-edge snapshots of the tracking instance, taken on time; wait
	// events are sampled separately.
	var before, after ClusterSnapshot
	var snapErr error
	snapDone := make(chan struct{})
	go func() {
		defer close(snapDone)
		time.Sleep(time.Until(phases.WindowStart))
		_ = ResetStatements(ctx, c.ExecAdmin)
		before, snapErr = SnapshotCluster(ctx, c.ExecAdmin, c.ExecContainer)
		time.Sleep(time.Until(phases.WindowEnd))
		backlog := 0
		for _, inst := range instances {
			backlog += len(inst.queue)
		}
		report.QueueBacklogEnd = int64(backlog)
		var err error
		after, err = SnapshotCluster(ctx, c.ExecAdmin, c.ExecContainer)
		snapErr = errors.Join(snapErr, err)
	}()
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		time.Sleep(time.Until(phases.WindowStart))
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for time.Now().Before(phases.WindowEnd) {
			<-ticker.C
			if events, err := WaitEvents(ctx, c.ExecAdmin); err == nil {
				for k, v := range events {
					report.WaitEvents[k] += v
				}
			}
		}
	}()

	var queueRejections, refused, sentConflicts, afterConflicts, conflictRequests, conflictInserted atomic.Int64
	total := len(txs)
	records := make([]RequestRecord, total)
	interval := time.Second / time.Duration(c.Rate)
	var wg sync.WaitGroup
	newIntent := func(tx q6Tx, principal [16]byte) *q6Intent {
		context := uuid16()
		return &q6Intent{hash: tx.hash, hashHex: tx.hashHex, signer: tx.signer, principal: principal, org: tx.org, nonce: tx.nonce, context: context, envelopeHash: crypto.Keccak256(tx.hash, context[:]), raw: tx.raw, enqueued: time.Now()}
	}
	// enqueue hands an intent to the committer; onCommit fires after its
	// batch commits (both variants), and done is closed with the result.
	type outcome struct {
		res  q6Result
		done chan struct{}
	}
	enqueue := func(inst *q6Instance, in *q6Intent, after func(q6Result)) (*outcome, bool) {
		o := &outcome{done: make(chan struct{})}
		in.onCommit = func(res q6Result) {
			wait := res.committed.Sub(in.enqueued)
			rec.add(func() { rec.commitWait = append(rec.commitWait, timed{in.enqueued, wait}) })
			o.res = res
			if after != nil {
				after(res)
			}
			close(o.done)
		}
		if c.Variant == "a" {
			return o, trySend(runCtx, inst.queue, in)
		}
		select {
		case inst.queue <- in:
			return o, true
		default:
			queueRejections.Add(1)
			return o, false
		}
	}
	waitCommit := func(o *outcome) bool {
		select {
		case <-o.done:
			return true
		case <-runCtx.Done():
			return false
		}
	}
	// submit is one bound submission: the row is acknowledged and handed to
	// the reconciler only once both its commit and the node's accept are in.
	submit := func(inst *q6Instance, i int, tx q6Tx) (int, *outcome) {
		var gate atomic.Int32
		gate.Store(2)
		var generation atomic.Int32
		ready := func() {
			if gate.Add(-1) == 0 {
				trySend(runCtx, inst.acks, q6Ack{tx.hash, generation.Load()})
				delivered.Store(tx.hashHex, i)
			}
		}
		in := newIntent(tx, tx.principal)
		o, ok := enqueue(inst, in, func(res q6Result) {
			if res.ok {
				generation.Store(res.generation)
				ready()
			}
		})
		if !ok {
			return 503, o
		}
		if c.Variant == "a" {
			if !waitCommit(o) || o.res.err != nil {
				return 503, o
			}
			if o.res.conflict {
				return 409, o
			}
		}
		result, err := nodeCall(runCtx, client, c.NodeURL, c.NodeToken, "ops_submitTransaction", json.RawMessage(q6Identity(c.DeploymentID, tx, tx.principal, in.context)), tx.rawHex)
		if err != nil {
			return 503, o
		}
		var sub struct {
			TransactionHash string `json:"transaction_hash"`
		}
		_ = json.Unmarshal(result, &sub)
		if sub.TransactionHash != tx.hashHex {
			return 502, o
		}
		ready()
		return 200, o
	}
	for i := 0; i < total && runCtx.Err() == nil; i++ {
		scheduled := phases.Start.Add(time.Duration(i) * interval)
		if d := time.Until(scheduled); d > 0 {
			time.Sleep(d)
		}
		records[i].Scheduled = scheduled
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := &records[i]
			rr.Sent = time.Now()
			plan, tx := r.plan[i], txs[i]
			inst := instances[i%len(instances)]
			if plan.claim && r.mainDB != nil {
				start := time.Now()
				if err := q6Claim(runCtx, r.mainDB, c.DeploymentID, tx.hash); err != nil {
					failures.Add(1)
				}
				d := time.Since(start)
				rec.add(func() { rec.claims = append(rec.claims, timed{start, d}) })
			}
			status, first := submit(inst, i, tx)
			rr.Done, rr.HTTPStatus, rr.OK = time.Now(), status, status == 200
			if status != 200 {
				return
			}
			if plan.retry && waitCommit(first) && first.res.ok {
				// A same-raw resend by the same principal after the first is
				// bound: generation 2, a history row, a node call and its ack.
				_, _ = submit(inst, i, tx)
			}
			if plan.conflictWith >= 0 {
				// An extra request: another principal sharing the signer
				// re-presents a ~150 ms older transaction's bytes (§9.5 Q6).
				conflictRequests.Add(1)
				other := txs[plan.conflictWith]
				principal := uuid16()
				bad := newIntent(other, principal)
				o, ok := enqueue(inst, bad, func(res q6Result) {
					switch {
					case res.ok:
						conflictInserted.Add(1) // the bound row was already gone: an anomaly
					case res.conflict && c.Variant == "b":
						afterConflicts.Add(1)
					}
				})
				if !ok {
					return
				}
				if c.Variant == "a" {
					if waitCommit(o) && o.res.conflict {
						refused.Add(1)
					}
					return
				}
				if _, err := nodeCall(runCtx, client, c.NodeURL, c.NodeToken, "ops_submitTransaction", json.RawMessage(q6Identity(c.DeploymentID, other, principal, bad.context)), other.rawHex); err == nil {
					sentConflicts.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	<-snapDone
	<-waitDone
	// Variant b: queued rows are not durable until written; measure the drain
	// until every queue is empty and no batch is committing.
	drainStart := time.Now()
	for time.Since(drainStart) < c.Drain {
		backlog := 0
		for _, inst := range instances {
			backlog += len(inst.queue) + int(inst.inFlight.Load())
		}
		if backlog == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	report.QueueDrainSec = time.Since(drainStart).Seconds()
	// Let finalization catch up: finality lag + a margin, bounded by Drain.
	deadline := time.Now().Add(min(c.FinalityLag+10*time.Second, c.Drain))
	for time.Now().Before(deadline) {
		var bound int64
		if r.execDB.QueryRowContext(ctx, `SELECT count(*) FROM node_tx_binding`).Scan(&bound) == nil && bound == 0 {
			break
		}
		time.Sleep(time.Second)
	}
	stopReconcile()
	<-reconcileDone
	cancel()

	report.Window = Account(records, phases)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	between := func(t, from, to time.Time) bool { return !t.Before(from) && t.Before(to) }
	inWindow := func(ts []time.Time) int64 {
		n := int64(0)
		for _, t := range ts {
			if between(t, phases.WindowStart, phases.WindowEnd) {
				n++
			}
		}
		return n
	}
	windowed := func(samples []timed) []time.Duration {
		var out []time.Duration
		for _, s := range samples {
			if between(s.at, phases.WindowStart, phases.WindowEnd) {
				out = append(out, s.d)
			}
		}
		return out
	}
	seconds := phases.WindowEnd.Sub(phases.WindowStart).Seconds()
	report.CommittedInWindow = inWindow(rec.accepted)
	report.CommittedPerSec = float64(report.CommittedInWindow) / seconds
	report.InsertedInWindow = inWindow(rec.inserted)
	report.CommitsInWindow = inWindow(rec.commits)
	report.CommitsPerSec = float64(report.CommitsInWindow) / seconds
	sum, count := 0, 0
	for _, b := range rec.batchSizes {
		if !between(b.at, phases.WindowStart, phases.WindowEnd) {
			continue
		}
		sum, count = sum+b.size, count+1
		bucket := "1"
		switch {
		case b.size >= 256:
			bucket = "256+"
		case b.size >= 64:
			bucket = "64-255"
		case b.size >= 16:
			bucket = "16-63"
		case b.size >= 4:
			bucket = "4-15"
		case b.size >= 2:
			bucket = "2-3"
		}
		report.BatchSizes[bucket]++
	}
	if count > 0 {
		report.BatchSizeMean = float64(sum) / float64(count)
	}
	report.CommitWaitMS = percentilesF(windowed(rec.commitWait))
	report.QuotaUpdateMS = percentilesF(windowed(rec.quota))
	report.BatchTxnMS = percentilesF(windowed(rec.batch))
	report.ClaimMS = percentilesF(windowed(rec.claims))
	for name, ts := range rec.background {
		report.Background[name] = inWindow(ts)
	}
	report.Lifecycle = rec.lifecycle
	report.MissingAtFinal = rec.missingAtFinal
	if stamps != nil {
		if st, err := stamps(); err == nil {
			var lags []time.Duration
			for hash, at := range rec.finalAt {
				if s, ok := st[hash]; ok && s.Finalized != 0 {
					finalized := time.Unix(0, s.Finalized)
					if between(finalized, phases.WindowStart, phases.WindowEnd) {
						lags = append(lags, at.Sub(finalized))
					}
				}
			}
			report.FinalizeLagMS = percentilesF(lags)
		} else {
			report.Errors = append(report.Errors, "stamps: "+err.Error())
		}
	}
	report.QueueRejections = queueRejections.Load()
	report.ConflictRequests = conflictRequests.Load()
	report.ConflictsRefused = refused.Load()
	report.ConflictsSent = sentConflicts.Load()
	report.ConflictsAfterTx = afterConflicts.Load()
	report.ConflictInserted = conflictInserted.Load()
	report.Deadlocks = deadlocks.Load()
	report.WriteFailures = failures.Load()
	_ = r.execDB.QueryRowContext(ctx, `SELECT count(*) FROM node_tx_binding`).Scan(&report.BindingRowsAtEnd)
	if c.NodeStats != nil {
		if st, err := c.NodeStats(); err == nil {
			report.StalledTxs = st.StalledTxs
		}
	}
	if snapErr != nil {
		report.Errors = append(report.Errors, "snapshot: "+snapErr.Error())
	} else {
		// Per-transaction figures over exactly the snapshot span.
		newRows := int64(0)
		for _, t := range rec.inserted {
			if between(t, before.At, after.At) {
				newRows++
			}
		}
		q6Finish(ctx, report, r.execDB, before, after, newRows)
	}
	return report, nil
}

type q6StatusRow struct {
	TransactionHash string `json:"transaction_hash"`
	Execution       struct {
		Status               string  `json:"status"`
		BlockNumber          *uint64 `json:"block_number"`
		Finalized            bool    `json:"finalized"`
		FinalizedBlockNumber *uint64 `json:"finalized_block_number"`
	} `json:"execution"`
}

type q6Tracked struct {
	index int
	block uint64
}

// q6Reconcile is the option-A prototype: every second, poll delivered rows
// that are not yet included in batches of MaxStatusBatch, write provisional
// rows once, and finalize in one transaction per page (delete binding and
// payload, insert the status row, quota Δ last). Provisional rows are polled
// again only once the finalized head passes their block (§4.5), plus one
// lowest-block row per tick to learn the head; scheduling lives in memory
// and only changed state is written.
func q6Reconcile(ctx context.Context, db *sql.DB, client *http.Client, c Q6Config, txs []q6Tx, delivered *sync.Map, rec *q6Recorder, report *Q6Report) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	pending := map[string]*q6Tracked{}
	provisional := map[string]*q6Tracked{}
	var finalizedHead uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		delivered.Range(func(k, v any) bool {
			pending[k.(string)] = &q6Tracked{index: v.(int)}
			delivered.Delete(k)
			return true
		})
		var poll []string
		for hash := range pending {
			poll = append(poll, hash)
		}
		lowest, lowestBlock := "", uint64(0)
		probed := false
		for hash, t := range provisional {
			if t.block <= finalizedHead {
				poll = append(poll, hash)
				probed = true
			} else if lowest == "" || t.block < lowestBlock {
				lowest, lowestBlock = hash, t.block
			}
		}
		if !probed && lowest != "" {
			poll = append(poll, lowest)
		}
		var toProvisional, toFinal []string
		finalSeen := map[string]bool{}
		calls := 0
		for start := 0; start < len(poll); start += MaxStatusBatch {
			chunk := poll[start:min(start+MaxStatusBatch, len(poll))]
			raw, err := nodeCall(ctx, client, c.NodeURL, c.NodeToken, "ops_transactionStatuses", chunk)
			calls++
			if err != nil {
				continue
			}
			var rows []*q6StatusRow
			if json.Unmarshal(raw, &rows) != nil {
				continue
			}
			for i, row := range rows {
				if row == nil {
					continue
				}
				if row.Execution.FinalizedBlockNumber != nil && *row.Execution.FinalizedBlockNumber > finalizedHead {
					finalizedHead = *row.Execution.FinalizedBlockNumber
				}
				if row.Execution.Status != "included" || row.Execution.BlockNumber == nil {
					continue
				}
				hash := chunk[i]
				t := pending[hash]
				if t == nil {
					t = provisional[hash]
				}
				if t == nil {
					continue
				}
				t.block = *row.Execution.BlockNumber
				if row.Execution.Finalized {
					if finalSeen[hash] {
						continue // a re-delivered retry can appear in both maps
					}
					finalSeen[hash] = true
					toFinal = append(toFinal, hash)
				} else if _, already := provisional[hash]; !already {
					toProvisional = append(toProvisional, hash)
				}
			}
		}
		now := time.Now()
		rec.add(func() {
			for i := 0; i < calls; i++ {
				rec.background["status_call"] = append(rec.background["status_call"], now)
			}
		})
		if len(toProvisional) > 0 {
			hashes := make([][]byte, len(toProvisional))
			for i, h := range toProvisional {
				hashes[i] = txs[pending[h].index].hash
			}
			sortHashes(hashes)
			var moved []string
			err := q6Txn(ctx, db, func(tx *sql.Tx) error {
				moved = moved[:0]
				// Lock first, in hash order, then update: no plan can reorder the locks.
				rows, err := tx.QueryContext(ctx, `WITH target AS (SELECT tx_hash FROM node_tx_binding WHERE tx_hash = ANY($1) AND state = 1 ORDER BY tx_hash FOR UPDATE)
 UPDATE node_tx_binding b SET state = 2 FROM target WHERE b.tx_hash = target.tx_hash RETURNING b.tx_hash`, hashes)
				if err != nil {
					return err
				}
				for rows.Next() {
					var h []byte
					if err := rows.Scan(&h); err != nil {
						rows.Close()
						return err
					}
					moved = append(moved, "0x"+hex.EncodeToString(h))
				}
				rows.Close()
				if len(moved) > 0 {
					_, err = tx.ExecContext(ctx, `UPDATE pending_quota SET used = used - $1`, len(moved))
				}
				return err
			})
			if err == nil {
				for _, h := range moved {
					provisional[h] = pending[h]
					delete(pending, h)
				}
				at := time.Now()
				rec.add(func() {
					rec.background["provisional"] = append(rec.background["provisional"], at)
					rec.lifecycle["pending_to_provisional"] += int64(len(moved))
				})
			}
		}
		for start := 0; start < len(toFinal); start += 1000 {
			chunk := toFinal[start:min(start+1000, len(toFinal))]
			type row struct {
				hash   []byte
				number int64
			}
			rows := make([]row, 0, len(chunk))
			for _, h := range chunk {
				t := pending[h]
				if t == nil {
					t = provisional[h]
				}
				rows = append(rows, row{txs[t.index].hash, int64(t.block)})
			}
			sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].hash, rows[j].hash) < 0 })
			hashes, numbers := make([][]byte, len(rows)), make([]int64, len(rows))
			for i, r := range rows {
				hashes[i], numbers[i] = r.hash, r.number
			}
			var fromPending, fromProvisional int64
			err := q6Txn(ctx, db, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `SELECT 1 FROM node_tx_binding WHERE tx_hash = ANY($1) ORDER BY tx_hash FOR UPDATE`, hashes); err != nil {
					return err
				}
				if err := tx.QueryRowContext(ctx, `WITH gone AS (DELETE FROM node_tx_binding WHERE tx_hash = ANY($1) RETURNING tx_hash, principal_id, org_id, state),
 ins AS (INSERT INTO node_tx_status (tx_hash, principal_id, org_id, state, reason, final_at, block_number)
   SELECT g.tx_hash, g.principal_id, g.org_id, 10, 0, clock_timestamp(), v.n FROM gone g JOIN unnest($1::bytea[], $2::bigint[]) AS v(h, n) ON v.h = g.tx_hash)
 SELECT count(*) FILTER (WHERE state = 1), count(*) FILTER (WHERE state = 2) FROM gone`, hashes, numbers).Scan(&fromPending, &fromProvisional); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM node_tx_payload WHERE tx_hash = ANY($1)`, hashes); err != nil {
					return err
				}
				// pending -> final releases one slot per row (Δ = −1); provisional -> final is 0.
				if fromPending > 0 {
					_, err := tx.ExecContext(ctx, `UPDATE pending_quota SET used = used - $1`, fromPending)
					return err
				}
				return nil
			})
			if err != nil {
				continue
			}
			at := time.Now()
			rec.add(func() {
				rec.background["finality"] = append(rec.background["finality"], at)
				rec.lifecycle["pending_to_final"] += fromPending
				rec.lifecycle["provisional_to_final"] += fromProvisional
				rec.missingAtFinal += int64(len(chunk)) - fromPending - fromProvisional
				for _, h := range chunk {
					rec.finalAt[h] = at
				}
			})
			for _, h := range chunk {
				delete(pending, h)
				delete(provisional, h)
			}
		}
		report.ReconcileBacklog = append(report.ReconcileBacklog, Sample{At: time.Now(), Value: float64(len(pending) + len(provisional))})
	}
}

// q6Finish fills the database-side numbers after the run; newRows are the
// transactions first inserted inside the snapshot span.
func q6Finish(ctx context.Context, report *Q6Report, db *sql.DB, before, after ClusterSnapshot, newRows int64) {
	report.Cluster = Delta(before, after)
	if rows := float64(newRows); rows > 0 {
		report.PerTx["tracking_instance_wal_bytes_per_tx"] = float64(report.Cluster.WALBytes) / rows
		report.PerTx["tracking_instance_db_cpu_ms_per_1k_tx"] = report.Cluster.CPUSeconds * 1e6 / rows
		report.PerTx["tracking_instance_write_xacts_per_tx"] = float64(report.Cluster.WriteTransactions) / rows
		report.PerTx["tracking_instance_wal_syncs_per_tx"] = float64(report.Cluster.WAL.Syncs) / rows
		report.PerTx["new_rows_in_snapshot_span"] = rows
		if len(report.Config.Layout) >= 12 && report.Config.Layout[:12] == "same_cluster" {
			// The instance also carries the server's main and audit load.
			for _, key := range []string{"tracking_instance_wal_bytes_per_tx", "tracking_instance_db_cpu_ms_per_1k_tx", "tracking_instance_write_xacts_per_tx", "tracking_instance_wal_syncs_per_tx"} {
				report.PerTx["cluster_wide_incl_server_"+key[len("tracking_instance_"):]] = report.PerTx[key]
				delete(report.PerTx, key)
			}
		}
	}
	report.Tables, _ = LargestTables(ctx, db, "tracking", 10)
	for name, query := range map[string]string{
		"node_tx_binding": `SELECT avg(pg_column_size(b.*)) FROM node_tx_binding b`,
		"node_tx_payload": `SELECT avg(pg_column_size(p.*)) FROM node_tx_payload p`,
		"node_tx_status":  `SELECT avg(pg_column_size(s.*)) FROM node_tx_status s`,
	} {
		var v sql.NullFloat64
		if db.QueryRowContext(ctx, query).Scan(&v) == nil && v.Valid {
			report.RowBytes[name] = v.Float64
		}
	}
	var statusBytes, statusRows int64
	if db.QueryRowContext(ctx, `SELECT coalesce(sum(pg_total_relation_size(inhrelid)), 0), (SELECT count(*) FROM node_tx_status) FROM pg_inherits WHERE inhparent = 'node_tx_status'::regclass`).Scan(&statusBytes, &statusRows) == nil && statusRows > 0 {
		report.RowBytes["node_tx_status_total_incl_index_per_row"] = float64(statusBytes) / float64(statusRows)
	}
	var used, pending int64
	if db.QueryRowContext(ctx, `SELECT (SELECT used FROM pending_quota), (SELECT count(*) FROM node_tx_binding WHERE state = 1)`).Scan(&used, &pending) == nil {
		report.QuotaConsistent = used == pending
		report.PerTx["quota_used_at_end"] = float64(used)
		report.PerTx["pending_rows_at_end"] = float64(pending)
	}
}
