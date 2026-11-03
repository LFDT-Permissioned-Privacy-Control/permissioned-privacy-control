package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/rbac"
)

var reconcileNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "reconcile-test"}

// statusNode answers ops_transactionStatus from a table.
type statusNode struct {
	mu       sync.Mutex
	statuses map[string]nodepolicy.TransactionStatus
	err      error
	polls    int
}

func (n *statusNode) set(s nodepolicy.TransactionStatus) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.statuses[s.TransactionHash] = s
}

func (n *statusNode) TransactionStatus(_ context.Context, hash string) (nodepolicy.TransactionStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.polls++
	if n.err != nil {
		return nodepolicy.TransactionStatus{}, n.err
	}
	s, ok := n.statuses[hash]
	if !ok {
		return nodepolicy.TransactionStatus{}, nodepolicy.ErrNodeRejected
	}
	return s, nil
}

// recordingAudit is the durable audit buffer, failing on demand.
type recordingAudit struct {
	mu     sync.Mutex
	events []db.AccessLogRecord
	fail   bool
}

func (a *recordingAudit) AppendBatch(data [][]byte) ([]uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return nil, errors.New("injected audit failure")
	}
	for _, d := range data {
		var rec db.AccessLogRecord
		if err := json.Unmarshal(d, &rec); err != nil {
			return nil, err
		}
		a.events = append(a.events, rec)
	}
	return make([]uint64, len(data)), nil
}

func (a *recordingAudit) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

// plainEffects is a main database for transactions without side effects.
type plainEffects struct{ applied int }

func (p *plainEffects) ApplyNodeTxEffects(context.Context, nodepolicy.Network, db.NodeTxEffects) (db.NodeTxEffectsResult, error) {
	p.applied++
	return db.NodeTxEffectsResult{}, nil
}
func (p *plainEffects) ExternalIDsByUserID(_ context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range ids {
		out[id] = "did:test:" + id
	}
	return out, nil
}

type reconcileFixture struct {
	tracking *testTracking
	writer   *nodeTracking
	counting *countingTracking
	node     *statusNode
	audit    *recordingAudit
	r        *nodeReconciler
	main     nodeEffectsStore
}

func newReconcileFixture(t *testing.T, main nodeEffectsStore) *reconcileFixture {
	t.Helper()
	tracking := newTestTracking(t, reconcileNetwork)
	counting := &countingTracking{trackingStore: tracking.runtime}
	writer := newNodeTracking(counting, tracking.meta.Incarnation, tracking.adopter(reconcileNetwork))
	if main == nil {
		main = &plainEffects{}
	}
	f := &reconcileFixture{tracking: tracking, writer: writer, counting: counting, node: &statusNode{statuses: map[string]nodepolicy.TransactionStatus{}}, audit: &recordingAudit{}, main: main}
	f.r = newNodeReconciler(writer, main, f.node, f.audit, reconcileNetwork)
	return f
}

type trackedTx struct {
	hash           []byte
	hex            string
	principal, org uuid.UUID
	context        uuid.UUID
	visibleTo      []string
	visibleSender  string
}

func (f *reconcileFixture) admit(t *testing.T, principal, org uuid.UUID, visibleTo ...string) trackedTx {
	t.Helper()
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	tx := trackedTx{hash: hash, hex: "0x" + hex.EncodeToString(hash), principal: principal, org: org, context: uuid.New(), visibleTo: visibleTo}
	a := db.TrackAdmission{Hash: hash, PrincipalID: principal, OrgID: org, Signer: hash[:20], Nonce: 1, ContextID: tx.context, EnvelopeHash: hash, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: hash}
	if len(visibleTo) > 0 {
		tx.visibleSender = "did:test:sender-" + principal.String()
		a.VisibleTo, a.VisibleSender = visibleTo, tx.visibleSender
	}
	results, err := f.tracking.runtime.AdmitBatch(context.Background(), f.writer.incarnation(), db.TrackLimits{}, []db.TrackAdmission{a})
	if err != nil || results[0].Outcome != db.AdmitInserted {
		t.Fatalf("admit: %+v %v", results, err)
	}
	return tx
}

func (tx trackedTx) status(state string, block uint64, finalizedHead uint64) nodepolicy.TransactionStatus {
	s := nodepolicy.TransactionStatus{TransactionHash: tx.hex, PrincipalID: tx.principal.String(), OrgID: tx.org.String(), ContextID: tx.context.String(), Execution: nodepolicy.ExecutionOutcome{Status: state, FactsVersion: 7, Created: []nodepolicy.CreatedContract{}}}
	head := "0x" + strings.Repeat("ee", 32)
	if state == "included" || state == "reverted" {
		blockHash := "0x" + strings.Repeat("bb", 32)
		s.Execution.BlockHash, s.Execution.BlockNumber = &blockHash, &block
		if finalizedHead >= block {
			s.Execution.Finalized = true
			head = blockHash
		}
	}
	if finalizedHead > 0 {
		s.Execution.FinalizedBlockNumber, s.Execution.FinalizedBlockHash = &finalizedHead, &head
		if s.Execution.Finalized && finalizedHead > block {
			other := "0x" + strings.Repeat("ff", 32)
			s.Execution.FinalizedBlockHash = &other
		}
	}
	return s
}

func (f *reconcileFixture) tick(t *testing.T) error {
	t.Helper()
	return f.r.tick(context.Background())
}

func (f *reconcileFixture) state(t *testing.T, tx trackedTx) db.TrackedTransaction {
	t.Helper()
	row, err := f.tracking.runtime.LookupTracked(context.Background(), tx.hash)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return row
}

func (f *reconcileFixture) quota(t *testing.T) int64 {
	t.Helper()
	used, pending, err := f.tracking.runtime.PendingQuota(context.Background())
	if err != nil || used != pending {
		t.Fatalf("quota %d, pending rows %d: %v", used, pending, err)
	}
	return used
}

func TestNodeReconcilerNeverFinalizesUnavailableOrMismatchedStatus(t *testing.T) {
	f := newReconcileFixture(t, nil)
	for _, test := range []string{"pending", "denied", "expired", "node_failure", "wrong_principal"} {
		tx := f.admit(t, uuid.New(), uuid.New())
		status := tx.status(test, 0, 0)
		switch test {
		case "node_failure":
			continue // no answer for this hash: the node rejects the call
		case "wrong_principal":
			status = tx.status("included", 3, 3)
			status.PrincipalID = uuid.NewString()
		}
		f.node.set(status)
	}
	if err := f.tick(t); err == nil {
		t.Fatal("unverifiable outcomes must surface as reconciliation errors")
	}
	if f.counting.transitions.Load()+f.counting.finals.Load() != 0 || f.audit.count() != 0 {
		t.Fatal("an unavailable or mismatched status was recorded")
	}
	if f.quota(t) != 5 {
		t.Fatal("pending work changed")
	}
}

// The reconciler half of G62: a provisional row is written once and then
// polled only as the finalized head reaches its block; unchanged polls write
// nothing; finality is recorded in one batch.
func TestProvisionalPollingIsFinalityDrivenInTheReconciler(t *testing.T) {
	f := newReconcileFixture(t, nil)
	var txs []trackedTx
	for i := 0; i < 5; i++ {
		tx := f.admit(t, uuid.New(), uuid.New())
		f.node.set(tx.status("included", 10, 9))
		txs = append(txs, tx)
	}
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	for _, tx := range txs {
		if s := f.state(t, tx).State; s != db.TrackProvisional {
			t.Fatalf("state %d, want provisional", s)
		}
	}
	if f.quota(t) != 0 {
		t.Fatal("provisional rows carry no quota")
	}
	written := f.counting.transitions.Load()
	f.node.mu.Lock()
	f.node.polls = 0
	f.node.mu.Unlock()
	for i := 0; i < 3; i++ {
		f.r.now = func() time.Time { return time.Now().Add(time.Duration(i+1) * time.Hour) }
		if err := f.tick(t); err != nil {
			t.Fatal(err)
		}
	}
	if f.counting.transitions.Load() != written || f.counting.finals.Load() != 0 {
		t.Fatal("unchanged polls wrote")
	}
	if f.node.polls > 3 {
		t.Fatalf("%d polls while the finalized head is below the block: only the lowest probe is due", f.node.polls)
	}
	for _, tx := range txs {
		f.node.set(tx.status("included", 10, 10))
	}
	f.r.now = func() time.Time { return time.Now().Add(5 * time.Hour) }
	for i := 0; i < 2; i++ { // the probe learns the head, the next tick polls the rest
		if err := f.tick(t); err != nil {
			t.Fatal(err)
		}
		f.r.now = func() time.Time { return time.Now().Add(6 * time.Hour) }
	}
	for _, tx := range txs {
		if s := f.state(t, tx).State; s != db.TrackIncluded {
			t.Fatalf("state %d, want included", s)
		}
	}
	if f.audit.count() != len(txs) {
		t.Fatalf("%d finality events for %d transactions", f.audit.count(), len(txs))
	}
}

func TestOrphanedProvisionalRowReturnsToPending(t *testing.T) {
	f := newReconcileFixture(t, nil)
	tx := f.admit(t, uuid.New(), uuid.New())
	f.node.set(tx.status("included", 4, 3))
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	f.node.set(tx.status("pending", 0, 4)) // reorged out, finalized head passed
	f.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	row := f.state(t, tx)
	if row.State != db.TrackPending || f.quota(t) != 1 {
		t.Fatalf("orphaned provisional row: state %d", row.State)
	}
}

// TestSystemDecisionsAuditedBeforeCommit is G61: the finality transition is
// appended to the durable audit buffer first; an append failure or a missing
// buffer takes no decision, and a crash between append and commit only
// over-reports.
func TestSystemDecisionsAuditedBeforeCommit(t *testing.T) {
	f := newReconcileFixture(t, nil)
	tx := f.admit(t, uuid.New(), uuid.New())
	f.node.set(tx.status("included", 2, 2))
	f.audit.fail = true
	if err := f.tick(t); !errors.Is(err, errSystemAuditUnavailable) {
		t.Fatalf("append failure: %v", err)
	}
	if f.state(t, tx).State != db.TrackPending || f.counting.finals.Load() != 0 {
		t.Fatal("a decision was taken without its audit event")
	}
	f.r.audit = nil
	f.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := f.tick(t); !errors.Is(err, errSystemAuditUnavailable) {
		t.Fatalf("no buffer: %v", err)
	}
	// Audited, then the commit failed: a retry in the same term does not
	// append again (no audit flood while the tracking database is down).
	f.r.audit, f.audit.fail = f.audit, false
	failing := &failOnceFinals{countingTracking: f.counting, times: 2}
	f.writer.store = failing
	for i := 2; i <= 3; i++ {
		f.r.now = func() time.Time { return time.Now().Add(time.Duration(i) * time.Hour) }
		if err := f.tick(t); err == nil {
			t.Fatal("injected commit failure not reported")
		}
	}
	if f.audit.count() != 1 {
		t.Fatalf("%d events for one decision retried in one term", f.audit.count())
	}
	// A restart (a new term) audits the decision again: over-report only,
	// with the same correlation id.
	f.r = newNodeReconciler(f.writer, f.main, f.node, f.audit, reconcileNetwork)
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	if f.state(t, tx).State != db.TrackIncluded {
		t.Fatal("not finalized after the retry")
	}
	if f.audit.count() != 2 || f.audit.events[0].CorrelationID != f.audit.events[1].CorrelationID {
		t.Fatalf("re-audit after a restart: %d events, ids %v", f.audit.count(), f.audit.events)
	}
	event := f.audit.events[0]
	if event.Method != "ops.system.finalized" || event.ExternalID != "did:test:"+tx.principal.String() || event.OrgID != tx.org.String() {
		t.Fatalf("system event %+v", event)
	}
}

// failOnceFinals fails the first times (default 1) finality batches.
type failOnceFinals struct {
	*countingTracking
	times, failed int
}

func (f *failOnceFinals) FinalizeBatch(ctx context.Context, inc uuid.UUID, fs []db.TrackFinal) ([]bool, error) {
	if f.failed < max(f.times, 1) {
		f.failed++
		return nil, errors.New("injected crash before the tracking commit")
	}
	return f.countingTracking.FinalizeBatch(ctx, inc, fs)
}

// TestSystemEventEncodingSurvivesSealing is G56: the finality event's
// transaction, context, generation, incarnation, outcome and actor survive
// sealing into access_logs, in the hashed parameters.
func TestSystemEventEncodingSurvivesSealing(t *testing.T) {
	f := newReconcileFixture(t, nil)
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	tx := f.admit(t, uuid.New(), uuid.New())
	f.node.set(tx.status("reverted", 6, 6))
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.audit.events[0])
	var rec db.AccessLogRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	auditDB := db.NewAuditHandle(database)
	if _, err := auditDB.SealBufferedAccessLog(context.Background(), audit.NewHashChain(""), rec, 1, "access_logs"); err != nil {
		t.Fatal(err)
	}
	var method, external, params string
	if err := database.Conn().QueryRow(`SELECT method, external_id, request_params::text FROM access_logs WHERE buffer_seq = 1`).Scan(&method, &external, &params); err != nil {
		t.Fatal(err)
	}
	if method != "ops.system.finalized" || external != "did:test:"+tx.principal.String() {
		t.Fatalf("sealed %s %s", method, external)
	}
	for _, want := range []string{tx.hex, tx.context.String(), f.writer.incarnation().String(), `"system:finality"`, `"reverted"`, `"generation":1`} {
		if !strings.Contains(params, want) {
			t.Fatalf("sealed parameters %s lack %s", params, want)
		}
	}
}

// TestSurvivingInstanceAdoptsNewIncarnation is G59 (server half): after the
// tracking database is dropped and recreated under a running instance, that
// instance re-initialises it, adopts the new incarnation, admits and
// finalizes new work; outstanding work of the old incarnation has no effect.
func TestSurvivingInstanceAdoptsNewIncarnation(t *testing.T) {
	f := newReconcileFixture(t, nil)
	ctx := context.Background()
	old := f.admit(t, uuid.New(), uuid.New())
	if err := f.tick(t); err == nil { // polls it; the node does not know it yet
		t.Log("old row polled")
	}
	oldInc := f.writer.incarnation()
	main, err := db.NewWithoutMigrate(f.tracking.mainURL)
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	name := f.tracking.url[strings.LastIndex(f.tracking.url, "/")+1:]
	if i := strings.Index(name, "?"); i >= 0 {
		name = name[:i]
	}
	for _, stmt := range []string{`DROP DATABASE ` + name + ` WITH (FORCE)`, `CREATE DATABASE ` + name} {
		if _, err := main.Conn().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	// Outstanding work issued before the recreation has no effect.
	f.writer.ack(old.hash, 1, oldInc, uuid.New())
	block := uint64(1)
	if _, err := f.tracking.runtime.ApplyTransitions(ctx, oldInc, []db.TrackTransition{{Hash: old.hash, From: db.TrackPending, To: db.TrackProvisional, BlockNumber: &block}}); err == nil {
		t.Fatal("old-incarnation work applied to the recreated database")
	}
	// A request on the surviving instance: the committer adopts and admits.
	runCtx, stop := context.WithCancel(ctx)
	wait := f.writer.run(runCtx)
	defer func() { stop(); wait() }()
	fresh := newSignedTransfer(t, 0)
	principal, org := uuid.New(), uuid.New()
	tx := trackedTx{hash: hashBytes(t, fresh.hash), hex: fresh.hash, principal: principal, org: org}
	contextID := uuid.New()
	tx.context = contextID
	result, inc, err := f.writer.admit(ctx, db.TrackAdmission{Hash: tx.hash, PrincipalID: principal, OrgID: org, Signer: hashBytes(t, fresh.signer), Nonce: 0, ContextID: contextID, EnvelopeHash: tx.hash, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: hashBytes(t, fresh.raw)})
	if err != nil || result.Outcome != db.AdmitInserted || inc == oldInc {
		t.Fatalf("admission after recreation: %+v %v (incarnation %s, old %s)", result, err, inc, oldInc)
	}
	f.writer.flushAcks(ctx, time.Now().Add(time.Hour)) // the old acknowledgement is void
	f.node.set(tx.status("included", 3, 3))
	f.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	for i := 0; i < 2; i++ {
		_ = f.tick(t)
	}
	if s := f.state(t, tx).State; s != db.TrackIncluded {
		t.Fatalf("new work on the adopted database: state %d", s)
	}
}

// TestReconcilerFinalizesSideEffectsExactlyOnce covers G47 and the server half
// of G48: the visibility rule of a finalized visibleTo transaction is created
// once, with the sender DID recorded at admission (it survives the user being
// deleted before finality), across a crash between the main-database effects
// and the tracking finalize.
func TestReconcilerFinalizesSideEffectsExactlyOnce(t *testing.T) {
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := database.EnsureNodeTxEffectsFloor(ctx, reconcileNetwork); err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	if err := database.CreateOrganization(ctx, &rbac.Organization{ID: org.String(), Slug: "rec-" + org.String()[:8], Name: "Reconcile"}); err != nil {
		t.Fatal(err)
	}
	f := newReconcileFixture(t, database)
	principal := uuid.New() // never a user row: deleted before finality (K24)
	tx := f.admit(t, principal, org, "did:test:recipient")
	f.node.set(tx.status("included", 8, 8))
	failing := &failOnceFinals{countingTracking: f.counting}
	f.writer.store = failing
	if err := f.tick(t); err == nil {
		t.Fatal("injected crash not reported")
	}
	f.r.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := f.tick(t); err != nil {
		t.Fatal(err)
	}
	var rules int
	var sender string
	if err := database.Conn().QueryRow(`SELECT count(*), max(sender_did) FROM pending_tx_visibility WHERE tx_hash = $1`, tx.hex).Scan(&rules, &sender); err != nil {
		t.Fatal(err)
	}
	if rules != 1 || sender != tx.visibleSender {
		t.Fatalf("%d visibility rules from %q, want one from %q", rules, sender, tx.visibleSender)
	}
	if s := f.state(t, tx).State; s != db.TrackIncluded {
		t.Fatalf("state %d", s)
	}
	if !strings.HasPrefix(f.audit.events[0].ExternalID, "principal:") {
		t.Fatalf("a deleted principal is named by id, got %q", f.audit.events[0].ExternalID)
	}
}

// A binding released (-32012) and admitted again with another visibleTo is a
// new binding: finality applies only the current one's visibility (security
// review B3a #1).
func TestReconcilerAppliesOnlyTheCurrentBindingsVisibility(t *testing.T) {
	database, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := database.EnsureNodeTxEffectsFloor(ctx, reconcileNetwork); err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	if err := database.CreateOrganization(ctx, &rbac.Organization{ID: org.String(), Slug: "vis-" + org.String()[:8], Name: "Visibility"}); err != nil {
		t.Fatal(err)
	}
	f := newReconcileFixture(t, database)
	principal := uuid.New()
	first := f.admit(t, principal, org, "did:test:removed-recipient")
	f.node.set(first.status("pending", 0, 0))
	if err := f.tick(t); err != nil { // scheduled with the first visibleTo
		t.Fatal(err)
	}
	released, err := f.tracking.runtime.ReleaseUndelivered(ctx, f.writer.incarnation(), first.hash, first.context)
	if err != nil || !released {
		t.Fatalf("release: %v %v", released, err)
	}
	second := first
	second.context = uuid.New()
	a := db.TrackAdmission{Hash: first.hash, PrincipalID: principal, OrgID: org, Signer: first.hash[:20], Nonce: 1, ContextID: second.context, EnvelopeHash: first.hash, ExpiresAt: time.Now().Add(time.Minute), MinVersion: 7, Raw: first.hash, VisibleTo: []string{"did:test:current-recipient"}, VisibleSender: first.visibleSender}
	if results, err := f.tracking.runtime.AdmitBatch(ctx, f.writer.incarnation(), db.TrackLimits{}, []db.TrackAdmission{a}); err != nil || results[0].Outcome != db.AdmitInserted {
		t.Fatalf("re-admission: %+v %v", results, err)
	}
	f.node.set(second.status("included", 4, 4))
	for i := 1; i <= 3; i++ {
		f.r.now = func() time.Time { return time.Now().Add(time.Duration(i) * time.Hour) }
		_ = f.tick(t)
	}
	if s := f.state(t, first).State; s != db.TrackIncluded {
		t.Fatalf("state %d", s)
	}
	var recipients []string
	rows, err := database.Conn().Query(`SELECT unnest(visible_to_dids) FROM pending_tx_visibility WHERE tx_hash = $1`, first.hex)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, r)
	}
	if len(recipients) != 1 || recipients[0] != "did:test:current-recipient" {
		t.Fatalf("visibility applied to %v, want only the current binding's recipient", recipients)
	}
}

// countingBatched answers every batched status call with no entries and
// counts the hashes polled; delay slows every call.
type countingBatched struct {
	mu     sync.Mutex
	polled int
	delay  time.Duration
}

func (c *countingBatched) TransactionStatus(context.Context, string) (nodepolicy.TransactionStatus, error) {
	return nodepolicy.TransactionStatus{}, nodepolicy.ErrNodeUnavailable
}

func (c *countingBatched) TransactionStatuses(_ context.Context, hashes []string) (nodepolicy.TransactionStatusBatch, error) {
	time.Sleep(c.delay)
	c.mu.Lock()
	c.polled += len(hashes)
	c.mu.Unlock()
	return nodepolicy.TransactionStatusBatch{BootID: strings.Repeat("ab", 16), Statuses: make([]*nodepolicy.BatchedStatus, len(hashes))}, nil
}

// With the batched status call a tick polls more pending transactions than
// the single-call bound (B4): at the expected rate the pending work exceeds
// 4,096 rows, and a row observed late still holds its pending-work quota.
func TestBatchedReconcilerPollsBeyondTheSingleCallBound(t *testing.T) {
	node := &countingBatched{}
	r := &nodeReconciler{node: node, batched: func() bool { return true }, now: time.Now, rows: map[string]*trackedRow{}}
	for i := 0; i < 6000; i++ {
		hash := make([]byte, 32)
		_, _ = rand.Read(hash)
		r.rows[string(hash)] = &trackedRow{row: db.TrackedTransaction{Hash: hash, State: db.TrackPending}, hashHex: "0x" + hex.EncodeToString(hash)}
	}
	if got := len(r.poll(context.Background())); got != 6000 || node.polled != 6000 {
		t.Fatalf("polled %d (%d answered) of 6000 pending rows in one tick", node.polled, got)
	}
	// A slow node: calls are started only for the first two seconds of a
	// tick; the rest stay due for the next tick instead of stalling it.
	node.delay, node.polled = 700*time.Millisecond, 0
	started := time.Now()
	got := len(r.poll(context.Background()))
	if elapsed := time.Since(started); elapsed > reconcilePollDeadline+2*node.delay || got == 6000 || got != node.polled {
		t.Fatalf("slow node: %d of 6000 polled in %s", got, elapsed)
	}
}
