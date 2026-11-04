package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/perfgate"
)

// L9, L13 and the two-minute outage (L7/L8) as perfgate-mock simulations
// (plan §8, P8). One simulated clock drives the mock node, the reconciler,
// the lease keeper and the issuing clock; the tracking store reports its
// database clock and the times its SQL defaults wrote on the same simulated
// clock. The arithmetic is production's (config.RenewalPlan), scaled down:
// lease 120 s (window opens at 60 s left, margin 30 s), maximum age 240 s,
// budget 20 renewals/s, two-block reorg headroom of 50-transaction blocks →
// renewable 600, pending-work limit 500. The mock includes at most 5
// transactions per one-second block.

// simClock is real time plus a simulated offset.
type simClock struct{ offset atomic.Int64 }

func (c *simClock) now() time.Time          { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *simClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// simIssuing is the issuing clock on simulated time.
type simIssuing struct {
	clock   *simClock
	version uint64
}

func (s simIssuing) NodePolicyClock(context.Context) (uint64, time.Time, error) {
	return s.version, s.clock.now(), nil
}

// simStore is the tracking store on simulated time: reads report the
// database clock plus the offset, and the times SQL defaults write
// (created_at at an insert or revival, claim_expires) are moved by the offset
// at the moment they are written.
type simStore struct {
	trackingStore
	conn  *sql.DB
	clock *simClock
}

func (s simStore) shifted(rows []db.TrackedTransaction) []db.TrackedTransaction {
	for i := range rows {
		rows[i].DBNow = rows[i].DBNow.Add(time.Duration(s.clock.offset.Load()))
	}
	return rows
}

func (s simStore) TrackedBatch(ctx context.Context, hashes [][]byte) ([]db.TrackedTransaction, error) {
	rows, err := s.trackingStore.TrackedBatch(ctx, hashes)
	return s.shifted(rows), err
}

func (s simStore) ListTracked(ctx context.Context, from, to uint64, after []byte, limit int) ([]db.TrackedTransaction, error) {
	rows, err := s.trackingStore.ListTracked(ctx, from, to, after, limit)
	return s.shifted(rows), err
}

func (s simStore) LookupTracked(ctx context.Context, hash []byte) (db.TrackedTransaction, error) {
	row, err := s.trackingStore.LookupTracked(ctx, hash)
	row.DBNow = row.DBNow.Add(time.Duration(s.clock.offset.Load()))
	return row, err
}

func (s simStore) shift(column string, hashes [][]byte) error {
	if len(hashes) == 0 {
		return nil
	}
	_, err := s.conn.Exec(`UPDATE node_tx_binding SET `+column+` = `+column+` + make_interval(secs => $2) WHERE tx_hash = ANY($1) AND `+column+` IS NOT NULL`,
		hashes, time.Duration(s.clock.offset.Load()).Seconds())
	return err
}

func (s simStore) AdmitBatch(ctx context.Context, inc uuid.UUID, limits db.TrackLimits, batch []db.TrackAdmission) ([]db.AdmitResult, error) {
	results, err := s.trackingStore.AdmitBatch(ctx, inc, limits, batch)
	if err != nil {
		return results, err
	}
	var created, claimed [][]byte
	for i, r := range results {
		if r.Outcome == db.AdmitInserted || r.Outcome == db.AdmitRevived {
			created = append(created, batch[i].Hash)
		}
		if r.Written() {
			claimed = append(claimed, batch[i].Hash)
		}
	}
	if err := s.shift("created_at", created); err != nil {
		return nil, err
	}
	return results, s.shift("claim_expires", claimed)
}

func (s simStore) RenewBatch(ctx context.Context, inc uuid.UUID, renewals []db.TrackRenewal) ([]bool, error) {
	applied, err := s.trackingStore.RenewBatch(ctx, inc, renewals)
	if err != nil {
		return applied, err
	}
	var claimed [][]byte
	for i, ok := range applied {
		if ok {
			claimed = append(claimed, renewals[i].Hash)
		}
	}
	return applied, s.shift("claim_expires", claimed)
}

type simSender struct {
	key            *ecdsa.PrivateKey
	address        string
	principal, org uuid.UUID
	next           uint64
}

type congestionSim struct {
	t        *testing.T
	ctx      context.Context
	clock    *simClock
	tracking *testTracking
	writer   *nodeTracking
	mock     *perfgate.MockNode
	client   *nodepolicy.Client
	public   string
	audit    *recordingAudit
	checker  *fakeRechecker
	r        *nodeReconciler
	plan     config.RenewalPlan
	signer   nodepolicy.Signer
	down     atomic.Bool
	reads    atomic.Uint64

	// Observed over the run.
	ticks, lapses, renewals int
	capped                  int // lapses at the maximum-age cap (the stop)
	maxUsed                 int64
	refused                 map[db.AdmitOutcome]int
	audited                 int
}

func newCongestionSim(t *testing.T) *congestionSim {
	t.Helper()
	plan, err := config.NodePolicyConfig{TransactionIdentityTTL: 120 * time.Second, MaxAge: 240 * time.Second, RenewalBudget: 20, MaxReorgDepth: 2,
		BlockGasLimit: 50 * 21_000, ExpectedTPS: 5, InclusionBound: 1500 * time.Millisecond}.RenewalPlan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.RenewLimit != 600 || plan.AdmitLimit != 500 {
		t.Fatalf("scaled plan %+v", plan)
	}
	s := &congestionSim{t: t, clock: &simClock{}, plan: plan, refused: map[db.AdmitOutcome]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.mock = perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: keeperNetwork.ChainID, DeploymentID: keeperNetwork.DeploymentID, PrivateToken: keeperToken, FinalityLag: 2 * time.Second, MaxBlockTxs: 5, Clock: s.clock.now})
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.down.Load() {
			http.Error(w, "node down", http.StatusServiceUnavailable)
			return
		}
		s.mock.Private().ServeHTTP(w, r)
	}))
	public := httptest.NewServer(s.mock.Public())
	s.public = public.URL
	t.Cleanup(private.Close)
	t.Cleanup(public.Close)
	if s.client, err = nodepolicy.NewClient(private.URL, keeperToken, keeperNetwork, nil); err != nil {
		t.Fatal(err)
	}
	s.tracking = newTestTracking(t, keeperNetwork)
	store := simStore{trackingStore: s.tracking.runtime, conn: s.tracking.runtime.Conn(), clock: s.clock}
	s.writer = newNodeTracking(store, s.tracking.meta.Incarnation, s.tracking.adopter(keeperNetwork))
	s.writer.limits = db.TrackLimits{Global: plan.AdmitLimit, Principal: plan.PrincipalLimit, Org: plan.OrgLimit}
	wait := s.writer.run(ctx)
	t.Cleanup(func() { cancel(); wait() })
	s.audit = &recordingAudit{}
	s.checker = &fakeRechecker{refuse: map[uuid.UUID]int16{}, fail: map[uuid.UUID]error{}, checked: map[uuid.UUID]int{}}
	s.signer = nodepolicy.Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	s.r = newNodeReconciler(s.writer, &plainEffects{}, s.client, s.audit, keeperNetwork)
	s.r.batched, s.r.notFound = func() bool { return true }, func() bool { return true }
	s.r.now = s.clock.now
	s.r.keeper = &nodeKeeper{node: s.client, checker: s.checker, clock: simIssuing{clock: s.clock, version: 9}, signer: s.signer, network: keeperNetwork,
		ttl: plan.TTL, maxAge: plan.MaxAge, budget: plan.Budget, now: s.clock.now,
		boot: func() (uuid.UUID, bool, uint64) {
			boot, _ := uuid.Parse(s.mock.BootID())
			return boot, !s.down.Load(), s.reads.Add(1)
		}}
	return s
}

func (s *congestionSim) sender(principal, org uuid.UUID) *simSender {
	key, err := crypto.GenerateKey()
	if err != nil {
		s.t.Fatal(err)
	}
	return &simSender{key: key, address: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()), principal: principal, org: org}
}

// submit is the request path for the sender's next nonce: record the intent
// (held to the pending-work limits), then deliver it and acknowledge the
// answering boot. A refused admission keeps the nonce for a later retry.
func (s *congestionSim) submit(snd *simSender) db.AdmitOutcome {
	s.t.Helper()
	tx := signTransferValue(s.t, snd.key, snd.next, 1)
	now := s.clock.now()
	expires := now.Add(s.plan.TTL).Truncate(time.Second)
	identity := nodepolicy.Identity{Header: nodepolicy.Header{Network: keeperNetwork, IssuedAt: now.Unix(), ExpiresAt: expires.Unix()}, Scope: "transaction", ContextID: uuid.NewString(),
		PrincipalID: snd.principal.String(), OrgID: snd.org.String(), Signer: snd.address, BindingHash: tx.hash, MinSnapshotVersion: 9}
	wire, err := s.signer.Seal("identity", identity)
	if err != nil {
		s.t.Fatal(err)
	}
	envelope := sha256.Sum256(wire)
	boot, _ := uuid.Parse(s.mock.BootID())
	a := db.TrackAdmission{Hash: hashBytes(s.t, tx.hash), PrincipalID: snd.principal, OrgID: snd.org, Signer: hashBytes(s.t, snd.address), Nonce: snd.next, ContextID: uuid.MustParse(identity.ContextID),
		EnvelopeHash: envelope[:], ExpiresAt: expires, MinVersion: 9, Raw: hashBytes(s.t, tx.raw), ClaimBoot: boot}
	result, inc, err := s.writer.admit(s.ctx, a)
	if err != nil {
		s.t.Fatalf("admission: %v", err)
	}
	if !result.Written() {
		s.refused[result.Outcome]++
		return result.Outcome
	}
	snd.next++
	if s.down.Load() {
		return result.Outcome // recorded, undelivered: the keeper delivers it
	}
	if submitted, err := s.client.SubmitTransaction(s.ctx, wire, tx.raw); err == nil {
		answered, _ := uuid.Parse(submitted.BootID)
		s.writer.ack(a.Hash, result.Generation, inc, answered)
	}
	return result.Outcome
}

// tick advances one simulated second: a block (unless stalled or down), one
// reconciler and keeper pass, the acknowledgement flush, and the invariants.
func (s *congestionSim) tick(produce bool) {
	s.t.Helper()
	s.clock.advance(time.Second)
	s.ticks++
	if produce && !s.down.Load() {
		s.mock.ProduceBlock()
	}
	if err := s.r.tick(s.ctx); err != nil && !s.down.Load() {
		s.t.Logf("tick %d: %v", s.ticks, err)
	}
	s.writer.flushAcks(s.ctx, time.Now().Add(time.Hour))
	s.check()
}

// check asserts the per-tick invariants: the quota counts exactly the
// pending bindings (globally and per principal), no pending transaction has a
// lapsed identity at the node while it is up, and renewals stay within the
// budget (its two-second burst per tick, and its rate overall).
func (s *congestionSim) check() {
	s.t.Helper()
	ctx := context.Background()
	used, pending, err := s.tracking.runtime.PendingQuota(ctx)
	if err != nil || used != pending {
		s.t.Fatalf("tick %d: quota %d, pending %d, %v", s.ticks, used, pending, err)
	}
	if mismatched, err := s.tracking.runtime.PendingQuotaMismatches(ctx); err != nil || mismatched != 0 {
		s.t.Fatalf("tick %d: per-principal or per-organization quota mismatches %d %v", s.ticks, mismatched, err)
	}
	s.maxUsed = max(s.maxUsed, used)
	if !s.down.Load() {
		for _, hash := range s.mock.Lapsed() {
			row, err := s.tracking.runtime.LookupTracked(ctx, hashBytes(s.t, hash))
			if err != nil || row.State != db.TrackPending {
				continue
			}
			// A lease capped at the maximum age ends with it (truncated to the
			// second) and the stop follows within a tick: that is the stop,
			// not renewal debt. Counted apart.
			if !row.ExpiresAt.Before(row.CreatedAt.Add(s.plan.MaxAge).Add(-time.Second)) {
				s.capped++
				continue
			}
			{
				s.lapses++
				s.t.Errorf("tick %d: pending %s has a lapsed identity at the node (expired %s)", s.ticks, hash, row.ExpiresAt)
			}
		}
	}
	s.audit.mu.Lock()
	decided := 0
	for _, e := range s.audit.events[s.audited:] {
		if e.Method == "ops.system.identity_renewal" || e.Method == "ops.system.recovery" {
			decided++
		}
	}
	s.audited = len(s.audit.events)
	s.audit.mu.Unlock()
	s.renewals += decided
	burst := int(float64(s.plan.Budget) * keeperBudgetBurst.Seconds())
	if decided > burst || s.renewals > s.plan.Budget*(s.ticks+1) {
		s.t.Fatalf("tick %d: %d renewals this tick, %d in total: over the budget of %d/s", s.ticks, decided, s.renewals, s.plan.Budget)
	}
}

func (s *congestionSim) state(hash []byte) db.TrackedTransaction {
	s.t.Helper()
	row, err := s.tracking.runtime.LookupTracked(context.Background(), hash)
	if err != nil {
		s.t.Fatalf("lookup: %v", err)
	}
	return row
}

func (s *congestionSim) count(where string) int {
	s.t.Helper()
	var n int
	if err := s.tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_binding WHERE ` + where).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *congestionSim) finals(state int16) int {
	s.t.Helper()
	var n int
	if err := s.tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_status WHERE state = $1`, state).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

// sendPublic offers a raw transaction on the node's public RPC (a competitor
// sent outside OPS).
func (s *congestionSim) sendPublic(raw string) {
	s.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": []any{raw}})
	resp, err := http.Post(s.public, "application/json", bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	var reply struct {
		Error *struct{ Message string } `json:"error"`
	}
	if json.NewDecoder(resp.Body).Decode(&reply) != nil || reply.Error != nil {
		s.t.Fatalf("public send refused: %+v", reply.Error)
	}
}

func TestCongestionRenewalSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation")
	}
	s := newCongestionSim(t)
	var senders []*simSender
	principals := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, p := range principals {
		org := uuid.New() // one organization per principal
		senders = append(senders, s.sender(p, org), s.sender(p, org))
	}

	// L9: congestion within the pending-work limit. 8 transactions/s are
	// admitted against 5 included per block for 150 s, so the backlog grows to
	// about 450 (< 500) and transactions wait longer than half their lease.
	// Every pending identity stays live at the node, later nonces are never
	// held back, renewals stay within the budget, and all are included.
	submitted := 0
	for second := 0; second < 150; second++ {
		for i := 0; i < 8; i++ {
			if s.submit(senders[submitted%len(senders)]) == db.AdmitInserted {
				submitted++
			}
		}
		s.tick(true)
	}
	if len(s.refused) != 0 {
		t.Fatalf("L9 stays within the limit, refused %v (max pending %d)", s.refused, s.maxUsed)
	}
	if s.maxUsed < 300 || s.renewals == 0 {
		t.Fatalf("L9 did not congest: max pending %d, renewals %d", s.maxUsed, s.renewals)
	}
	for i := 0; i < 150 && s.finals(db.TrackIncluded) < submitted; i++ {
		s.tick(true)
	}
	if got := s.finals(db.TrackIncluded); got != submitted || s.lapses != 0 {
		t.Fatalf("L9: %d of %d included, %d lapsed identities", got, submitted, s.lapses)
	}
	if stalled, waiting := s.mock.Stalled(); stalled != 0 || waiting != 0 {
		t.Fatalf("L9: later nonces held back: %d senders, %d transactions", stalled, waiting)
	}
	l9Renewals := s.renewals
	t.Logf("L9: %d transactions, max pending %d of %d, %d renewals in %d s (budget %d/s), 0 lapses", submitted, s.maxUsed, s.plan.AdmitLimit, l9Renewals, s.ticks, s.plan.Budget)

	// L7 + L8: a two-minute node outage (crash: new boot, empty registry and
	// pool) with pending work, a principal revoked during it. Afterwards every
	// pending transaction is renewed within the budget and included with no
	// client action; the revoked principal's are never renewed or executed.
	before := s.finals(db.TrackIncluded)
	for i := 0; i < 60; i++ {
		s.submit(senders[i%len(senders)])
	}
	s.tick(false) // recorded and delivered, not yet included
	s.down.Store(true)
	revoked := principals[2]
	revokedIncluded := s.includedFor(revoked)
	s.checker.mu.Lock()
	s.checker.refuse[revoked] = db.TrackReasonPrincipalBanned
	s.checker.mu.Unlock()
	for second := 0; second < 120; second++ {
		if second < 30 {
			s.submit(senders[second%len(senders)]) // recorded, delivery fails
		}
		s.tick(false)
	}
	s.mock.Restart(true)
	s.down.Store(false)
	keep := s.count(`state = 1 AND principal_id <> '` + revoked.String() + `'`)
	recoveryStart := s.ticks
	for i := 0; i < 120 && s.finals(db.TrackIncluded) < before+keep; i++ {
		s.tick(true)
	}
	if got := s.finals(db.TrackIncluded) - before; got != keep {
		t.Fatalf("after the outage %d of %d pending transactions included with no client action", got, keep)
	}
	if stopped := s.count(`state = 3 AND reason = 20 AND principal_id = '` + revoked.String() + `'`); stopped != 30 {
		t.Fatalf("revoked principal: %d of 30 stopped principal_banned", stopped)
	}
	if got := s.includedFor(revoked); got != revokedIncluded {
		t.Fatalf("the revoked principal's transactions executed after the revocation: %d → %d", revokedIncluded, got)
	}
	t.Logf("outage: %d pending renewed and included %d s after restart; %d of the revoked principal stopped", keep, s.ticks-recoveryStart, 30)
	// The revoked principal's senders stay out of the rest of the run.
	senders = senders[:4]

	// L13: a burst above the limit (40/s against 5/s): backpressure at the
	// pending-work limit and never beyond it. Then a full inclusion stall:
	// renewals keep every pending identity live within the budget, renewal
	// stops at the maximum age (not final), the limit frees up, and once
	// blocks are finalized again every stopped transaction becomes final:
	// dropped with nonce_consumed where a finalized competitor used its
	// nonce; lease expiry alone keeps an immutable non-final binding past its
	// last identity's expiry (no stopped row is kept for ever, finding 2).
	var stoppedAfter int
	for second := 0; second < 30; second++ {
		for i := 0; i < 40; i++ {
			s.submit(senders[i%len(senders)])
		}
		s.tick(true)
	}
	if s.refused[db.AdmitOverLimit] == 0 || s.maxUsed > s.plan.AdmitLimit {
		t.Fatalf("L13 burst: refused %v, max pending %d of %d", s.refused, s.maxUsed, s.plan.AdmitLimit)
	}
	stallStart := s.ticks
	accepted := 0
	for second := 0; second < 260; second++ {
		if s.submit(senders[second%len(senders)]) == db.AdmitInserted && second > 0 {
			accepted++
		}
		s.tick(false)
	}
	stoppedAfter = s.count(`state = 3 AND reason = 8`)
	if stoppedAfter == 0 || accepted == 0 || s.lapses != 0 {
		t.Fatalf("L13 stall: %d stopped at the maximum age, %d admitted after the limit freed up, %d lapses", stoppedAfter, accepted, s.lapses)
	}
	if s.maxUsed > s.plan.AdmitLimit {
		t.Fatalf("L13: pending work %d exceeded the limit %d", s.maxUsed, s.plan.AdmitLimit)
	}
	stallRenewals := s.renewals
	t.Logf("L13: refused %v, max pending %d of %d, %d renewals during a %d s stall, %d stopped at the maximum age (%d pending-tick observations at the cap before the stop), %d admitted after", s.refused, s.maxUsed, s.plan.AdmitLimit, stallRenewals-l9Renewals, s.ticks-stallStart, stoppedAfter, s.capped, accepted)

	// Dropped on finalized evidence: one stopped transaction's nonce is used
	// by a competitor sent outside OPS; another stopped one (another sender)
	// has no competitor, but its identity has expired.
	var target, other db.TrackedTransaction
	rows, err := s.tracking.runtime.Conn().Query(`SELECT DISTINCT ON (signer) tx_hash, signer FROM node_tx_binding WHERE state = 3 AND reason = 8 ORDER BY signer, nonce`)
	if err != nil {
		t.Fatal(err)
	}
	var lowest [][]byte
	for rows.Next() {
		var hash, signer []byte
		if err := rows.Scan(&hash, &signer); err != nil {
			t.Fatal(err)
		}
		lowest = append(lowest, hash)
	}
	rows.Close()
	if len(lowest) < 2 {
		t.Fatalf("need two stopped senders, have %d", len(lowest))
	}
	target, other = s.state(lowest[0]), s.state(lowest[1])
	var competitorSender *simSender
	for _, snd := range senders {
		if snd.address == "0x"+hex.EncodeToString(target.Signer) {
			competitorSender = snd
		}
	}
	if competitorSender == nil {
		t.Fatal("target sender not found")
	}
	s.mock.Evict("0x" + hex.EncodeToString(target.Hash)) // the pool drops the unexecutable one
	s.sendPublic(signTransferValue(t, competitorSender.key, target.Nonce, 2).raw)
	for i := 0; i < 70; i++ {
		s.tick(true)
	}
	if got := s.state(target.Hash); got.State != db.TrackDropped || got.Reason != db.TrackReasonNonceConsumed {
		t.Fatalf("a stopped transaction whose nonce a finalized competitor used: %+v", got)
	}
	if got := s.state(other.Hash); got.State != db.TrackDropped || got.Reason != db.TrackReasonFinalizedLeaseExpiry {
		t.Fatalf("a stopped transaction whose identity expired before a finalized block: %+v", got)
	}
	if left := s.count(`state = 3`); left != 0 {
		t.Fatalf("%d stopped transactions left after their identities expired at a finalized block", left)
	}
	var expired int
	if err := s.tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_status WHERE state = $1 AND reason = $2`, db.TrackDropped, db.TrackReasonFinalizedLeaseExpiry).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	t.Logf("dropped: 1 on finalized nonce evidence, %d on finalized lease expiry, 0 stopped left; %d ticks simulated", expired, s.ticks)
}

func (s *congestionSim) includedFor(principal uuid.UUID) int {
	s.t.Helper()
	var n int
	if err := s.tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_status WHERE principal_id = $1 AND state = $2`, principal.String(), db.TrackIncluded).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}
