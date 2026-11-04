package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/perfgate"
	"privacy-proxy/internal/proxy"
)

var keeperNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "keeper-test"}

const keeperToken = "private-token-0123456789"

// fakeRechecker answers the admission re-check per principal.
type fakeRechecker struct {
	mu      sync.Mutex
	refuse  map[uuid.UUID]int16
	fail    map[uuid.UUID]error
	checked map[uuid.UUID]int
}

func (c *fakeRechecker) Recheck(_ context.Context, row db.TrackedTransaction, raw []byte, did string, _ uuid.UUID) (int16, uuid.UUID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checked[row.PrincipalID]++
	if len(raw) == 0 || did == "" {
		return 0, uuid.Nil, errors.New("missing payload or principal")
	}
	if err := c.fail[row.PrincipalID]; err != nil {
		return 0, uuid.Nil, err
	}
	return c.refuse[row.PrincipalID], uuid.Nil, nil
}

func (c *fakeRechecker) count(p uuid.UUID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checked[p]
}

// keeperClockFixture is the issuing clock: the fact version moves on demand.
type keeperClockFixture struct{ version atomic.Uint64 }

func (c *keeperClockFixture) NodePolicyClock(context.Context) (uint64, time.Time, error) {
	return c.version.Load(), time.Now(), nil
}

// countingRecovery counts recovery deliveries per hash.
type countingRecovery struct {
	*nodepolicy.Client
	mu     sync.Mutex
	sent   map[string]int
	block  atomic.Bool // fail every delivery (transport)
	refuse atomic.Bool // the node answers every delivery with a refusal
}

func (c *countingRecovery) SubmitRecovery(ctx context.Context, identity []byte, raw string) (nodepolicy.Submission, error) {
	c.mu.Lock()
	hash := strings.ToLower(rawHash(raw))
	c.sent[hash]++
	c.mu.Unlock()
	if c.block.Load() {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
	}
	if c.refuse.Load() {
		return nodepolicy.Submission{}, nodepolicy.ErrNodeRejected
	}
	return c.Client.SubmitRecovery(ctx, identity, raw)
}

func (c *countingRecovery) deliveries(hash string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent[hash]
}

func rawHash(raw string) string {
	b, _ := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	return "0x" + hex.EncodeToString(crypto.Keccak256(b))
}

// signTransferValue is signTransfer with another value: a different
// transaction at the same nonce.
func signTransferValue(t testing.TB, k *ecdsa.PrivateKey, nonce uint64, value int64) signedTransfer {
	t.Helper()
	to := crypto.PubkeyToAddress(k.PublicKey)
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: nonce, To: &to, Value: big.NewInt(value), Gas: 21000, GasPrice: big.NewInt(1)}), types.NewEIP155Signer(big.NewInt(31337)), k)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	return signedTransfer{raw: "0x" + hex.EncodeToString(raw), hash: strings.ToLower(tx.Hash().Hex()), signer: strings.ToLower(crypto.PubkeyToAddress(k.PublicKey).Hex())}
}

type keeperFixture struct {
	t        *testing.T
	tracking *testTracking
	writer   *nodeTracking
	mock     *perfgate.MockNode
	client   *nodepolicy.Client
	node     *countingRecovery
	audit    *recordingAudit
	checker  *fakeRechecker
	clock    *keeperClockFixture
	r        *nodeReconciler
	k        *nodeKeeper
	skew     atomic.Int64 // the keeper's and reconciler's clock offset
	ready    atomic.Bool
	batched  atomic.Bool
	finality time.Duration
}

func newKeeperFixture(t *testing.T, finality time.Duration) *keeperFixture {
	t.Helper()
	f := &keeperFixture{t: t, finality: finality}
	f.tracking = newTestTracking(t, keeperNetwork)
	f.writer = newNodeTracking(f.tracking.runtime, f.tracking.meta.Incarnation, f.tracking.adopter(keeperNetwork))
	f.mock = perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: keeperNetwork.ChainID, DeploymentID: keeperNetwork.DeploymentID, PrivateToken: keeperToken, FinalityLag: finality})
	private := httptest.NewServer(f.mock.Private())
	public := httptest.NewServer(f.mock.Public())
	t.Cleanup(private.Close)
	t.Cleanup(public.Close)
	var err error
	if f.client, err = nodepolicy.NewClient(private.URL, keeperToken, keeperNetwork, nil); err != nil {
		t.Fatal(err)
	}
	f.node = &countingRecovery{Client: f.client, sent: map[string]int{}}
	f.audit = &recordingAudit{}
	f.checker = &fakeRechecker{refuse: map[uuid.UUID]int16{}, fail: map[uuid.UUID]error{}, checked: map[uuid.UUID]int{}}
	f.clock = &keeperClockFixture{}
	f.clock.version.Store(9)
	f.ready.Store(true)
	f.r = newNodeReconciler(f.writer, &plainEffects{}, f.client, f.audit, keeperNetwork)
	f.r.batched = f.batched.Load
	now := func() time.Time { return time.Now().Add(time.Duration(f.skew.Load())) }
	f.r.now = now
	f.k = &nodeKeeper{node: f.node, chain: rpcChain{forward: proxy.New(public.URL).ForwardContext}, checker: f.checker, clock: f.clock, signer: nodepolicy.Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))},
		network: keeperNetwork, ttl: 300 * time.Second, maxAge: 10 * time.Minute, now: now,
		boot: func() (uuid.UUID, bool, uint64) {
			boot, _ := uuid.Parse(f.mock.BootID())
			return boot, f.ready.Load(), uint64(f.skew.Load()) // a newer read every tick
		}}
	f.r.keeper = f.k
	return f
}

// admit records an intent the way the request path does, without sending it
// (an OPS crash between the intent INSERT and transport, R12).
func (f *keeperFixture) admit(tx signedTransfer, principal, org uuid.UUID, claim time.Duration) {
	f.t.Helper()
	f.admitAs(tx, principal, org, claim, db.AdmitInserted)
}

func (f *keeperFixture) admitAs(tx signedTransfer, principal, org uuid.UUID, claim time.Duration, want db.AdmitOutcome) {
	f.t.Helper()
	raw := hashBytes(f.t, tx.raw)
	envelope := sha256.Sum256(raw)
	a := db.TrackAdmission{Hash: hashBytes(f.t, tx.hash), PrincipalID: principal, OrgID: org, Signer: hashBytes(f.t, tx.signer), Nonce: nonceOf(f.t, tx), ContextID: uuid.New(), EnvelopeHash: envelope[:],
		ExpiresAt: time.Now().Add(300 * time.Second).Truncate(time.Second), MinVersion: 7, Raw: raw}
	if claim > 0 {
		a.ClaimOwner, a.ClaimTTL = uuid.New(), claim
		a.ClaimBoot, _ = uuid.Parse(f.mock.BootID())
	}
	results, err := f.tracking.runtime.AdmitBatch(context.Background(), f.writer.incarnation(), db.TrackLimits{}, []db.TrackAdmission{a})
	if err != nil || results[0].Outcome != want {
		f.t.Fatalf("admit: %+v %v", results, err)
	}
}

// tick advances the keeper's and reconciler's clock by two seconds (time
// passes between passes) and runs one pass.
func (f *keeperFixture) tick() {
	f.t.Helper()
	f.skew.Add(int64(2 * time.Second))
	if err := f.r.tick(context.Background()); err != nil {
		f.t.Logf("tick: %v", err)
	}
}

func (f *keeperFixture) row(tx signedTransfer) db.TrackedTransaction {
	f.t.Helper()
	row, err := f.tracking.runtime.LookupTracked(context.Background(), hashBytes(f.t, tx.hash))
	if err != nil {
		f.t.Fatalf("lookup %s: %v", tx.hash, err)
	}
	return row
}

// flushAcks writes every acknowledgement in memory now.
func (f *keeperFixture) flushAcks() {
	f.writer.flushAcks(context.Background(), time.Now().Add(time.Hour))
}

func (f *keeperFixture) events(method string) []db.AccessLogRecord {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var out []db.AccessLogRecord
	for _, e := range f.audit.events {
		if e.Method == method {
			out = append(out, e)
		}
	}
	return out
}

func (f *keeperFixture) receipt(tx signedTransfer) bool {
	f.t.Helper()
	status, err := f.client.TransactionStatus(context.Background(), tx.hash)
	return err == nil && status.Execution.Status == "included"
}

func nonceOf(t testing.TB, tx signedTransfer) uint64 {
	t.Helper()
	_, _, _, _, nonce, err := decodeRawTransaction(tx.raw)
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

// G12 + G30 (R12, R13): an intent saved but never sent (OPS crashed between
// the INSERT and transport) is delivered by the keeper — re-checked, signed
// at the current clock, audited as ops.system.recovery, recorded as a new
// generation in history before transport — and executes; a pass that fails
// part-way retries without a node restart, and a delivered row is not
// renewed again.
func TestIntentSavedButNeverSentIsDelivered(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	principal, org := uuid.New(), uuid.New()
	saved := newSignedTransfer(t, 0)
	f.admit(saved, principal, org, 0)
	f.node.block.Store(true) // the first delivery fails: a partial pass
	f.tick()
	if got := f.row(saved); got.Generation != 2 || f.mock.Stats().Pooled != 0 {
		t.Fatalf("renewal not recorded before transport, or delivered: %+v", got)
	}
	if len(f.events("ops.system.recovery")) != 1 {
		t.Fatalf("recovery not audited: %+v", f.audit.events)
	}
	f.node.block.Store(false)
	f.skew.Add(int64(2 * time.Second)) // past the resend backoff, same boot
	f.tick()
	if f.mock.Stats().Pooled != 1 || f.node.deliveries(saved.hash) != 2 {
		t.Fatalf("partial pass not resumed: pooled=%d deliveries=%d", f.mock.Stats().Pooled, f.node.deliveries(saved.hash))
	}
	if len(f.events("ops.system.recovery")) != 1 || f.row(saved).Generation != 2 {
		t.Fatal("a resend of the same generation is a new decision")
	}
	f.flushAcks()
	boot, _ := uuid.Parse(f.mock.BootID())
	if row := f.row(saved); !row.DeliveredTo(boot) {
		t.Fatalf("delivery not acknowledged against the answering boot: %+v", row)
	}
	f.skew.Add(int64(time.Minute))
	f.tick()
	f.tick()
	if f.node.deliveries(saved.hash) != 2 || f.checker.count(principal) != 1 {
		t.Fatalf("a delivered row was renewed again: deliveries=%d checks=%d", f.node.deliveries(saved.hash), f.checker.count(principal))
	}
	f.mock.ProduceBlock()
	if !f.receipt(saved) {
		t.Fatal("recovered transaction not included")
	}
	var identities int
	if err := f.tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_identities WHERE tx_hash = $1 AND generation = 2 AND reason = $2 AND actor = 2`, hashBytes(t, saved.hash), db.TrackReasonUndelivered).Scan(&identities); err != nil || identities != 1 {
		t.Fatalf("renewal history row: %d %v", identities, err)
	}
}

// L6/L7 + G27 (R7, R11): after a node restart (new boot id, empty registry)
// every pending transaction is renewed — full re-check, the current fact
// clock as its floor, audited with reason node_restarted — and included with
// no client action; a principal revoked meanwhile is not renewed, stops with
// the reason (not final), and never executes (L8).
//
// With the batched status call (final A3 wire), the restarted node answers
// null entries for the hashes it no longer holds: no evidence, re-polled,
// never a transition.
func TestRecoveryRenewsAtCurrentClockAfterRevocation(t *testing.T) {
	for _, variant := range []struct {
		crash, batched bool
	}{{false, false}, {true, false}, {false, true}, {true, true}} {
		crash := variant.crash
		name := "graceful"
		if crash {
			name = "crash"
		}
		if variant.batched {
			name += "_batched"
		}
		t.Run(name, func(t *testing.T) {
			f := newKeeperFixture(t, time.Hour)
			f.batched.Store(variant.batched)
			org := uuid.New()
			kept, revoked := uuid.New(), uuid.New()
			txKept, txRevoked := newSignedTransfer(t, 0), newSignedTransfer(t, 0)
			f.admit(txKept, kept, org, 0)
			f.admit(txRevoked, revoked, org, 0)
			f.tick() // delivered (the takeover scan)
			f.flushAcks()
			if f.mock.Stats().Pooled != 2 {
				t.Fatalf("not delivered: %+v", f.mock.Stats())
			}
			f.mock.Restart(crash)
			f.checker.mu.Lock()
			f.checker.refuse[revoked] = db.TrackReasonPrincipalBanned
			f.checker.mu.Unlock()
			f.clock.version.Store(12) // a revocation committed before the recovery pass
			f.mock.ProduceBlock()
			if f.receipt(txKept) || f.receipt(txRevoked) {
				t.Fatal("a pooled transaction executed without an identity after the restart")
			}
			f.tick() // the new boot id is seen
			f.tick() // and confirmed: renew for it
			if got := f.row(txKept); got.MinVersion != 12 || got.Generation != 3 {
				t.Fatalf("renewal floor %d generation %d, want the current clock 12 and a new generation", got.MinVersion, got.Generation)
			}
			stopped := f.row(txRevoked)
			if stopped.State != db.TrackRenewalStopped || stopped.Reason != db.TrackReasonPrincipalBanned || stopped.Final() {
				t.Fatalf("revoked principal: %+v", stopped)
			}
			if f.node.deliveries(txRevoked.hash) != 1 {
				t.Fatal("a refused re-check was signed or sent")
			}
			recovery := f.events("ops.system.recovery")
			refused := f.events("ops.system.renewal_refused")
			if len(recovery) != 3 || len(refused) != 1 || refused[0].DenialReason != "principal_banned" || refused[0].StatusCode != 403 || !strings.Contains(string(recovery[2].Params), `"reason":"node_restarted"`) {
				t.Fatalf("audit trail: %d recoveries, refusals %+v", len(recovery), refused)
			}
			f.mock.ProduceBlock()
			if !f.receipt(txKept) || f.receipt(txRevoked) {
				t.Fatalf("after recovery: kept included=%v revoked included=%v", f.receipt(txKept), f.receipt(txRevoked))
			}
		})
	}
}

// R14/G18: at the maximum age the keeper stops renewing (renewal_stopped,
// audited, not final) while outcome discovery continues: a late inclusion is
// still recorded and finalized.
func TestMaxAgeStopsRenewalButNotOutcomeDiscovery(t *testing.T) {
	f := newKeeperFixture(t, 0)
	principal, org := uuid.New(), uuid.New()
	tx := newSignedTransfer(t, 0)
	f.admit(tx, principal, org, 0)
	f.tick() // delivered
	f.flushAcks()
	if _, err := f.tracking.runtime.Conn().Exec(`UPDATE node_tx_binding SET created_at = clock_timestamp() - interval '11 minutes'`); err != nil {
		t.Fatal(err)
	}
	f.k.lastBoot = uuid.Nil // reconsider every row
	f.r.rows = nil
	f.tick()
	row := f.row(tx)
	if row.State != db.TrackRenewalStopped || row.Reason != db.TrackReasonMaxAge || row.Final() {
		t.Fatalf("at maximum age: %+v", row)
	}
	if stops := f.events("ops.system.renewal_stopped"); len(stops) != 1 || stops[0].StatusCode != 410 {
		t.Fatalf("stop not audited: %+v", stops)
	}
	f.mock.ProduceBlock() // the still-valid lease executes it
	f.mock.ProduceBlock()
	f.tick()
	f.tick()
	if final := f.row(tx); final.State != db.TrackIncluded {
		t.Fatalf("late inclusion after the maximum age not recorded: %+v", final)
	}
}

// G33 + G31: dropped needs finalized nonce evidence — a stopped binding whose
// nonce a finalized competitor consumed, with no own receipt, at the
// finalized block the node reported; lease expiry alone never drops, and the
// binding is kept until then.
//
// The evidence comes from the private node's batched status call when it
// offers it (final A3 wire: receipts and the sender's nonce at the node's own
// finalized block, no public RPC), else from the public RPC.
func TestFinalDroppedRequiresFinalizedNonceEvidence(t *testing.T) {
	for _, fromNode := range []bool{false, true} {
		name := "public_rpc"
		if fromNode {
			name = "node_evidence"
		}
		t.Run(name, func(t *testing.T) { finalDroppedRequiresEvidence(t, fromNode) })
	}
	// A null receipt (a failed lookup on the node) or a null entry is no
	// evidence: never dropped, however often it is read.
	t.Run("null_receipts_are_no_evidence", func(t *testing.T) {
		f := newKeeperFixture(t, 0)
		f.batched.Store(true)
		f.k.chain = nil
		f.r.node = nullReceipts{f.client}
		key, _ := crypto.GenerateKey()
		ours := signTransfer(t, key, 0)
		f.admit(ours, uuid.New(), uuid.New(), 0)
		f.tick()
		f.mock.Evict(ours.hash)
		if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonPrincipalBanned}}); err != nil {
			t.Fatal(err)
		}
		f.r.rows = nil
		competitor := signTransferValue(t, key, 0, 2)
		f.admit(competitor, uuid.New(), uuid.New(), 0)
		f.tick()
		f.mock.ProduceBlock()
		f.mock.ProduceBlock()
		for i := 0; i < 4; i++ {
			f.skew.Add(int64(time.Minute))
			f.tick()
		}
		if row := f.row(ours); row.State != db.TrackRenewalStopped {
			t.Fatalf("dropped without a receipt answer: %+v", row)
		}
	})
}

// nullReceipts is a node whose receipt lookups all fail (receipts null).
type nullReceipts struct{ *nodepolicy.Client }

func (n nullReceipts) TransactionEvidence(ctx context.Context, hashes, senders []string) (nodepolicy.TransactionStatusBatch, error) {
	batch, err := n.Client.TransactionEvidence(ctx, hashes, senders)
	for i := range batch.Receipts {
		batch.Receipts[i] = nil
	}
	return batch, err
}

func finalDroppedRequiresEvidence(t *testing.T, fromNode bool) {
	f := newKeeperFixture(t, 0)
	if fromNode {
		f.batched.Store(true)
		f.k.chain = nil // no public RPC at all
	}
	key, _ := crypto.GenerateKey()
	principal, org := uuid.New(), uuid.New()
	ours := signTransfer(t, key, 0)
	f.admit(ours, principal, org, 0)
	f.tick()
	f.flushAcks()
	f.mock.Evict(ours.hash)
	// Stopped (e.g. a refused re-check) while its nonce is still free.
	if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonPrincipalBanned}}); err != nil {
		t.Fatal(err)
	}
	f.r.rows = nil
	other := newSignedTransfer(t, 0) // another sender, to learn a finalized head
	f.admit(other, uuid.New(), org, 0)
	f.tick()
	f.mock.ProduceBlock()
	f.mock.ProduceBlock()
	f.tick()
	// Its identity is still valid at the finalized block: no evidence yet.
	f.skew.Add(int64(time.Hour))
	f.tick()
	f.skew.Add(int64(time.Minute))
	f.tick()
	if row := f.row(ours); row.State != db.TrackRenewalStopped {
		t.Fatalf("dropped while its identity is valid and its nonce free: %+v", row)
	}
	// A competitor at the same nonce is finalized: now the nonce is consumed.
	competitor := signTransferValue(t, key, 0, 2)
	f.admit(competitor, principal, org, 0)
	f.tick()
	f.mock.ProduceBlock()
	f.mock.ProduceBlock()
	f.tick() // the competitor finalizes; the head advances
	f.skew.Add(int64(time.Minute))
	f.tick() // first evidence read
	if row := f.row(ours); row.State != db.TrackRenewalStopped {
		t.Fatalf("dropped on a single evidence read: %+v", row)
	}
	f.skew.Add(int64(time.Minute))
	f.tick() // the same verdict again, later
	got, err := f.tracking.runtime.LookupTracked(context.Background(), hashBytes(t, ours.hash))
	if err != nil || got.State != db.TrackDropped || got.Reason != db.TrackReasonNonceConsumed {
		t.Fatalf("dropped on finalized evidence: %+v %v", got, err)
	}
	dropped := f.events("ops.system.dropped")
	if len(dropped) != 1 {
		t.Fatalf("dropped not audited: %+v", dropped)
	}
	source := `"evidence":"public_rpc"`
	if fromNode {
		source = `"evidence":"private_node"`
	}
	for _, want := range []string{source, `"sender_finalized_nonce":1`, `"nonce":0`, `"finalized_block_hash":"0x`, `"evidence_first_seen":`} {
		if !strings.Contains(string(dropped[0].Params), want) {
			t.Fatalf("dropped audit event lacks its evidence %s: %s", want, dropped[0].Params)
		}
	}
}

// G37: a delivered row that the node's pool no longer holds (same boot, no
// receipt) is detected on the status path and renewed; the batched status
// answer's pool flag and the public-RPC fallback both detect it.
func TestPoolEvictionDetectedOnStatusPath(t *testing.T) {
	for _, batched := range []bool{false, true} {
		name := "single"
		if batched {
			name = "batched"
		}
		t.Run(name, func(t *testing.T) {
			f := newKeeperFixture(t, time.Hour)
			f.batched.Store(batched)
			principal, org := uuid.New(), uuid.New()
			tx := newSignedTransfer(t, 0)
			f.admit(tx, principal, org, 0)
			f.tick()
			f.flushAcks()
			f.tick()
			if !f.mock.Evict(tx.hash) {
				t.Fatal("not pooled")
			}
			f.skew.Add(int64(time.Minute)) // past the settle time
			f.tick()
			f.tick()
			if f.node.deliveries(tx.hash) != 2 || len(f.events("ops.system.recovery")) != 2 {
				t.Fatalf("eviction not recovered: deliveries=%d", f.node.deliveries(tx.hash))
			}
			if !strings.Contains(string(f.events("ops.system.recovery")[1].Params), `"reason":"evicted"`) {
				t.Fatalf("eviction reason: %s", f.events("ops.system.recovery")[1].Params)
			}
			f.mock.ProduceBlock()
			if !f.receipt(tx) {
				t.Fatal("re-pooled transaction not included")
			}
		})
	}
}

// G36 + G23: a delivery claim keeps the keeper off a row while its owner
// delivers it to the current boot (no duplicate re-check or signature); after
// the owner crashed (the claim expired) it is renewed exactly once; a claim is
// void at once when the node restarts, and a new term (leader failover)
// honours the previous term's claims until then.
func TestDeliveryClaimPreventsDuplicateRenewal(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	principal, org := uuid.New(), uuid.New()
	tx := newSignedTransfer(t, 0)
	f.admit(tx, principal, org, 20*time.Second) // a request is delivering it
	f.tick()
	if f.checker.count(principal) != 0 || f.node.deliveries(tx.hash) != 0 {
		t.Fatal("the keeper raced a claimed delivery")
	}
	// The request's instance crashed: its claim expires.
	if _, err := f.tracking.runtime.Conn().Exec(`UPDATE node_tx_binding SET claim_expires = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	f.skew.Add(int64(25 * time.Second))
	f.tick()
	f.tick()
	if f.checker.count(principal) != 1 || f.node.deliveries(tx.hash) != 1 {
		t.Fatalf("after the claim expired: checks=%d deliveries=%d, want 1/1", f.checker.count(principal), f.node.deliveries(tx.hash))
	}
	// Leader failover before the acknowledgement was written: the new term
	// honours the claim the old term took for this boot.
	f.r.reset()
	f.tick()
	if f.node.deliveries(tx.hash) != 1 {
		t.Fatal("a new term renewed a row the previous term had just claimed")
	}
	// The node restarts: the claim is void at once (for the confirmed new
	// boot) and the new term renews.
	f.mock.Restart(true)
	f.tick()
	f.tick()
	if f.node.deliveries(tx.hash) != 2 {
		t.Fatalf("not renewed after a restart: %d", f.node.deliveries(tx.hash))
	}
}

// G16: every refusal of the full re-check stops renewal with its reason (not
// final, no signature, no node call); an infrastructure error is retried.
func TestRenewalRerunsEveryAdmissionCheck(t *testing.T) {
	for _, reason := range []int16{db.TrackReasonPrincipalBanned, db.TrackReasonKYCMissing, db.TrackReasonNotMember, db.TrackReasonOrganizationDeleted, db.TrackReasonMethodNotAllowed, db.TrackReasonSenderUnlinked, db.TrackReasonComplianceDenied, db.TrackReasonPrincipalDeleted} {
		t.Run(db.TrackReasonName(reason), func(t *testing.T) {
			f := newKeeperFixture(t, time.Hour)
			principal, org := uuid.New(), uuid.New()
			tx := newSignedTransfer(t, 0)
			f.admit(tx, principal, org, 0)
			f.checker.refuse[principal] = reason
			f.tick()
			row := f.row(tx)
			if row.State != db.TrackRenewalStopped || row.Reason != reason || row.Final() || row.Generation != 1 || f.node.deliveries(tx.hash) != 0 {
				t.Fatalf("refusal: %+v deliveries=%d", row, f.node.deliveries(tx.hash))
			}
		})
	}
	t.Run("infrastructure_error", func(t *testing.T) {
		f := newKeeperFixture(t, time.Hour)
		principal, org := uuid.New(), uuid.New()
		tx := newSignedTransfer(t, 0)
		f.admit(tx, principal, org, 0)
		f.checker.fail[principal] = errors.New("database unavailable")
		f.tick()
		if row := f.row(tx); row.State != db.TrackPending || row.Generation != 1 || f.audit.count() != 0 {
			t.Fatalf("an infrastructure error decided: %+v", row)
		}
		delete(f.checker.fail, principal)
		f.skew.Add(int64(5 * time.Second))
		f.tick()
		if f.node.deliveries(tx.hash) != 1 {
			t.Fatal("not retried after the error cleared")
		}
	})
}

// G50 + G24: a renewal is appended to the durable audit buffer before it is
// recorded or sent; without the buffer nothing is decided (fail closed).
func TestSystemRenewalAuditedBeforeTransport(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	principal, org := uuid.New(), uuid.New()
	tx := newSignedTransfer(t, 0)
	f.admit(tx, principal, org, 0)
	f.audit.fail = true
	f.tick()
	if row := f.row(tx); row.Generation != 1 || f.node.deliveries(tx.hash) != 0 {
		t.Fatalf("decided without its audit event: %+v deliveries=%d", row, f.node.deliveries(tx.hash))
	}
	f.audit.fail = false
	f.skew.Add(int64(keeperAuditPause)) // renewals pause after an audit refusal
	f.tick()
	events := f.events("ops.system.recovery")
	if len(events) != 1 || f.node.deliveries(tx.hash) != 1 {
		t.Fatalf("renewal after the buffer recovered: %d events", len(events))
	}
	e := events[0]
	if e.ExternalID != "did:test:"+principal.String() || e.OrgID != org.String() || e.StatusCode != 200 || !strings.Contains(string(e.Params), `"actor":"system:identity-renewal"`) || !strings.Contains(string(e.Params), tx.hash) {
		t.Fatalf("event not on behalf of the principal: %+v %s", e, e.Params)
	}
}

// L12 + G9: a reorg before finality returns a provisional row to pending
// without a renewal (the node keeps the identity until finality); when the
// rival chain also dropped it from the pool, the eviction is detected and the
// keeper renews it once; it re-executes in a rival block, and after a leader
// failover the new term records it final exactly once, only at finality.
func TestReorgedProvisionalRowFinalizesOnce(t *testing.T) {
	f := newKeeperFixture(t, 3*time.Second)
	f.batched.Store(true)
	effects := &countingEffects{}
	f.r.main = effects
	principal, org := uuid.New(), uuid.New()
	tx := newSignedTransfer(t, 0)
	f.admit(tx, principal, org, 0)
	f.tick() // delivered
	f.flushAcks()
	f.mock.ProduceBlock()
	f.tick()
	if row := f.row(tx); row.State != db.TrackProvisional {
		t.Fatalf("not provisional: %+v", row)
	}
	if f.mock.Reorg(1, tx.hash) != 1 {
		t.Fatal("no reorg")
	}
	f.tick() // the canonical epoch changed: provisional rows are re-polled
	if row := f.row(tx); row.State != db.TrackPending {
		t.Fatalf("orphaned row not back to pending: %+v", row)
	}
	f.tick()
	if f.node.deliveries(tx.hash) != 1 {
		t.Fatal("renewed although the node still holds the identity and its boot")
	}
	// The rival chain dropped it from the pool: eviction recovery re-pools it.
	f.skew.Add(int64(time.Minute))
	f.tick()
	f.tick()
	if f.node.deliveries(tx.hash) != 2 {
		t.Fatalf("eviction after the reorg not renewed once: %d", f.node.deliveries(tx.hash))
	}
	f.mock.ProduceBlock()
	f.r.reset() // leader failover
	f.tick()
	if row := f.row(tx); row.State != db.TrackProvisional || effects.applied.Load() != 0 {
		t.Fatalf("after failover: %+v effects=%d", row, effects.applied.Load())
	}
	time.Sleep(3500 * time.Millisecond)
	f.mock.ProduceBlock()
	f.tick()
	f.tick()
	final, err := f.tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
	if err != nil || final.State != db.TrackIncluded {
		t.Fatalf("not final once: %+v %v", final, err)
	}
	if finals := f.events("ops.system.finalized"); len(finals) != 1 {
		t.Fatalf("finalized %d times", len(finals))
	}
}

type countingEffects struct {
	plainEffects
	applied atomic.Int64
}

func (c *countingEffects) ApplyNodeTxEffects(ctx context.Context, n nodepolicy.Network, e db.NodeTxEffects) (db.NodeTxEffectsResult, error) {
	c.applied.Add(1)
	return c.plainEffects.ApplyNodeTxEffects(ctx, n, e)
}

// A reorg whose rival chain keeps the transaction in the pool needs no
// renewal at all: the node re-executes it under the identity it kept.
func TestReorgKeepsIdentityWithoutRenewal(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	f.batched.Store(true)
	tx := newSignedTransfer(t, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.tick()
	f.flushAcks()
	f.mock.ProduceBlock()
	f.tick()
	if f.mock.Reorg(1) != 1 {
		t.Fatal("no reorg")
	}
	f.tick()
	if row := f.row(tx); row.State != db.TrackPending {
		t.Fatalf("not back to pending: %+v", row)
	}
	f.skew.Add(int64(time.Minute))
	f.tick()
	f.tick()
	f.mock.ProduceBlock()
	f.tick()
	if f.node.deliveries(tx.hash) != 1 || !f.receipt(tx) {
		t.Fatalf("renewed after a reorg the node absorbed: deliveries=%d included=%v", f.node.deliveries(tx.hash), f.receipt(tx))
	}
}

// A same-principal resubmission revives a stopped binding; the keeper
// notices it (a periodic re-read of stopped rows) and keeps it deliverable.
func TestRevivedBindingIsKeptDeliverable(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	principal, org := uuid.New(), uuid.New()
	tx := newSignedTransfer(t, 0)
	f.admit(tx, principal, org, 0)
	f.checker.refuse[principal] = db.TrackReasonMethodNotAllowed
	f.tick()
	if row := f.row(tx); row.State != db.TrackRenewalStopped {
		t.Fatalf("not stopped: %+v", row)
	}
	delete(f.checker.refuse, principal)
	f.admitAs(tx, principal, org, 0, db.AdmitRevived) // revival by the same principal (never sent)
	if row := f.row(tx); row.State != db.TrackPending {
		t.Fatalf("not revived: %+v", row)
	}
	f.skew.Add(int64(15 * time.Second))
	f.tick()
	f.tick()
	if f.node.deliveries(tx.hash) != 1 {
		t.Fatalf("revived binding not delivered by the keeper: %d", f.node.deliveries(tx.hash))
	}
}

// The steady-state renewal: a pending, delivered row whose lease is within
// the renewal margin gets a new identity (ops.system.identity_renewal).
func TestLeaseExpiringIsRenewed(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	tx := newSignedTransfer(t, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.tick()
	f.flushAcks()
	if _, err := f.tracking.runtime.Conn().Exec(`UPDATE node_tx_binding SET expires_at = clock_timestamp() + interval '30 seconds'`); err != nil {
		t.Fatal(err)
	}
	f.r.rows = nil // re-read (as a new term would)
	f.tick()
	renewals := f.events("ops.system.identity_renewal")
	if len(renewals) != 1 || !strings.Contains(string(renewals[0].Params), `"reason":"lease_expiring"`) || f.node.deliveries(tx.hash) != 2 {
		t.Fatalf("expiring lease not renewed: %d renewals, %d deliveries", len(renewals), f.node.deliveries(tx.hash))
	}
	if row := f.row(tx); time.Until(row.ExpiresAt) < 4*time.Minute {
		t.Fatalf("renewed lease too short: %s", row.ExpiresAt)
	}
}

// A node that keeps refusing a recorded generation (an answer, not an
// outage) stops renewal with the reason node_rejected instead of
// re-authorizing it until the maximum age.
func TestPersistentNodeRefusalStopsRenewal(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	tx := newSignedTransfer(t, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.node.refuse.Store(true)
	for i := 0; i < 6; i++ {
		f.skew.Add(int64(20 * time.Second))
		f.tick()
	}
	row := f.row(tx)
	if row.State != db.TrackRenewalStopped || row.Reason != db.TrackReasonNodeRejected || row.Final() {
		t.Fatalf("persistent refusal: %+v", row)
	}
	if renewals := f.events("ops.system.recovery"); len(renewals) != 1 {
		t.Fatalf("a refused generation was re-authorized: %d decisions", len(renewals))
	}
}

// A boot id that flaps between two answers (two nodes behind one URL) never
// starts a renewal pass: a new boot id is adopted only when a later read
// still reports it.
func TestFlappingBootIDNeverRenews(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	tx := newSignedTransfer(t, 0)
	f.admit(tx, uuid.New(), uuid.New(), 0)
	f.tick()
	f.flushAcks()
	real, _ := uuid.Parse(f.mock.BootID())
	other := uuid.New()
	flip := false
	read := uint64(0)
	f.k.boot = func() (uuid.UUID, bool, uint64) {
		read++
		flip = !flip
		if flip {
			return other, true, read
		}
		return real, true, read
	}
	for i := 0; i < 8; i++ {
		f.tick()
	}
	if f.node.deliveries(tx.hash) != 1 {
		t.Fatalf("a flapping boot id renewed: %d deliveries", f.node.deliveries(tx.hash))
	}
}

// setLease moves a binding's lease (and optionally its age) on the database
// clock.
func (f *keeperFixture) setLease(tx signedTransfer, remaining, age time.Duration) {
	f.t.Helper()
	if _, err := f.tracking.runtime.Conn().Exec(`UPDATE node_tx_binding SET expires_at = date_trunc('second', clock_timestamp()) + make_interval(secs => $2), created_at = clock_timestamp() - make_interval(secs => $3) WHERE tx_hash = $1`,
		hashBytes(f.t, tx.hash), remaining.Seconds(), age.Seconds()); err != nil {
		f.t.Fatal(err)
	}
}

// G17 (plan §4.8.2): a delivered pending transaction is renewed only once its
// lease is inside the renewal window (at most TTL/2 left), never earlier; a
// provisional or final row is never renewed; and near the maximum age, where a
// renewal could not extend the lease, the keeper waits for the stop instead of
// re-authorizing for nothing.
func TestRenewalOnlyInsideWindowAndNeverForProvisionalRows(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	outside, inside, provisional, capped := newSignedTransfer(t, 0), newSignedTransfer(t, 0), newSignedTransfer(t, 0), newSignedTransfer(t, 0)
	f.admit(provisional, uuid.New(), uuid.New(), 0)
	f.tick()              // delivered (undelivered trigger)
	f.mock.ProduceBlock() // included at the node…
	f.tick()              // …provisional at OPS (finality an hour away)
	if got := f.row(provisional); got.State != db.TrackProvisional {
		t.Fatalf("not provisional: %+v", got)
	}
	for _, tx := range []signedTransfer{outside, inside, capped} {
		f.admit(tx, uuid.New(), uuid.New(), 0)
	}
	f.tick() // delivered, still pending (no block)
	f.flushAcks()
	f.setLease(outside, 160*time.Second, time.Minute) // window opens at 150 s left
	f.setLease(inside, 140*time.Second, time.Minute)  // inside the window
	f.setLease(provisional, 20*time.Second, time.Minute)
	// Nine and a half minutes old, lease capped at the maximum age: a renewal
	// would end at the same instant.
	f.setLease(capped, 30*time.Second, 570*time.Second)
	f.r.rows = nil
	f.tick()
	f.tick()
	renewals := f.events("ops.system.identity_renewal")
	if len(renewals) != 1 || !strings.Contains(string(renewals[0].Params), strings.TrimPrefix(inside.hash, "0x")) {
		t.Fatalf("renewals %d: want exactly the transaction inside the window", len(renewals))
	}
	if got := f.row(inside); got.Generation != 3 || time.Until(got.ExpiresAt) < 4*time.Minute {
		t.Fatalf("renewed lease: %+v", got)
	}
	for _, tx := range []signedTransfer{outside, provisional, capped} {
		if got := f.row(tx); got.Generation != 2 {
			t.Fatalf("renewed outside the window, provisional or without gain: %s %+v", tx.hash, got)
		}
	}
	// The capped one stops at the maximum age (the keeper waits for it).
	f.setLease(capped, 0, 601*time.Second)
	f.r.rows = nil
	f.tick()
	if got := f.row(capped); got.State != db.TrackRenewalStopped || got.Reason != db.TrackReasonMaxAge {
		t.Fatalf("capped lease at the maximum age: %+v", got)
	}
}

// G25 (plan §4.8.2, §4.8.7): renewals are spent within the budget, earliest
// expiry first; the rest wait for the next tick and none is lost.
func TestRenewalBudgetEarliestExpiryFirst(t *testing.T) {
	f := newKeeperFixture(t, time.Hour)
	f.k.budget = 2
	var txs []signedTransfer
	for i := 0; i < 6; i++ {
		tx := newSignedTransfer(t, 0)
		f.admit(tx, uuid.New(), uuid.New(), 0)
		txs = append(txs, tx)
	}
	// Delivery of six undelivered rows is itself budgeted: 2 now, then 4/tick.
	for i := 0; i < 4 && f.mock.Stats().Pooled < 6; i++ {
		f.tick()
	}
	if f.mock.Stats().Pooled != 6 {
		t.Fatalf("undelivered rows not all delivered within the budget: %d", f.mock.Stats().Pooled)
	}
	f.flushAcks()
	before := len(f.events("ops.system.identity_renewal"))
	// Remaining leases 140 s, 130 s, …, 90 s: all inside the window.
	for i, tx := range txs {
		f.setLease(tx, time.Duration(140-10*i)*time.Second, time.Minute)
	}
	f.r.rows = nil
	f.k.tokens, f.k.tokensAt = 0, time.Time{} // a new term: one second's worth
	f.tick()
	first := f.events("ops.system.identity_renewal")[before:]
	if len(first) > 2*f.k.budget || len(first) == 0 {
		t.Fatalf("first tick renewed %d, budget %d/s over two seconds", len(first), f.k.budget)
	}
	// Earliest expiry first: the renewed ones are the latest-indexed (shortest leases).
	for _, e := range first {
		renewedLate := false
		for _, tx := range txs[6-len(first):] {
			renewedLate = renewedLate || strings.Contains(string(e.Params), strings.TrimPrefix(tx.hash, "0x"))
		}
		if !renewedLate {
			t.Fatalf("renewed out of expiry order: %s", e.Params)
		}
	}
	for i := 0; i < 4; i++ {
		f.tick()
	}
	if got := len(f.events("ops.system.identity_renewal")) - before; got != 6 {
		t.Fatalf("renewals deferred by the budget were lost or repeated: %d of 6", got)
	}
}

// The renewal budget holds its rate over slow ticks (a five-second tick
// accrues five seconds' worth) and an idle keeper banks at most its burst.
func TestRenewalBudgetAccrual(t *testing.T) {
	k := &nodeKeeper{budget: 10}
	at := time.Unix(1000, 0)
	k.refill(at)
	if got := k.spend(100); got != 10 {
		t.Fatalf("a new term starts with one second's worth: %d", got)
	}
	at = at.Add(5 * time.Second)
	k.refill(at)
	if got := k.spend(100); got != 50 {
		t.Fatalf("a five-second tick: %d renewals, want 50", got)
	}
	for i := 0; i < 30; i++ {
		at = at.Add(time.Second)
		k.refill(at)
	}
	if got := k.spend(1000); got != 20 {
		t.Fatalf("idle for 30 one-second ticks banked %d, want the 2 s burst (20)", got)
	}
	k.refund(3)
	if got := k.spend(1000); got != 3 {
		t.Fatalf("refunded renewals: %d", got)
	}
}

// A stopped transaction whose every recorded identity has expired by a
// finalized block that does not hold it can never execute (the node checks
// the identity at the block's timestamp, and OPS never renews a stopped
// binding): it becomes dropped with finalized_lease_expiry on two evidence
// reads, so stopped rows do not live for ever (independent review, finding
// 2). Not while the finalized block is earlier than the longest lease.
func TestStoppedTransactionDropsAfterFinalizedLeaseExpiry(t *testing.T) {
	for _, fromNode := range []bool{false, true} {
		name := "public_rpc"
		if fromNode {
			name = "node_evidence"
		}
		t.Run(name, func(t *testing.T) {
			f := newKeeperFixture(t, 0)
			if fromNode {
				f.batched.Store(true)
				f.k.chain = nil
			}
			key, _ := crypto.GenerateKey()
			principal, org := uuid.New(), uuid.New()
			ours := signTransfer(t, key, 5) // a nonce gap: never includable
			f.admit(ours, principal, org, 0)
			f.tick()
			f.flushAcks()
			if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonMaxAge}}); err != nil {
				t.Fatal(err)
			}
			f.r.rows = nil
			other := newSignedTransfer(t, 0) // another sender, to finalize blocks
			f.admit(other, uuid.New(), org, 0)
			f.tick()
			f.mock.ProduceBlock()
			f.mock.ProduceBlock()
			for i := 0; i < 3; i++ {
				f.skew.Add(int64(time.Minute))
				f.tick()
			}
			if row := f.row(ours); row.State != db.TrackRenewalStopped {
				t.Fatalf("dropped while a finalized block is before its lease expiry: %+v", row)
			}
			// Every recorded identity has expired; a later block is finalized.
			if _, err := f.tracking.runtime.Conn().Exec(`UPDATE node_tx_binding SET expires_at = clock_timestamp() - interval '1 hour', max_expires_at = clock_timestamp() - interval '1 hour' WHERE tx_hash = $1`, hashBytes(t, ours.hash)); err != nil {
				t.Fatal(err)
			}
			// The tracking database is younger than the longest identity
			// lifetime: an identity of an earlier incarnation (lost with
			// it) may still be valid, so nothing is decided yet.
			f.r.rows = nil
			for i := 0; i < 2; i++ {
				f.skew.Add(int64(time.Minute))
				f.tick()
			}
			if row := f.row(ours); row.State != db.TrackRenewalStopped {
				t.Fatalf("dropped within the longest identity lifetime of the tracking incarnation: %+v", row)
			}
			if _, err := f.tracking.runtime.Conn().Exec(`UPDATE tracking_meta SET created_at = clock_timestamp() - interval '1 hour'`); err != nil {
				t.Fatal(err)
			}
			f.r.rows, f.k.expiredAfter = nil, time.Time{}
			f.tick() // the first read past its longest lease
			if row := f.row(ours); row.State != db.TrackRenewalStopped {
				t.Fatalf("dropped on a single evidence read: %+v", row)
			}
			f.skew.Add(int64(time.Minute))
			f.tick()
			got := f.row(ours)
			if got.State != db.TrackDropped || got.Reason != db.TrackReasonFinalizedLeaseExpiry {
				t.Fatalf("not dropped after its last identity expired at a finalized block: %+v", got)
			}
			dropped := f.events("ops.system.dropped")
			if len(dropped) != 1 || dropped[0].DenialReason != "finalized_lease_expiry" {
				t.Fatalf("dropped audit %+v", dropped)
			}
			for _, want := range []string{`"max_expires_at":`, `"finalized_block_timestamp":`, `"receipt":false`, `"finalized_block_hash":"0x`} {
				if !strings.Contains(string(dropped[0].Params), want) {
					t.Fatalf("dropped audit event lacks %s: %s", want, dropped[0].Params)
				}
			}
			// The quota and shares are released, and the hash is never
			// admitted again while its status is kept.
			if used, pending, err := f.tracking.runtime.PendingQuota(context.Background()); err != nil || used != pending {
				t.Fatalf("quota %d/%d %v", used, pending, err)
			}
			if n, err := f.tracking.runtime.PendingQuotaMismatches(context.Background()); err != nil || n != 0 {
				t.Fatalf("share mismatches %d %v", n, err)
			}
			f.admitAs(ours, principal, org, 0, db.AdmitConflict)
		})
	}
}

// foreignEvidence reports a hash as executed (included, finalized) under
// another principal: a resubmission of a transaction that already executed.
type foreignEvidence struct {
	*nodepolicy.Client
	hash string
}

func (n foreignEvidence) TransactionEvidence(ctx context.Context, hashes, senders []string) (nodepolicy.TransactionStatusBatch, error) {
	batch, err := n.Client.TransactionEvidence(ctx, hashes, senders)
	if err != nil || batch.Finalized == nil {
		return batch, err
	}
	for i, h := range hashes {
		if h == n.hash {
			number, blockHash := batch.Finalized.Number, batch.Finalized.Hash
			batch.Statuses[i] = &nodepolicy.BatchedStatus{Status: nodepolicy.TransactionStatus{TransactionHash: h, PrincipalID: uuid.NewString(), OrgID: uuid.NewString(), ContextID: uuid.NewString(), BootID: batch.BootID,
				Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 9, BlockHash: &blockHash, BlockNumber: &number, Finalized: true, FinalizedBlockHash: &blockHash, FinalizedBlockNumber: &number, Created: []nodepolicy.CreatedContract{}}}}
			t := true
			batch.Receipts[i] = &t
		}
	}
	return batch, nil
}

// A stopped binding whose hash executed, finalized, under another submission
// (a shared signer resubmitting an executed transaction after its status was
// pruned) can never execute for this one: dropped, nonce_consumed (finding
// 2), instead of being polled for ever.
func TestStoppedResubmissionOfAnExecutedTransactionIsDropped(t *testing.T) {
	f := newKeeperFixture(t, 0)
	f.batched.Store(true)
	f.k.chain = nil
	key, _ := crypto.GenerateKey()
	ours := signTransfer(t, key, 3)
	f.r.node = foreignEvidence{Client: f.client, hash: ours.hash}
	f.admit(ours, uuid.New(), uuid.New(), 0)
	f.tick()
	if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonMaxAge}}); err != nil {
		t.Fatal(err)
	}
	f.r.rows = nil
	other := newSignedTransfer(t, 0)
	f.admit(other, uuid.New(), uuid.New(), 0)
	f.tick()
	f.mock.ProduceBlock()
	f.mock.ProduceBlock()
	for i := 0; i < 3; i++ {
		f.skew.Add(int64(time.Minute))
		f.tick()
	}
	got := f.row(ours)
	if got.State != db.TrackDropped || got.Reason != db.TrackReasonNonceConsumed {
		t.Fatalf("a stopped resubmission of an executed transaction: %+v", got)
	}
	if dropped := f.events("ops.system.dropped"); len(dropped) != 1 || !strings.Contains(string(dropped[0].Params), `"executed_by_another_submission":true`) {
		t.Fatalf("dropped audit %+v", dropped)
	}
}

// Stopped rows wait on a slow lane: a tick polls every due pending or
// provisional row first, and stopped rows only with the room left, so one
// principal's stopped rows never crowd out other tenants' polls (finding 2).
func TestStoppedRowsArePolledOnASlowLane(t *testing.T) {
	r := &nodeReconciler{now: time.Now, rows: map[string]*trackedRow{}}
	add := func(state int16) *trackedRow {
		hash := make([]byte, 32)
		_, _ = rand.Read(hash)
		row := &trackedRow{row: db.TrackedTransaction{Hash: hash, State: state}, hashHex: "0x" + hex.EncodeToString(hash)}
		r.rows[string(hash)] = row
		return row
	}
	for i := 0; i < 100; i++ {
		add(db.TrackRenewalStopped)
	}
	var pending []*trackedRow
	for i := 0; i < 10; i++ {
		pending = append(pending, add(db.TrackPending))
	}
	due := r.due(time.Now(), 20)
	polled := map[*trackedRow]bool{}
	stopped := 0
	for _, t := range due {
		polled[t] = true
		if t.row.State == db.TrackRenewalStopped {
			stopped++
		}
	}
	for _, row := range pending {
		if !polled[row] {
			t.Fatal("a pending row was crowded out by stopped rows")
		}
	}
	if len(due) != 19 || stopped != 9 {
		t.Fatalf("due %d rows (%d stopped), want 10 pending + 9 stopped", len(due), stopped)
	}
	// A stopped row's interval grows on the slow lane, also when the node no
	// longer knows it.
	now := time.Now()
	row := add(db.TrackRenewalStopped)
	r.apply(context.Background(), []observation{{tracked: row, err: nodepolicy.ErrNodeRejected}})
	first := row.nextPoll.Sub(now)
	r.apply(context.Background(), []observation{{tracked: row, err: nodepolicy.ErrNodeRejected}})
	if first < reconcileStoppedPoll-time.Second || row.nextPoll.Sub(now) <= first {
		t.Fatalf("slow lane %s then %s", first, row.nextPoll.Sub(now))
	}
}

// A dropped decision is re-judged on a fresh read before it is audited: a
// schedule entry whose longest lease is stale (renewed since it was read)
// appends no ops.system.dropped event for a final the database would refuse,
// and its evidence is read twice again (code review of finding 2).
func TestDroppedIsRejudgedOnAFreshReadBeforeItIsAudited(t *testing.T) {
	f := newKeeperFixture(t, 0)
	f.batched.Store(true)
	f.k.chain = nil
	key, _ := crypto.GenerateKey()
	ours := signTransfer(t, key, 5)
	f.admit(ours, uuid.New(), uuid.New(), 0)
	f.tick()
	if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonMaxAge}}); err != nil {
		t.Fatal(err)
	}
	f.r.rows = nil
	f.k.expiredAfter, f.k.expiredAfterInc = time.Unix(1, 0), f.writer.incarnation() // an incarnation older than any identity
	other := newSignedTransfer(t, 0)
	f.admit(other, uuid.New(), uuid.New(), 0)
	f.tick()
	f.mock.ProduceBlock()
	f.mock.ProduceBlock()
	f.tick()
	scheduled := f.r.rows[string(hashBytes(t, ours.hash))]
	if scheduled == nil || scheduled.row.State != db.TrackRenewalStopped {
		t.Fatalf("not scheduled as stopped: %+v", scheduled)
	}
	// The schedule believes every identity expired an hour ago; the
	// database knows a lease valid for minutes.
	scheduled.row.MaxExpiresAt = time.Now().Add(-time.Hour)
	scheduled.refreshAt = time.Now().Add(24 * time.Hour)
	for i := 0; i < 3; i++ {
		f.skew.Add(int64(time.Minute))
		f.tick()
	}
	if dropped := f.events("ops.system.dropped"); len(dropped) != 0 {
		t.Fatalf("dropped audited for a final the database refuses: %+v", dropped)
	}
	if row := f.row(ours); row.State != db.TrackRenewalStopped {
		t.Fatalf("dropped while an identity is valid: %+v", row)
	}
}

// fakeChain answers the public-RPC evidence: every hash has a receipt (the
// transaction is included) at a finalized block of now.
type fakeChain struct{}

func (fakeChain) DroppedEvidence(_ context.Context, _ uint64, _, _ string, hashes []string) (chainEvidence, error) {
	receipts := map[string]bool{}
	for _, h := range hashes {
		receipts[h] = true
	}
	return chainEvidence{Nonce: 9, Timestamp: time.Now(), Receipts: receipts}, nil
}

func (fakeChain) Known(_ context.Context, hashes []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, h := range hashes {
		out[h] = true
	}
	return out, nil
}

// foreignStatus answers the private status of one hash as included and
// finalized under another principal.
type foreignStatus struct {
	*nodepolicy.Client
	hash string
}

func (n foreignStatus) TransactionStatus(ctx context.Context, hash string) (nodepolicy.TransactionStatus, error) {
	if hash != n.hash {
		return n.Client.TransactionStatus(ctx, hash)
	}
	number, blockHash := uint64(1), "0x"+strings.Repeat("ab", 32)
	return nodepolicy.TransactionStatus{TransactionHash: hash, PrincipalID: uuid.NewString(), OrgID: uuid.NewString(), ContextID: uuid.NewString(), BootID: strings.Repeat("ab", 16),
		Execution: nodepolicy.ExecutionOutcome{Status: "included", FactsVersion: 9, BlockHash: &blockHash, BlockNumber: &number, Finalized: true, FinalizedBlockHash: &blockHash, FinalizedBlockNumber: &number, Created: []nodepolicy.CreatedContract{}}}, nil
}

// The executed-under-another-submission exit also works with the public-RPC
// evidence (security review of finding 2): otherwise such a stopped row
// would hold its owner's cap slot for ever.
func TestStoppedResubmissionIsDroppedWithPublicEvidence(t *testing.T) {
	f := newKeeperFixture(t, 0)
	key, _ := crypto.GenerateKey()
	ours := signTransfer(t, key, 3)
	f.admit(ours, uuid.New(), uuid.New(), 0)
	f.tick()
	if _, err := f.tracking.runtime.ApplyTransitions(context.Background(), f.writer.incarnation(), []db.TrackTransition{{Hash: hashBytes(t, ours.hash), From: db.TrackPending, To: db.TrackRenewalStopped, Reason: db.TrackReasonMaxAge}}); err != nil {
		t.Fatal(err)
	}
	f.r.rows = nil
	other := newSignedTransfer(t, 0) // learns a finalized head
	f.admit(other, uuid.New(), uuid.New(), 0)
	f.tick()
	f.mock.ProduceBlock()
	f.mock.ProduceBlock()
	f.tick()
	f.k.chain = fakeChain{}
	f.r.node = foreignStatus{Client: f.client, hash: ours.hash}
	for i := 0; i < 3; i++ {
		f.skew.Add(int64(time.Minute))
		f.tick()
	}
	got := f.row(ours)
	if got.State != db.TrackDropped || got.Reason != db.TrackReasonNonceConsumed {
		t.Fatalf("a stopped resubmission of an executed transaction (public evidence): %+v", got)
	}
	if dropped := f.events("ops.system.dropped"); len(dropped) != 1 || !strings.Contains(string(dropped[0].Params), `"executed_by_another_submission":true`) {
		t.Fatalf("dropped audit %+v", dropped)
	}
}
