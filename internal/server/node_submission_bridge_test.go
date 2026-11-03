package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
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
)

var bridgeNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "bridge-test"}

// bridgeSource is the database fact version the bridge reads.
type bridgeSource struct{}

func (bridgeSource) NodePolicyVersion(context.Context) (uint64, error) { return 7, nil }

// recordingNode is a private node that records each submission and checks
// that the binding was durable before it was called.
type recordingNode struct {
	nodeClientFixture
	tracking  *testTracking
	calls     atomic.Int64
	submitErr error
	mu        sync.Mutex
	unbound   int // calls that found no binding row
}

func (n *recordingNode) SubmitTransaction(ctx context.Context, identity []byte, raw string) (nodepolicy.Submission, error) {
	n.calls.Add(1)
	var envelope nodepolicy.Envelope
	var i nodepolicy.Identity
	if json.Unmarshal(identity, &envelope) != nil || json.Unmarshal(envelope.Payload, &i) != nil {
		return nodepolicy.Submission{}, nodepolicy.ErrIdentity
	}
	hash, _ := hex.DecodeString(i.BindingHash[2:])
	if _, err := n.tracking.runtime.LookupTracked(ctx, hash); err != nil {
		n.mu.Lock()
		n.unbound++
		n.mu.Unlock()
		return nodepolicy.Submission{}, errors.New("node called before the binding was durable")
	}
	if n.submitErr != nil {
		return nodepolicy.Submission{}, n.submitErr
	}
	return nodepolicy.Submission{TransactionHash: i.BindingHash, ContextID: i.ContextID, Status: "accepted"}, nil
}

// signedTransfer is a signed raw transaction and its hash and sender.
type signedTransfer struct {
	raw, hash, signer string
}

func newSignedTransfer(t testing.TB, nonce uint64) signedTransfer {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return signTransfer(t, key, nonce)
}

func signTransfer(t testing.TB, k *ecdsa.PrivateKey, nonce uint64) signedTransfer {
	t.Helper()
	to := crypto.PubkeyToAddress(k.PublicKey)
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: nonce, To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)}), types.NewEIP155Signer(big.NewInt(31337)), k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return signedTransfer{raw: "0x" + hex.EncodeToString(raw), hash: strings.ToLower(tx.Hash().Hex()), signer: strings.ToLower(crypto.PubkeyToAddress(k.PublicKey).Hex())}
}

func newBridgeFixture(t *testing.T) (*nodeExecutionBridge, *recordingNode, *testTracking) {
	t.Helper()
	tracking := newTestTracking(t, bridgeNetwork)
	node := &recordingNode{tracking: tracking, nodeClientFixture: nodeClientFixture{status: nodepolicy.NodeStatus{ProtocolVersion: 1, Network: bridgeNetwork, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}}}
	bridge, err := newNodeExecutionBridge(bridgeSource{}, node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, bridgeNetwork, time.Minute, func() time.Time { return time.Unix(1020, 0) })
	if err != nil {
		t.Fatal(err)
	}
	bridge.tracking = newNodeTracking(tracking.runtime, tracking.meta.Incarnation, nil)
	ctx, cancel := context.WithCancel(context.Background())
	wait := bridge.tracking.run(ctx)
	t.Cleanup(func() { cancel(); wait() })
	return bridge, node, tracking
}

func (f signedTransfer) submit(t testing.TB, bridge *nodeExecutionBridge, principal, org string, visibleTo ...string) (nodepolicy.Submission, error) {
	t.Helper()
	wire, err := bridge.PrepareIdentity(context.Background(), NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: principal, OrgID: org, Signer: f.signer, BindingHash: f.hash})
	if err != nil {
		t.Fatal(err)
	}
	return bridge.SubmitTransaction(context.Background(), wire, f.raw, NodeSubmissionMetadata{SenderDID: "did:test:author", VisibleTo: visibleTo})
}

func hashBytes(t testing.TB, hash string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(hash, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNodeSubmissionBridgePersistsBeforeTransport: the binding is durable
// before the node is called, a tracking failure sends nothing, an ambiguous
// node failure keeps the binding, and -32012 releases a fresh one.
func TestNodeSubmissionBridgePersistsBeforeTransport(t *testing.T) {
	bridge, node, tracking := newBridgeFixture(t)
	principal, org := uuid.NewString(), uuid.NewString()

	ok := newSignedTransfer(t, 0)
	if _, err := ok.submit(t, bridge, principal, org, "did:test:recipient"); err != nil {
		t.Fatalf("accepted transaction reported failed: %v", err)
	}
	row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, ok.hash))
	if err != nil || row.PrincipalID.String() != principal || len(row.VisibleTo) != 1 || row.VisibleSender != "did:test:author" {
		t.Fatalf("durable binding lost: %+v %v", row, err)
	}

	node.submitErr = nodepolicy.ErrNodeUnavailable
	lost := newSignedTransfer(t, 0)
	if _, err := lost.submit(t, bridge, principal, org); err == nil {
		t.Fatal("ambiguous transport was claimed accepted")
	}
	if row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, lost.hash)); err != nil || row.State != db.TrackPending {
		t.Fatalf("an ambiguous failure must keep the pending binding: %+v %v", row, err)
	}

	node.submitErr = nodepolicy.ErrFactsPending
	refused := newSignedTransfer(t, 0)
	if _, err := refused.submit(t, bridge, principal, org); !errors.Is(err, nodepolicy.ErrFactsPending) {
		t.Fatalf("-32012 not surfaced: %v", err)
	}
	if _, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, refused.hash)); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("-32012 must not leave a stale pending binding: %v", err)
	}
	used, pending, err := tracking.runtime.PendingQuota(context.Background())
	if err != nil || used != pending || used != 2 {
		t.Fatalf("quota %d pending %d %v, want 2 = 2", used, pending, err)
	}

	// The tracking database failing: nothing is sent.
	calls := node.calls.Load()
	tracking.runtime.Close()
	down := newSignedTransfer(t, 0)
	if _, err := down.submit(t, bridge, principal, org); err == nil {
		t.Fatal("submission escaped without a durable binding")
	}
	if node.calls.Load() != calls || node.unbound != 0 {
		t.Fatal("the node was called without a durable binding")
	}
}

// TestSharedSignerCannotRebindAfterNodeRestart is G13: once P1's binding is
// durable, P2 sharing the signer is refused before transport, even when the
// node (restarted, empty registry) would accept its identity.
func TestSharedSignerCannotRebindAfterNodeRestart(t *testing.T) {
	bridge, node, _ := newBridgeFixture(t)
	org := uuid.NewString()
	tx := newSignedTransfer(t, 3)
	if _, err := tx.submit(t, bridge, uuid.NewString(), org); err != nil {
		t.Fatal(err)
	}
	calls := node.calls.Load()
	if _, err := tx.submit(t, bridge, uuid.NewString(), org); err == nil {
		t.Fatal("another principal rebound the transaction")
	}
	if node.calls.Load() != calls {
		t.Fatal("the conflicting identity reached the node")
	}
}

// countingTracking counts the tracking writes made through it.
type countingTracking struct {
	trackingStore
	admitted, released, flushed, transitions, finals atomic.Int64
}

func (c *countingTracking) AdmitBatch(ctx context.Context, inc uuid.UUID, limit int64, batch []db.TrackAdmission) ([]db.AdmitResult, error) {
	c.admitted.Add(int64(len(batch)))
	return c.trackingStore.AdmitBatch(ctx, inc, limit, batch)
}
func (c *countingTracking) FlushAcks(ctx context.Context, inc uuid.UUID, acks []db.TrackAck) (map[string]bool, error) {
	c.flushed.Add(int64(len(acks)))
	return c.trackingStore.FlushAcks(ctx, inc, acks)
}
func (c *countingTracking) ApplyTransitions(ctx context.Context, inc uuid.UUID, ts []db.TrackTransition) ([]bool, error) {
	c.transitions.Add(int64(len(ts)))
	return c.trackingStore.ApplyTransitions(ctx, inc, ts)
}
func (c *countingTracking) FinalizeBatch(ctx context.Context, inc uuid.UUID, fs []db.TrackFinal) ([]bool, error) {
	c.finals.Add(int64(len(fs)))
	return c.trackingStore.FinalizeBatch(ctx, inc, fs)
}

// TestAcceptedStateIsNotWrittenOnRequestPath is G14: a request writes its
// binding once (one admission) and nothing after the node accepted; the
// acknowledgement waits in memory for the next transition or the flush.
func TestAcceptedStateIsNotWrittenOnRequestPath(t *testing.T) {
	bridge, _, tracking := newBridgeFixture(t)
	counting := &countingTracking{trackingStore: tracking.runtime}
	bridge.tracking.store = counting
	const n = 20
	for i := 0; i < n; i++ {
		if _, err := newSignedTransfer(t, 0).submit(t, bridge, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	if got := counting.admitted.Load(); got != n {
		t.Fatalf("%d admissions for %d requests", got, n)
	}
	if counting.flushed.Load()+counting.transitions.Load()+counting.finals.Load() != 0 {
		t.Fatal("the request path wrote more than its binding")
	}
	var delivered int
	if err := tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_binding WHERE delivered_generation IS NOT NULL`).Scan(&delivered); err != nil || delivered != 0 {
		t.Fatalf("delivery recorded on the request path: %d %v", delivered, err)
	}
	// The flush writes the acknowledgements still pending, later, in a batch.
	bridge.tracking.flushAcks(context.Background(), time.Now().Add(time.Second))
	if err := tracking.runtime.Conn().QueryRow(`SELECT count(*) FROM node_tx_binding WHERE delivered_generation = 1`).Scan(&delivered); err != nil || delivered != n {
		t.Fatalf("flushed %d of %d acknowledgements: %v", delivered, n, err)
	}
}

// TestTrackingAdmissionGroupCommits: concurrent requests share commits — one
// commit per batch, not per transaction (plan §6.1, Q6 (a)) — and every one of
// them still waited for its own durable row before transport.
func TestTrackingAdmissionGroupCommits(t *testing.T) {
	bridge, node, tracking := newBridgeFixture(t)
	const n = 400
	transfers := make([]signedTransfer, n)
	wires := make([][]byte, n)
	org := uuid.NewString()
	for i := range transfers {
		transfers[i] = newSignedTransfer(t, 0)
		wire, err := bridge.PrepareIdentity(context.Background(), NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: uuid.NewString(), OrgID: org, Signer: transfers[i].signer, BindingHash: transfers[i].hash})
		if err != nil {
			t.Fatal(err)
		}
		wires[i] = wire
	}
	before := bridge.tracking.commits.Load()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range transfers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := bridge.SubmitTransaction(context.Background(), wires[i], transfers[i].raw, NodeSubmissionMetadata{SenderDID: "did:test:author"}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	commits := bridge.tracking.commits.Load() - before
	t.Logf("group commit: %d transactions in %d commits (%.3f commits per transaction)", n, commits, float64(commits)/n)
	if commits >= n/2 {
		t.Fatalf("%d commits for %d concurrent transactions: not group-committed", commits, n)
	}
	if node.unbound != 0 || tracking.count(t, "node_tx_binding") != n {
		t.Fatal("a request reached the node before its binding was durable")
	}
}
