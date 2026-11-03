package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

func nodePolicyTestDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = sharedTestDBURL(t)
	} else if err := db.EnsureTestDatabase(url); err != nil {
		t.Fatalf("PostgreSQL not available: %v", err)
	}
	database, err := db.New(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatal(err)
	}
	return database
}

func clockVersion(t *testing.T, d *db.DB) uint64 {
	t.Helper()
	v, err := d.NodePolicyVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// feedNode is an in-process private node: the Go reference fact stream behind
// the node's status and apply calls.
type feedNode struct {
	mu       sync.Mutex
	feed     nodepolicy.Feed
	verifier nodepolicy.Verifier
	network  nodepolicy.Network
	caps     []string
	applied  chan uint64
}

func newFeedNode(network nodepolicy.Network, signer nodepolicy.Signer) *feedNode {
	return &feedNode{network: network, caps: nodepolicy.RequiredCapabilities(), applied: make(chan uint64, 256),
		verifier: nodepolicy.Verifier{Network: network, Keys: map[string]ed25519.PublicKey{signer.KeyID: signer.PrivateKey.Public().(ed25519.PublicKey)}, Now: time.Now}}
}

func (n *feedNode) PolicyStatus(context.Context) (nodepolicy.NodeStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := nodepolicy.NodeStatus{ProtocolVersion: nodepolicy.ProtocolVersion, Network: n.network, Capabilities: slices.Clone(n.caps)}
	if v, err := n.feed.Pin(time.Now()); err == nil {
		s.Version, s.Digest, s.ExpiresAt, s.Ready = v.Version(), v.Digest(), v.Lease().ExpiresAt, true
	}
	return s, nil
}

func (n *feedNode) ApplyPolicy(_ context.Context, wire []byte) (nodepolicy.AppliedState, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.feed.Apply(n.verifier, wire); err != nil {
		return nodepolicy.AppliedState{}, err
	}
	v, err := n.feed.Pin(time.Now())
	if err != nil {
		return nodepolicy.AppliedState{}, err
	}
	select {
	case n.applied <- v.Version():
	default:
	}
	return nodepolicy.AppliedState{Version: v.Version(), Digest: v.Digest(), ExpiresAt: v.Lease().ExpiresAt}, nil
}

func (n *feedNode) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	return nodepolicy.Submission{}, nodepolicy.ErrNodeUnavailable
}
func (n *feedNode) Simulate(context.Context, []byte, []byte) (json.RawMessage, error) {
	return nil, nodepolicy.ErrNodeUnavailable
}

// drainApplied forgets the publications seen so far.
func (n *feedNode) drainApplied() {
	for {
		select {
		case <-n.applied:
		default:
			return
		}
	}
}

// waitApplied waits until the node has applied at least version.
func (n *feedNode) waitApplied(t *testing.T, version uint64, within time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := time.After(within)
	for {
		select {
		case v := <-n.applied:
			if v >= version {
				return time.Since(start)
			}
		case <-deadline:
			t.Fatalf("version %d not applied within %v", version, within)
			return 0
		}
	}
}

type publicationHarness struct {
	db        *db.DB
	node      *feedNode
	publisher *nodepolicy.Publisher
	wake      chan struct{}
	kicks     chan struct{}
}

func newPublicationHarness(t *testing.T) *publicationHarness {
	t.Helper()
	database := nodePolicyTestDB(t)
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "notify-" + uuid.NewString()[:8]}
	signer := nodepolicy.Signer{KeyID: "ops-notify", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	h := &publicationHarness{db: database, node: newFeedNode(network, signer), wake: make(chan struct{}, 1), kicks: make(chan struct{}, 64)}
	p, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: "producer-" + uuid.NewString()[:8], Signer: signer, Source: database, Node: h.node, Lifetime: time.Minute, Wake: h.wake})
	if err != nil {
		t.Fatal(err)
	}
	h.publisher = p
	return h
}

// listen runs the notification wiring until the returned stop is called.
func (h *publicationHarness) listen() (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runNodePolicyNotifications(ctx, h.db.ListenNodePolicy, h.wake, func() {
			select {
			case h.kicks <- struct{}{}:
			default:
			}
		})
	}()
	return func() { cancel(); <-done }
}

func (h *publicationHarness) run(interval time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = h.publisher.Run(ctx, interval, nil) }()
	return func() { cancel(); <-done }
}

func (h *publicationHarness) user(t *testing.T) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := h.db.Conn().ExecContext(context.Background(), `INSERT INTO users(id,external_id,kyc) VALUES($1::uuid,'did:test:notify-'||$1::text,true)`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (h *publicationHarness) toggle(t *testing.T, user string) uint64 {
	t.Helper()
	if _, err := h.db.Conn().ExecContext(context.Background(), `UPDATE users SET banned=NOT banned WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	return clockVersion(t, h.db)
}

// G3 end to end: with a 20 s heartbeat, a committed fact change reaches the
// node through LISTEN/NOTIFY, and the acknowledgement kicks the status probe
// on every instance. The latency figures are logged for the report.
func TestFactChangeReachesNodeOnNotification(t *testing.T) {
	h := newPublicationHarness(t)
	user := h.user(t)
	defer h.listen()()
	defer h.run(20 * time.Second)()
	h.node.waitApplied(t, clockVersion(t, h.db), 5*time.Second)
	var latencies []time.Duration
	for i := 0; i < 25; i++ {
		start := time.Now()
		version := h.toggle(t, user)
		h.node.waitApplied(t, version, 5*time.Second)
		latencies = append(latencies, time.Since(start))
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50, max := latencies[len(latencies)/2], latencies[len(latencies)-1]
	t.Logf("fact change -> node applied: p50 %v, max %v over %d changes (heartbeat 20 s)", p50, max, len(latencies))
	if max > 2*time.Second {
		t.Fatalf("publication waited for the timer: max %v", max)
	}
	// The acknowledgement of a publication refreshes the node status cache
	// (every instance gets it; this one is not the only reader).
	time.Sleep(100 * time.Millisecond) // let the last acknowledgement's notification arrive
	for len(h.kicks) > 0 {
		<-h.kicks
	}
	h.node.waitApplied(t, h.toggle(t, user), 5*time.Second)
	select {
	case <-h.kicks:
	case <-time.After(2 * time.Second):
		t.Fatal("an acknowledgement did not refresh the node status cache")
	}
}

// G4: without notifications the heartbeat timer still publishes; after the
// listener's connection is killed it resubscribes and catches up at once.
func TestPublisherFallsBackToTimerAfterListenLoss(t *testing.T) {
	h := newPublicationHarness(t)
	user := h.user(t)
	stopListen := h.listen()
	stopRun := h.run(20 * time.Second)
	h.node.waitApplied(t, clockVersion(t, h.db), 5*time.Second)

	// The listener's connection dies; the change committed in the gap is
	// published by the resubscription's catch-up, long before the 20 s
	// heartbeat.
	if _, err := h.db.Conn().ExecContext(context.Background(), `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1`, db.NodePolicyListenerApplication); err != nil {
		t.Fatal(err)
	}
	h.node.waitApplied(t, h.toggle(t, user), 3*time.Second)
	stopRun()

	// LISTEN gone for good: the heartbeat timer publishes.
	stopListen()
	h.node.drainApplied()
	defer h.run(time.Second)()
	h.node.waitApplied(t, clockVersion(t, h.db), 5*time.Second) // Run's first tick
	took := h.node.waitApplied(t, h.toggle(t, user), 5*time.Second)
	t.Logf("without LISTEN the timer published in %v (interval 1 s)", took)
	if took < 300*time.Millisecond {
		t.Fatalf("published in %v without LISTEN: not the timer", took)
	}
}

// G7: a revocation committed before a request raises that request's minimum
// fact version: the identity carries the clock read after the commit, never a
// cached one, so the node cannot execute it on facts from before the
// revocation.
func TestRevocationCommittedBeforeRequestRaisesMinVersion(t *testing.T) {
	database := nodePolicyTestDB(t)
	ctx := context.Background()
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "g7"}
	signer := nodepolicy.Signer{KeyID: "ops-g7", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	user := uuid.NewString()
	did := "did:test:g7-" + user
	address := "0x" + strings.Repeat("71", 20)
	if _, err := database.Conn().ExecContext(ctx, `INSERT INTO users(id,external_id,kyc) VALUES($1,$2,true)`, user, did); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Conn().ExecContext(ctx, `INSERT INTO eth_address_links(did,eth_address,link_type) VALUES($1,$2,'system')`, did, address); err != nil {
		t.Fatal(err)
	}
	node := newFeedNode(network, signer)
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: "g7", Signer: signer, Source: database, Node: node, Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	bridge, err := newNodeExecutionBridge(database, node, signer, network, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: user, OrgID: uuid.NewString(), Signer: address, BindingHash: "0x" + strings.Repeat("72", 32)}
	minVersion := func() uint64 {
		t.Helper()
		wire, err := bridge.PrepareIdentity(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		i, err := node.verifier.OpenIdentity(wire)
		if err != nil {
			t.Fatal(err)
		}
		return i.MinSnapshotVersion
	}
	before := minVersion()
	if _, err := database.Conn().ExecContext(ctx, `UPDATE eth_address_links SET revoked=true WHERE did=$1`, did); err != nil {
		t.Fatal(err)
	}
	revoked := clockVersion(t, database)
	if revoked <= before {
		t.Fatal("revocation did not advance the fact clock")
	}
	// A node that waits for facts (fact_wait_v1) gets the request before it
	// applied the revocation: the identity still requires the revoked
	// version, so the node cannot execute it on the older facts.
	node.mu.Lock()
	node.caps = append(node.caps, nodepolicy.CapabilityFactWait)
	node.mu.Unlock()
	if got := minVersion(); got != revoked {
		t.Fatalf("request before the node applied the revocation carries min version %d, want %d", got, revoked)
	}
	// The node has applied the revocation by the time the request runs.
	if err := publisher.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := minVersion(); got != revoked {
		t.Fatalf("request after the revocation carries min version %d, want %d", got, revoked)
	}
}
