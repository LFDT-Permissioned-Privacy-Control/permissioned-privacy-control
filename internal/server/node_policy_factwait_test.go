package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/nodepolicy"
)

// countingNode reports a fixed status and counts the status reads.
type countingNode struct {
	status nodepolicy.NodeStatus
	reads  atomic.Int32
}

type advancingFactClock struct {
	reads  int
	onRead func()
}

func (c *advancingFactClock) NodePolicyVersion(context.Context) (uint64, error) {
	c.reads++
	if c.reads == 1 {
		if c.onRead != nil {
			c.onRead()
		}
		return 7, nil
	}
	return 8, nil
}

// A fact commit and its publication can both finish after the first DB
// clock read. This is normal churn, not evidence of a foreign node feed.
func TestReadinessRechecksClockWhenPublicationOvertakesItsRead(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(map[bool]string{false: "request", true: "live readiness"}[live], func(t *testing.T) {
			now := time.Now()
			network := nodepolicy.Network{ChainID: 31337, DeploymentID: "clock-overtaken"}
			status := nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 8, Digest: strings.Repeat("a", 64), Ready: true, ExpiresAt: now.Add(time.Minute).Unix()}
			source := &advancingFactClock{}
			bridge, err := newNodeExecutionBridge(source, &countingNode{status: status}, nodepolicy.Signer{KeyID: "ops", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}, network, time.Minute, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			source.onRead = func() { bridge.cache.finish(bridge.cache.begin(now), status, nil) }
			var version uint64
			if live {
				version, _, err = bridge.executionStatus(context.Background())
			} else {
				version, _, _, err = bridge.readiness(context.Background())
			}
			if err != nil || version != 8 || source.reads < 2 {
				t.Fatalf("publication overtook clock: version=%d reads=%d error=%v", version, source.reads, err)
			}
		})
	}
}

func (n *countingNode) PolicyStatus(context.Context) (nodepolicy.NodeStatus, error) {
	n.reads.Add(1)
	return n.status, nil
}
func (n *countingNode) SubmitTransaction(context.Context, []byte, string) (nodepolicy.Submission, error) {
	return nodepolicy.Submission{}, nil
}
func (n *countingNode) Simulate(context.Context, []byte, []byte) (json.RawMessage, error) {
	return nil, nil
}

// While the node is behind the database version but otherwise ready, OPS
// lets the request through to the node's bounded wait (it advertises
// fact_wait_v1) for at most that wait after it first saw the node behind;
// it never refuses earlier itself, and refuses with ErrFactsPending, before
// any side effect, once the lag is older. A node without the wait is refused
// at once.
func TestBridgeLeavesYoungLagToTheNodesWait(t *testing.T) {
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "fact-wait"}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: "user-a", OrgID: "org-a", Signer: "0x" + strings.Repeat("11", 20), BindingHash: "0x" + strings.Repeat("22", 32)}
	for _, c := range []struct {
		name    string
		waits   bool
		age     time.Duration
		wantErr error
	}{
		{"young lag, node waits", true, 0, nil},
		{"lag older than the wait", true, nodeFactWaitBudget + time.Millisecond, nodepolicy.ErrFactsPending},
		{"node does not wait", false, 0, nodepolicy.ErrFactsPending},
	} {
		t.Run(c.name, func(t *testing.T) {
			now := time.Unix(1020, 0)
			status := nodepolicy.NodeStatus{ProtocolVersion: 1, Network: network, Capabilities: nodepolicy.RequiredCapabilities(), Version: 7, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}
			if c.waits {
				status.Capabilities = append(status.Capabilities, nodepolicy.CapabilityFactWait)
			}
			node := &countingNode{status: status}
			bridge, err := newNodeExecutionBridge(nodeVersionFixture{version: 8}, node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: key}, network, time.Minute, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			bridge.observe(context.Background())
			// The node was first seen behind age ago.
			if _, _, _, err := bridge.readiness(context.Background()); c.age == 0 && c.waits && err != nil {
				t.Fatal(err)
			}
			now = now.Add(c.age)
			reads := node.reads.Load()
			wire, err := bridge.PrepareIdentity(context.Background(), request)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("PrepareIdentity: %v, want %v", err, c.wantErr)
			}
			if c.wantErr == nil {
				if node.reads.Load() != reads {
					t.Fatal("a young lag the node waits on cost a status read on the request path")
				}
				v := nodepolicy.Verifier{Network: network, Keys: map[string]ed25519.PublicKey{"ops-a": key.Public().(ed25519.PublicKey)}, Now: func() time.Time { return now }}
				i, err := v.OpenIdentity(wire)
				if err != nil || i.MinSnapshotVersion != 8 {
					t.Fatalf("the identity must require the database version: %+v %v", i, err)
				}
			}
			// /ready agrees with the request path.
			s := &Server{config: &config.Config{NodePolicy: config.NodePolicyConfig{Mode: "reth"}}, nodeExecution: bridge}
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/ready", nil)
			s.handleReady(ctx)
			if want := map[bool]int{true: http.StatusOK, false: http.StatusServiceUnavailable}[c.wantErr == nil]; w.Code != want {
				t.Fatalf("/ready %d, want %d", w.Code, want)
			}
		})
	}
}

// G6: facts pending (the node's bounded wait expired, or a node without the
// wait is behind) is 503 with Retry-After: 1 and the publication_pending
// reason, for submissions and simulations alike; a policy rejection stays 403.
func TestFactsPendingMapsTo503WithRetryAfter(t *testing.T) {
	for _, c := range []struct {
		name, method string
		prepare      bool
	}{
		{"submission waits out", "eth_sendRawTransaction", false},
		{"simulation waits out", "eth_call", false},
		{"node without the wait is behind", "eth_sendRawTransaction", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, node, raw := nodeRPCFixture(t)
			params := []any{raw}
			if c.method == "eth_call" {
				params = []any{map[string]any{"to": nodeRPCTarget}}
			}
			if c.prepare {
				node.err = nodepolicy.ErrFactsPending
			} else {
				node.executionErr = nodepolicy.ErrFactsPending
			}
			got := p.Process(context.Background(), nodeRPCRequest(t, c.method, params))
			if got.Error == nil || got.Error.StatusCode != http.StatusServiceUnavailable || got.Error.RetryAfter != 1 || got.Error.Reason != ReasonPublicationPending {
				t.Fatalf("got %+v", got.Error)
			}
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			writeProcessErrorHeaders(ctx, got.Error)
			if w.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
			}
		})
	}
	if wireReason(ReasonPublicationPending) != ReasonPublicationPending {
		t.Fatal("publication_pending must reach verbose callers: it describes no tenant state")
	}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	writeProcessErrorHeaders(ctx, &ProcessError{StatusCode: http.StatusForbidden})
	if w.Header().Get("Retry-After") != "" {
		t.Fatal("Retry-After on an error that is not retryable")
	}
}

func waitingBridge(t *testing.T, dbVersion *atomic.Uint64, node *countingNode, now *time.Time) *nodeExecutionBridge {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	bridge, err := newNodeExecutionBridge(versionFunc(func() uint64 { return dbVersion.Load() }), node, nodepolicy.Signer{KeyID: "ops-a", PrivateKey: key}, node.status.Network, time.Minute, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	bridge.observe(context.Background())
	return bridge
}

type versionFunc func() uint64

func (f versionFunc) NodePolicyVersion(context.Context) (uint64, error) { return f(), nil }

func waitingStatus(version uint64) nodepolicy.NodeStatus {
	return nodepolicy.NodeStatus{ProtocolVersion: 1, Network: nodepolicy.Network{ChainID: 31337, DeploymentID: "fact-wait"}, Capabilities: append(nodepolicy.RequiredCapabilities(), nodepolicy.CapabilityFactWait),
		Version: version, Digest: strings.Repeat("a", 64), ExpiresAt: 1060, Ready: true}
}

var waitRequest = NodeExecutionIdentityRequest{Scope: "simulation", PrincipalID: "user-a", OrgID: "org-a", Signer: "0x" + strings.Repeat("11", 20), BindingHash: "0x" + strings.Repeat("22", 32)}

// Requests waiting on the node for facts hold transaction-lane connections,
// so at most maxFactWaiters go at once; the rest wait in OPS, holding no node
// connection, for the publication in flight (within the lag budget) and are
// refused with ErrFactsPending only when it does not arrive (F8); a slot
// frees when its node call returns.
func TestFactWaitersAreBoundedAndReleased(t *testing.T) {
	now := time.Unix(1020, 0)
	var dbVersion atomic.Uint64
	dbVersion.Store(8)
	bridge := waitingBridge(t, &dbVersion, &countingNode{status: waitingStatus(7)}, &now)
	var identities [][]byte
	for i := 0; i < maxFactWaiters; i++ {
		wire, err := bridge.PrepareIdentity(context.Background(), waitRequest)
		if err != nil {
			t.Fatalf("waiter %d: %v", i, err)
		}
		identities = append(identities, wire)
	}
	started := time.Now()
	if _, err := bridge.PrepareIdentity(context.Background(), waitRequest); !errors.Is(err, nodepolicy.ErrFactsPending) {
		t.Fatalf("waiter over the cap without a publication: %v, want ErrFactsPending", err)
	}
	if waited := time.Since(started); waited < nodeFactWaitBudget/2 {
		t.Fatalf("an over-cap waiter was refused after %v, not after waiting for the publication", waited)
	}
	// The publication lands while an over-cap request waits: it is admitted
	// at the new version, without a node fact wait.
	done := make(chan error, 1)
	go func() {
		_, err := bridge.PrepareIdentity(context.Background(), waitRequest)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	bridge.cache.applied(now, nodepolicy.AppliedState{Version: 8, Digest: strings.Repeat("b", 64), ExpiresAt: 1060})
	if err := <-done; err != nil {
		t.Fatalf("an over-cap request whose publication landed: %v", err)
	}
	if _, err := bridge.Simulate(context.Background(), identities[0], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.PrepareIdentity(context.Background(), waitRequest); err != nil {
		t.Fatalf("a returned node call did not free its slot: %v", err)
	}
}

func TestOverflowWaiterAcceptsACoalescedNewerPublication(t *testing.T) {
	now := time.Unix(1020, 0)
	var dbVersion atomic.Uint64
	dbVersion.Store(8)
	bridge := waitingBridge(t, &dbVersion, &countingNode{status: waitingStatus(7)}, &now)
	for i := 0; i < maxFactWaiters; i++ {
		if _, err := bridge.PrepareIdentity(context.Background(), waitRequest); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		wire []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		wire, err := bridge.PrepareIdentity(context.Background(), waitRequest)
		done <- result{wire, err}
	}()
	time.Sleep(50 * time.Millisecond)
	dbVersion.Store(9)
	bridge.cache.applied(now, nodepolicy.AppliedState{Version: 9, Digest: strings.Repeat("b", 64), ExpiresAt: 1060})
	got := <-done
	if got.err != nil {
		t.Fatalf("coalesced publication: %v", got.err)
	}
	var envelope nodepolicy.Envelope
	var identity nodepolicy.Identity
	if json.Unmarshal(got.wire, &envelope) != nil || json.Unmarshal(envelope.Payload, &identity) != nil || identity.MinSnapshotVersion != 9 {
		t.Fatalf("waiter did not require the refreshed clock: %+v", identity)
	}
}

// A lag episode lasts until the node reaches the version it was first seen
// behind: progress short of it opens no new window, nor does a restart to a
// lower version; reaching it does.
func TestLagEpisodeEndsOnlyWhenTheNodeReachesItsTarget(t *testing.T) {
	now := time.Unix(1020, 0)
	var dbVersion atomic.Uint64
	dbVersion.Store(9)
	node := &countingNode{status: waitingStatus(7)}
	bridge := waitingBridge(t, &dbVersion, node, &now)
	prepare := func() error {
		_, err := bridge.PrepareIdentity(context.Background(), waitRequest)
		bridge.releaseFactWait("") // slots are not under test here
		return err
	}
	if err := prepare(); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name        string
		nodeVersion uint64
		advance     time.Duration
		want        error
	}{
		{"still young", 8, 500 * time.Millisecond, nil},
		{"progress short of the target opens no window", 8, 600 * time.Millisecond, nodepolicy.ErrFactsPending},
		{"restart below the target opens no window", 6, 0, nodepolicy.ErrFactsPending},
		{"target reached, newer change: new window", 9, 0, nil},
	} {
		if step.name == "target reached, newer change: new window" {
			dbVersion.Store(10)
		}
		node.status = waitingStatus(step.nodeVersion)
		now = now.Add(step.advance)
		bridge.observe(context.Background())
		if err := prepare(); !errors.Is(err, step.want) {
			t.Fatalf("%s: %v, want %v", step.name, err, step.want)
		}
	}
}
