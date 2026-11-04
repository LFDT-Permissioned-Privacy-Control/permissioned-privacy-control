package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/perfgate"
	"privacy-proxy/internal/rbac"
)

// timedFactNode records when each fact version was sent to the node and when
// the node acknowledged it.
type timedFactNode struct {
	nodepolicy.FactNode
	mu      sync.Mutex
	sent    map[uint64]time.Time
	applied map[uint64]time.Time
}

func (n *timedFactNode) ApplyPolicy(ctx context.Context, wire []byte) (nodepolicy.AppliedState, error) {
	start := time.Now()
	ack, err := n.FactNode.ApplyPolicy(ctx, wire)
	if err == nil {
		n.mu.Lock()
		if _, seen := n.applied[ack.Version]; !seen {
			n.sent[ack.Version], n.applied[ack.Version] = start, time.Now()
		}
		n.mu.Unlock()
	}
	return ack, err
}

// appliedBy is when the node first held version v or a later one.
func (n *timedFactNode) appliedBy(v uint64) (sent, applied time.Time, ok bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for version, at := range n.applied {
		if version >= v && (!ok || at.Before(applied)) {
			sent, applied, ok = n.sent[version], at, true
		}
	}
	return sent, applied, ok
}

// Under churn of one deployment and one membership change per second, every
// fact version reaches the node quickly (P7 L5, finding F8): commit →
// published → applied is measured per version with the real publisher, the
// real fact export and notifications on PostgreSQL, and the mock node.
func TestFactPublicationKeepsUpWithChurn(t *testing.T) {
	database := nodePolicyTestDB(t)
	ctx := context.Background()
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "churn-" + uuid.NewString()[:8]}
	signer := nodepolicy.Signer{KeyID: "ops-churn", PrivateKey: ed25519.NewKeyFromSeed(make([]byte, 32))}
	token := "private-token-0123456789"
	// Every node call takes 40 ms, as on a loaded node and network (P7 L5).
	const nodeLatency = 40 * time.Millisecond
	mock := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: network.ChainID, DeploymentID: network.DeploymentID, PrivateToken: token, Latency: nodeLatency})
	private := httptest.NewServer(mock.Private())
	t.Cleanup(private.Close)
	client, err := nodepolicy.NewPooledClient(private.URL, token, network, nodepolicy.DefaultLanes())
	if err != nil {
		t.Fatal(err)
	}
	node := &timedFactNode{FactNode: client, sent: map[uint64]time.Time{}, applied: map[uint64]time.Time{}}
	// The request path's view of the node, as in production: the publisher's
	// node feeds the status cache, and a one-second probe plus the applied
	// notification refresh it.
	bridge, err := newNodeExecutionBridge(database, client, signer, network, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	wake := make(chan struct{}, 1)
	publisher, err := nodepolicy.NewPublisher(nodepolicy.PublisherConfig{Network: network, ConsumerID: "churn-" + uuid.NewString()[:8], Signer: signer, Source: database, Node: observingFactNode{node: node, bridge: bridge}, Lifetime: 30 * time.Second, Wake: wake})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureNodeTxEffectsFloor(ctx, network); err != nil {
		t.Fatal(err)
	}
	// A deploying organization with a deploy group and its member, and the
	// principal whose membership churns.
	org := uuid.NewString()
	if err := database.CreateOrganization(ctx, &rbac.Organization{ID: org, Slug: "churn-" + org[:8], Name: "Churn"}); err != nil {
		t.Fatal(err)
	}
	group := &rbac.Group{ID: uuid.NewString(), OrgID: org, Slug: "deployers-" + org[:8], Name: "Deployers", Path: "deployers"}
	if err := database.CreateGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Conn().ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims) VALUES($1,$2,$3,$4)`, uuid.NewString(), group.ID, []string{"eth_sendRawTransaction"}, []string{"deploy"}); err != nil {
		t.Fatal(err)
	}
	user := func() string {
		id := uuid.NewString()
		if _, err := database.Conn().ExecContext(ctx, `INSERT INTO users(id,external_id,kyc) VALUES($1::uuid,'did:test:churn-'||$1::text,true)`, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	deployer, member := user(), user()
	if err := database.CreateMembership(ctx, &rbac.UserMembership{ID: uuid.NewString(), UserID: deployer, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}); err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runNodePolicyNotifications(runCtx, database.ListenNodePolicy, wake, bridge.kickProbe)
	}()
	go func() { defer wg.Done(); _ = publisher.Run(runCtx, time.Second, nil) }()
	waitProbe := bridge.startStatusProbe(runCtx, time.Second)
	defer func() { cancel(); wg.Wait(); waitProbe() }()
	waitApplied := func(v uint64, within time.Duration) bool {
		deadline := time.Now().Add(within)
		for time.Now().Before(deadline) {
			if _, _, ok := node.appliedBy(v); ok {
				return true
			}
			time.Sleep(2 * time.Millisecond)
		}
		return false
	}
	if !waitApplied(clockVersion(t, database), 10*time.Second) {
		t.Fatal("initial facts not applied")
	}

	// An unaffected principal sends 150 transactions per second throughout:
	// each takes an identity at the current fact version; one the node must
	// wait for holds its fact-wait slot until the node has the version (as
	// the node's own bounded wait does), and a refusal is a 503 to the client.
	var requests, refused, waited int
	var requestsMu sync.Mutex
	requestsDone := make(chan struct{})
	go func() {
		defer close(requestsDone)
		ticker := time.NewTicker(time.Second / 150)
		defer ticker.Stop()
		var inflight sync.WaitGroup
		defer inflight.Wait()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
			inflight.Add(1)
			go func() {
				defer inflight.Done()
				request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: member, OrgID: org, Signer: "0x" + strings.Repeat("ab", 20), BindingHash: "0x" + strings.Repeat("cd", 32)}
				wire, err := bridge.PrepareIdentity(runCtx, request)
				requestsMu.Lock()
				requests++
				if err != nil {
					if runCtx.Err() == nil {
						refused++
					}
					requestsMu.Unlock()
					return
				}
				requestsMu.Unlock()
				identity, err := (&nodepolicy.Verifier{Network: network, Keys: map[string]ed25519.PublicKey{signer.KeyID: signer.PrivateKey.Public().(ed25519.PublicKey)}}).OpenIdentity(wire)
				if err != nil {
					t.Error(err)
					return
				}
				deadline := time.Now().Add(time.Second)
				if _, _, ok := node.appliedBy(identity.MinSnapshotVersion); !ok {
					requestsMu.Lock()
					waited++
					requestsMu.Unlock()
					for time.Now().Before(deadline) {
						if _, _, ok := node.appliedBy(identity.MinSnapshotVersion); ok {
							break
						}
						time.Sleep(2 * time.Millisecond)
					}
				}
				time.Sleep(nodeLatency) // the submission's own answer
				bridge.releaseFactWait(identity.ContextID)
			}()
		}
	}()

	type change struct {
		kind      string
		version   uint64
		committed time.Time
	}
	var changes []change
	membership := ""
	for i := 0; i < 40; i++ {
		next := time.Now().Add(500 * time.Millisecond)
		start := time.Now()
		kind := "deployment"
		if i%2 == 0 {
			address := fmt.Sprintf("0x%040x", i+1)
			if _, err := database.ApplyNodeTxEffects(ctx, network, db.NodeTxEffects{TransactionHash: "0x" + strings.Repeat("0", 62) + fmt.Sprintf("%02x", i+1), PrincipalID: deployer, OrgID: org, BlockNumber: uint64(10 + i), Ownership: true,
				Created: []nodepolicy.CreatedContract{{Address: address, OrgID: org, PrincipalID: deployer}}}); err != nil {
				t.Fatal(err)
			}
		} else {
			kind = "membership"
			if membership == "" {
				membership = uuid.NewString()
				if err := database.CreateMembership(ctx, &rbac.UserMembership{ID: membership, UserID: member, GroupID: group.ID, Source: rbac.MembershipSourceAdmin}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := database.Conn().ExecContext(ctx, `DELETE FROM user_memberships WHERE id = $1`, membership); err != nil {
					t.Fatal(err)
				}
				membership = ""
			}
		}
		changes = append(changes, change{kind: kind, version: clockVersion(t, database), committed: start})
		time.Sleep(time.Until(next))
	}
	cancel()
	<-requestsDone
	var lags, sends []time.Duration
	var late []string
	for _, c := range changes {
		if !waitApplied(c.version, 10*time.Second) {
			t.Fatalf("%s version %d never applied", c.kind, c.version)
		}
		sent, applied, _ := node.appliedBy(c.version)
		lag := applied.Sub(c.committed)
		lags, sends = append(lags, lag), append(sends, sent.Sub(c.committed))
		if lag > time.Second {
			late = append(late, fmt.Sprintf("%s v%d %v", c.kind, c.version, lag))
		}
	}
	sort.Slice(lags, func(i, j int) bool { return lags[i] < lags[j] })
	sort.Slice(sends, func(i, j int) bool { return sends[i] < sends[j] })
	p50, p95, worst := lags[len(lags)/2], lags[len(lags)*95/100], lags[len(lags)-1]
	t.Logf("fact change -> node applied over %d changes: p50 %v, p95 %v, max %v (commit -> sent p95 %v); later than the 1 s fact wait: %v", len(lags), p50, p95, worst, sends[len(sends)*95/100], late)
	t.Logf("unaffected requests: %d, refused %d, waited for facts %d", requests, refused, waited)
	if len(late) > 0 || p95 > 150*time.Millisecond { // target 100 ms; each node call here takes 40 ms
		t.Fatalf("publication lags under churn: p95 %v, beyond the fact wait %v", p95, late)
	}
	if refused != 0 || requests < 2000 {
		t.Fatalf("%d of %d unaffected requests refused under churn", refused, requests)
	}
}
