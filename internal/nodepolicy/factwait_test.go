package nodepolicy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/perfgate"
)

// The node answers -32012 when its bounded wait for the identity's minimum
// fact version expired (RD-1411 §5.3): a retryable "facts pending", never a
// policy rejection.
func TestClientMapsFactWaitExpiryToFactsPending(t *testing.T) {
	_, identity, rawTx := signedSubmissionFixture(t, false)
	for code, want := range map[int]error{-32012: ErrFactsPending, -32000: ErrNodeRejected} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": code, "message": "x"}})
		}))
		c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.SubmitTransaction(context.Background(), identity, rawTx)
		s.Close()
		if !errors.Is(err, want) {
			t.Fatalf("code %d: %v, want %v", code, err, want)
		}
		if code == -32012 && errors.Is(err, ErrNodeRejected) {
			t.Fatal("facts pending reported as a node rejection")
		}
	}
	// Only an execution waits for facts: -32012 on a status read is no
	// "facts pending" a client could be told to retry.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32012, "message": "x"}})
	}))
	defer s.Close()
	c, err := NewClient(s.URL, "private-test-token", identityFixture().Network, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PolicyStatus(context.Background()); errors.Is(err, ErrFactsPending) || !errors.Is(err, ErrNodeRejected) {
		t.Fatalf("status read: %v", err)
	}
}

func TestNodeStatusReportsTheFactWait(t *testing.T) {
	s := NodeStatus{Capabilities: RequiredCapabilities()}
	if s.WaitsForFacts() {
		t.Fatal("a node without fact_wait_v1 waits")
	}
	s.Capabilities = append(s.Capabilities, CapabilityFactWait)
	if !s.WaitsForFacts() || slices.Contains(RequiredCapabilities(), CapabilityFactWait) {
		t.Fatal("fact_wait_v1 is optional and detected")
	}
}

// The gate-2 mock waits for an identity's minimum fact version like the node
// (T14): it executes once the facts arrive within the wait, and answers
// -32012 when they do not.
func TestPerfgateMockWaitsForMinimumFacts(t *testing.T) {
	network := Network{ChainID: 31337, DeploymentID: "perfgate-wait"}
	node := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: network.ChainID, DeploymentID: network.DeploymentID, PrivateToken: "private-token-0123456789", FactWait: 300 * time.Millisecond})
	server := httptest.NewServer(node.Private())
	defer server.Close()
	client, err := NewClient(server.URL, "private-token-0123456789", network, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	source := &memorySource{snapshot: snapshotFixture()}
	signer := testSigner()
	publisher, err := NewPublisher(PublisherConfig{Network: network, ConsumerID: "producer", Signer: signer, Source: source, Node: client, Lifetime: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if status, err := client.PolicyStatus(ctx); err != nil || !status.WaitsForFacts() {
		t.Fatalf("mock does not advertise the wait: %+v %v", status, err)
	}
	submit := func(nonce uint64, minVersion uint64) error {
		key, _ := crypto.GenerateKey()
		to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(31337), Nonce: nonce, Gas: 21_000, GasFeeCap: big.NewInt(3e9), GasTipCap: big.NewInt(1e6), To: &to, Value: big.NewInt(1)}), types.LatestSignerForChainID(big.NewInt(31337)), key)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		now := time.Now()
		wire, err := signer.Seal("identity", Identity{Header: Header{Network: network, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}, Scope: "transaction", ContextID: "11111111-1111-4111-8111-111111111111",
			PrincipalID: "22222222-2222-4222-8222-222222222222", OrgID: "33333333-3333-4333-8333-333333333333", Signer: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()), BindingHash: strings.ToLower(tx.Hash().Hex()), MinSnapshotVersion: minVersion})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.SubmitTransaction(ctx, wire, "0x"+hex.EncodeToString(raw))
		return err
	}
	if err := submit(0, source.snapshot.Version); err != nil {
		t.Fatalf("current facts: %v", err)
	}
	start := time.Now()
	if err := submit(0, source.snapshot.Version+1); !errors.Is(err, ErrFactsPending) || time.Since(start) < 300*time.Millisecond {
		t.Fatalf("facts never arrived: %v after %v, want ErrFactsPending after the wait", err, time.Since(start))
	}
	// The facts arrive during the wait: the submission executes.
	source.snapshot.Version++
	source.snapshot.Principals[0].Banned = true
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = publisher.Tick(ctx)
	}()
	if err := submit(0, source.snapshot.Version); err != nil {
		t.Fatalf("facts published during the wait: %v", err)
	}
}
