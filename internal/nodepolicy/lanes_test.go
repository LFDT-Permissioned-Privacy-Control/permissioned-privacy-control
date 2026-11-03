package nodepolicy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"privacy-proxy/internal/perfgate"
)

const laneToken = "private-token-0123456789"

// countingNode serves handler and counts the TCP connections clients open.
func countingNode(t *testing.T, handler http.Handler) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var opened atomic.Int64
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			opened.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	return server, &opened
}

// signedSubmissions returns n distinct (identity, raw transaction) pairs for
// the perfgate mock node.
func signedSubmissions(t *testing.T, network Network, n int) ([][]byte, []string) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	from := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	chain := new(big.Int).SetUint64(network.ChainID)
	identities, raws := make([][]byte, n), make([]string, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: chain, Nonce: uint64(i), Gas: 21_000, GasFeeCap: big.NewInt(3e9), GasTipCap: big.NewInt(1e6), To: &to, Value: big.NewInt(1)}), types.LatestSignerForChainID(chain), key)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := tx.MarshalBinary()
		identities[i], err = testSigner().Seal("identity", Identity{Header: Header{Network: network, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}, Scope: "transaction",
			ContextID: fmt.Sprintf("11111111-1111-4111-8111-%012d", i), PrincipalID: "22222222-2222-4222-8222-222222222222", OrgID: "33333333-3333-4333-8333-333333333333",
			Signer: from, BindingHash: strings.ToLower(tx.Hash().Hex()), MinSnapshotVersion: 1})
		if err != nil {
			t.Fatal(err)
		}
		raws[i] = "0x" + hex.EncodeToString(raw)
	}
	return identities, raws
}

// G8 (RD-1410): the client built for production keeps its
// connections to the private node alive. At 64 concurrent submissions, round
// after round, it never opens more connections than its pools hold; the old
// http.DefaultTransport (2 idle connections per host) opened and discarded one
// per call above two.
func TestNodePolicyClientUsesPooledTransport(t *testing.T) {
	network := Network{ChainID: 31337, DeploymentID: "lanes-test"}
	node := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: network.ChainID, DeploymentID: network.DeploymentID, PrivateToken: laneToken, Latency: 2 * time.Millisecond})
	server, opened := countingNode(t, node.Private())
	client, err := NewClient(server.URL, laneToken, network, nil)
	if err != nil {
		t.Fatal(err)
	}
	const workers, rounds = 64, 5
	identities, raws := signedSubmissions(t, network, workers*rounds)
	ctx := context.Background()
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			i := round*workers + w
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := client.SubmitTransaction(ctx, identities[i], raws[i]); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: %v", round, err)
		}
		if _, err := client.PolicyStatus(ctx); err != nil {
			t.Fatal(err)
		}
	}
	lanes := DefaultLanes()
	if limit := int64(min(workers, lanes.Transaction) + lanes.Control); opened.Load() > limit {
		t.Fatalf("%d connections opened for %d calls, want <= %d: the client churns connections", opened.Load(), workers*rounds+rounds, limit)
	}
}

// RD-1410: control calls (fact publication, readiness) never queue behind
// transaction calls, and recovery calls have their own lane too.
func TestNodePolicyLanesIsolateControlFromTransactions(t *testing.T) {
	network := Network{ChainID: 31337, DeploymentID: "lanes-test"}
	node := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: network.ChainID, DeploymentID: network.DeploymentID, PrivateToken: laneToken})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var blocked atomic.Int64
	server, _ := countingNode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method == "ops_submitTransaction" {
			blocked.Add(1)
			<-release
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		node.Private().ServeHTTP(w, r)
	}))
	t.Cleanup(unblock) // runs before the server's Close (cleanups are LIFO), so a failure cannot hang it
	client, err := NewPooledClient(server.URL, laneToken, network, Lanes{Control: 1, Transaction: 2, Recovery: 1})
	if err != nil {
		t.Fatal(err)
	}
	identities, raws := signedSubmissions(t, network, 3)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ { // two hold the transaction lane, the third waits for it
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = client.SubmitTransaction(ctx, identities[i], raws[i]) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for blocked.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if blocked.Load() != 2 {
		t.Fatalf("%d submissions reached the node, want exactly the 2 the transaction lane holds", blocked.Load())
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := client.PolicyStatus(call); err != nil {
		t.Fatalf("control call starved by transaction calls: %v", err)
	}
	if _, err := client.TransactionStatus(call, "0x"+strings.Repeat("ab", 32)); err != nil && !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("recovery call starved by transaction calls: %v", err)
	}
	unblock()
	wg.Wait()
}

func TestLanesValidate(t *testing.T) {
	if err := DefaultLanes().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Lanes{{Control: 0, Transaction: 1, Recovery: 1}, {Control: 1, Transaction: 0, Recovery: 1}, {Control: 1, Transaction: 1, Recovery: 2000}} {
		if bad.Validate() == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}
