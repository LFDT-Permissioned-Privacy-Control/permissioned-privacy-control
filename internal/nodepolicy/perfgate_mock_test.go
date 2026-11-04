package nodepolicy

import (
	"context"
	"encoding/hex"
	"math/big"
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

// The gate-2 mock node must be accepted by the real strict client, publisher
// and outcome validator, or gate-2 numbers would measure a broken protocol.
func TestPerfgateMockSpeaksTheStrictNodeProtocol(t *testing.T) {
	for _, c := range RequiredCapabilities() {
		if !slices.Contains(perfgate.Capabilities, c) {
			t.Fatalf("mock capabilities %v lack required %s", perfgate.Capabilities, c)
		}
	}
	for _, c := range perfgate.Capabilities {
		if !slices.Contains(RequiredCapabilities(), c) && !slices.Contains(OptionalCapabilities(), c) {
			t.Fatalf("mock advertises %s, which OPS does not know", c)
		}
	}
	network := Network{ChainID: 31337, DeploymentID: "perfgate-compat"}
	clock := time.Now
	node := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: network.ChainID, DeploymentID: network.DeploymentID, PrivateToken: "private-token-0123456789", FinalityLag: 0, Clock: clock})
	server := httptest.NewServer(node.Private())
	defer server.Close()
	client, err := NewClient(server.URL, "private-token-0123456789", network, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if status, err := client.PolicyStatus(ctx); err != nil || status.Version != 0 || status.Ready {
		t.Fatalf("initial status %+v %v", status, err)
	}

	source := &memorySource{snapshot: snapshotFixture()}
	signer := testSigner()
	// The publisher's clock moves a heartbeat interval per tick: a heartbeat
	// right after a publication is skipped.
	var offset time.Duration
	publisher, err := NewPublisher(PublisherConfig{Network: network, ConsumerID: "producer", Signer: signer, Source: source, Node: client, Lifetime: 30 * time.Second, Now: func() time.Time { return time.Now().Add(offset) }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // snapshot, heartbeat, then a delta after a change
		offset = time.Duration(i) * heartbeatSkip
		if i == 2 {
			source.snapshot.Version++
			source.snapshot.Principals[0].Banned = true
		}
		if err := publisher.Tick(ctx); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	status, err := client.PolicyStatus(ctx)
	if err != nil || status.RequireReady(time.Now(), source.snapshot.Version) != nil || len(source.acks) != 3 {
		t.Fatalf("status after publication %+v %v acks=%d", status, err, len(source.acks))
	}

	key, _ := crypto.GenerateKey()
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(31337), Gas: 21_000, GasFeeCap: big.NewInt(3e9), GasTipCap: big.NewInt(1e6), To: &to, Value: big.NewInt(1)}), types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	hash := strings.ToLower(tx.Hash().Hex())
	now := time.Now()
	wire, err := signer.Seal("identity", Identity{Header: Header{Network: network, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}, Scope: "transaction", ContextID: "11111111-1111-4111-8111-111111111111",
		PrincipalID: "22222222-2222-4222-8222-222222222222", OrgID: "33333333-3333-4333-8333-333333333333", Signer: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()), BindingHash: hash, MinSnapshotVersion: source.snapshot.Version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SubmitTransaction(ctx, wire, "0x"+hex.EncodeToString(raw)); err != nil {
		t.Fatalf("submit: %v", err)
	}
	pending, err := client.TransactionStatus(ctx, hash)
	if err != nil || pending.Execution.Status != "pending" {
		t.Fatalf("pending status %+v %v", pending, err)
	}
	node.ProduceBlock()
	node.ProduceBlock() // FinalityLag 0: the inclusion block is final once a newer head exists
	final, err := client.TransactionStatus(ctx, hash)
	if err != nil || final.Execution.Status != "included" || !final.Execution.Finalized {
		t.Fatalf("final status %+v %v", final, err)
	}
}
