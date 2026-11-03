package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/perfgate"
	"privacy-proxy/internal/proxy"
)

func signedMockTransfer(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, value int64) (string, string) {
	t.Helper()
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(31337), Nonce: nonce, GasTipCap: big.NewInt(1_000_000), GasFeeCap: big.NewInt(3_000_000_000), Gas: 21_000, To: &to, Value: big.NewInt(value)}), types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	return strings.ToLower(tx.Hash().Hex()), "0x" + hex.EncodeToString(raw)
}

// The public-RPC evidence reader answers from the node's canonical chain and
// pool, in batches, and treats an unusable answer as unavailable, never as
// absence.
func TestNodeChainReaderReadsCanonicalEvidence(t *testing.T) {
	node := perfgate.NewMockNode(perfgate.MockNodeConfig{ChainID: 31337, DeploymentID: "chain-test", PrivateToken: "private-token-0123456789", FinalityLag: time.Hour})
	public := httptest.NewServer(node.Public())
	defer public.Close()
	upstream := proxy.New(public.URL)
	chain := rpcChain{forward: upstream.ForwardContext}
	key, _ := crypto.GenerateKey()
	signer := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	h0, raw0 := signedMockTransfer(t, key, 0, 1)
	h1, _ := signedMockTransfer(t, key, 1, 1)
	ctx := context.Background()
	call := func(method string, params ...any) {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":["` + params[0].(string) + `"]}`
		if _, _, err := upstream.ForwardContext(ctx, []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	call("eth_sendRawTransaction", raw0)
	known, err := chain.Known(ctx, []string{h0, h1})
	if err != nil || !known[h0] || known[h1] {
		t.Fatalf("known %v %v", known, err)
	}
	block := node.ProduceBlock()
	nonce, receipts, err := chain.DroppedEvidence(ctx, block.Number, block.Hash, signer, []string{h0, h1})
	if err != nil || nonce != 1 || !receipts[h0] || receipts[h1] {
		t.Fatalf("evidence %d %v %v", nonce, receipts, err)
	}
	if _, _, err := chain.DroppedEvidence(ctx, block.Number, "0x"+strings.Repeat("ab", 32), signer, []string{h1}); err == nil {
		t.Fatal("evidence accepted from a chain without the finalized block's hash")
	}
	if _, _, err := chain.DroppedEvidence(ctx, 99, block.Hash, signer, []string{h1}); err == nil {
		t.Fatal("a missing block read as evidence")
	}
	down := rpcChain{forward: proxy.New("http://127.0.0.1:1").ForwardContext}
	if _, _, err := down.DroppedEvidence(ctx, block.Number, block.Hash, signer, []string{h0}); err == nil {
		t.Fatal("an unreachable node read as no receipt")
	}
	many := make([]string, maxChainBatch+3)
	for i := range many {
		many[i] = h1
	}
	if got, err := chain.Known(ctx, many); err != nil || len(got) != 1 || got[h1] {
		t.Fatalf("multi-batch read %v %v", len(got), err)
	}
}
