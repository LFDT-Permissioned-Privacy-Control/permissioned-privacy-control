package perfgate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func testNode(t *testing.T, lag time.Duration) (*MockNode, *fakeClock, *httptest.Server, *httptest.Server) {
	t.Helper()
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	node := NewMockNode(MockNodeConfig{ChainID: 31337, DeploymentID: "perfgate-test", PrivateToken: "private-token-0123456789", FinalityLag: lag, Clock: clock.Now})
	public := httptest.NewServer(node.Public())
	private := httptest.NewServer(node.Private())
	t.Cleanup(public.Close)
	t.Cleanup(private.Close)
	return node, clock, public, private
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedTransfer(t *testing.T, key *ecdsa.PrivateKey, nonce uint64) (*types.Transaction, string) {
	t.Helper()
	return signedTransferValue(t, key, nonce, 1)
}

func signedTransferValue(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, value int64) (*types.Transaction, string) {
	t.Helper()
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(31337), Nonce: nonce, GasTipCap: big.NewInt(1_000_000), GasFeeCap: big.NewInt(3_000_000_000), Gas: 21_000, To: &to, Value: big.NewInt(value)}), types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return tx, "0x" + hex.EncodeToString(raw)
}

type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	status int
}

func call(t *testing.T, url, token, method string, params ...any) rpcReply {
	t.Helper()
	if params == nil {
		params = []any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "t-1", "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out rpcReply
	out.status = resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func resultString(t *testing.T, r rpcReply) string {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("rpc error %d %s", r.Error.Code, r.Error.Message)
	}
	var s string
	if err := json.Unmarshal(r.Result, &s); err != nil {
		t.Fatalf("result %s: %v", r.Result, err)
	}
	return s
}

func mustOK(t *testing.T, r rpcReply) {
	t.Helper()
	if r.status != http.StatusOK || r.Error != nil {
		t.Fatalf("call failed: http %d %+v", r.status, r.Error)
	}
}

func identityEnvelope(t *testing.T, binding, context string) json.RawMessage {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"network": map[string]any{"chain_id": 31337, "deployment_id": "perfgate-test"}, "issued_at": 1, "expires_at": 2,
		"scope": "transaction", "context_id": context, "principal_id": "11111111-1111-4111-8111-111111111111",
		"org_id": "22222222-2222-4222-8222-222222222222", "signer": "0x0000000000000000000000000000000000000001",
		"binding_hash": binding, "min_snapshot_version": 1,
	})
	envelope, _ := json.Marshal(map[string]any{"version": 1, "kind": "identity", "key_id": "k", "payload": payload, "signature": make([]byte, 64)})
	return envelope
}

func factEnvelope(t *testing.T, kind string, payload map[string]any) (json.RawMessage, string) {
	t.Helper()
	encoded, _ := json.Marshal(payload)
	envelope, _ := json.Marshal(map[string]any{"version": 1, "kind": kind, "key_id": "k", "payload": encoded, "signature": make([]byte, 64)})
	digest := sha256.Sum256(encoded)
	return envelope, hex.EncodeToString(digest[:])
}

func TestMockNodeReturnsRealTransactionHash(t *testing.T) {
	_, _, public, _ := testNode(t, time.Second)
	key, _ := crypto.GenerateKey()
	tx, raw := signedTransfer(t, key, 0)
	got := resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw))
	if got != strings.ToLower(tx.Hash().Hex()) {
		t.Fatalf("hash %s, want %s", got, tx.Hash().Hex())
	}
	// A resend of the same bytes is idempotent ("already known") and pools once.
	if again := resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw)); again != got {
		t.Fatalf("resend hash %s", again)
	}
}

func TestMockNodeHoldsNonceGapsAndIncludesInNonceOrder(t *testing.T) {
	node, _, public, _ := testNode(t, time.Second)
	key, _ := crypto.GenerateKey()
	sender := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	tx1, raw1 := signedTransfer(t, key, 1)
	tx0, raw0 := signedTransfer(t, key, 0)
	_, raw3 := signedTransfer(t, key, 3)
	for _, raw := range []string{raw1, raw0, raw3} {
		resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw))
	}
	if pending := resultString(t, call(t, public.URL, "", "eth_getTransactionCount", sender, "pending")); pending != "0x2" {
		t.Fatalf("pending nonce %s, want 0x2 (nonce 3 waits behind the gap)", pending)
	}
	block := node.ProduceBlock()
	if len(block.Transactions) != 2 || block.Transactions[0] != strings.ToLower(tx0.Hash().Hex()) || block.Transactions[1] != strings.ToLower(tx1.Hash().Hex()) {
		t.Fatalf("block %v, want nonce 0 then 1", block.Transactions)
	}
	if latest := resultString(t, call(t, public.URL, "", "eth_getTransactionCount", sender, "latest")); latest != "0x2" {
		t.Fatalf("latest nonce %s", latest)
	}
	if next := node.ProduceBlock(); len(next.Transactions) != 0 {
		t.Fatalf("gap transaction included: %v", next.Transactions)
	}
	// Known bytes stay idempotent; a different transaction at a consumed nonce
	// is refused.
	if resultString(t, call(t, public.URL, "", "eth_sendRawTransaction", raw0)) != strings.ToLower(tx0.Hash().Hex()) {
		t.Fatal("known transaction lost its hash")
	}
	_, stale := signedTransferValue(t, key, 0, 2)
	if r := call(t, public.URL, "", "eth_sendRawTransaction", stale); r.Error == nil {
		t.Fatal("nonce too low accepted")
	}
}

func TestMockNodeReceiptAfterBlockAndFinalityAfterLag(t *testing.T) {
	node, clock, public, private := testNode(t, 2*time.Second)
	key, _ := crypto.GenerateKey()
	tx, raw := signedTransfer(t, key, 0)
	hash := strings.ToLower(tx.Hash().Hex())
	mustOK(t, call(t, private.URL, "private-token-0123456789", "ops_submitTransaction", identityEnvelope(t, hash, "ctx-1"), raw))
	if r := call(t, public.URL, "", "eth_getTransactionReceipt", hash); string(r.Result) != "null" {
		t.Fatalf("receipt before inclusion: %s", r.Result)
	}
	status := func() map[string]any {
		r := call(t, private.URL, "private-token-0123456789", "ops_transactionStatus", hash)
		if r.Error != nil {
			t.Fatalf("status error %v", r.Error)
		}
		var out map[string]any
		_ = json.Unmarshal(r.Result, &out)
		return out["execution"].(map[string]any)
	}
	if s := status(); s["status"] != "pending" || s["finalized"] != false {
		t.Fatalf("pending status %v", s)
	}
	clock.Advance(time.Second)
	block := node.ProduceBlock()
	var receipt map[string]any
	_ = json.Unmarshal(call(t, public.URL, "", "eth_getTransactionReceipt", hash).Result, &receipt)
	if receipt["status"] != "0x1" || receipt["blockHash"] != block.Hash {
		t.Fatalf("receipt %v", receipt)
	}
	if s := status(); s["status"] != "included" || s["finalized"] != false || s["block_hash"] != block.Hash {
		t.Fatalf("included status %v", s)
	}
	clock.Advance(2 * time.Second)
	node.ProduceBlock() // finality advances with the head
	if s := status(); s["status"] != "included" || s["finalized"] != true || s["finalized_block_number"] == nil {
		t.Fatalf("finalized status %v", s)
	}
}

func TestMockNodeSubmitTransactionChecksAuthAndBinding(t *testing.T) {
	_, _, _, private := testNode(t, time.Second)
	key, _ := crypto.GenerateKey()
	tx, raw := signedTransfer(t, key, 0)
	hash := strings.ToLower(tx.Hash().Hex())
	if r := call(t, private.URL, "", "ops_submitTransaction", identityEnvelope(t, hash, "ctx-1"), raw); r.status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status %d", r.status)
	}
	if r := call(t, private.URL, "private-token-0123456789", "ops_submitTransaction", identityEnvelope(t, "0x"+strings.Repeat("ab", 32), "ctx-1"), raw); r.Error == nil {
		t.Fatal("binding mismatch accepted")
	}
	r := call(t, private.URL, "private-token-0123456789", "ops_submitTransaction", identityEnvelope(t, hash, "ctx-7"), raw)
	var out map[string]any
	if r.Error != nil || json.Unmarshal(r.Result, &out) != nil {
		t.Fatalf("submit failed: %v", r.Error)
	}
	if out["transaction_hash"] != hash || out["context_id"] != "ctx-7" || out["status"] != "accepted" || len(out) != 3 {
		t.Fatalf("submission %v", out)
	}
}

func TestMockNodeBatchedStatus(t *testing.T) {
	node, _, _, private := testNode(t, time.Second)
	key, _ := crypto.GenerateKey()
	var hashes []string
	for nonce := uint64(0); nonce < 3; nonce++ {
		tx, raw := signedTransfer(t, key, nonce)
		hash := strings.ToLower(tx.Hash().Hex())
		hashes = append(hashes, hash)
		mustOK(t, call(t, private.URL, "private-token-0123456789", "ops_submitTransaction", identityEnvelope(t, hash, "ctx-"+hash[2:10]), raw))
	}
	node.ProduceBlock()
	unknown := "0x" + strings.Repeat("cd", 32)
	r := call(t, private.URL, "private-token-0123456789", "ops_transactionStatuses", append(hashes, unknown))
	var rows []json.RawMessage
	if r.Error != nil || json.Unmarshal(r.Result, &rows) != nil || len(rows) != 4 {
		t.Fatalf("batched status %s %v", r.Result, r.Error)
	}
	for i, hash := range hashes {
		var row map[string]any
		_ = json.Unmarshal(rows[i], &row)
		if row["transaction_hash"] != hash || row["execution"].(map[string]any)["status"] != "included" {
			t.Fatalf("row %d %v", i, row)
		}
	}
	if string(rows[3]) != "null" {
		t.Fatalf("unknown row %s", rows[3])
	}
	tooMany := make([]string, 257)
	for i := range tooMany {
		tooMany[i] = unknown
	}
	if r := call(t, private.URL, "private-token-0123456789", "ops_transactionStatuses", tooMany); r.Error == nil {
		t.Fatal("more than 256 hashes accepted")
	}
}

func TestMockNodePolicyApplyAndStatusAreCoherent(t *testing.T) {
	_, clock, _, private := testNode(t, time.Second)
	token := "private-token-0123456789"
	status := func() map[string]any {
		var out map[string]any
		_ = json.Unmarshal(call(t, private.URL, token, "ops_policyStatus").Result, &out)
		return out
	}
	if s := status(); s["ready"] != false || s["version"] != float64(0) || s["digest"] != "" {
		t.Fatalf("initial status %v", s)
	}
	header := map[string]any{"network": map[string]any{"chain_id": 31337, "deployment_id": "perfgate-test"}, "issued_at": clock.Now().Unix(), "expires_at": clock.Now().Unix() + 30}
	snapshot, digest := factEnvelope(t, "snapshot", map[string]any{"network": header["network"], "issued_at": header["issued_at"], "expires_at": header["expires_at"], "version": 3})
	var ack map[string]any
	_ = json.Unmarshal(call(t, private.URL, token, "ops_policyApply", snapshot).Result, &ack)
	if ack["version"] != float64(3) || ack["digest"] != digest || ack["expires_at"] != float64(clock.Now().Unix()+30) || len(ack) != 3 {
		t.Fatalf("snapshot ack %v", ack)
	}
	if s := status(); s["ready"] != true || s["version"] != float64(3) || s["digest"] != digest {
		t.Fatalf("status after snapshot %v", s)
	}
	stale, _ := factEnvelope(t, "delta", map[string]any{"network": header["network"], "issued_at": header["issued_at"], "expires_at": header["expires_at"], "previous_version": 2, "version": 4})
	if r := call(t, private.URL, token, "ops_policyApply", stale); r.Error == nil || r.Error.Code != -32011 {
		t.Fatalf("stale delta reply %v", r.Error)
	}
	heartbeat, _ := factEnvelope(t, "heartbeat", map[string]any{"network": header["network"], "issued_at": header["issued_at"], "expires_at": clock.Now().Unix() + 60, "version": 3, "digest": digest})
	_ = json.Unmarshal(call(t, private.URL, token, "ops_policyApply", heartbeat).Result, &ack)
	if ack["digest"] != digest || ack["expires_at"] != float64(clock.Now().Unix()+60) {
		t.Fatalf("heartbeat ack %v", ack)
	}
	clock.Advance(61 * time.Second)
	if s := status(); s["ready"] != false {
		t.Fatalf("expired facts still ready: %v", s)
	}
}

func TestMockNodeInjectsLatency(t *testing.T) {
	node := NewMockNode(MockNodeConfig{ChainID: 31337, DeploymentID: "perfgate-test", PrivateToken: "private-token-0123456789", FinalityLag: time.Second, Latency: 5 * time.Millisecond})
	public := httptest.NewServer(node.Public())
	defer public.Close()
	start := time.Now()
	resultString(t, call(t, public.URL, "", "eth_chainId"))
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Fatalf("latency %s below 5ms", elapsed)
	}
}

func TestMockNodeBase64PayloadMatchesGoEncoding(t *testing.T) {
	// The private API decodes envelopes the way OPS encodes them: []byte fields
	// as standard base64 strings.
	payload := []byte(`{"version":1}`)
	encoded, _ := json.Marshal(struct {
		Payload []byte `json:"payload"`
	}{payload})
	if !strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(payload)) {
		t.Fatalf("unexpected encoding %s", encoded)
	}
}
