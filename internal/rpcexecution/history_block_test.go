package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/transactioninput"
)

func historySigned(t *testing.T, kind uint8, nonce uint64, creation, unprotected bool) *types.Transaction {
	t.Helper()
	key, e := crypto.HexToECDSA(strings.Repeat("11", 32))
	if e != nil {
		t.Fatal(e)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	destination := &to
	if creation {
		destination = nil
	}
	a := types.AccessList{{Address: to, StorageKeys: []common.Hash{{2}}}}
	var inner types.TxData
	switch kind {
	case 0:
		inner = &types.LegacyTx{Nonce: nonce, To: destination, Gas: 100000, GasPrice: big.NewInt(3), Value: big.NewInt(0), Data: []byte{0x60, 1}}
	case 1:
		inner = &types.AccessListTx{ChainID: big.NewInt(1), Nonce: nonce, To: destination, Gas: 100000, GasPrice: big.NewInt(3), Value: big.NewInt(0), Data: []byte{0x60, 1}, AccessList: a}
	case 2:
		inner = &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: nonce, To: destination, Gas: 100000, GasFeeCap: big.NewInt(3), GasTipCap: big.NewInt(1), Value: big.NewInt(0), Data: []byte{0x60, 1}, AccessList: a}
	case 3:
		inner = &types.BlobTx{ChainID: uint256.NewInt(1), Nonce: nonce, To: to, Gas: 100000, GasFeeCap: uint256.NewInt(3), GasTipCap: uint256.NewInt(1), Value: uint256.NewInt(0), Data: []byte{0x60, 1}, AccessList: a, BlobFeeCap: uint256.NewInt(5), BlobHashes: []common.Hash{{1, 2}}}
	case 4:
		auth, e := types.SignSetCode(key, types.SetCodeAuthorization{ChainID: *uint256.NewInt(1), Address: to, Nonce: nonce + 1})
		if e != nil {
			t.Fatal(e)
		}
		inner = &types.SetCodeTx{ChainID: uint256.NewInt(1), Nonce: nonce, To: to, Gas: 100000, GasFeeCap: uint256.NewInt(3), GasTipCap: uint256.NewInt(1), Value: uint256.NewInt(0), Data: []byte{0x60, 1}, AccessList: a, AuthList: []types.SetCodeAuthorization{auth}}
	default:
		t.Fatal("bad fixture type")
	}
	var signer types.Signer = types.LatestSignerForChainID(big.NewInt(1))
	if unprotected {
		signer = types.FrontierSigner{}
	}
	tx, e := types.SignNewTx(key, signer, inner)
	if e != nil {
		t.Fatal(e)
	}
	return tx
}

type historyFixture struct {
	mu              sync.Mutex
	header, genesis *types.Header
	txs             []*types.Transaction
	block           map[string]any
	receipts        []any
	methods         []string
	change          func(string, any) any
	padding         int
	blockRead       bool
	entered         chan struct{}
	wrongID         bool
	source          creationfacts.Source
	transport       Transport
}

func newHistoryFixture(t *testing.T, txs ...*types.Transaction) *historyFixture {
	t.Helper()
	zero := uint64(0)
	wr := types.EmptyWithdrawalsHash
	beacon := common.Hash{3}
	requests := types.EmptyRequestsHash
	g := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, BaseFee: big.NewInt(1), UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}, WithdrawalsHash: &wr, BlobGasUsed: &zero, ExcessBlobGas: &zero, ParentBeaconRoot: &beacon, RequestsHash: &requests}
	h := types.CopyHeader(g)
	h.Number, h.Time, h.ParentHash = big.NewInt(1), 2, g.Hash()
	h.GasUsed = 21000 * uint64(len(txs))
	f := &historyFixture{header: h, genesis: g, txs: txs, receipts: []any{}}
	var blobs uint64
	for _, tx := range txs {
		if tx.Type() == 3 {
			blobs += uint64(len(tx.BlobHashes())) * 131072
		}
	}
	h.BlobGasUsed = &blobs
	f.rebind(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "history-fixture" {
			t.Error("wrong selected request/credential")
			w.WriteHeader(400)
			return
		}
		var q headerLaneRPC
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("bad request")
			return
		}
		f.mu.Lock()
		f.methods = append(f.methods, q.Method)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
		case "eth_getHeaderByHash":
			result = f.header
		case "eth_getHeaderByNumber":
			var selector string
			_ = json.Unmarshal(q.Params[0], &selector)
			result = f.header
			if selector == "0x0" {
				result = f.genesis
			}
		case "eth_getBlockByHash":
			var hash string
			var full bool
			if len(q.Params) != 2 || json.Unmarshal(q.Params[0], &hash) != nil || hash != f.header.Hash().Hex() || json.Unmarshal(q.Params[1], &full) != nil || !full {
				t.Error("not exact full block acquisition")
			}
			result = f.block
		case "eth_getBlockReceipts":
			var hash string
			if len(q.Params) != 1 || json.Unmarshal(q.Params[0], &hash) != nil || hash != f.header.Hash().Hex() {
				t.Error("not exact receipt-set hash")
			}
			result = f.receipts
		default:
			t.Error("unexpected history method", q.Method)
			w.WriteHeader(500)
			f.mu.Unlock()
			return
		}
		if f.change != nil {
			result = f.change(q.Method, result)
		}
		padding, blocked, entered, wrong := f.padding, f.blockRead, f.entered, f.wrongID
		f.mu.Unlock()
		if blocked {
			if entered != nil {
				select {
				case entered <- struct{}{}:
				default:
				}
			}
			<-r.Context().Done()
			return
		}
		if padding > 0 && (q.Method == "eth_getHeaderByNumber" || q.Method == "eth_getHeaderByHash") {
			_, _ = w.Write([]byte(strings.Repeat(" ", padding)))
		}
		id := q.ID
		if wrong {
			id++
		}
		_ = json.NewEncoder(w).Encode(struct {
			JSONRPC string `json:"jsonrpc"`
			ID      uint64 `json:"id"`
			Result  any    `json:"result"`
		}{"2.0", id, result})
	}))
	t.Cleanup(srv.Close)
	binding := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: g.Hash().Hex(), DeploymentID: "history-block"}
	key, e := binding.Key()
	if e != nil {
		t.Fatal(e)
	}
	f.source = creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: g.Hash(), Deployment: binding.DeploymentID}, URL: srv.URL, CredentialRef: "history", CredentialHeader: "Idempotency-Key", Profile: IncludedProfileID, PragueStart: 0, PragueEnd: 10}
	f.transport = headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("counted history request can replay")
		}
		return srv.Client().Transport.RoundTrip(r)
	})
	return f
}

func (f *historyFixture) rebind(t *testing.T) {
	t.Helper()
	f.block = includedObject(t, f.header)
	f.block["uncles"], f.block["withdrawals"] = []any{}, []any{}
	items := []any{}
	f.receipts = []any{}
	for i, tx := range f.txs {
		var signer types.Signer
		if !tx.Protected() {
			signer = types.FrontierSigner{}
		} else {
			signer = types.LatestSignerForChainID(tx.ChainId())
		}
		from, e := types.Sender(signer, tx)
		if e != nil {
			t.Fatal(e)
		}
		fields := includedObject(t, tx)
		fields["from"], fields["blockHash"], fields["blockNumber"], fields["transactionIndex"] = from.Hex(), f.header.Hash().Hex(), "0x1", fmtHistoryQuantity(uint64(i))
		items = append(items, fields)
		var to any
		var contract any
		if tx.To() != nil {
			to = tx.To().Hex()
		} else {
			contract = crypto.CreateAddress(from, tx.Nonce()).Hex()
		}
		// Independent fixture expectations: these constructors use price3 for
		// legacy/access-list, and base1+tip1 below cap3 for dynamic types.
		price := big.NewInt(3)
		if tx.Type() >= 2 {
			price = big.NewInt(2)
		}
		r := map[string]any{"transactionHash": tx.Hash().Hex(), "blockHash": f.header.Hash().Hex(), "blockNumber": "0x1", "transactionIndex": fmtHistoryQuantity(uint64(i)), "from": from.Hex(), "to": to, "type": fmtHistoryQuantity(uint64(tx.Type())), "contractAddress": contract, "status": "0x1", "gasUsed": "0x5208", "cumulativeGasUsed": fmtHistoryQuantity(21000 * uint64(i+1)), "effectiveGasPrice": "0x" + price.Text(16), "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
		if tx.Type() == 3 {
			r["blobGasUsed"] = fmtHistoryQuantity(uint64(len(tx.BlobHashes())) * 131072)
			r["blobGasPrice"] = "0x1"
		}
		f.receipts = append(f.receipts, r)
	}
	f.block["transactions"] = items
}
func fmtHistoryQuantity(n uint64) string { return "0x" + new(big.Int).SetUint64(n).Text(16) }
func (f *historyFixture) client(t *testing.T, l HistoryBlockLimits) *HistoryBlockClient {
	t.Helper()
	c, e := NewHistoryBlockClient(f.transport, f.source, Credential{f.source.CredentialHeader, "history-fixture"}, l)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func historyAcquire(t *testing.T, c *HistoryBlockClient) *HistoryBlockObservation {
	t.Helper()
	s, _ := HistoryBlockNumber(1)
	b, e := c.AcquireBlock(t.Context(), s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestHistoryBlockTLSCompleteAllSignedTypesAndDetachedData(t *testing.T) {
	for _, kind := range []uint8{0, 1, 2, 3, 4} {
		t.Run(fmtHistoryQuantity(uint64(kind)), func(t *testing.T) {
			tx := historySigned(t, kind, 7, false, false)
			f := newHistoryFixture(t, tx)
			c := f.client(t, DefaultHistoryBlockLimits())
			b := historyAcquire(t, c)
			want := []string{"eth_chainId", "eth_getHeaderByNumber", "eth_syncing", "eth_getHeaderByNumber", "eth_getBlockByHash", "eth_getBlockReceipts", "eth_chainId", "eth_getHeaderByNumber", "eth_syncing", "eth_getHeaderByNumber"}
			if !reflect.DeepEqual(f.methods, want) || b.TransactionCount() != 1 || b.Source() != f.source || b.Header().Hash != f.header.Hash() {
				t.Fatal("not exact complete source", f.methods)
			}
			got, ok := b.Transaction(0)
			if !ok || got.Hash() != tx.Hash() || got.Type() != kind {
				t.Fatal("wrong signed transaction")
			}
			if kind >= 3 {
				if _, e := transactioninput.DecodeRaw("0x"+common.Bytes2Hex(got.SignedBytes()), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits()); e == nil {
					t.Fatal("history widened admission")
				}
			}
			signed := got.SignedBytes()
			signed[0] ^= 1
			input := got.Input()
			input[0] ^= 1
			fees := got.Fees()
			fees.ChainID.SetUint64(99)
			h := b.Header()
			h.BaseFeePerGas.SetUint64(99)
			if got.Hash() != tx.Hash() || got.SignedBytes()[0] != txBytes(t, tx)[0] || got.Input()[0] != 0x60 || got.Fees().ChainID.Uint64() != 1 || b.Header().BaseFeePerGas.Uint64() != 1 {
				t.Fatal("detached payload aliases")
			}
			if kind > 0 {
				a := got.AccessList()
				a[0].StorageKeys[0] = common.Hash{}
				if got.AccessList()[0].StorageKeys[0] == (common.Hash{}) {
					t.Fatal("access-list alias")
				}
			}
			if kind == 3 {
				a := got.BlobHashes()
				a[0] = common.Hash{}
				if got.BlobHashes()[0] == (common.Hash{}) {
					t.Fatal("blob alias")
				}
			}
			if kind == 4 {
				a := got.Authorizations()
				a[0].Nonce = 999
				if got.Authorizations()[0].Nonce == 999 {
					t.Fatal("authorization alias")
				}
			}
			r, ok := b.Receipt(0)
			status, present := r.Status()
			_, root := r.PostStateRoot()
			if !ok || !present || status != 1 || root || r.GasUsed() != 21000 {
				t.Fatal("wrong receipt outcome")
			}
			p := r.EffectiveGasPrice()
			p.SetUint64(99)
			if r.EffectiveGasPrice().Uint64() == 99 {
				t.Fatal("receipt price alias")
			}
			if e := c.Recheck(t.Context(), b); e != nil {
				t.Fatal(e)
			}
			if len(f.methods) != 14 {
				t.Fatal("wrong physical recheck cost")
			}
			again := historyAcquire(t, c)
			if again.Digest() != b.Digest() {
				t.Fatal("wire IDs changed semantic digest")
			}
		})
	}
}
func txBytes(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	b, e := tx.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestHistoryBlockLegacyCreationUnprotectedAndRootOutcome(t *testing.T) {
	for _, unprotected := range []bool{false, true} {
		for _, root := range []bool{false, true} {
			t.Run(fmtHistoryQuantity(uint64(boolHistory(unprotected)*2+boolHistory(root))), func(t *testing.T) {
				f := newHistoryFixture(t, historySigned(t, 0, 3, true, unprotected))
				if root {
					r := f.receipts[0].(map[string]any)
					delete(r, "status")
					r["root"] = "0x" + strings.Repeat("12", 32)
				}
				c := f.client(t, DefaultHistoryBlockLimits())
				b := historyAcquire(t, c)
				tx, _ := b.Transaction(0)
				if _, call := tx.To(); call {
					t.Fatal("root creation became CALL")
				}
				r, _ := b.Receipt(0)
				_, s := r.Status()
				_, p := r.PostStateRoot()
				if s == root || p != root || tx.Fees().Protected == unprotected {
					t.Fatal("outcome/protection inferred")
				}
				if _, ok := r.ContractAddress(); !ok {
					t.Fatal("missing actual create address")
				}
			})
		}
	}
}
func boolHistory(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestHistoryBlockRejectsWholePopulationOnMalformedRow(t *testing.T) {
	cases := []string{"tx-hash", "tx-from", "tx-chain", "tx-index", "tx-null", "tx-type", "tx-unknown", "tx-parity", "receipt-missing", "receipt-extra", "receipt-order", "receipt-hash", "receipt-from", "receipt-index", "receipt-price", "receipt-cumulative", "receipt-status", "receipt-both", "receipt-neither", "receipt-root-short", "receipt-root-long", "receipt-root-null", "receipt-create-child", "logs-bloom", "unknown-receipt", "wrong-id", "syncing", "changed-canonical"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHistoryFixture(t, historySigned(t, 2, 0, false, false), historySigned(t, 2, 1, false, false))
			tx := f.block["transactions"].([]any)[1].(map[string]any)
			r := f.receipts[1].(map[string]any)
			switch name {
			case "tx-hash":
				tx["hash"] = common.Hash{99}.Hex()
			case "tx-from":
				tx["from"] = common.Address{99}.Hex()
			case "tx-chain":
				tx["chainId"] = "0x2"
			case "tx-index":
				tx["transactionIndex"] = "0x0"
			case "tx-null":
				tx["input"] = nil
			case "tx-type":
				tx["type"] = "0x5"
			case "tx-unknown":
				tx["unselected"] = true
			case "tx-parity":
				tx["yParity"] = "0x2"
			case "receipt-missing":
				f.receipts = f.receipts[:1]
			case "receipt-extra":
				f.receipts = append(f.receipts, r)
			case "receipt-order":
				f.receipts[0], f.receipts[1] = f.receipts[1], f.receipts[0]
			case "receipt-hash":
				r["transactionHash"] = common.Hash{99}.Hex()
			case "receipt-from":
				r["from"] = common.Address{99}.Hex()
			case "receipt-index":
				r["transactionIndex"] = "0x0"
			case "receipt-price":
				r["effectiveGasPrice"] = "0x3"
			case "receipt-cumulative":
				r["cumulativeGasUsed"] = "0x5208"
			case "receipt-status":
				r["status"] = "0x2"
			case "receipt-both":
				r["root"] = "0x" + strings.Repeat("12", 32)
			case "receipt-neither":
				delete(r, "status")
			case "receipt-root-short":
				delete(r, "status")
				r["root"] = "0x" + strings.Repeat("12", 31)
			case "receipt-root-long":
				delete(r, "status")
				r["root"] = "0x" + strings.Repeat("12", 33)
			case "receipt-root-null":
				delete(r, "status")
				r["root"] = nil
			case "receipt-create-child":
				r["contractAddress"] = common.Address{99}.Hex()
			case "logs-bloom":
				r["logsBloom"] = "0x" + strings.Repeat("11", 256)
			case "unknown-receipt":
				r["unselected"] = true
			case "wrong-id":
				f.wrongID = true
			case "syncing":
				f.change = func(method string, v any) any {
					if method == "eth_syncing" {
						return map[string]any{"startingBlock": "0x0", "currentBlock": "0x1", "highestBlock": "0x2"}
					}
					return v
				}
			case "changed-canonical":
				f.change = func(method string, v any) any {
					if method == "eth_getHeaderByNumber" && len(f.methods) > 6 && v == f.header {
						h := types.CopyHeader(f.header)
						h.Time++
						return h
					}
					return v
				}
			}
			c := f.client(t, DefaultHistoryBlockLimits())
			s, _ := HistoryBlockNumber(1)
			b, e := c.AcquireBlock(t.Context(), s)
			if e == nil || b != nil {
				t.Fatal("partial/malformed population accepted")
			}
		})
	}
}

func TestHistoryBlockEmptyHashAndClosedBindings(t *testing.T) {
	f := newHistoryFixture(t)
	c := f.client(t, DefaultHistoryBlockLimits())
	s, _ := HistoryBlockHash(f.header.Hash())
	b, e := c.AcquireBlock(t.Context(), s)
	if e != nil || b.TransactionCount() != 0 {
		t.Fatal("actual empty block rejected", e)
	}
	if _, ok := b.Transaction(0); ok {
		t.Fatal("invented transaction")
	}
	if _, ok := b.Receipt(0); ok {
		t.Fatal("invented receipt")
	}
	if f.methods[3] != "eth_getHeaderByHash" || f.methods[9] != "eth_getHeaderByNumber" {
		t.Fatal("hash lookup used as canonicality")
	}
	if e := c.Recheck(t.Context(), &HistoryBlockObservation{}); e == nil {
		t.Fatal("zero observation current")
	}
	other := f.client(t, DefaultHistoryBlockLimits())
	if e := other.Recheck(t.Context(), b); e == nil {
		t.Fatal("foreign observation current")
	}
	if _, e := c.AcquireBlock(t.Context(), HistoryBlockSelector{}); e == nil {
		t.Fatal("zero selector")
	}
	if _, e := HistoryBlockHash(common.Hash{}); e == nil {
		t.Fatal("zero hash")
	}
	if _, e := HistoryBlockNumber(^uint64(0)); e == nil {
		t.Fatal("overflow number")
	}
	if _, e := HistoryBlockNumber(0); e != nil {
		t.Fatal("genesis rejected")
	}
	bad := f.source
	bad.Network.Key[0] ^= 1
	if _, e := NewHistoryBlockClient(f.transport, bad, Credential{bad.CredentialHeader, "history-fixture"}, DefaultHistoryBlockLimits()); e == nil {
		t.Fatal("fabricated source key")
	}
	if (*HistoryBlockObservation)(nil).Digest() != (common.Hash{}) || (&HistoryBlockObservation{}).Source() != (creationfacts.Source{}) {
		t.Fatal("zero observation looked qualified")
	}
}

func TestHistoryBlockSelectedLimitsAndActualRecheckFences(t *testing.T) {
	for _, name := range []string{"requests", "wire", "transactions", "signed", "observation"} {
		t.Run(name, func(t *testing.T) {
			f := newHistoryFixture(t, historySigned(t, 2, 0, false, false), historySigned(t, 2, 1, false, false))
			l := DefaultHistoryBlockLimits()
			switch name {
			case "requests":
				l.MaxRequests = 9
			case "wire":
				l.MaxTotalWireBytes = 1
			case "transactions":
				l.MaxTransactions = 1
			case "signed":
				l.MaxSignedBytes = 1
			case "observation":
				l.MaxObservationBytes = 1
			}
			c := f.client(t, l)
			s, _ := HistoryBlockNumber(1)
			b, e := c.AcquireBlock(t.Context(), s)
			if e == nil || b != nil {
				t.Fatal("lower cap ignored")
			}
			if name == "requests" && len(f.methods) != 9 {
				t.Fatal("wrong physical cap", f.methods)
			}
		})
	}
	t.Run("recheck-selected-wire", func(t *testing.T) {
		f := newHistoryFixture(t)
		l := DefaultHistoryBlockLimits()
		l.MaxTotalWireBytes = 20000
		c := f.client(t, l)
		b := historyAcquire(t, c)
		f.mu.Lock()
		f.padding = 11000
		f.mu.Unlock()
		if e := c.Recheck(t.Context(), b); e == nil {
			t.Fatal("recheck reset selected wire cap")
		}
	})
	t.Run("original-cancel-before", func(t *testing.T) {
		f := newHistoryFixture(t)
		c := f.client(t, DefaultHistoryBlockLimits())
		ctx, cancel := context.WithCancel(t.Context())
		s, _ := HistoryBlockNumber(1)
		b, e := c.AcquireBlock(ctx, s)
		if e != nil {
			t.Fatal(e)
		}
		cancel()
		n := len(f.methods)
		if e := c.Recheck(context.Background(), b); e == nil || len(f.methods) != n {
			t.Fatal("new context bypassed old cancellation")
		}
	})
	t.Run("original-cancel-during", func(t *testing.T) {
		f := newHistoryFixture(t)
		c := f.client(t, DefaultHistoryBlockLimits())
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		s, _ := HistoryBlockNumber(1)
		b, e := c.AcquireBlock(ctx, s)
		if e != nil {
			t.Fatal(e)
		}
		f.mu.Lock()
		f.blockRead = true
		f.entered = make(chan struct{}, 1)
		entered := f.entered
		f.mu.Unlock()
		out := make(chan error, 1)
		go func() { out <- c.Recheck(context.Background(), b) }()
		<-entered
		cancel()
		select {
		case e := <-out:
			if e == nil {
				t.Fatal("cancellation bridge ignored")
			}
		case <-time.After(time.Second):
			t.Fatal("bridge stalled")
		}
	})
	t.Run("recheck-selected-timeout", func(t *testing.T) {
		f := newHistoryFixture(t)
		l := DefaultHistoryBlockLimits()
		l.Timeout = 500 * time.Millisecond
		c := f.client(t, l)
		b := historyAcquire(t, c)
		f.mu.Lock()
		f.blockRead = true
		f.mu.Unlock()
		start := time.Now()
		if e := c.Recheck(t.Context(), b); e == nil || time.Since(start) > 2*time.Second {
			t.Fatal("recheck reset lower timeout", e)
		}
	})
	t.Run("recheck-shorter-parent", func(t *testing.T) {
		f := newHistoryFixture(t)
		c := f.client(t, DefaultHistoryBlockLimits())
		b := historyAcquire(t, c)
		f.mu.Lock()
		f.blockRead = true
		f.mu.Unlock()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		start := time.Now()
		if e := c.Recheck(ctx, b); e == nil || time.Since(start) > time.Second {
			t.Fatal("parent deadline ignored", e)
		}
	})
}
