package disclosuretest

// This is a finite typed TLS node fixture, never a production acquisition or
// inclusion authority. Actual cached-node qualification is recorded separately.
import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
)

type HistoryNode struct {
	mu              sync.Mutex
	server          *httptest.Server
	genesis, header *types.Header
	transactions    []*types.Transaction
	block           map[string]any
	receipts        []any
	logs            []any
	reorg           bool
	calls           map[string]int
}

func HistoryKey(n byte) *ecdsa.PrivateKey {
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 62) + common.Bytes2Hex([]byte{n}))
	return key
}
func HistoryTransaction(t testing.TB, signer byte, nonce uint64, to common.Address) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(7), 100000, big.NewInt(1), []byte{1, 2, 3, 4}), types.LatestSignerForChainID(big.NewInt(1)), HistoryKey(signer))
	if err != nil {
		t.Fatal(err)
	}
	return tx
}
func fixtureObject(t testing.TB, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("history fixture object")
	}
	return out
}
func NewHistoryNode(t testing.TB, txs []*types.Transaction, perTxLogs [][]*types.Log) *HistoryNode {
	t.Helper()
	g := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: uint64(Now - 1), BaseFee: big.NewInt(1), UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}
	h := types.CopyHeader(g)
	h.Number = big.NewInt(1)
	h.Time = uint64(Now)
	h.ParentHash = g.Hash()
	h.GasUsed = 21000 * uint64(len(txs))
	n := &HistoryNode{genesis: g, header: h, transactions: txs, receipts: []any{}, logs: []any{}, calls: map[string]int{}}
	all := []*types.Log{}
	for _, logs := range perTxLogs {
		all = append(all, logs...)
	}
	h.Bloom = types.CreateBloom(&types.Receipt{Logs: all})
	n.block = fixtureObject(t, h)
	n.block["uncles"] = []any{}
	items := []any{}
	nextLog := uint64(0)
	for i, tx := range txs {
		from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
		if err != nil {
			t.Fatal(err)
		}
		fields := fixtureObject(t, tx)
		fields["from"], fields["blockHash"], fields["blockNumber"], fields["transactionIndex"] = from.Hex(), h.Hash().Hex(), "0x1", historyHex(uint64(i))
		items = append(items, fields)
		logs := []any{}
		rawLogs := []*types.Log{}
		if i < len(perTxLogs) {
			rawLogs = perTxLogs[i]
		}
		for _, l := range rawLogs {
			topics := []string{}
			for _, topic := range l.Topics {
				topics = append(topics, topic.Hex())
			}
			row := map[string]any{"address": l.Address.Hex(), "topics": topics, "data": "0x" + common.Bytes2Hex(l.Data), "blockHash": h.Hash().Hex(), "blockNumber": "0x1", "transactionHash": tx.Hash().Hex(), "transactionIndex": historyHex(uint64(i)), "logIndex": historyHex(nextLog), "removed": false}
			nextLog++
			logs = append(logs, row)
			n.logs = append(n.logs, row)
		}
		bloom := types.CreateBloom(&types.Receipt{Logs: rawLogs})
		var to any
		if tx.To() != nil {
			to = tx.To().Hex()
		}
		n.receipts = append(n.receipts, map[string]any{"transactionHash": tx.Hash().Hex(), "blockHash": h.Hash().Hex(), "blockNumber": "0x1", "transactionIndex": historyHex(uint64(i)), "from": from.Hex(), "to": to, "type": "0x0", "contractAddress": nil, "status": "0x1", "gasUsed": "0x5208", "cumulativeGasUsed": historyHex(21000 * uint64(i+1)), "effectiveGasPrice": "0x1", "logsBloom": "0x" + common.Bytes2Hex(bloom[:]), "logs": logs})
	}
	n.block["transactions"] = items
	n.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
			t.Error("history fixture transport or leaked OPS JWT")
			w.WriteHeader(400)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
		if err != nil {
			t.Error(err)
			return
		}
		batch := len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '['
		type request struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		var calls []request
		if batch {
			err = json.Unmarshal(raw, &calls)
		} else {
			calls = make([]request, 1)
			err = json.Unmarshal(raw, &calls[0])
		}
		if err != nil {
			t.Error(err)
			return
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		out := []any{}
		for _, q := range calls {
			n.calls[q.Method]++
			selector := ""
			if len(q.Params) > 0 {
				_ = json.Unmarshal(q.Params[0], &selector)
			}
			var result any
			switch q.Method {
			case "eth_chainId":
				result = "0x1"
			case "eth_syncing":
				result = false
			case "eth_getHeaderByNumber":
				result = n.header
				if selector == "0x0" {
					result = n.genesis
				} else if n.reorg {
					copy := types.CopyHeader(n.header)
					copy.Extra = []byte{9}
					result = copy
				}
			case "eth_getHeaderByHash":
				if selector == n.header.Hash().Hex() {
					result = n.header
				}
			case "eth_getBlockByHash", "eth_getBlockByNumber":
				result = n.block
			case "eth_getBlockReceipts":
				result = n.receipts
			case "eth_getTransactionByHash", "eth_getTransactionByBlockHashAndIndex", "eth_getTransactionByBlockNumberAndIndex":
				index := -1
				if q.Method == "eth_getTransactionByHash" {
					for i, tx := range n.transactions {
						if selector == tx.Hash().Hex() {
							index = i
							break
						}
					}
				} else if len(q.Params) > 1 {
					var s string
					_ = json.Unmarshal(q.Params[1], &s)
					value, e := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
					if e == nil && value < uint64(len(n.transactions)) {
						index = int(value)
					}
				}
				if index >= 0 {
					result = n.block["transactions"].([]any)[index]
				}
			case "eth_getTransactionReceipt":
				for i, tx := range n.transactions {
					if selector == tx.Hash().Hex() {
						result = n.receipts[i]
						break
					}
				}
			case "eth_getLogs":
				result = n.logs
			default:
				t.Error("unexpected history fixture method", q.Method)
				w.WriteHeader(500)
				return
			}
			out = append(out, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		}
		if batch {
			_ = json.NewEncoder(w).Encode(out)
		} else {
			_ = json.NewEncoder(w).Encode(out[0])
		}
	}))
	t.Cleanup(n.server.Close)
	return n
}
func historyHex(n uint64) string { return "0x" + strconv.FormatUint(n, 16) }
func (n *HistoryNode) Network() networkidentity.Binding {
	return networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: n.genesis.Hash().Hex(), DeploymentID: "history-serving"}
}
func (n *HistoryNode) Source(org string) creationfacts.Source {
	b := n.Network()
	key, _ := b.Key()
	return creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(key), Environment: b.Environment, ChainID: b.ChainID, Genesis: n.genesis.Hash(), Deployment: b.DeploymentID}, Organization: org, URL: n.server.URL, Profile: "reth-prague-included-creations/v1", PragueStart: 0, PragueEnd: ^uint64(0)}
}
func (n *HistoryNode) Transport() http.RoundTripper { return n.server.Client().Transport }
func (n *HistoryNode) Hash() common.Hash            { return n.header.Hash() }
func (n *HistoryNode) Reorg(value bool)             { n.mu.Lock(); defer n.mu.Unlock(); n.reorg = value }
func (n *HistoryNode) Calls() map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]int{}
	for k, v := range n.calls {
		out[k] = v
	}
	return out
}
