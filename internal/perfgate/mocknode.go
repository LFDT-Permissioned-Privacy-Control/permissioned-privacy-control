package perfgate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// MockNodeConfig configures the only mocked component of the gate-2 runner.
type MockNodeConfig struct {
	ChainID      uint64
	DeploymentID string
	PrivateToken string
	// BlockTime is the block cadence used by Run (default 1 s).
	BlockTime time.Duration
	// FinalityLag: a block is final once it is at least this old.
	FinalityLag time.Duration
	// Latency is added to every response before it is written.
	Latency time.Duration
	// MaxBlockTxs caps transactions per block (0 = unlimited).
	MaxBlockTxs int
	Clock       func() time.Time
	// FactWait is how long a submission whose identity requires newer facts
	// than installed waits for them before -32012, like the node's
	// OPS_NODE_POLICY_FACT_WAIT (default 1 s).
	FactWait time.Duration
}

// MockNode answers the public JSON-RPC methods the legacy path forwards and the
// private V2 API (ops_*), from one coherent pool/chain state: real transaction
// hashes, per-sender nonces with gaps held back, receipts only after a block,
// finality after the configured lag, and fact versions/digests derived from the
// published envelopes. Signatures on identity and fact envelopes are not
// verified: the mock stands in for node behaviour, not node security.
type MockNode struct {
	cfg MockNodeConfig

	// factsVersion mirrors facts.version for fact waiters, without m.mu.
	factsVersion atomic.Uint64

	// bootID changes at every Restart, like the node's per-process boot id;
	// epoch counts non-append canonical changes (Reorg); salt keeps rival
	// blocks' hashes distinct from the blocks they replace.
	bootID string
	epoch  uint64
	salt   uint64

	mu       sync.Mutex
	txs      map[string]*mockTx
	accounts map[string]*mockAccount
	dirty    map[string]struct{}
	blocks   []*MockBlock
	index    map[string]indexedTx
	facts    mockFacts
	// Incremental counters: Stats never walks the transaction map.
	pooledCount, includedCount, finalAnswered int64

	statsMu sync.Mutex
	methods map[string]*methodStat
	unknown map[string]int

	// Reply stamps have their own lock so stamping never waits behind block
	// production or status polls on mu.
	stampMu sync.Mutex
	replies map[string]int64
}

type indexedTx struct {
	sender string
	nonce  uint64
}

type mockTx struct {
	hash, sender            string
	nonce                   uint64
	raw                     []byte
	principal, org, context string
	identity                bool
	// guarded: submitted through the private API, so it executes only under
	// a live identity (a restart empties the registry, I3); the identity's
	// floor and expiry decide dominance (T17).
	guarded      bool
	idMin        uint64
	idExpires    int64
	idSigner     string
	block        *MockBlock
	index        int
	factsVersion uint64
	// First submission's arrival (unix ns), for per-stage timing.
	arrivedNS     int64
	finalAnswered bool
}

type mockAccount struct {
	confirmed uint64
	pooled    map[uint64]*mockTx
}

type mockFacts struct {
	version   uint64
	digest    string
	expiresAt int64
}

// MockBlock is one produced block.
type MockBlock struct {
	Number       uint64
	Hash         string
	Parent       string
	Time         time.Time
	Transactions []string
	// Cumulative counts transactions in this block and all earlier ones.
	Cumulative int
}

type methodStat struct {
	Count     int64
	ServiceNS int64
	MaxNS     int64
}

// MethodStat reports calls and the mock's own service time, excluding the
// injected latency.
type MethodStat struct {
	Count            int64   `json:"count"`
	MeanServiceMicro float64 `json:"mean_service_us"`
	MaxServiceMicro  float64 `json:"max_service_us"`
}

// MockStats is a snapshot of the mock's counters.
type MockStats struct {
	Methods        map[string]MethodStat `json:"methods"`
	UnknownMethods map[string]int        `json:"unknown_methods"`
	Pooled         int                   `json:"pooled"`
	Included       int                   `json:"included"`
	Blocks         int                   `json:"blocks"`
	Head           uint64                `json:"head"`
	Finalized      uint64                `json:"finalized"`
	FactsVersion   uint64                `json:"facts_version"`
	FinalAnswered  int64                 `json:"final_status_answered"`
	FinalizedTxs   int64                 `json:"finalized_txs"`
	StalledSenders int                   `json:"stalled_senders"`
	StalledTxs     int                   `json:"stalled_txs"`
	// ConnectionsOpened counts TCP connections accepted per listener (public,
	// private): OPS's node clients churning connections show up here.
	ConnectionsOpened map[string]int64 `json:"connections_opened,omitempty"`
}

func NewMockNode(cfg MockNodeConfig) *MockNode {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.BlockTime <= 0 {
		cfg.BlockTime = time.Second
	}
	if cfg.FactWait <= 0 {
		cfg.FactWait = time.Second
	}
	genesis := &MockBlock{Number: 0, Hash: blockHash(0, "", 0), Time: cfg.Clock()}
	return &MockNode{cfg: cfg, bootID: newBootID(), txs: map[string]*mockTx{}, accounts: map[string]*mockAccount{}, dirty: map[string]struct{}{}, blocks: []*MockBlock{genesis}, index: map[string]indexedTx{}, methods: map[string]*methodStat{}, unknown: map[string]int{}, replies: map[string]int64{}}
}

func blockHash(number uint64, parent string, salt uint64) string {
	var b, s [8]byte
	binary.BigEndian.PutUint64(b[:], number)
	binary.BigEndian.PutUint64(s[:], salt)
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte("perfgate-block"), b[:], []byte(parent), s[:]))
}

func newBootID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// BootID is the mock process's current boot id.
func (m *MockNode) BootID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bootID
}

// Restart models a node process restart: a new boot id and an empty identity
// registry (identities live in memory only). A graceful restart keeps the pool
// (Reth restores it from its backup); a crash (dropPool) loses it. Included
// transactions keep the identity their block's manifest records.
func (m *MockNode) Restart(dropPool bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bootID = newBootID()
	m.epoch = 0 // an in-memory counter restarts with the process
	for _, tx := range m.txs {
		if tx.block == nil {
			tx.identity = false
		}
	}
	if dropPool {
		for sender, account := range m.accounts {
			m.pooledCount -= int64(len(account.pooled))
			account.pooled = map[uint64]*mockTx{}
			delete(m.dirty, sender)
		}
	}
}

// Evict drops a pooled transaction from the pool (same boot); its identity
// stays registered. Reports whether it was pooled.
func (m *MockNode) Evict(hash string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := m.txs[strings.ToLower(hash)]
	if tx == nil || tx.block != nil {
		return false
	}
	account := m.accounts[tx.sender]
	if account == nil || account.pooled[tx.nonce] != tx {
		return false
	}
	delete(account.pooled, tx.nonce)
	m.pooledCount--
	return true
}

// Reorg removes the newest depth blocks (never a finalized one) and puts their
// transactions back into the pool, except those in omit, which leave the pool
// (a rival chain that never carried them). The next blocks are rivals with
// new hashes, and the canonical epoch advances. Returns the blocks removed.
func (m *MockNode) Reorg(depth int, omit ...string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	skip := map[string]bool{}
	for _, hash := range omit {
		skip[strings.ToLower(hash)] = true
	}
	finalized := m.finalizedLocked()
	removed := 0
	for ; removed < depth && len(m.blocks) > 1; removed++ {
		block := m.blocks[len(m.blocks)-1]
		if finalized != nil && block.Number <= finalized.Number {
			break
		}
		for _, hash := range block.Transactions {
			tx := m.txs[hash]
			tx.block, tx.index = nil, 0
			m.includedCount--
			account := m.accounts[tx.sender]
			account.confirmed = min(account.confirmed, tx.nonce)
			if !skip[hash] {
				account.pooled[tx.nonce] = tx
				m.pooledCount++
				m.dirty[tx.sender] = struct{}{}
			}
		}
		m.blocks = m.blocks[:len(m.blocks)-1]
	}
	if removed > 0 {
		m.salt++
		m.epoch++
	}
	return removed
}

// Index registers a pre-signed transaction so submission avoids signature
// recovery on the hot path. hash must be the lowercase 0x-prefixed tx hash.
func (m *MockNode) Index(hash, sender string, nonce uint64) {
	m.mu.Lock()
	m.index[hash] = indexedTx{sender: strings.ToLower(sender), nonce: nonce}
	m.mu.Unlock()
}

// Run produces a block every BlockTime until ctx ends.
func (m *MockNode) Run(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.BlockTime)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.ProduceBlock()
		}
	}
}

// ProduceBlock includes, for every sender, the contiguous run of pooled
// transactions starting at its next nonce.
func (m *MockNode) ProduceBlock() MockBlock {
	m.mu.Lock()
	defer m.mu.Unlock()
	parent := m.blocks[len(m.blocks)-1]
	block := &MockBlock{Number: parent.Number + 1, Parent: parent.Hash, Time: m.cfg.Clock()}
	block.Hash = blockHash(block.Number, parent.Hash, m.salt)
	now := m.cfg.Clock().Unix()
	senders := make([]string, 0, len(m.dirty))
	for sender := range m.dirty {
		senders = append(senders, sender)
	}
	sort.Strings(senders)
	for _, sender := range senders {
		account := m.accounts[sender]
		for {
			if m.cfg.MaxBlockTxs > 0 && len(block.Transactions) >= m.cfg.MaxBlockTxs {
				break
			}
			tx, ok := account.pooled[account.confirmed]
			if !ok {
				break
			}
			if tx.guarded && (!tx.identity || tx.idExpires <= now) {
				// No live identity: denied at build, it stays pooled and
				// holds back the sender's later nonces (I3).
				break
			}
			delete(account.pooled, account.confirmed)
			account.confirmed++
			tx.block, tx.index, tx.raw = block, len(block.Transactions), nil
			tx.factsVersion = max(m.facts.version, 1)
			block.Transactions = append(block.Transactions, tx.hash)
			m.pooledCount--
			m.includedCount++
		}
		if len(account.pooled) == 0 {
			delete(m.dirty, sender)
		}
	}
	block.Cumulative = parent.Cumulative + len(block.Transactions)
	m.blocks = append(m.blocks, block)
	return *block
}

// FinalityCounts is the number of included and of finalized transactions.
type FinalityCounts struct {
	Included, Finalized int64
}

// FinalityCounts reports cumulative included and finalized transactions.
func (m *MockNode) FinalityCounts() FinalityCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := FinalityCounts{Included: int64(m.blocks[len(m.blocks)-1].Cumulative)}
	if f := m.finalizedLocked(); f != nil {
		out.Finalized = int64(f.Cumulative)
	}
	return out
}

// FinalizationTimes maps every included transaction to the instant the mock
// starts reporting it as finalized (block time + finality lag).
func (m *MockNode) FinalizationTimes() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]time.Time, len(m.txs))
	for _, block := range m.blocks {
		at := block.Time.Add(m.cfg.FinalityLag)
		for _, hash := range block.Transactions {
			out[hash] = at
		}
	}
	return out
}

// finalizedLocked returns the newest block at least FinalityLag old.
func (m *MockNode) finalizedLocked() *MockBlock {
	cutoff := m.cfg.Clock().Add(-m.cfg.FinalityLag)
	i := sort.Search(len(m.blocks), func(i int) bool { return m.blocks[i].Time.After(cutoff) })
	if i == 0 {
		return nil
	}
	return m.blocks[i-1]
}

// Stats returns a snapshot of the counters.
func (m *MockNode) Stats() MockStats {
	m.mu.Lock()
	out := MockStats{Blocks: len(m.blocks) - 1, Head: m.blocks[len(m.blocks)-1].Number, FactsVersion: m.facts.version, Pooled: int(m.pooledCount), Included: int(m.includedCount), FinalAnswered: m.finalAnswered}
	if f := m.finalizedLocked(); f != nil {
		out.Finalized, out.FinalizedTxs = f.Number, int64(f.Cumulative)
	}
	m.mu.Unlock()
	out.StalledSenders, out.StalledTxs = m.Stalled()
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	out.Methods = map[string]MethodStat{}
	for name, s := range m.methods {
		out.Methods[name] = MethodStat{Count: s.Count, MeanServiceMicro: float64(s.ServiceNS) / float64(s.Count) / 1e3, MaxServiceMicro: float64(s.MaxNS) / 1e3}
	}
	out.UnknownMethods = map[string]int{}
	for name, n := range m.unknown {
		out.UnknownMethods[name] = n
	}
	return out
}

type rpcRequest struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// poolRejected is the node's -32013 (T18 wire).
func poolRejected(reason string) *rpcError {
	return &rpcError{Code: -32013, Message: "transaction pool rejected", Data: map[string]string{"reason": reason}}
}

// errRejected is the node's opaque -32000.
var errRejected = &rpcError{Code: -32000, Message: "private execution request rejected"}

func (e *rpcError) Error() string { return e.Message }

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// MarshalJSON keeps a null result explicit (receipts of pending transactions).
func (r rpcResponse) MarshalJSON() ([]byte, error) {
	id := r.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	if r.Error != nil {
		return json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   *rpcError       `json:"error"`
		}{"2.0", id, r.Error})
	}
	return json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result"`
	}{"2.0", id, r.Result})
}

// callInfo carries the request's arrival time in and, for a submission, the
// transaction hash to stamp with the reply time out.
type callInfo struct {
	arrived time.Time
	stamp   string
}

type handlerFunc func(params []json.RawMessage, call *callInfo) (any, *rpcError)

// Public is the node's public JSON-RPC endpoint (NODE_URL).
func (m *MockNode) Public() http.Handler {
	return m.serve(func(method string) handlerFunc {
		return m.publicMethods()[method]
	}, "")
}

// Private is the V2 private policy/identity endpoint (OPS_NODE_POLICY_URL).
func (m *MockNode) Private() http.Handler {
	return m.serve(func(method string) handlerFunc {
		return m.privateMethods()[method]
	}, m.cfg.PrivateToken)
}

func (m *MockNode) serve(lookup func(string) handlerFunc, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		started := time.Now()
		var payload any
		stamp := ""
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var batch []rpcRequest
			if json.Unmarshal(trimmed, &batch) != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			responses := make([]rpcResponse, len(batch))
			for i, req := range batch {
				responses[i], _ = m.dispatch(lookup, req, started)
			}
			payload = responses
		} else {
			var req rpcRequest
			if json.Unmarshal(trimmed, &req) != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			payload, stamp = m.dispatch(lookup, req, started)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if m.cfg.Latency > 0 {
			time.Sleep(m.cfg.Latency)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
		if stamp != "" {
			// Push the reply out before stamping, so the stamp is the send time.
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			m.stampReply(stamp, time.Now())
		}
	})
}

func (m *MockNode) stampReply(hash string, at time.Time) {
	m.stampMu.Lock()
	if _, seen := m.replies[hash]; !seen {
		m.replies[hash] = at.UnixNano()
	}
	m.stampMu.Unlock()
}

func (m *MockNode) dispatch(lookup func(string) handlerFunc, req rpcRequest, started time.Time) (rpcResponse, string) {
	handler := lookup(req.Method)
	if handler == nil {
		m.statsMu.Lock()
		m.unknown[req.Method]++
		m.statsMu.Unlock()
		return rpcResponse{ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}}, ""
	}
	call := &callInfo{arrived: started}
	result, rpcErr := handler(req.Params, call)
	elapsed := time.Since(started).Nanoseconds()
	m.statsMu.Lock()
	s := m.methods[req.Method]
	if s == nil {
		s = &methodStat{}
		m.methods[req.Method] = s
	}
	s.Count++
	s.ServiceNS += elapsed
	s.MaxNS = max(s.MaxNS, elapsed)
	m.statsMu.Unlock()
	if rpcErr != nil {
		return rpcResponse{ID: req.ID, Error: rpcErr}, ""
	}
	return rpcResponse{ID: req.ID, Result: result}, call.stamp
}

func hexUint(v uint64) string { return "0x" + strconv.FormatUint(v, 16) }

func stringParam(params []json.RawMessage, i int) (string, *rpcError) {
	var s string
	if len(params) <= i || json.Unmarshal(params[i], &s) != nil {
		return "", &rpcError{Code: -32602, Message: "invalid params"}
	}
	return s, nil
}

func (m *MockNode) publicMethods() map[string]handlerFunc {
	constant := func(v any) handlerFunc { return func([]json.RawMessage, *callInfo) (any, *rpcError) { return v, nil } }
	return map[string]handlerFunc{
		"eth_chainId":              constant(hexUint(m.cfg.ChainID)),
		"net_version":              constant(strconv.FormatUint(m.cfg.ChainID, 10)),
		"net_listening":            constant(true),
		"web3_clientVersion":       constant("perfgate-mock/1"),
		"eth_syncing":              constant(false),
		"eth_gasPrice":             constant("0x3b9aca00"),
		"eth_maxPriorityFeePerGas": constant("0xf4240"),
		"eth_getCode":              constant("0x"),
		"eth_call":                 constant("0x"),
		"eth_estimateGas":          constant("0x5208"),
		"eth_getBalance":           constant("0xd3c21bcecceda1000000"),
		"eth_blockNumber": func([]json.RawMessage, *callInfo) (any, *rpcError) {
			m.mu.Lock()
			defer m.mu.Unlock()
			return hexUint(m.blocks[len(m.blocks)-1].Number), nil
		},
		"eth_getTransactionCount": m.transactionCount,
		"eth_sendRawTransaction": func(params []json.RawMessage, call *callInfo) (any, *rpcError) {
			raw, e := stringParam(params, 0)
			if e != nil {
				return nil, e
			}
			hash, e := m.pool(raw, nil, call.arrived)
			if e != nil {
				return nil, e
			}
			call.stamp = hash
			return hash, nil
		},
		"eth_getTransactionReceipt": m.receipt,
		"eth_getTransactionByHash":  m.transactionByHash,
		"eth_getBlockByNumber":      m.blockByNumber,
		"debug_traceCall":           m.traceCall,
	}
}

func (m *MockNode) transactionCount(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	address, e := stringParam(params, 0)
	if e != nil {
		return nil, e
	}
	tag := "latest"
	var byHash struct {
		BlockHash string `json:"blockHash"`
	}
	if len(params) > 1 {
		if json.Unmarshal(params[1], &tag) != nil && json.Unmarshal(params[1], &byHash) != nil {
			return nil, &rpcError{Code: -32602, Message: "invalid block selector"}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if byHash.BlockHash != "" {
		// EIP-1898: the nonce at exactly this canonical block.
		tag = ""
		for _, block := range m.blocks {
			if strings.EqualFold(block.Hash, byHash.BlockHash) {
				tag = hexUint(block.Number)
			}
		}
		if tag == "" {
			return nil, &rpcError{Code: -32001, Message: "block not found"}
		}
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64); err == nil && strings.HasPrefix(tag, "0x") {
		// The nonce at a block: transactions of the sender included up to it.
		if n >= uint64(len(m.blocks)) {
			return nil, &rpcError{Code: -32000, Message: "header not found"}
		}
		return hexUint(m.nonceAtLocked(strings.ToLower(address), n)), nil
	}
	account := m.accounts[strings.ToLower(address)]
	if account == nil {
		return "0x0", nil
	}
	nonce := account.confirmed
	if tag == "pending" {
		for {
			if _, ok := account.pooled[nonce]; !ok {
				break
			}
			nonce++
		}
	}
	return hexUint(nonce), nil
}

// identity is the fields the mock reads from an identity payload.
type identity struct {
	Network struct {
		ChainID      uint64 `json:"chain_id"`
		DeploymentID string `json:"deployment_id"`
	} `json:"network"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"`
	Scope              string `json:"scope"`
	ContextID          string `json:"context_id"`
	PrincipalID        string `json:"principal_id"`
	OrgID              string `json:"org_id"`
	Signer             string `json:"signer"`
	BindingHash        string `json:"binding_hash"`
	MinSnapshotVersion uint64 `json:"min_snapshot_version"`
}

type envelope struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
}

// decodeRaw decodes raw transaction bytes and their sender (from the
// pre-signed index when registered).
func (m *MockNode) decodeRaw(rawHex string) ([]byte, string, indexedTx, *rpcError) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(rawHex, "0x"), "0X"))
	if err != nil || len(raw) == 0 {
		return nil, "", indexedTx{}, &rpcError{Code: -32602, Message: "invalid raw transaction"}
	}
	hash := "0x" + hex.EncodeToString(crypto.Keccak256(raw))
	m.mu.Lock()
	known, ok := m.index[hash]
	m.mu.Unlock()
	if !ok {
		var tx types.Transaction
		if tx.UnmarshalBinary(raw) != nil {
			return nil, "", indexedTx{}, &rpcError{Code: -32602, Message: "invalid raw transaction"}
		}
		from, err := types.Sender(types.LatestSignerForChainID(new(big.Int).SetUint64(m.cfg.ChainID)), &tx)
		if err != nil {
			return nil, "", indexedTx{}, &rpcError{Code: -32000, Message: "invalid sender"}
		}
		known = indexedTx{sender: strings.ToLower(from.Hex()), nonce: tx.Nonce()}
	}
	return raw, hash, known, nil
}

// submitGuarded is ops_submitTransaction: register the identity (dominance,
// T17), then offer the bytes to the pool (T18). A definitive pool refusal
// undoes exactly this registration.
func (m *MockNode) submitGuarded(rawHex string, id *identity, arrived time.Time) (string, *rpcError) {
	raw, hash, known, e := m.decodeRaw(rawHex)
	if e != nil {
		return "", e
	}
	if id.BindingHash != hash {
		return "", &rpcError{Code: -32003, Message: "identity is bound to another transaction"}
	}
	now := m.cfg.Clock().Unix()
	if id.ExpiresAt != 0 && id.ExpiresAt <= now {
		return "", errRejected // expired envelope
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := m.txs[hash]
	fresh := tx == nil
	if fresh {
		tx = &mockTx{hash: hash, sender: known.sender, nonce: known.nonce, raw: raw, arrivedNS: arrived.UnixNano()}
	}
	prior := *tx
	live := tx.identity && (tx.idExpires == 0 || tx.idExpires > now)
	install := true
	if live {
		if tx.principal != id.PrincipalID || tx.org != id.OrgID || tx.idSigner != strings.ToLower(id.Signer) {
			return "", errRejected // bound to another identity
		}
		attemptCovers := id.MinSnapshotVersion >= tx.idMin && id.ExpiresAt >= tx.idExpires
		storedCovers := tx.idMin >= id.MinSnapshotVersion && tx.idExpires >= id.ExpiresAt
		switch {
		case attemptCovers:
		case storedCovers:
			install = false // dominated: idempotent success, registration unchanged
		default:
			return "", errRejected // incomparable
		}
	}
	if install {
		tx.principal, tx.org, tx.context, tx.identity, tx.guarded = id.PrincipalID, id.OrgID, id.ContextID, true, true
		tx.idMin, tx.idExpires, tx.idSigner = id.MinSnapshotVersion, id.ExpiresAt, strings.ToLower(id.Signer)
	}
	undo := func(reason string) (string, *rpcError) {
		if !fresh {
			*tx = prior
		}
		return "", poolRejected(reason)
	}
	if tx.block != nil {
		return hash, nil // nonce used by its own canonical receipt: accepted
	}
	account := m.accounts[tx.sender]
	if account == nil {
		account = &mockAccount{pooled: map[uint64]*mockTx{}}
		m.accounts[tx.sender] = account
	}
	if account.pooled[tx.nonce] == tx {
		return hash, nil // already known
	}
	if tx.nonce < account.confirmed {
		return undo("nonce_used")
	}
	if _, occupied := account.pooled[tx.nonce]; occupied {
		return undo("replaced")
	}
	if fresh {
		m.txs[hash] = tx
	}
	if tx.raw == nil {
		tx.raw = raw
	}
	account.pooled[tx.nonce] = tx
	m.pooledCount++
	m.dirty[tx.sender] = struct{}{}
	return hash, nil
}

// pool admits raw bytes on the public path. Known bytes are idempotent; a
// different transaction at a consumed or occupied nonce is refused like a
// real pool.
func (m *MockNode) pool(rawHex string, id *identity, arrived time.Time) (string, *rpcError) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(rawHex, "0x"), "0X"))
	if err != nil || len(raw) == 0 {
		return "", &rpcError{Code: -32602, Message: "invalid raw transaction"}
	}
	hash := "0x" + hex.EncodeToString(crypto.Keccak256(raw))
	if id != nil && id.BindingHash != hash {
		return "", &rpcError{Code: -32003, Message: "identity is bound to another transaction"}
	}
	m.mu.Lock()
	known, ok := m.index[hash]
	m.mu.Unlock()
	if !ok {
		var tx types.Transaction
		if tx.UnmarshalBinary(raw) != nil {
			return "", &rpcError{Code: -32602, Message: "invalid raw transaction"}
		}
		from, err := types.Sender(types.LatestSignerForChainID(new(big.Int).SetUint64(m.cfg.ChainID)), &tx)
		if err != nil {
			return "", &rpcError{Code: -32000, Message: "invalid sender"}
		}
		known = indexedTx{sender: strings.ToLower(from.Hex()), nonce: tx.Nonce()}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.txs[hash]; existing != nil {
		if id != nil {
			existing.principal, existing.org, existing.context, existing.identity = id.PrincipalID, id.OrgID, id.ContextID, true
		}
		return hash, nil
	}
	account := m.accounts[known.sender]
	if account == nil {
		account = &mockAccount{pooled: map[uint64]*mockTx{}}
		m.accounts[known.sender] = account
	}
	if known.nonce < account.confirmed {
		return "", &rpcError{Code: -32000, Message: "nonce too low"}
	}
	if _, occupied := account.pooled[known.nonce]; occupied {
		return "", &rpcError{Code: -32000, Message: "replacement transaction underpriced"}
	}
	tx := &mockTx{hash: hash, sender: known.sender, nonce: known.nonce, raw: raw, arrivedNS: arrived.UnixNano()}
	m.pooledCount++
	if id != nil {
		tx.principal, tx.org, tx.context, tx.identity = id.PrincipalID, id.OrgID, id.ContextID, true
	}
	m.txs[hash] = tx
	account.pooled[known.nonce] = tx
	m.dirty[known.sender] = struct{}{}
	return hash, nil
}

func (m *MockNode) receipt(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	hash, e := stringParam(params, 0)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := m.txs[strings.ToLower(hash)]
	if tx == nil || tx.block == nil {
		return nil, nil
	}
	return map[string]any{"transactionHash": tx.hash, "blockHash": tx.block.Hash, "blockNumber": hexUint(tx.block.Number), "transactionIndex": hexUint(uint64(tx.index)),
		"from": tx.sender, "to": nil, "status": "0x1", "gasUsed": "0x5208", "cumulativeGasUsed": hexUint(uint64(21000 * (tx.index + 1))), "effectiveGasPrice": "0x3b9aca00",
		"logs": []any{}, "logsBloom": "0x" + strings.Repeat("00", 256), "contractAddress": nil, "type": "0x2"}, nil
}

func (m *MockNode) transactionByHash(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	hash, e := stringParam(params, 0)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := m.txs[strings.ToLower(hash)]
	if tx == nil || (tx.block == nil && m.accounts[tx.sender].pooled[tx.nonce] != tx) {
		return nil, nil // neither pooled nor included (evicted, or lost in a crash)
	}
	out := map[string]any{"hash": tx.hash, "from": tx.sender, "nonce": hexUint(tx.nonce), "blockHash": nil, "blockNumber": nil, "transactionIndex": nil}
	if tx.block != nil {
		out["blockHash"], out["blockNumber"], out["transactionIndex"] = tx.block.Hash, hexUint(tx.block.Number), hexUint(uint64(tx.index))
	}
	return out, nil
}

func (m *MockNode) blockByNumber(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	tag, e := stringParam(params, 0)
	if e != nil {
		return nil, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var block *MockBlock
	switch tag {
	case "latest", "pending", "safe":
		block = m.blocks[len(m.blocks)-1]
	case "finalized":
		block = m.finalizedLocked()
	case "earliest":
		block = m.blocks[0]
	default:
		n, err := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 64)
		if err == nil && n < uint64(len(m.blocks)) {
			block = m.blocks[n]
		}
	}
	if block == nil {
		return nil, nil
	}
	return map[string]any{"number": hexUint(block.Number), "hash": block.Hash, "parentHash": block.Parent, "timestamp": hexUint(uint64(block.Time.Unix())),
		"transactions": append([]string{}, block.Transactions...), "gasLimit": "0xbebc200", "gasUsed": hexUint(uint64(21000 * len(block.Transactions))), "baseFeePerGas": "0x3b9aca00"}, nil
}

// traceCall answers a callTracer frame for a value transfer: no subcalls, no logs.
func (m *MockNode) traceCall(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	if len(params) == 0 {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	var call map[string]any
	if json.Unmarshal(params[0], &call) != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	field := func(name, fallback string) string {
		if s, ok := call[name].(string); ok && s != "" {
			return strings.ToLower(s)
		}
		return fallback
	}
	input := field("data", field("input", "0x"))
	return map[string]any{"type": "CALL", "from": field("from", "0x0000000000000000000000000000000000000000"), "to": field("to", "0x0000000000000000000000000000000000000000"),
		"value": field("value", "0x0"), "gas": field("gas", "0x5208"), "gasUsed": "0x5208", "input": input, "output": "0x"}, nil
}

func (m *MockNode) privateMethods() map[string]handlerFunc {
	return map[string]handlerFunc{
		"ops_policyStatus":        m.policyStatus,
		"ops_policyApply":         m.policyApply,
		"ops_submitTransaction":   m.submitTransaction,
		"ops_transactionStatus":   m.transactionStatus,
		"ops_transactionStatuses": m.transactionStatuses,
	}
}

// Capabilities mirrors nodepolicy.RequiredCapabilities plus the optional
// fact_wait_v1 (RD-1411). The compatibility test in internal/nodepolicy
// fails if they drift.
var Capabilities = []string{"per_frame_a5", "signed_identity_v1", "fact_stream_v1", "simulation_v1", "archive_v1", "candidate_simulation_v1", "scoped_diagnostics_v1", "finalized_status_v1", "boot_id_v1", "fact_wait_v1", "transaction_statuses_v1"}

type network struct {
	ChainID      uint64 `json:"chain_id"`
	DeploymentID string `json:"deployment_id"`
}

func (m *MockNode) policyStatus([]json.RawMessage, *callInfo) (any, *rpcError) {
	m.mu.Lock()
	facts, boot := m.facts, m.bootID
	m.mu.Unlock()
	ready := facts.version > 0 && facts.expiresAt > m.cfg.Clock().Unix()
	reason := ""
	if !ready {
		reason = "facts_unavailable"
	}
	return struct {
		ProtocolVersion int      `json:"protocol_version"`
		Network         network  `json:"network"`
		Capabilities    []string `json:"capabilities"`
		Version         uint64   `json:"version"`
		Digest          string   `json:"digest"`
		ExpiresAt       int64    `json:"expires_at"`
		Ready           bool     `json:"ready"`
		Reason          string   `json:"reason"`
		BootID          string   `json:"boot_id"`
	}{1, network{m.cfg.ChainID, m.cfg.DeploymentID}, Capabilities, facts.version, facts.digest, facts.expiresAt, ready, reason, boot}, nil
}

func (m *MockNode) decodeEnvelope(raw json.RawMessage, kinds ...string) (envelope, *rpcError) {
	var e envelope
	if json.Unmarshal(raw, &e) != nil {
		return e, &rpcError{Code: -32602, Message: "invalid envelope"}
	}
	for _, kind := range kinds {
		if e.Kind == kind {
			return e, nil
		}
	}
	return e, &rpcError{Code: -32602, Message: "unexpected envelope kind"}
}

func (m *MockNode) policyApply(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	if len(params) != 1 {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	e, rpcErr := m.decodeEnvelope(params[0], "snapshot", "delta", "heartbeat")
	if rpcErr != nil {
		return nil, rpcErr
	}
	var payload struct {
		Network         network `json:"network"`
		ExpiresAt       int64   `json:"expires_at"`
		Version         uint64  `json:"version"`
		PreviousVersion uint64  `json:"previous_version"`
		Digest          string  `json:"digest"`
	}
	if json.Unmarshal(e.Payload, &payload) != nil || payload.Network != (network{m.cfg.ChainID, m.cfg.DeploymentID}) || payload.Version == 0 {
		return nil, &rpcError{Code: -32602, Message: "invalid fact payload"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch e.Kind {
	case "heartbeat":
		if payload.Version != m.facts.version || payload.Digest != m.facts.digest {
			return nil, &rpcError{Code: -32011, Message: "resync required"}
		}
		m.facts.expiresAt = max(m.facts.expiresAt, payload.ExpiresAt)
	case "delta":
		if payload.PreviousVersion != m.facts.version || payload.Version <= m.facts.version {
			return nil, &rpcError{Code: -32011, Message: "resync required"}
		}
		fallthrough
	default:
		if payload.Version < m.facts.version {
			return nil, &rpcError{Code: -32000, Message: "stale snapshot"}
		}
		digest := sha256.Sum256(e.Payload)
		m.facts = mockFacts{version: payload.Version, digest: hex.EncodeToString(digest[:]), expiresAt: payload.ExpiresAt}
		m.factsVersion.Store(payload.Version)
	}
	return struct {
		Version   uint64 `json:"version"`
		Digest    string `json:"digest"`
		ExpiresAt int64  `json:"expires_at"`
		BootID    string `json:"boot_id"`
	}{m.facts.version, m.facts.digest, m.facts.expiresAt, m.bootID}, nil
}

// waitForFacts waits up to FactWait for the installed facts to reach version,
// then answers -32012, as the node does (T14). Before any facts were
// published the mock does not enforce versions (its own unit tests submit
// without a publisher; the real node refuses).
func (m *MockNode) waitForFacts(version uint64) *rpcError {
	deadline := time.Now().Add(m.cfg.FactWait)
	for {
		installed := m.factsVersion.Load()
		if installed == 0 || installed >= version {
			return nil
		}
		if time.Now().After(deadline) {
			return &rpcError{Code: -32012, Message: "policy facts pending"}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (m *MockNode) submitTransaction(params []json.RawMessage, call *callInfo) (any, *rpcError) {
	if len(params) != 2 {
		return nil, &rpcError{Code: -32602, Message: "invalid params"}
	}
	e, rpcErr := m.decodeEnvelope(params[0], "identity")
	if rpcErr != nil {
		return nil, rpcErr
	}
	var id identity
	if json.Unmarshal(e.Payload, &id) != nil || id.Scope != "transaction" || id.ContextID == "" || id.Network.ChainID != m.cfg.ChainID || id.Network.DeploymentID != m.cfg.DeploymentID {
		return nil, &rpcError{Code: -32003, Message: "invalid identity"}
	}
	raw, rpcErr := stringParam(params, 1)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if rpcErr := m.waitForFacts(id.MinSnapshotVersion); rpcErr != nil {
		return nil, rpcErr
	}
	hash, rpcErr := m.submitGuarded(raw, &id, call.arrived)
	if rpcErr != nil {
		return nil, rpcErr
	}
	call.stamp = hash
	return struct {
		TransactionHash string `json:"transaction_hash"`
		ContextID       string `json:"context_id"`
		Status          string `json:"status"`
		BootID          string `json:"boot_id"`
	}{hash, id.ContextID, "accepted", m.BootID()}, nil
}

type executionOutcome struct {
	Status               string   `json:"status"`
	FactsVersion         uint64   `json:"facts_version"`
	BlockHash            *string  `json:"block_hash"`
	BlockNumber          *uint64  `json:"block_number"`
	Finalized            bool     `json:"finalized"`
	FinalizedBlockHash   *string  `json:"finalized_block_hash"`
	FinalizedBlockNumber *uint64  `json:"finalized_block_number"`
	ReasonCode           string   `json:"reason_code"`
	Created              []string `json:"created"`
}

type transactionStatus struct {
	TransactionHash string           `json:"transaction_hash"`
	PrincipalID     string           `json:"principal_id"`
	OrgID           string           `json:"org_id"`
	ContextID       string           `json:"context_id"`
	Execution       executionOutcome `json:"execution"`
}

func (m *MockNode) statusLocked(hash string, finalized *MockBlock) *transactionStatus {
	tx := m.txs[hash]
	// Not included: only a live registration answers (a restart empties the
	// registry); included: the block's manifest names the executed identity.
	if tx == nil || tx.principal == "" || (tx.block == nil && !tx.identity) {
		return nil
	}
	out := &transactionStatus{TransactionHash: tx.hash, PrincipalID: tx.principal, OrgID: tx.org, ContextID: tx.context, Execution: executionOutcome{Status: "pending", FactsVersion: m.facts.version, Created: []string{}}}
	if tx.block == nil && tx.idExpires != 0 && tx.idExpires <= m.cfg.Clock().Unix() {
		out.Execution.Status, out.Execution.ReasonCode = "expired", "IDENTITY_EXPIRED"
	}
	if finalized != nil {
		number, hash := finalized.Number, finalized.Hash
		out.Execution.FinalizedBlockHash, out.Execution.FinalizedBlockNumber = &hash, &number
	}
	if tx.block != nil {
		number, hash := tx.block.Number, tx.block.Hash
		out.Execution.Status, out.Execution.FactsVersion = "included", tx.factsVersion
		out.Execution.BlockHash, out.Execution.BlockNumber = &hash, &number
		out.Execution.Finalized = finalized != nil && finalized.Number >= number
		if out.Execution.Finalized && !tx.finalAnswered {
			tx.finalAnswered = true
			m.finalAnswered++
		}
	}
	return out
}

func (m *MockNode) transactionStatus(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	hash, rpcErr := stringParam(params, 0)
	if rpcErr != nil {
		return nil, rpcErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.statusLocked(strings.ToLower(hash), m.finalizedLocked())
	if status == nil {
		return nil, errRejected
	}
	return struct {
		*transactionStatus
		BootID string `json:"boot_id"`
	}{status, m.bootID}, nil
}

// MaxStatusBatch is the per-call cap of the batched status prototype.
const MaxStatusBatch = 256

type batchedEntry struct {
	*transactionStatus
	Pooled bool `json:"pooled"`
}

type finalizedHead struct {
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

// transactionStatuses is ops_transactionStatuses (capability
// transaction_statuses_v1, the final A3 wire): the boot id, the finalized
// head (null while only genesis is final), the canonical epoch and one entry
// per hash (null when unknown), at most MaxStatusBatch hashes. With the
// optional senders parameter it adds receipts (a canonical block holds the
// hash) and the senders' nonces after the finalized block (null without one).
// Malformed parameters are the node's opaque -32000.
func (m *MockNode) transactionStatuses(params []json.RawMessage, _ *callInfo) (any, *rpcError) {
	var hashes, senders []string
	valid := func(raw json.RawMessage, size int, out *[]string) bool {
		if json.Unmarshal(raw, out) != nil || len(*out) == 0 || len(*out) > MaxStatusBatch {
			return false
		}
		for _, v := range *out {
			if len(v) != 2+2*size || !strings.HasPrefix(v, "0x") || strings.ToLower(v) != v {
				return false
			}
			if _, err := hex.DecodeString(v[2:]); err != nil {
				return false
			}
		}
		return true
	}
	if len(params) < 1 || len(params) > 2 || !valid(params[0], 32, &hashes) || (len(params) == 2 && !valid(params[1], 20, &senders)) {
		return nil, errRejected
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	finalized := m.finalizedLocked()
	if finalized != nil && finalized.Number == 0 {
		finalized = nil // only genesis is final: no finality to report
	}
	out := make([]*batchedEntry, len(hashes))
	for i, hash := range hashes {
		if status := m.statusLocked(hash, finalized); status != nil {
			tx := m.txs[hash]
			out[i] = &batchedEntry{transactionStatus: status, Pooled: tx.block == nil && m.accounts[tx.sender].pooled[tx.nonce] == tx}
		}
	}
	var head *finalizedHead
	if finalized != nil {
		head = &finalizedHead{Number: finalized.Number, Hash: finalized.Hash, Timestamp: max(finalized.Time.Unix(), 1)}
	}
	type batch struct {
		BootID         string          `json:"boot_id"`
		Finalized      *finalizedHead  `json:"finalized"`
		CanonicalEpoch uint64          `json:"canonical_epoch"`
		Statuses       []*batchedEntry `json:"statuses"`
	}
	answer := batch{m.bootID, head, m.epoch, out}
	if senders == nil {
		return answer, nil
	}
	receipts := make([]bool, len(hashes))
	for i, hash := range hashes {
		tx := m.txs[hash]
		receipts[i] = tx != nil && tx.block != nil
	}
	var nonces []uint64
	if finalized != nil {
		nonces = make([]uint64, len(senders))
		for j, sender := range senders {
			nonces[j] = m.nonceAtLocked(sender, finalized.Number)
		}
	}
	return struct {
		batch
		Receipts     []bool   `json:"receipts"`
		SenderNonces []uint64 `json:"sender_nonces"`
	}{answer, receipts, nonces}, nil
}

// nonceAtLocked is a sender's account nonce after block number: its
// transactions included up to it (the mock's senders start at nonce 0).
func (m *MockNode) nonceAtLocked(sender string, number uint64) uint64 {
	var count uint64
	for _, block := range m.blocks[1 : min(number, uint64(len(m.blocks)-1))+1] {
		for _, hash := range block.Transactions {
			if m.txs[hash].sender == sender {
				count++
			}
		}
	}
	return count
}

// Stalled reports senders whose pooled transactions wait behind a nonce gap
// (a rejected or never-sent earlier nonce) and how many transactions wait.
func (m *MockNode) Stalled() (senders, txs int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, account := range m.accounts {
		if len(account.pooled) == 0 {
			continue
		}
		if _, ready := account.pooled[account.confirmed]; !ready {
			senders++
			txs += len(account.pooled)
		}
	}
	return senders, txs
}

// Lapsed returns the pooled guarded transactions whose identity has expired
// (a lease gap: the node would not include them, and they hold back their
// sender's later nonces).
func (m *MockNode) Lapsed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Clock().Unix()
	var out []string
	for _, account := range m.accounts {
		for _, tx := range account.pooled {
			if tx.guarded && tx.identity && tx.idExpires != 0 && tx.idExpires <= now {
				out = append(out, tx.hash)
			}
		}
	}
	return out
}

// Stamp is one transaction's mock-side timeline (unix ns; 0 = never).
type Stamp struct {
	Arrived, Replied, Finalized int64
}

// Stamps returns per-hash arrival, reply and finalization instants.
func (m *MockNode) Stamps() map[string]Stamp {
	m.stampMu.Lock()
	replies := make(map[string]int64, len(m.replies))
	for hash, at := range m.replies {
		replies[hash] = at
	}
	m.stampMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Stamp, len(m.txs))
	for hash, tx := range m.txs {
		s := Stamp{Arrived: tx.arrivedNS, Replied: replies[hash]}
		if tx.block != nil {
			s.Finalized = tx.block.Time.Add(m.cfg.FinalityLag).UnixNano()
		}
		out[hash] = s
	}
	return out
}
