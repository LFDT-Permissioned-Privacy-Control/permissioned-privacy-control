// Package activitymethoddata defines completion populations. Classification is
// not permission or proof that an HTTP/RPC operation actually executed.
package activitymethoddata

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

const (
	Version            = "ops.activity.method-population/v2"
	PopulationRPC      = "SEALED_RPC_COMPLETIONS_AS_OF_CHAIN_HEAD"
	PopulationRequests = "SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD"
	RPCPredicateID     = "sealed-rpc-only/explorer-prefix-reserved/v2"
	RequestPredicateID = "sealed-recognized-requests/explorer-prefix-reserved/v2"
)

type Class uint8

const (
	Unknown Class = iota
	RPC
	Explorer
)

type Operation struct {
	Method, Route, Label, Gate string
	OrgAdminOnly               bool
}

var operations = [...]Operation{
	{"GET", "/chain-id", "explorer.chain_id", "eth_chainId", false},
	{"GET", "/stats", "explorer.stats", "eth_getTransactionByHash", false},
	{"GET", "/stats/tx-history", "explorer.tx_history", "eth_getTransactionByHash", false},
	{"GET", "/blocks", "explorer.blocks", "eth_getBlockByNumber", false},
	{"GET", "/blocks/latest/number", "explorer.head", "eth_blockNumber", false},
	{"GET", "/blocks/hash/:hash", "explorer.block_hash", "eth_getBlockByHash", false},
	{"GET", "/blocks/:number", "explorer.block_number", "eth_getBlockByNumber", false},
	{"GET", "/blocks/:number/transactions", "explorer.block_transactions", "eth_getTransactionByHash", false},
	{"GET", "/blocks/:number/internal", "explorer.block_internal", "eth_getTransactionByHash", false},
	{"GET", "/transactions/paginated", "explorer.transactions_page", "eth_getTransactionByHash", false},
	{"GET", "/transactions", "explorer.transactions", "eth_getTransactionByHash", false},
	{"GET", "/transactions/:hash", "explorer.transaction", "eth_getTransactionByHash", false},
	{"GET", "/transactions/:hash/internal", "explorer.transaction_internal", "eth_getTransactionByHash", false},
	{"GET", "/transactions/:hash/transfers", "explorer.transaction_transfers", "eth_getLogs", false},
	{"GET", "/transactions/:hash/logs", "explorer.transaction_logs", "eth_getLogs", false},
	{"GET", "/addresses/:address/stats", "explorer.address_stats", "eth_getTransactionByHash", false},
	{"GET", "/addresses/:address/transactions", "explorer.address_transactions", "eth_getTransactionByHash", false},
	{"GET", "/addresses/:address/balance", "explorer.address_balance", "eth_getBalance", false},
	{"GET", "/addresses/:address/code", "explorer.address_code", "eth_getCode", false},
	{"GET", "/addresses/:address/balances", "explorer.address_balances", "eth_getLogs", false},
	{"GET", "/addresses/:address/transfers", "explorer.address_transfers", "eth_getLogs", false},
	{"GET", "/addresses/:address/internal", "explorer.address_internal", "eth_getTransactionByHash", false},
	{"GET", "/addresses/:address/logs", "explorer.address_logs", "eth_getLogs", false},
	{"GET", "/addresses/:address/contract", "explorer.address_contract", "eth_getCode", false},
	{"GET", "/addresses/:address/is-contract", "explorer.address_is_contract", "eth_getCode", false},
	{"GET", "/logs", "explorer.logs", "eth_getLogs", false},
	{"GET", "/tokens", "explorer.tokens", "eth_getLogs", false},
	{"GET", "/tokens/:address", "explorer.token", "eth_getLogs", false},
	{"GET", "/tokens/:address/holders", "explorer.token_holders", "eth_getLogs", false},
	{"GET", "/tokens/:address/transfers", "explorer.token_transfers", "eth_getLogs", false},
	{"GET", "/transfers", "explorer.transfers", "eth_getLogs", false},
	{"GET", "/accounts", "explorer.accounts", "eth_getTransactionByHash", false},
	{"GET", "/search/suggestions", "explorer.search_suggestions", "eth_getTransactionByHash", false},
	{"GET", "/sync/status", "explorer.sync_status", "eth_syncing", true},
	{"GET", "/sync/indexer-progress", "explorer.indexer_progress", "eth_syncing", true},
	{"GET", "/sync/catchup", "explorer.catchup", "eth_syncing", true},
}

func Operations() []Operation { return append([]Operation{}, operations[:]...) }

var explorerLabels = func() []string {
	labels := []string{"explorer.invalid_request", "explorer.invalid_transport"}
	for _, op := range operations {
		labels = append(labels, op.Label)
	}
	sort.Strings(labels)
	return labels
}()

// ValidMethod is the existing durable completion grammar, unchanged. It does
// not classify a reserved label or authorize its registration as an RPC name.
func ValidMethod(v string) bool {
	if len(v) < 1 || len(v) > 100 {
		return false
	}
	for i, b := range []byte(v) {
		letter := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
		if !letter && (i == 0 || !(b >= '0' && b <= '9' || b == '_' || b == '.')) {
			return false
		}
	}
	return true
}

// Reserved also catches wrong-case aliases of the closed Explorer namespace.
func Reserved(method string) bool {
	return len(method) >= 9 && strings.EqualFold(method[:9], "explorer.")
}
func Classify(method string) Class {
	if !ValidMethod(method) {
		return Unknown
	}
	if !Reserved(method) {
		return RPC
	}
	n := sort.SearchStrings(explorerLabels[:], method)
	if n < len(explorerLabels) && explorerLabels[n] == method {
		return Explorer
	}
	return Unknown
}
func ExplorerLabels() []string { return append([]string{}, explorerLabels[:]...) }

func framed(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range append([][]byte{[]byte(domain)}, parts...) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var classifierDigest = func() [32]byte {
	parts := [][]byte{
		[]byte("grammar=1..100 ASCII bytes; first=letter; rest=letter,digit,underscore,dot"),
		[]byte("reserved=explorer.;ASCII-case-insensitive"),
		[]byte("RPC=valid and nonreserved"),
		[]byte("Explorer=valid and exact lower-case compiled label"),
	}
	for _, label := range explorerLabels {
		parts = append(parts, []byte(label))
	}
	return framed(Version, parts...)
}()

func ClassifierDigest() [32]byte { return classifierDigest }
func RPCPredicateDigest() [32]byte {
	return framed("ops.activity.population-predicate/v2", []byte(PopulationRPC), classifierDigest[:], []byte(RPCPredicateID))
}
func RequestPredicateDigest() [32]byte {
	return framed("ops.activity.population-predicate/v2", []byte(PopulationRequests), classifierDigest[:], []byte(RequestPredicateID))
}
