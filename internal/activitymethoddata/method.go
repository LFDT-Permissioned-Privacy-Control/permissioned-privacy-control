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

var explorerLabels = [...]string{
	"explorer.accounts",
	"explorer.address_balance",
	"explorer.address_balances",
	"explorer.address_code",
	"explorer.address_contract",
	"explorer.address_internal",
	"explorer.address_is_contract",
	"explorer.address_logs",
	"explorer.address_stats",
	"explorer.address_transactions",
	"explorer.address_transfers",
	"explorer.block_hash",
	"explorer.block_internal",
	"explorer.block_number",
	"explorer.block_transactions",
	"explorer.blocks",
	"explorer.catchup",
	"explorer.chain_id",
	"explorer.head",
	"explorer.indexer_progress",
	"explorer.invalid_request",
	"explorer.invalid_transport",
	"explorer.logs",
	"explorer.search_suggestions",
	"explorer.stats",
	"explorer.sync_status",
	"explorer.token",
	"explorer.token_holders",
	"explorer.token_transfers",
	"explorer.tokens",
	"explorer.transaction",
	"explorer.transaction_internal",
	"explorer.transaction_logs",
	"explorer.transaction_transfers",
	"explorer.transactions",
	"explorer.transactions_page",
	"explorer.transfers",
	"explorer.tx_history",
}

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
