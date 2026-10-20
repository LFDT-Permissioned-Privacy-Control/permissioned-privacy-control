package server

import (
	"sort"
	"testing"
)

// TestExtractTxHashesFromResponse covers the three JSON-RPC response shapes the
// extractor must handle: log arrays (eth_getLogs), receipts (eth_getTransactionReceipt),
// and transaction objects (eth_getTransactionByHash et al.). The transaction-object
// case uses "hash" rather than "transactionHash" — that's canonical per the Ethereum
// execution-apis spec. Missing that branch is what silently broke visibleTo for
// eth_getTransactionByHash.
func TestExtractTxHashesFromResponse(t *testing.T) {
	const hashA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const hashB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const hashAUpper = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "eth_getTransactionByHash — transaction object with hash field",
			body: `{"jsonrpc":"2.0","id":1,"result":{
				"hash":"` + hashA + `",
				"from":"0x1111111111111111111111111111111111111111",
				"to":"0x2222222222222222222222222222222222222222",
				"blockHash":"0x0000000000000000000000000000000000000000000000000000000000000001",
				"blockNumber":"0x1",
				"transactionIndex":"0x0",
				"value":"0x0",
				"gas":"0x5208",
				"gasPrice":"0x1",
				"input":"0x",
				"nonce":"0x0",
				"v":"0x0","r":"0x0","s":"0x0"
			}}`,
			want: []string{hashA},
		},
		{
			name: "eth_getTransactionByBlockHashAndIndex — same shape as ByHash",
			body: `{"jsonrpc":"2.0","id":1,"result":{"hash":"` + hashA + `","from":"0x1","to":"0x2"}}`,
			want: []string{hashA},
		},
		{
			name: "eth_getTransactionReceipt — receipt uses transactionHash",
			body: `{"jsonrpc":"2.0","id":1,"result":{
				"transactionHash":"` + hashA + `",
				"status":"0x1",
				"from":"0x1111111111111111111111111111111111111111",
				"to":"0x2222222222222222222222222222222222222222",
				"logs":[
					{"address":"0x3333333333333333333333333333333333333333","transactionHash":"` + hashA + `","topics":[],"data":"0x"}
				]
			}}`,
			want: []string{hashA},
		},
		{
			name: "eth_getTransactionReceipt — logs with different tx hashes (should be captured)",
			body: `{"jsonrpc":"2.0","id":1,"result":{
				"transactionHash":"` + hashA + `",
				"logs":[
					{"transactionHash":"` + hashA + `"},
					{"transactionHash":"` + hashB + `"}
				]
			}}`,
			want: []string{hashA, hashB},
		},
		{
			name: "eth_getLogs — array of logs",
			body: `{"jsonrpc":"2.0","id":1,"result":[
				{"address":"0x33","transactionHash":"` + hashA + `","topics":[],"data":"0x"},
				{"address":"0x33","transactionHash":"` + hashB + `","topics":[],"data":"0x"}
			]}`,
			want: []string{hashA, hashB},
		},
		{
			name: "eth_getLogs — duplicate hashes are deduped",
			body: `{"jsonrpc":"2.0","id":1,"result":[
				{"transactionHash":"` + hashA + `"},
				{"transactionHash":"` + hashA + `"}
			]}`,
			want: []string{hashA},
		},
		{
			name: "eth_getLogs — empty array",
			body: `{"jsonrpc":"2.0","id":1,"result":[]}`,
			want: nil,
		},
		{
			name: "hashes are lowercased for consistent DB lookup",
			body: `{"jsonrpc":"2.0","id":1,"result":{"hash":"` + hashAUpper + `","from":"0x1"}}`,
			want: []string{hashA},
		},
		{
			name: "null result returns nil",
			body: `{"jsonrpc":"2.0","id":1,"result":null}`,
			want: nil,
		},
		{
			name: "missing result field returns nil",
			body: `{"jsonrpc":"2.0","id":1}`,
			want: nil,
		},
		{
			name: "invalid JSON returns nil",
			body: `not json`,
			want: nil,
		},
		{
			name: "empty hash field in tx object returns nil",
			body: `{"jsonrpc":"2.0","id":1,"result":{"hash":"","from":"0x1"}}`,
			want: nil,
		},
		{
			name: "tx object with neither hash nor transactionHash returns nil",
			body: `{"jsonrpc":"2.0","id":1,"result":{"from":"0x1","to":"0x2"}}`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTxHashesFromResponse([]byte(tt.body))

			// Sort both for stable comparison — the extractor's output order is
			// map-iteration order, which is not guaranteed.
			sort.Strings(got)
			want := append([]string(nil), tt.want...)
			sort.Strings(want)

			if len(got) != len(want) {
				t.Fatalf("extractTxHashesFromResponse() returned %d hashes, want %d\n got: %v\nwant: %v", len(got), len(want), got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("hash[%d] = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

// TestExtractTxHashesFromResponse_ReceiptDoesNotFalselyClaimTxObject verifies
// that a receipt body (which has no top-level "hash" field, only "transactionHash")
// does not somehow get an empty string added via the tx-object branch. The
// addHash helper must skip empty strings.
func TestExtractTxHashesFromResponse_ReceiptDoesNotFalselyClaimTxObject(t *testing.T) {
	const hashA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	body := `{"jsonrpc":"2.0","id":1,"result":{"transactionHash":"` + hashA + `","logs":[]}}`
	got := extractTxHashesFromResponse([]byte(body))

	if len(got) != 1 || got[0] != hashA {
		t.Fatalf("expected [%s], got %v", hashA, got)
	}
}
