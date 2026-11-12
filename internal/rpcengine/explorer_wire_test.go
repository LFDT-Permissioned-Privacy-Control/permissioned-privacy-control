package rpcengine

import (
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"

	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/explorerdata"
	wire "privacy-proxy/internal/explorerv2data"
)

func TestExplorerRoutesAndLosslessMaskedValue(t *testing.T) {
	for _, op := range activitymethoddata.Operations() {
		path := op.Route
		path = strings.ReplaceAll(path, ":hash", "0x"+strings.Repeat("1", 64))
		path = strings.ReplaceAll(path, ":address", "0x"+strings.Repeat("2", 40))
		path = strings.ReplaceAll(path, ":number", "1")
		query := ""
		if op.Label == "explorer.search_suggestions" {
			query = "q=bank"
		}
		r, err := parseExplorerRequest("/api/v2/explorer"+path, query)
		if err != nil || r.operation.Label != op.Label {
			t.Fatalf("%s: %s %v", op.Route, r.operation.Label, err)
		}
	}
	for _, tc := range []struct{ input, expected string }{{"", `"value":null`}, {"0", `"value":"0"`}, {"340282366920938463463374607431768211456", `"value":"340282366920938463463374607431768211456"`}} {
		out, err := json.Marshal(wire.Transaction{Value: maskedQuantity(explorerdata.JSONString(tc.input))})
		if err != nil || !strings.Contains(string(out), tc.expected) {
			t.Fatal("masked/zero/lossless distinction", string(out), err)
		}
	}
}

func TestExplorerCategoriesMatchExistingIndexerMeanings(t *testing.T) {
	for _, test := range []struct {
		name              string
		creation, success bool
		value             int64
		input             []byte
		want              []string
	}{
		{"native-value", false, true, 7, nil, []string{"coin_transfer"}},
		{"zero-value", false, true, 0, nil, []string{}},
		{"short-calldata", false, true, 7, []byte{1}, []string{}},
		{"selector", false, true, 0, []byte{1, 2, 3, 4}, []string{"contract_call"}},
		{"creation", true, true, 0, []byte{1}, []string{"contract_creation"}},
		{"failed-creation", true, false, 0, []byte{1}, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := explorerTransactionCategories(test.creation, big.NewInt(test.value), test.input, test.success); !slices.Equal(got, test.want) {
				t.Fatalf("got %v want %v", got, test.want)
			}
		})
	}
}
