package rpcexecution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Exact public result from the owned cached-Reth metadata wire qualification.
// Its stage/warp shape also matches Alloy rpc-types-eth 2.3.0 SyncInfo/Stage.
const metadataObservedRethSync = `{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0","warpChunksAmount":null,"warpChunksProcessed":null,"stages":[{"name":"AccountHashing","block":"0x0"},{"name":"Bodies","block":"0x0"},{"name":"Era","block":"0x0"},{"name":"Execution","block":"0x0"},{"name":"Finish","block":"0x0"},{"name":"Headers","block":"0x0"},{"name":"IndexAccountHistory","block":"0x0"},{"name":"IndexStorageHistory","block":"0x0"},{"name":"MerkleExecute","block":"0x0"},{"name":"MerkleUnwind","block":"0x0"},{"name":"Prune","block":"0x0"},{"name":"PruneSenderRecovery","block":"0x0"},{"name":"SenderRecovery","block":"0x0"},{"name":"StorageHashing","block":"0x0"},{"name":"TransactionLookup","block":"0x0"}]}`

func TestMetadataSyncingObservedResultTLS(t *testing.T) {
	n, source, transport := metadataFixture(t)
	n.mu.Lock()
	n.results["eth_syncing"] = json.RawMessage(metadataObservedRethSync)
	n.mu.Unlock()
	q := metadataQuery(t, MetadataSyncing, "[]")
	observation, err := metadataClient(t, source, transport, DefaultMetadataLimits()).Query(t.Context(), q)
	if err != nil || observation == nil || observation.Method() != MetadataSyncing {
		t.Fatal("actual Reth progress rejected", err)
	}
	if !bytes.Equal(observation.ResultJSON(), []byte(metadataObservedRethSync)) {
		t.Fatal("stage order, labels or optional nulls changed")
	}
	detached := observation.ResultJSON()
	detached[0] = '['
	if !bytes.Equal(observation.ResultJSON(), []byte(metadataObservedRethSync)) {
		t.Fatal("result getter aliased the observation")
	}
	n.mu.Lock()
	calls := append([]metadataTestRPC(nil), n.calls...)
	n.mu.Unlock()
	if len(calls) != 3 || calls[0].Method != "eth_chainId" || calls[1].Method != "eth_getHeaderByNumber" || calls[2].Method != "eth_syncing" {
		t.Fatal("network qualification or physical call count changed", calls)
	}
}

func TestMetadataSyncingTypedProgress(t *testing.T) {
	progress := func(extra string) string {
		return `{"startingBlock":"0x0","currentBlock":"0x0","highestBlock":"0x0"` + extra + `}`
	}
	cases := []struct {
		name, raw string
		valid     bool
	}{
		{"not-syncing", "false", true},
		{"required-only", progress(""), true},
		{"warp-null", progress(`,"warpChunksAmount":null,"warpChunksProcessed":null`), true},
		{"warp-quantity", progress(`,"warpChunksAmount":"0x` + strings.Repeat("f", 64) + `","warpChunksProcessed":"0x1"`), true},
		{"stages-null", progress(`,"stages":null`), true},
		{"stages-empty", progress(`,"stages":[]`), true},
		{"spaced-name-uint64", progress(`,"stages":[{"name":"Stage 1","block":"0xffffffffffffffff"}]`), true},
		{"unicode-name", progress(`,"stages":[{"name":"étape 一","block":"0x0"}]`), true},
		{"name-128bytes", progress(`,"stages":[{"name":"` + strings.Repeat("é", 64) + `","block":"0x0"}]`), true},
		{"duplicate-stage-order", progress(`,"stages":[{"name":"Stage 1","block":"0x1"},{"name":"Stage 1","block":"0x0"}]`), true},
		{"old-scalar-extension", progress(`,"healedBytecodes":"0x1"`), true},
		{"true", "true", false}, {"null", "null", false}, {"array-root", "[]", false},
		{"missing-required", `{"currentBlock":"0x0","highestBlock":"0x0"}`, false},
		{"null-required", `{"startingBlock":null,"currentBlock":"0x0","highestBlock":"0x0"}`, false},
		{"wrong-warp-type", progress(`,"warpChunksAmount":0`), false},
		{"warp-overflow", progress(`,"warpChunksProcessed":"0x1` + strings.Repeat("0", 64) + `"`), false},
		{"stages-object", progress(`,"stages":{}`), false},
		{"stages-text", progress(`,"stages":"x"`), false},
		{"null-stage", progress(`,"stages":[null]`), false},
		{"nested-stage", progress(`,"stages":[[]]`), false},
		{"missing-name", progress(`,"stages":[{"block":"0x0"}]`), false},
		{"missing-block", progress(`,"stages":[{"name":"Stage 1"}]`), false},
		{"extra-stage-field", progress(`,"stages":[{"name":"Stage 1","block":"0x0","other":"0x0"}]`), false},
		{"stage-case", progress(`,"stages":[{"Name":"Stage 1","block":"0x0"}]`), false},
		{"stage-duplicate", progress(`,"stages":[{"name":"Stage 1","name":"Stage 2","block":"0x0"}]`), false},
		{"stage-fold-duplicate", progress(`,"stages":[{"name":"Stage 1","Name":"Stage 2","block":"0x0"}]`), false},
		{"stage-alias", progress(`,"stages":[{"stage_name":"Stage 1","block_number":"0x0"}]`), false},
		{"empty-name", progress(`,"stages":[{"name":"","block":"0x0"}]`), false},
		{"name-129bytes", progress(`,"stages":[{"name":"` + strings.Repeat("x", 129) + `","block":"0x0"}]`), false},
		{"name-control", progress(`,"stages":[{"name":"Stage\n1","block":"0x0"}]`), false},
		{"name-delete", progress(`,"stages":[{"name":"Stage\u007f1","block":"0x0"}]`), false},
		{"numeric-name", progress(`,"stages":[{"name":1,"block":"0x0"}]`), false},
		{"stage-block-overflow", progress(`,"stages":[{"name":"Stage 1","block":"0x10000000000000000"}]`), false},
		{"stage-block-numeric", progress(`,"stages":[{"name":"Stage 1","block":0}]`), false},
		{"stage-block-noncanonical", progress(`,"stages":[{"name":"Stage 1","block":"0x00"}]`), false},
		{"stage-block-uppercase", progress(`,"stages":[{"name":"Stage 1","block":"0xA"}]`), false},
		{"unknown-null", progress(`,"other":null`), false},
		{"unknown-object", progress(`,"other":{"block":"0x0"}`), false},
		{"unknown-array", progress(`,"other":[]`), false},
		{"reserved-warp-case", progress(`,"WarpChunksAmount":"0x0"`), false},
		{"reserved-stages-case", progress(`,"Stages":"0x0"`), false},
		{"reserved-fold-duplicate", progress(`,"stages":[],"Stages":[]`), false},
		{"invalid-UTF8-name", progress(`,"stages":[{"name":"` + string([]byte{0xff}) + `","block":"0x0"}]`), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result, err := metadataResult(metadataQuery(t, MetadataSyncing, "[]"), []byte(test.raw), DefaultMetadataLimits())
			if (err == nil) != test.valid || err != nil && result != nil {
				t.Fatal("typed progress shape mismatch", err)
			}
		})
	}
}

func TestMetadataSyncingCollectionBounds(t *testing.T) {
	for _, count := range []int{64, 65} {
		t.Run(fmt.Sprintf("stages-%d", count), func(t *testing.T) {
			stages := make([]map[string]string, count)
			for i := range stages {
				stages[i] = map[string]string{"name": "Stage 1", "block": "0x0"}
			}
			raw, err := json.Marshal(map[string]any{"startingBlock": "0x0", "currentBlock": "0x0", "highestBlock": "0x0", "stages": stages})
			if err != nil {
				t.Fatal(err)
			}
			_, err = metadataResult(metadataQuery(t, MetadataSyncing, "[]"), raw, DefaultMetadataLimits())
			if (err != nil) != (count == 65) {
				t.Fatal("stage collection cap ignored", err)
			}
		})
	}
	for _, count := range []int{32, 33} {
		t.Run(fmt.Sprintf("root-members-%d", count), func(t *testing.T) {
			object := map[string]any{"startingBlock": "0x0", "currentBlock": "0x0", "highestBlock": "0x0", "warpChunksAmount": nil, "warpChunksProcessed": nil, "stages": nil}
			for i := 6; i < count; i++ {
				object[fmt.Sprintf("counter%d", i)] = "0x0"
			}
			raw, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			_, err = metadataResult(metadataQuery(t, MetadataSyncing, "[]"), raw, DefaultMetadataLimits())
			if (err != nil) != (count == 33) {
				t.Fatal("root member cap ignored", err)
			}
		})
	}
	n, source, transport := metadataFixture(t)
	n.mu.Lock()
	n.results["eth_syncing"] = json.RawMessage(metadataObservedRethSync)
	n.mu.Unlock()
	limits := DefaultMetadataLimits()
	limits.MaxResultBytes = 128
	if result, err := metadataClient(t, source, transport, limits).Query(t.Context(), metadataQuery(t, MetadataSyncing, "[]")); err == nil || result != nil {
		t.Fatal("lower response-wire cap ignored")
	}
}
