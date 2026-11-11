package rpcexecution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const stateTestAddress = "0x1111111111111111111111111111111111111111"

func stateQuery(t *testing.T, method StateMethod, params string) StateQuery {
	t.Helper()
	q, err := ParseStateQuery(method, []byte(params), DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func stateProofFixture(target string, keys []StateStorageKey) map[string]any {
	rows := make([]any, 0, len(keys))
	for _, key := range keys {
		_, text, _ := stateStorageKey(key.Original)
		rows = append(rows, map[string]any{"key": text, "value": "0x0", "proof": []any{}})
	}
	return map[string]any{"address": target, "accountProof": nil, "balance": "0x0", "codeHash": "0x" + strings.Repeat("00", 32), "nonce": "0x0", "storageHash": "0x" + strings.Repeat("00", 32), "storageProof": rows}
}

func TestStateMethodsActualTLSRetainQueryAndWire(t *testing.T) {
	for method := StateBalance; method <= StateNonce; method++ {
		t.Run(method.String(), func(t *testing.T) {
			n, source, transport := metadataFixture(t)
			params := `["` + stateTestAddress + `","pending"]`
			var expected any = "0x0"
			switch method {
			case StateStorage:
				params, expected = `["`+stateTestAddress+`","0X01","pending"]`, "0x"+strings.Repeat("00", 32)
			case StateCode:
				expected = "0x0102"
			case StateProof:
				params = `["` + stateTestAddress + `",["1","0x` + strings.Repeat("00", 31) + `01","1"],{"blockNumber":"latest"}]`
			}
			q := stateQuery(t, method, params)
			if method == StateProof {
				expected = stateProofFixture(stateTestAddress, q.StorageKeys())
			}
			n.mu.Lock()
			n.results[method.String()] = expected
			n.mu.Unlock()
			client, err := NewStateClient(transport, source, Credential{source.CredentialHeader, "metadata-test-only"}, DefaultStateLimits())
			if err != nil {
				t.Fatal(err)
			}
			obs, err := client.Query(t.Context(), q)
			if err != nil || obs == nil || obs.Method() != method || obs.Query().Digest() != q.Digest() || obs.Query().Target() != q.Target() || obs.Query().Block() != q.Block() || obs.Source() != client.Source() {
				t.Fatal("query/result/source pairing lost", err)
			}
			if len(n.calls) != 3 || n.calls[2].Method != method.String() {
				t.Fatal("wire sequence changed", n.calls)
			}
			wire, _ := json.Marshal(n.calls[2].Params)
			if !bytes.Equal(wire, q.ParamsJSON()) {
				t.Fatal("original normalized params changed", string(wire), string(q.ParamsJSON()))
			}
			detached := obs.ResultJSON()
			detached[0] = '!'
			if obs.ResultJSON()[0] == '!' {
				t.Fatal("result alias")
			}
			copyParams := obs.Query().ParamsJSON()
			copyParams[0] = '!'
			if obs.Query().ParamsJSON()[0] == '!' {
				t.Fatal("query alias")
			}
			copyKeys := obs.Query().StorageKeys()
			if len(copyKeys) > 0 {
				copyKeys[0].Original = "other"
				if obs.Query().StorageKeys()[0].Original == "other" {
					t.Fatal("key alias")
				}
			}
			if client.Source().Profile != "rpc-state/v1" {
				t.Fatal("wrong source diagnostic tag")
			}
			if _, err := client.wire.AcquireCall(t.Context(), Call{}, BlockSelector{}); err == nil {
				t.Fatal("state wire activated execution")
			}
		})
	}
}

func TestStateInputFormAndPairing(t *testing.T) {
	seen := map[[32]byte]bool{}
	for _, tc := range []struct {
		block string
		form  StateInputForm
		hist  bool
	}{
		{"", StateInputOmitted, false}, {",null", StateInputNull, false},
		{`,"latest"`, StateInputString, false}, {`,{"blockNumber":"latest"}`, StateInputObject, true},
		{`,"pending"`, StateInputString, false}, {`,"earliest"`, StateInputString, false},
		{`,"safe"`, StateInputString, false}, {`,"finalized"`, StateInputString, false},
		{`,"0x0"`, StateInputString, true}, {`,{"blockNumber":"0x0"}`, StateInputObject, true},
		{`,"0x` + strings.Repeat("ab", 32) + `"`, StateInputString, true},
		{`,{"blockHash":"0x` + strings.Repeat("ab", 32) + `","requireCanonical":true}`, StateInputObject, true},
	} {
		q := stateQuery(t, StateBalance, `["`+stateTestAddress+`"`+tc.block+`]`)
		if q.Block().InputForm != tc.form || q.Block().HistoricalInput() != tc.hist || seen[q.Digest()] {
			t.Fatal("original input form/query pairing discarded", tc, q.Block())
		}
		seen[q.Digest()] = true
	}
	a := stateQuery(t, StateBalance, `["`+stateTestAddress+`"]`)
	b := stateQuery(t, StateBalance, `["0x2222222222222222222222222222222222222222"]`)
	if a.Digest() == b.Digest() || a.Target() == b.Target() {
		t.Fatal("two scalar-result targets share a query identity")
	}
	raw := []byte(`["` + stateTestAddress + `",["abc"]]`)
	q, err := ParseStateQuery(StateProof, raw, DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = '!'
	}
	if q.StorageKeys()[0].Original != "abc" || !strings.Contains(string(q.ParamsJSON()), "0xabc") {
		t.Fatal("caller input alias or key normalization error")
	}
}

func TestStateStorageKeyWidthAndNullProof(t *testing.T) {
	for _, input := range []string{"", "0x", "0x0", "01", "0Xabc", strings.Repeat("0", 63) + "1", strings.Repeat("f", 63)} {
		t.Run(fmt.Sprintf("bytes-%d-%s", len(input), input), func(t *testing.T) {
			encoded, _ := json.Marshal([]any{stateTestAddress, []string{input}})
			q := stateQuery(t, StateProof, string(encoded))
			key := q.StorageKeys()[0]
			fixture := stateProofFixture(stateTestAddress, q.StorageKeys())
			raw, _ := json.Marshal(fixture)
			if _, err := stateResult(q, raw, DefaultStateLimits()); err != nil {
				t.Fatal("normal key-width/null account proof rejected", input, key, err)
			}
			fixture["storageProof"].([]any)[0].(map[string]any)["key"] = "0x2"
			raw, _ = json.Marshal(fixture)
			if _, err := stateResult(q, raw, DefaultStateLimits()); err == nil {
				t.Fatal("unrequested key accepted")
			}
		})
	}
	q := stateQuery(t, StateProof, `["`+stateTestAddress+`",[]]`)
	raw, _ := json.Marshal(stateProofFixture(stateTestAddress, nil))
	if _, err := stateResult(q, raw, DefaultStateLimits()); err != nil {
		t.Fatal("zero-key account-only proof refused", err)
	}
}

func TestStateInvalidParams(t *testing.T) {
	for _, tc := range []struct {
		method StateMethod
		params string
	}{
		{InvalidStateMethod, `[]`}, {StateMethod(255), `[]`}, {StateBalance, `[]`}, {StateBalance, `null`},
		{StateBalance, `[1]`}, {StateBalance, `["bad"]`}, {StateBalance, `["` + stateTestAddress + `",null,{}]`},
		{StateStorage, `["` + stateTestAddress + `"]`}, {StateStorage, `["` + stateTestAddress + `",null]`},
		{StateStorage, `["` + stateTestAddress + `","` + strings.Repeat("a", 65) + `"]`},
		{StateProof, `["` + stateTestAddress + `",null]`}, {StateProof, `["` + stateTestAddress + `",[null]]`},
		{StateProof, `["` + stateTestAddress + `",["zz"]]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockNumber":"latest","BlockNumber":"pending"}]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockNumber":"latest","requireCanonical":false}]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockHash":"latest"}]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockNumber":null}]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockNumber":"0x1","blockHash":"0x` + strings.Repeat("ab", 32) + `"}]`},
		{StateBalance, `["` + stateTestAddress + `",{"blockNumber":{"blockNumber":"latest"}}]`},
		{StateBalance, `["` + stateTestAddress + `",""]`}, {StateBalance, `["` + stateTestAddress + `",0]`},
		{StateBalance, `["` + stateTestAddress + `","0x8000000000000000"]`},
		{StateBalance, `["` + stateTestAddress + `","0x00"]`},
	} {
		if _, err := ParseStateQuery(tc.method, []byte(tc.params), DefaultStateLimits()); err == nil {
			t.Fatal("invalid state params accepted", tc)
		}
	}
}

func TestStateQueryDigestIndependentFrame(t *testing.T) {
	// Independently calculated with Python hashlib and big-endian length framing.
	q := stateQuery(t, StateBalance, `["`+stateTestAddress+`"]`)
	if fmt.Sprintf("%x", q.Digest()) != "04521da1b6c106d5febac7f25c549339be85448b68f18f20b1369f08a1477aad" {
		t.Fatal("query digest framing changed")
	}
}

func TestStateDefaultTotalProofNodeBoundary(t *testing.T) {
	// Opaque hex-node shapes exercise logical collection limits, not Merkle
	// validity. No proof verification or confidentiality claim is made here.
	l := DefaultStateLimits()
	count := (l.MaxTotalProofNodes + l.MaxProofNodesPerProof - 1) / l.MaxProofNodesPerProof
	keys := make([]string, count)
	for i := range keys {
		keys[i] = "0x1"
	}
	params, _ := json.Marshal([]any{stateTestAddress, keys})
	q := stateQuery(t, StateProof, string(params))
	for _, total := range []int{l.MaxTotalProofNodes, l.MaxTotalProofNodes + 1} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			fixture := stateProofFixture(stateTestAddress, q.StorageKeys())
			remaining := total
			for _, row := range fixture["storageProof"].([]any) {
				n := min(remaining, l.MaxProofNodesPerProof)
				nodes := make([]string, n)
				for i := range nodes {
					nodes[i] = "0x"
				}
				row.(map[string]any)["proof"] = nodes
				remaining -= n
			}
			if remaining != 0 {
				t.Fatal("invalid boundary fixture")
			}
			raw, _ := json.Marshal(fixture)
			_, err := stateResult(q, raw, l)
			if (err != nil) != (total > l.MaxTotalProofNodes) {
				t.Fatal("declared aggregate node ceiling inconsistent with JSON work bound", total, err)
			}
		})
	}
}
