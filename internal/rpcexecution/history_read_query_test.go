package rpcexecution

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHistoryReadAllTenTypedParameterShapes(t *testing.T) {
	hash := "0x" + strings.Repeat("12", 32)
	cases := []struct {
		method HistoryMethod
		raw    string
	}{
		{HistoryTransactionByHash, `["` + hash + `"]`}, {HistoryTransactionReceipt, `["` + hash + `"]`},
		{HistoryBlockByHash, `["` + hash + `",true]`}, {HistoryBlockByNumber, `["latest",false]`},
		{HistoryBlockCountByHash, `["` + hash + `"]`}, {HistoryBlockCountByNumber, `["0x0"]`},
		{HistoryTransactionByHashIndex, `["` + hash + `","0xffffffffffffffff"]`}, {HistoryTransactionByNumberIndex, `["pending","0x0"]`},
		{HistoryLogs, `[{"fromBlock":"safe","toBlock":"finalized","topics":[null,[null,"` + hash + `"]]}]`},
		{HistoryBlockReceipts, `[{"blockHash":"` + hash + `","requireCanonical":true}]`},
	}
	seen := map[HistoryMethod]bool{}
	for _, c := range cases {
		q, err := ParseHistoryReadQuery(c.method, json.RawMessage(c.raw), DefaultHistoryReadLimits())
		if err != nil || !q.validFor(DefaultHistoryReadLimits()) || q.Method() != c.method {
			t.Fatal(c.method, err)
		}
		if named, ok := HistoryMethodNamed(c.method.String()); !ok || named != c.method {
			t.Fatal("method catalog mismatch")
		}
		seen[c.method] = true
		copy := q.ParamsJSON()
		copy[0] = 'x'
		if q.ParamsJSON()[0] != '[' {
			t.Fatal("query aliases caller")
		}
	}
	if len(seen) != 10 {
		t.Fatal("not all ten shapes")
	}
}
func TestHistoryReadLogsClosedFieldsAndWildcardSemantics(t *testing.T) {
	hash := "0x" + strings.Repeat("12", 32)
	address := "0x" + strings.Repeat("34", 20)
	q, err := ParseHistoryReadQuery(HistoryLogs, json.RawMessage(`[{"blockHash":null,"fromBlock":null,"address":["`+address+`","`+address+`"],"topics":[[],[null,"`+hash+`"]]}]`), DefaultHistoryReadLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(q.logs.addresses) != 1 || len(q.logs.topics) != 2 || q.logs.topics[0] != nil || q.logs.topics[1] != nil || q.logs.from.Kind != StateLatest || q.logs.to.Kind != StateLatest {
		t.Fatal("geth wildcard/default semantics lost")
	}
	for _, raw := range []string{`[{"blockHash":"` + hash + `","fromBlock":"0x0"}]`, `[{"fromBlock":"0x2","toBlock":"0x1"}]`, `[{"topics":["0x01"]}]`, `[{"address":"0x01"}]`, `[{"topics":[1]}]`, `[{"Unknown":true}]`, `[{"fromBlock":"latest","fromBlock":"earliest"}]`, `[{"topics":[null,null,null,null,null]}]`} {
		if _, err := ParseHistoryReadQuery(HistoryLogs, json.RawMessage(raw), DefaultHistoryReadLimits()); err == nil {
			t.Fatal("malformed/contradictory log query accepted", raw)
		}
	}
}
func TestHistoryReadQueryBoundsPresenceAndCanonicalDigest(t *testing.T) {
	hash := "0x" + strings.Repeat("ab", 32)
	for _, test := range []struct {
		method HistoryMethod
		raw    string
	}{{HistoryInvalid, `[]`}, {HistoryBlockByNumber, `[null,false]`}, {HistoryBlockByNumber, `["` + hash + `",false]`}, {HistoryBlockByNumber, `["latest"]`}, {HistoryBlockByHash, `["` + hash + `",0]`}, {HistoryTransactionByHashIndex, `["` + hash + `","0x00"]`}, {HistoryBlockReceipts, `[{"blockHash":"` + hash + `","blockNumber":"latest"}]`}, {HistoryTransactionReceipt, `["` + hash + `",true]`}} {
		if _, err := ParseHistoryReadQuery(test.method, json.RawMessage(test.raw), DefaultHistoryReadLimits()); err == nil {
			t.Fatal("invalid shape accepted", test.raw)
		}
	}
	l := DefaultHistoryReadLimits()
	l.MaxParamsBytes = 1
	if _, err := ParseHistoryReadQuery(HistoryLogs, json.RawMessage(`[{}]`), l); err == nil {
		t.Fatal("lower input ceiling ignored")
	}
	q, err := ParseHistoryReadQuery(HistoryBlockReceipts, json.RawMessage(`[{"blockNumber":"0x1","requireCanonical":false}]`), DefaultHistoryReadLimits())
	if err != nil || q.block.Kind != StateNumber || q.block.InputForm != StateInputObject {
		t.Fatal("EIP block object lost", err)
	}
	// History does not call HistoricalInput or impose State's admin floor.
	x, _ := ParseHistoryReadQuery(HistoryTransactionByHash, json.RawMessage(`["`+hash+`"]`), DefaultHistoryReadLimits())
	y, _ := ParseHistoryReadQuery(HistoryTransactionByHash, json.RawMessage(`["0x`+strings.ToUpper(hash[2:])+`"]`), DefaultHistoryReadLimits())
	if !bytes.Equal(x.ParamsJSON(), y.ParamsJSON()) || x.Digest() != y.Digest() {
		t.Fatal("equivalent hash spelling changed normalized identity")
	}
}
