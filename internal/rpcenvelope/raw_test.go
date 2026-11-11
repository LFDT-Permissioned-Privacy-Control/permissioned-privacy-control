package rpcenvelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRawOwnsExactIDAndOmission(t *testing.T) {
	input := []byte(`{"jsonrpc":"2.0","id":9007199254740993,"method":"eth_chainId","params":["0x"],"visibleTo":["bank"]}`)
	e, err := ParseRaw(input, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 'x'
	}
	id, present := e.IDJSON()
	if !present || string(id) != "9007199254740993" || e.Method() != "eth_chainId" || string(e.ParamsJSON()) != `["0x"]` || string(e.VersionJSON()) != `"2.0"` {
		t.Fatal("lost exact selected members")
	}
	id[0] = '0'
	params := e.ParamsJSON()
	params[0] = 'x'
	version := e.VersionJSON()
	version[0] = 'x'
	if again, _ := e.IDJSON(); string(again) != "9007199254740993" || string(e.ParamsJSON()) != `["0x"]` || string(e.VersionJSON()) != `"2.0"` {
		t.Fatal("getter aliases owned storage")
	}
	for _, test := range []struct {
		body, id, params string
		present          bool
	}{{`{"method":"eth_chainId"}`, "", "", false}, {`{"method":"eth_chainId","id":null,"params":null}`, "null", "null", true}, {`{"method":"eth_chainId","id":""}`, `""`, "", true}, {`{"method":"eth_chainId","id":1.500e+2}`, "1.500e+2", "", true}} {
		e, err := ParseRaw([]byte(test.body), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		id, present := e.IDJSON()
		if present != test.present || string(id) != test.id || string(e.ParamsJSON()) != test.params {
			t.Fatal("omission/null/lexical number lost", test.body)
		}
	}
}

func TestRawSharesLegacyAmbiguityAndTypeFloor(t *testing.T) {
	for _, body := range []string{
		`{"method":"eth_chainId","Method":"eth_accounts"}`,
		`{"method":"eth_chainId","extra":{"k":1,"\u212a":2}}`,
		`{"method":"eth_chainId","extra":"\ud800"}`,
		`{"method":{},"id":1}`, `{"method":"eth_chainId","id":[]}`,
		`{"method":"eth_chainId","id":1e309}`, `{"method":"eth_chainId","params":{}}`,
		`{"method":"eth_chainId","jsonrpc":2}`, `{"method":"eth_chainId"} {}`,
		"{\"method\":\"\xff\"}",
	} {
		if e, err := ParseRaw([]byte(body), DefaultLimits()); err == nil || e != nil {
			t.Fatalf("ambiguous/malformed accepted: %q", body)
		}
	}
	if _, err := ParseRaw([]byte(`[{"method":"eth_chainId"}]`), DefaultLimits()); !errors.Is(err, ErrBatchRequest) {
		t.Fatal("batch error identity lost", err)
	}
	// Parser keeps legacy nullable types; the engine chooses protocol validity.
	if e, err := ParseRaw([]byte(`{"method":null,"jsonrpc":"1.0"}`), DefaultLimits()); err != nil || e.Method() != "" || string(e.VersionJSON()) != `"1.0"` {
		t.Fatal("parser silently changed protocol validity", e, err)
	}
}

func TestRawBudgetIncludesDroppedMembersAndScalarValues(t *testing.T) {
	body := []byte(`{"method":"eth_chainId","extra":[0,{"x":true}]}`)
	limits := DefaultLimits()
	limits.MaxBytes, limits.MaxDepth, limits.MaxValues = len(body), 4, 6
	if _, err := ParseRaw(body, limits); err != nil {
		t.Fatal("exact byte/depth/value boundary", err)
	}
	for _, change := range []func(*Limits){func(l *Limits) { l.MaxBytes-- }, func(l *Limits) { l.MaxDepth-- }, func(l *Limits) { l.MaxValues-- }, func(l *Limits) { l.MaxValues = 0 }} {
		lower := limits
		change(&lower)
		if _, err := ParseRaw(body, lower); err == nil {
			t.Fatal("dropped unknown/scalar member escaped budget", lower)
		}
	}
	large := []byte(`{"method":"eth_chainId","extra":[` + strings.Repeat(`null,`, 120000) + `null]}`)
	if _, err := ParseRaw(large, DefaultLimits()); err == nil {
		t.Fatal("global value ceiling escaped")
	}
	if _, err := ParseEnvelope(bytes.ReplaceAll(body, []byte(`true`), []byte(`false`))); err != nil {
		t.Fatal("raw limits tightened legacy parser", err)
	}
}
