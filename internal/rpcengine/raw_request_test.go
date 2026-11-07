package rpcengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"privacy-proxy/internal/admission"
)

func recipientActor() string {
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
}
func rawEnvelope(params any, extra map[string]any) []byte {
	m := map[string]any{"jsonrpc": "2.0", "id": json.Number("9007199254740995"), "method": "eth_sendRawTransaction", "params": params}
	for k, v := range extra {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return raw
}

func TestRawWireFormsBoundTotalEntriesBeforeDedup(t *testing.T) {
	a := recipientActor()
	for name, raw := range map[string][]byte{
		"top":    rawEnvelope([]any{"0x00"}, map[string]any{"visibleTo": []string{a}}),
		"alias":  rawEnvelope([]any{"0x00"}, map[string]any{"privateFor": []string{a}}),
		"params": rawEnvelope([]any{"0x00", map[string]any{"visibleTo": []string{a}}}, nil),
		"empty":  rawEnvelope([]any{"0x00", map[string]any{"visibleTo": []string{}}}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := parseRawRequest(raw)
			entries, ok := r.entries()
			if err != nil || !ok || !r.present || string(r.id) != "9007199254740995" {
				t.Fatal("valid metadata rejected", err)
			}
			if name != "empty" && (len(entries) != 1 || entries[0] != a) {
				t.Fatal(entries)
			}
		})
	}
	list := make([]string, 32)
	for i := range list {
		list[i] = a
	}
	r, err := parseRawRequest(rawEnvelope([]any{"0x00"}, map[string]any{"visibleTo": list}))
	if _, ok := r.entries(); err != nil || !ok {
		t.Fatal("exact raw cap rejected")
	}
	r, err = parseRawRequest(rawEnvelope([]any{"0x00", map[string]any{"visibleTo": []string{a}}}, map[string]any{"visibleTo": list}))
	if _, ok := r.entries(); err != nil || ok {
		t.Fatal("combined cap applied after dedup")
	}
	for _, value := range []any{nil, "actor", map[string]any{}, []any{nil}, []any{[]string{a}}, []string{""}, []string{"did:example:legacy"}, []string{"0x1234"}} {
		r, err := parseRawRequest(rawEnvelope([]any{"0x00"}, map[string]any{"visibleTo": value}))
		if err != nil {
			t.Fatal("presence must survive shape inspection", err)
		}
		if _, ok := r.entries(); ok {
			t.Fatalf("malformed metadata accepted %#v", value)
		}
	}
	if _, err := parseRawRequest(rawEnvelope([]any{"0x00", map[string]any{"privateFor": []string{a}}}, nil)); err == nil {
		t.Fatal("invented params alias")
	}
}

func TestStrictRawMetadataPresenceRejectsBeforeAnyAuthorityOrStoreWork(t *testing.T) {
	// No factory/store/node exists. Any accidental progression beyond the
	// source presence guard would fail instead of silently using stale facts.
	e := &Engine{raw: &rawEngine{readProfile: "strict"}}
	for _, value := range []any{nil, []string{}, []string{recipientActor()}, "malformed"} {
		for _, top := range []string{"visibleTo", "privateFor"} {
			out := e.SubmitRaw(context.Background(), "", "", rawEnvelope([]any{"0x00"}, map[string]any{top: value}))
			if out.Error == nil || out.Error.Code != -32602 {
				t.Fatal("strict presence progressed", out)
			}
		}
		out := e.SubmitRaw(context.Background(), "", "", rawEnvelope([]any{"0x00", map[string]any{"visibleTo": value}}, nil))
		if out.Error == nil || out.Error.Code != -32602 {
			t.Fatal("strict options presence progressed", out)
		}
	}
}

func TestRawEnvelopeClosedShapeAndIndependentCallLimit(t *testing.T) {
	for _, raw := range []string{
		`[{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00"]}]`,
		`{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x00"]}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_call","method":"eth_sendRawTransaction","params":["0x00"]}`,
		`{"jsonrpc":"2.0","id":1,"Method":"eth_sendRawTransaction","params":["0x00"]}`,
		`{"jsonrpc":"2.0","id":{},"method":"eth_sendRawTransaction","params":["0x00"]}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00",{},3]}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00"],"stateOverrides":{}}`,
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00"]} {}`,
	} {
		if _, err := parseRawRequest([]byte(raw)); err == nil {
			t.Fatal("ambiguous raw envelope accepted", raw)
		}
	}
	valid := rawEnvelope([]any{"0x00"}, nil)
	padded := append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, MaxRawRequestBytes-len(valid))...)
	if _, err := parseRawRequest(padded); err != nil {
		t.Fatal("exact outer bound rejected", err)
	}
	if _, err := parseRawRequest(append(padded, ' ')); err == nil {
		t.Fatal("outer bound exceeded")
	}
	call := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x1111111111111111111111111111111111111111"}]}`)
	call = append(call, bytes.Repeat([]byte{' '}, MaxRequestBytes-len(call)+1)...)
	if _, err := parseRequest(call); err == nil {
		t.Fatal("raw engine weakened call body limit")
	}
}

func TestRawFinancialErrorsNeverExposeReasons(t *testing.T) {
	for _, err := range []error{admission.ErrConflict, admission.ErrForbidden, admission.ErrUnauthorized, admission.ErrInvalid, admission.ErrUnavailable, admission.ErrCoverage, admission.ErrValuation, errors.New("secret SQL/record/provider reason")} {
		out := rawFailure(json.RawMessage("1"), err)
		raw, _ := json.Marshal(out)
		if out.Error == nil || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), err.Error()) {
			t.Fatal("raw error leaked", string(raw))
		}
		want := -32002
		if err == admission.ErrConflict || err == admission.ErrForbidden || err == admission.ErrUnauthorized {
			want = -32001
		}
		if out.Error.Code != want {
			t.Fatal("wrong error class", out)
		}
	}
}

func TestRawStartupComposedResourceBudgets(t *testing.T) {
	var budget rawBudget
	for i := 0; i < 8; i++ {
		if !budget.add(8, 4, 15625) {
			t.Fatal("exact aggregate budget rejected")
		}
	}
	if budget.bindings != 64 || budget.lanes != 256 || budget.retained != 1_000_000 || budget.add(1, 0, 0) {
		t.Fatal("aggregate budget failed", budget)
	}
	for _, input := range [][3]int{{9, 0, 0}, {1, 257, 0}, {2, 0, 500001}, {0, 0, 0}, {1, -1, 0}, {1, 0, -1}, {8, math.MaxInt, 0}, {8, 0, math.MaxInt}} {
		b := rawBudget{}
		if b.add(input[0], input[1], input[2]) {
			t.Fatal("over-cap/overflow startup accepted", input)
		}
	}
}
