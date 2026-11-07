package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizedCallPreservesSupportedExecutionFieldsAndCopies(t *testing.T) {
	raw := `{"to":"` + testTarget + `","from":"` + testTarget + `","gas":"0x100","nonce":"0x2","type":"0x2","chainId":"0x1","maxFeePerGas":"0x10","maxPriorityFeePerGas":"0x1","value":"0x5","data":"0xABCD","input":"0xabcd","accessList":[{"address":"` + testTarget + `","storageKeys":["` + testHash + `","` + testHash + `"]}]}`
	c, e := NormalizeCall([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	wire := c.Object()
	for key, value := range map[string]string{"gas": "0x100", "nonce": "0x2", "type": "0x2", "chainId": "0x1", "maxFeePerGas": "0x10", "maxPriorityFeePerGas": "0x1", "value": "0x5", "data": "0xabcd", "input": "0xabcd"} {
		if wire[key] != value {
			t.Fatalf("lost execution field %s: %v", key, wire[key])
		}
	}
	if !c.FromSupplied() || c.Value().Int64() != 5 || !bytes.Equal(c.Input(), []byte{0xab, 0xcd}) {
		t.Fatal("normalization lost independent root")
	}
	tuple := wire["accessList"].([]any)[0].(map[string]any)
	tuple["storageKeys"].([]any)[0] = "changed"
	if c.Object()["accessList"].([]any)[0].(map[string]any)["storageKeys"].([]any)[0] != testHash {
		t.Fatal("access-list slice escaped")
	}
	c.Input()[0] = 0
	c.Value().SetInt64(100)
	if c.Input()[0] != 0xab || c.Value().Int64() != 5 {
		t.Fatal("root inputs escaped")
	}
	c, e = NormalizeCall([]byte(`{"to":"` + testTarget + `"}`))
	if e != nil || c.FromSupplied() || c.Value().Sign() != 0 {
		t.Fatal("omitted simulation defaults", e)
	}
	c, e = NormalizeCall([]byte(`{"to":"` + testTarget + `","from":"0x0000000000000000000000000000000000000000"}`))
	if e != nil || !c.FromSupplied() {
		t.Fatal("explicit zero lost supplied-from floor", e)
	}
	for _, extra := range []string{
		`"To":"` + testTarget + `"`, `"to":null`, `"from":1`, `"gas":"0x01"`, `"nonce":"0x10000000000000000"`,
		`"data":"0x1"`, `"data":"0x00","input":"0x01"`, `"value":1`, `"gasPrice":"0x1","maxFeePerGas":"0x2"`,
		`"type":"0x0","maxFeePerGas":"0x1"`, `"type":"0x2","gasPrice":"0x1"`, `"type":"0x4"`,
		`"maxFeePerGas":"0x1","maxPriorityFeePerGas":"0x2"`, `"authorizationList":[]`, `"accessList":[{"address":"` + testTarget + `","storageKeys":["0x00"]}]`,
	} {
		if _, e := NormalizeCall([]byte(`{"to":"` + testTarget + `",` + extra + `}`)); e == nil {
			t.Fatalf("accepted %s", extra)
		}
	}
}

func TestBlockSelectorsDoNotInventLatestOrHistoricalPrivilege(t *testing.T) {
	for raw, wantHistorical := range map[string]bool{`"latest"`: false, `"safe"`: false, `"finalized"`: false, `"0x1"`: true, `"` + testHash + `"`: true, `{"blockHash":"` + testHash + `","requireCanonical":true}`: true, `{"blockNumber":"0x1"}`: true} {
		b, e := ParseBlockSelector([]byte(raw))
		if e != nil || b.Historical() != wantHistorical {
			t.Fatalf("%s: %+v %v", raw, b, e)
		}
	}
	for _, raw := range []string{`null`, `"pending"`, `""`, `"0x01"`, `{"blockHash":"` + testHash + `","blockNumber":"0x1"}`, `{"blockNumber":"latest"}`, `{"blockHash":"` + testHash + `","requireCanonical":null}`} {
		if _, e := ParseBlockSelector([]byte(raw)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestTrustedNodeCredentialsCannotRedirectOrUseCallerFallback(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++; w.WriteHeader(500) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	b := testBinding(redirect.URL)
	b.Credentials = map[string]Credential{"allowed": {Header: "X-Key", Value: "secret"}}
	c, e := NewClient(http.DefaultTransport, b, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.WithCredential("allowed")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := ParseBlockSelector(nil)
	if _, e := c.AcquireCall(t.Context(), testCall(t), block); e == nil || redirected != 0 {
		t.Fatal("redirect followed", e, redirected)
	}
	for name, change := range map[string]func(*NodeBinding){
		"URL credentials": func(b *NodeBinding) { b.URL = "http://secret:password@host" },
		"wrong profile":   func(b *NodeBinding) { b.Profile = "unknown" },
		"open-ended fork": func(b *NodeBinding) { b.PragueEndExclusive = 0 },
		"header injection": func(b *NodeBinding) {
			b.Credentials = map[string]Credential{"x": {Header: "X-Key", Value: "secret\r\nX-Injected: x"}}
		},
		"protocol header": func(b *NodeBinding) { b.Credentials = map[string]Credential{"x": {Header: "Host", Value: "host"}} },
	} {
		t.Run(name, func(t *testing.T) {
			b := testBinding("http://trusted.invalid")
			change(&b)
			if _, e := NewClient(http.DefaultTransport, b, DefaultLimits()); e == nil {
				t.Fatal("invalid startup binding")
			}
		})
	}
	called := false
	c, e = NewClient(transportFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}), testBinding("http://trusted.invalid"), DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	c, _ = c.WithCredential("")
	call, _ := NormalizeCall([]byte(`{"to":"` + testTarget + `","chainId":"0x2"}`))
	if _, e = c.AcquireCall(t.Context(), call, block); e == nil || called {
		t.Fatal("wrong source chain reached node", e)
	}
	// Normal JSON round-trip of independent input does not create an acquisition.
	encoded, _ := json.Marshal(c.Metadata())
	if bytes.Contains(encoded, []byte("secret")) {
		t.Fatal("metadata leaked credential")
	}
}
