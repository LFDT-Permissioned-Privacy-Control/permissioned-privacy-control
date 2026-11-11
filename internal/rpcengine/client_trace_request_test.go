package rpcengine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientTraceRequestCanonicalAndClosedOptions(t *testing.T) {
	e := &Engine{traceMethods: map[string]bool{"debug_traceCall": true, "bank_trace": true}}
	call := `{"to":"0x1111111111111111111111111111111111111111","input":"0xABcd","data":"0xabCD","value":"0X000a","gas":"ignored"}`
	for _, item := range []struct {
		name, params string
		ok           bool
	}{
		{"plain", "[" + call + "]", true}, {"null-block", "[" + call + ",null]", true}, {"default-config", "[" + call + ",\"latest\",null]", true},
		{"harmless", "[" + call + `,"latest",{"tracer":"callTracer","unknown":[],"tracerConfig":{"onlyTopCall":true,"withLog":false}}]`, true},
		{"js", "[" + call + `,"latest",{"tracer":"{}"}]`, false}, {"logs", "[" + call + `,"latest",{"tracerConfig":{"withLog":true}}]`, false},
		{"structlog", "[" + call + `,"latest",{"disableStack":false}]`, false}, {"override", "[" + call + `,"latest",{"StateOverrides":{}}]`, false},
		{"txindex", "[" + call + `,"latest",{"txIndex":0}]`, false}, {"casecollision", "[" + call + `,"latest",{"tracer":"callTracer","Tracer":"callTracer"}]`, false},
		{"configarray", "[" + call + `,"latest",[]]`, false}, {"badlogtype", "[" + call + `,"latest",{"tracerConfig":{"withLog":null}}]`, false},
		{"pending", "[" + call + `,"pending"]`, false}, {"badblock", "[" + call + `,{"blockNumber":"0x1","unknown":true}]`, false},
		{"input-mismatch", `[{"to":"0x1111111111111111111111111111111111111111","data":"0x00","input":"0x01"}]`, false},
		{"duplicated", `[{"to":"0x1111111111111111111111111111111111111111","data":"0x00","data":"0x00"}]`, false},
		{"creation-null", `[{"to":null,"data":"0x6000"}]`, true}, {"creation-empty", `[{"to":"0x","data":"0x6000"}]`, true},
		{"badfrom", `[{"to":"0x1111111111111111111111111111111111111111","from":null}]`, false}, {"extraarg", "[" + call + `,"latest",{},{}]`, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			q, code := e.parseClientTrace([]byte(`{"jsonrpc":"2.0","id":1.2500e+03,"method":"DEBUG_TRACECALL","params":` + item.params + `}`))
			if (code == 0) != item.ok {
				t.Fatal(code)
			}
			if code == 0 && !q.call.Creation() {
				if string(q.id) != "1.2500e+03" || q.call.Value().String() != "10" || string(q.call.Input()) != "\xab\xcd" {
					t.Fatal("canonical actual call mismatch", string(q.id), q.call.Value(), q.call.Input())
				}
				raw, _ := json.Marshal(q.call.Object())
				if strings.Contains(string(raw), "ignored") {
					t.Fatal("gas forwarded")
				}
			}
		})
	}
	q, code := e.parseClientTrace([]byte(`{"method":"bank_trace","params":[{"to":"0x1111111111111111111111111111111111111111"}]}`))
	if code != 0 || !q.notification || q.method != "bank_trace" {
		t.Fatal("notification/alias", q, code)
	}
}
func TestClientTraceFixedErrorsPreserveRawID(t *testing.T) {
	e := &Engine{}
	for _, id := range []string{`1.2500e+03`, `"\u003c\\\"x>"`, `null`} {
		r := (&TraceOperationResult{owner: e, id: json.RawMessage(id)}).fail(DeniedCompletion, -32001)
		wire, err := r.MarshalResponseFor(e)
		if err != nil || !strings.Contains(string(wire), `"id":`+id+`,"error"`) {
			t.Fatal("error raw ID changed", string(wire), err)
		}
		failed, err := r.MarshalRecordingFailureFor(e)
		if err != nil || !strings.Contains(string(failed), `"id":`+id+`,"error"`) {
			t.Fatal("recording failure raw ID changed", string(failed), err)
		}
	}
}
