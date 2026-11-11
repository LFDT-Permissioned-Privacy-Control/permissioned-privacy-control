package rpcengine

import (
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/readprivacy"
)

func TestMinedConfigComposedV1NullAndProfileVocabulary(t *testing.T) {
	for _, tc := range []struct {
		name, config     string
		strict, standard bool
	}{
		{"absent", "", true, true},
		{"whole-null", ",null", true, true},
		{"named", `,{"tracer":"callTracer"}`, true, true},
		{"empty-nested", `,{"tracer":"callTracer","tracerConfig":{}}`, true, true},
		{"nested-null", `,{"tracer":"callTracer","tracerConfig":null}`, false, false},
		{"top-no-logs", `,{"tracer":"callTracer","tracerConfig":{"onlyTopCall":true,"withLog":false}}`, true, true},
		{"full-request", `,{"tracer":"callTracer","tracerConfig":{"onlyTopCall":false}}`, false, true},
		{"with-logs", `,{"tracer":"callTracer","tracerConfig":{"withLog":true}}`, false, false},
		{"harmless", `,{"tracer":"callTracer","timeout":"100000h","ignored":true}`, false, true},
		{"case-key", `,{"Tracer":"callTracer"}`, false, true},
		{"ambiguous", `,{"Tracer":"callTracer","tracer":"callTracer"}`, false, false},
		{"override", `,{"tracer":"callTracer","txIndex":"0x0"}`, false, false},
		{"javascript", `,{"tracer":"function(){return 'private'}"}`, false, false},
	} {
		for _, profile := range []readprivacy.ReadProfile{readprivacy.ReadProfileStrict, readprivacy.ReadProfileStandard} {
			t.Run(tc.name+"/"+profile.String(), func(t *testing.T) {
				e := &Engine{mined: &minedTraceEngine{profile: profile, methods: map[string]bool{"debug_traceTransaction": true}}}
				raw := `{"jsonrpc":"2.0","id":1.2500e+03,"method":"debug_traceTransaction","params":["0X` + strings.Repeat("A1", 32) + `"` + tc.config + `]}`
				q, code := e.parseMinedTrace([]byte(raw))
				want := tc.standard
				if profile.Strict() {
					want = tc.strict
				}
				if (code == 0) != want {
					t.Fatal("composed V1 config changed", raw, code)
				}
				if tc.name != "ambiguous" && string(q.id) != "1.2500e+03" {
					t.Fatal("original raw ID changed", string(q.id))
				}
			})
		}
	}
}

func TestMinedRequestHashAliasAndNotificationShapes(t *testing.T) {
	e := &Engine{mined: &minedTraceEngine{profile: readprivacy.ReadProfileStrict, methods: map[string]bool{"debug_traceTransaction": true, "bank_trace": true}}}
	for _, tc := range []struct {
		body   string
		code   int
		notify bool
	}{
		{`{"method":"bank_trace","params":["0x` + strings.Repeat("11", 32) + `"]}`, 0, true},
		{`{"id":null,"method":"DEBUG_TRACETRANSACTION","params":["0x` + strings.Repeat("11", 32) + `"]}`, 0, false},
		{`{"id":"x","method":"bank_trace","params":["0x` + strings.Repeat("00", 32) + `"]}`, -32602, false},
		{`{"id":"x","method":"bank_trace","params":[]}`, -32602, false},
		{`{"id":"x","method":"bank_trace","params":[3]}`, -32602, false},
		{`{"id":"x","method":"bank_trace","params":["0x11"]}`, -32602, false},
		{`{"id":"x","method":"bank_trace","params":["0x` + strings.Repeat("11", 32) + `",null,null]}`, -32602, false},
		{`{"id":"x","method":"Bank_trace","params":["0x` + strings.Repeat("11", 32) + `"]}`, -32601, false},
	} {
		q, code := e.parseMinedTrace([]byte(tc.body))
		if code != tc.code || q.notification != tc.notify {
			t.Fatal(tc.body, code, q.notification)
		}
		if !json.Valid(q.id) {
			t.Fatal("invalid owned error ID")
		}
	}
}
