package tracer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientTraceBoundedProjectionMarkersAndEscaping(t *testing.T) {
	raw := json.RawMessage(`{"type":"CALL","from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","output":"0x","calls":[{"type":"CALL","from":"0x2222222222222222222222222222222222222222","to":"0x3333333333333333333333333333333333333333","input":"0x1234","output":"0xabcd","value":"0x0","redacted":["injected"],"logs":[]}]}`)
	legacy, _, err := ParseStrictCallTrace(raw)
	if err != nil {
		t.Fatal(err)
	}
	bounded, _, err := ParseStrictCallTraceBounded(raw, 4096)
	if err != nil || string(legacy) != string(bounded) {
		t.Fatal("legacy strict parity", err)
	}
	first, err := RedactStrictCallTraceBounded(bounded, map[string]bool{}, 4096)
	if err != nil || !strings.Contains(string(first), `"redacted":["input","value","output","revertReason"]`) || strings.Contains(string(first), "1234") || strings.Contains(string(first), "injected") {
		t.Fatal("masking", string(first), err)
	}
	empty := json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(string(raw), "0x1234", "0x"), "0xabcd", "0x"))
	second, _, _ := ParseStrictCallTraceBounded(empty, 4096)
	second, _ = RedactStrictCallTraceBounded(second, map[string]bool{}, 4096)
	if string(first) != string(second) {
		t.Fatal("hidden size/presence leaked")
	}
	if _, _, err = ParseStrictCallTraceBounded(raw, 100); err == nil {
		t.Fatal("public marshal budget ignored")
	}
	escaped := json.RawMessage(`{"type":"CALL","to":"0x2222222222222222222222222222222222222222","error":"` + strings.Repeat("<", 1000) + `"}`)
	if _, _, err = ParseStrictCallTraceBounded(escaped, 4000); err == nil {
		t.Fatal("escaped text amplification unbudgeted")
	}
}
