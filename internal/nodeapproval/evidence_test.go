package nodeapproval

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestRetentionIsExactDetachedAndOriginSealed(t *testing.T) {
	s := &Service{}
	a := Approval{HashMode: HashCalls, ChainID: 1, TxHash: common.HexToHash("0x1"), Fingerprint: common.HexToHash("0x2")}
	header := common.HexToHash("0x3")
	calls := `{ "value":"0x0", "large":9007199254740995 }`
	pre := `{ "nonce":18446744073709551615 }`
	mux := []byte(`{"callTracer":` + calls + `,"prestateTracer":` + pre + `}`)
	p := &Prepared{Approval: a, evidence: retainPreparedEvidence(s, a, mux, header, json.RawMessage(`"0x0"`), json.RawMessage(`"0x0"`))}
	p.evidence.prepared = p
	e, ok := s.EvidenceFor(p)
	if !ok || string(e.Calls()) != calls || string(e.Prestate()) != pre || e.HeaderNumber() != 0 || e.HeaderTimestamp() != 0 {
		t.Fatal("retention changed original JSON")
	}
	mux[0] = '['
	e.Calls()[0] = '['
	e.Prestate()[0] = '['
	if string(e.Calls()) != calls || string(e.Prestate()) != pre {
		t.Fatal("retention aliased caller")
	}
	if _, ok := (&Service{}).EvidenceFor(p); ok {
		t.Fatal("other service accepted evidence")
	}
	p.Approval.TxHash = common.Hash{}
	if _, ok := s.EvidenceFor(p); ok {
		t.Fatal("mutated approval accepted")
	}
	if _, ok := new(Prepared).Evidence(); ok {
		t.Fatal("literal fabricated evidence")
	}
}

func TestRetentionBoundsAndClosedDuplicateAwareEnvelope(t *testing.T) {
	s := &Service{}
	a := Approval{}
	header := common.HexToHash("0x3")
	number := json.RawMessage(`"0x0"`)
	retain := func(mux []byte) *preparedEvidence { return retainPreparedEvidence(s, a, mux, header, number, number) }
	for _, raw := range []string{`{"callTracer":{},"callTracer":{},"prestateTracer":{}}`, `{"callTracer":{},"prestateTracer":{},"extra":0}`, `{"callTracer":{}}`, `{"callTracer":{},"prestateTracer":{}}[]`} {
		if retain([]byte(raw)) != nil {
			t.Fatal("ambiguous envelope retained")
		}
	}
	part := []byte(`{"p":"` + strings.Repeat("x", MaxRetainedPartBytes-8) + `"}`)
	if len(part) != MaxRetainedPartBytes {
		t.Fatal("test boundary")
	}
	mux := append([]byte(`{"callTracer":`), part...)
	mux = append(mux, []byte(`,"prestateTracer":{}}`)...)
	if retain(mux) == nil {
		t.Fatal("exact part boundary rejected")
	}
	part = append(part[:len(part)-2], []byte(`x"}`)...)
	mux = append([]byte(`{"callTracer":`), part...)
	mux = append(mux, []byte(`,"prestateTracer":{}}`)...)
	if retain(mux) != nil {
		t.Fatal("part overflow retained")
	}
	if retain(bytes.Repeat([]byte{' '}, MaxRetainedMuxBytes+1)) != nil {
		t.Fatal("mux overflow retained")
	}
	for _, raw := range []json.RawMessage{nil, []byte(`null`), []byte(`false`), []byte(`"0x00"`), []byte(`"0x10000000000000000"`)} {
		if retainPreparedEvidence(s, a, []byte(`{"callTracer":{},"prestateTracer":{}}`), header, raw, number) != nil {
			t.Fatal("invalid optional header available")
		}
	}
}
