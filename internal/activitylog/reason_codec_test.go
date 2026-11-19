package activitylog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	r "privacy-proxy/internal/activityreasondata"
)

func TestReasonV2CanonicalWireAndUnchangedLegacyV1(t *testing.T) {
	legacy, raw := normalEnvelope(t)
	if legacy.Reason != "" {
		t.Fatal("historical reason fabricated")
	}
	encoded, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("legacy canonical bytes changed", err)
	}
	golden := bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":2`), 1)
	golden = bytes.Replace(golden, []byte(`"s":502,`), []byte(`"s":502,"c":"submission_outcome_unknown",`), 1)
	e, err := DecodeEnvelope(golden)
	if err != nil || e.Reason != r.SubmissionOutcomeUnknown || e.Version != 2 {
		t.Fatal("v2 reason rejected", err)
	}
	e.BufferSeq = ""
	spool, err := EncodeSpool(toRecord(e))
	if err != nil || !bytes.Contains(spool, []byte(`"s":502,"c":"submission_outcome_unknown"`)) || bytes.Contains(spool, []byte(`"b":`)) {
		t.Fatal("v2 spool shape changed", err)
	}
	restored, err := DecodeSpool(spool)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealEnvelope(restored, 1099511627777)
	if err != nil || !bytes.Equal(sealed, golden) {
		t.Fatal("v2 canonical seal round trip changed", err)
	}
	format := Format()
	if hex.EncodeToString(format[:]) != "5c438991d27e95b4bd0bf76c9a95a5e604d9c4dbdfab8a8e32e65e5ba8ace337" {
		t.Fatal("dual-read profile digest changed")
	}
	if LegacyFormat() == Format() {
		t.Fatal("dual-read format did not invalidate old format-bound continuations")
	}
	for name, bad := range map[string][]byte{
		"v1 reason forbidden":   bytes.Replace(golden, []byte(`"v":2`), []byte(`"v":1`), 1),
		"v2 reason required":    bytes.Replace(golden, []byte(`,"c":"submission_outcome_unknown"`), nil, 1),
		"v2 null reason":        bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":null`), 1),
		"v2 zero reason":        bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":""`), 1),
		"unknown policy prefix": bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":"policy_unreviewed"`), 1),
		"wrong outcome":         bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":"method_not_allowed"`), 1),
		"unknown version":       bytes.Replace(golden, []byte(`"v":2`), []byte(`"v":3`), 1),
		"duplicate reason":      bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":"submission_outcome_unknown","c":"submission_outcome_unknown"`), 1),
		"unreviewed field":      bytes.Replace(golden, []byte(`"c":"submission_outcome_unknown"`), []byte(`"c":"submission_outcome_unknown","reasonText":"untrusted"`), 1),
		"entry cap":             append(bytes.Clone(golden), bytes.Repeat([]byte(" "), MaxEncodedBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEnvelope(bad); err == nil {
				t.Fatal("invalid durable metadata accepted")
			}
		})
	}
}

func TestRecorderFixedV2ReasonValidationAndMixedCrashRecovery(t *testing.T) {
	cfg, store := recorderFixture(t)
	first, err := New(t.Context(), cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := normalEnvelope(t)
	binding := first.run.Binding()
	legacy.Network, legacy.Generation, legacy.Configuration = hex.EncodeToString(binding.Metadata.NetworkKey[:]), binding.Metadata.Generation, hex.EncodeToString(binding.Metadata.Configuration[:])
	legacy.ProducerID, legacy.RunID, legacy.BufferSeq = binding.ProducerID, binding.RunID, ""
	oldSpool, err := EncodeSpool(toRecord(legacy))
	if err != nil {
		t.Fatal(err)
	}
	oldSeq, err := first.buffer.Append(oldSpool)
	if err != nil {
		t.Fatal(err)
	}
	oldSealed, err := SealEnvelope(toRecord(legacy), oldSeq)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	second, err := New(t.Context(), cfg, store)
	if err != nil {
		t.Fatal("old pending spool not recovered", err)
	}
	for _, code := range []r.Code{"unknown", r.MethodNotAllowed} {
		slot, err := second.Reserve()
		if err != nil {
			t.Fatal(err)
		}
		if receipt, err := slot.Complete(Completion{Method: "eth_call", HTTPStatus: 200, Outcome: Success, Reason: code}); err == nil || receipt != nil {
			t.Fatal("unknown/wrong-pair reason normalized or appended")
		}
	}
	slot, err := second.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	code := int32(-32001)
	receipt, err := slot.Complete(Completion{Method: "eth_call", HTTPStatus: 200, Outcome: Denied, RPCErrorCode: &code, Reason: r.SenderNotLinked})
	if err != nil {
		t.Fatal(err)
	}
	slot, err = second.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slot.Complete(Completion{Method: "eth_call", HTTPStatus: 200, Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	pending, err := second.buffer.DrainBounded(0, 8, MaxEncodedBytes, MaxBatchBytes)
	if err != nil || len(pending) != 3 {
		t.Fatal("mixed pending records lost or invalid input appended", len(pending), err)
	}
	versions, reasons := []uint8{}, []r.Code{}
	for _, entry := range pending {
		record, err := DecodeSpool(entry.Data)
		if err != nil {
			t.Fatal(err)
		}
		versions, reasons = append(versions, record.Fields().Version), append(reasons, record.Fields().Reason)
	}
	if versions[0] != 1 || versions[1] != 2 || versions[2] != 2 || reasons[0] != "" || reasons[1] != r.SenderNotLinked || reasons[2] != r.NotRecorded {
		t.Fatal("legacy reason or fixedv2 writer changed", versions, reasons)
	}
	// Model a committed SQL write whose acknowledgment was lost before deletion.
	if err := second.run.SealBatch(t.Context(), pending[:2]); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	third, err := New(t.Context(), cfg, store)
	if err != nil {
		t.Fatal("mixed committed/pending recovery failed", err)
	}
	defer third.Close(t.Context())
	if _, err := third.sealer.Tick(t.Context()); err != nil {
		t.Fatal("mixed recovered batch failed", err)
	}
	left, err := third.buffer.DrainBounded(0, 8, MaxEncodedBytes, MaxBatchBytes)
	if err != nil || len(left) != 0 {
		t.Fatal("verified mixed batch not settled", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.sealed) != 3 || store.sealed[oldSeq] != string(oldSealed) {
		t.Fatal("legacy bytes/history changed or records duplicated")
	}
	sealed, err := DecodeEnvelope([]byte(store.sealed[receipt.Sequence()]))
	if err != nil || sealed.Version != 2 || sealed.Reason != r.SenderNotLinked || strings.Contains(store.sealed[oldSeq], `"c":`) {
		t.Fatal("recorded v2 reason lost or historical reason invented", err)
	}
}
