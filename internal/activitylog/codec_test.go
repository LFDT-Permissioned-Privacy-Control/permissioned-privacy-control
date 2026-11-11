package activitylog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func normalEnvelope(t *testing.T) (Envelope, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/normal-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	e, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e, raw
}
func TestExactSpoolAndSealedCodecVector(t *testing.T) {
	e, raw := normalEnvelope(t)
	if len(raw) != 625 {
		t.Fatal(len(raw))
	}
	e.BufferSeq = ""
	record := toRecord(e)
	spoolRaw, err := EncodeSpool(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(spoolRaw, []byte(`"b":`)) {
		t.Fatal("spool accepted caller sequence")
	}
	restored, err := DecodeSpool(spoolRaw)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealEnvelope(restored, 1099511627777)
	if err != nil || !bytes.Equal(sealed, raw) {
		t.Fatal("actual sequence changed canonical envelope", err)
	}
	if _, err := DecodeSpool(raw); err == nil {
		t.Fatal("sealed variant accepted as spool")
	}
	if _, err := DecodeEnvelope(spoolRaw); err == nil {
		t.Fatal("spool accepted as sealed")
	}
	if _, err := SealEnvelope(Record{}, 1); err == nil {
		t.Fatal("zero record accepted")
	}
	if _, err := SealEnvelope(record, 0); err == nil {
		t.Fatal("zero buffer sequence accepted")
	}
	var vectors struct {
		Format string `json:"format"`
	}
	b, err := os.ReadFile("testdata/wire-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	d := Format()
	if vectors.Format != "sha256:"+hex.EncodeToString(d[:]) {
		t.Fatal("format digest changed", vectors.Format)
	}
	copyError := restored.Fields().RPCError
	*copyError = 42
	if *restored.Fields().RPCError == 42 {
		t.Fatal("aliased error pointer")
	}
}

func TestClosedCanonicalCodecRejectsMalformedVariants(t *testing.T) {
	e, raw := normalEnvelope(t)
	for _, cell := range []struct {
		name string
		edit func(*Envelope)
	}{
		{"version", func(e *Envelope) { e.Version = 2 }},
		{"kind", func(e *Envelope) { e.Kind = 2 }},
		{"network", func(e *Envelope) { e.Network = strings.Repeat("A", 64) }},
		{"generation", func(e *Envelope) { e.Generation = "11111111111111111111111111111111" }},
		{"producer", func(e *Envelope) { e.ProducerID = "00000000-0000-0000-0000-000000000000" }},
		{"record", func(e *Envelope) { e.RecordID = "missing" }},
		{"ordinal", func(e *Envelope) { e.Ordinal = "01" }},
		{"ordinal overflow", func(e *Envelope) { e.Ordinal = "9223372036854775808" }},
		{"negative time", func(e *Envelope) { e.ObservedMicros = -1 }},
		{"time overflow", func(e *Envelope) { e.ObservedMicros = MaxObservedMicros + 1 }},
		{"bad actor", func(e *Envelope) { e.ActorID = "unverified-name" }},
		{"org without actor", func(e *Envelope) { e.ActorID = "" }},
		{"missing policy", func(e *Envelope) { e.Policy = "" }},
		{"zero policy", func(e *Envelope) { e.Policy = strings.Repeat("0", 64) }},
		{"method pipe", func(e *Envelope) { e.Method = "eth_call|other" }},
		{"method control", func(e *Envelope) { e.Method = "eth_call\n" }},
		{"method starts digit", func(e *Envelope) { e.Method = "1bad" }},
		{"method long", func(e *Envelope) { e.Method = strings.Repeat("a", 101) }},
		{"IP zone", func(e *Envelope) { e.IP = "fe80::1%eth0" }},
		{"IP not canonical", func(e *Envelope) { e.IP = "2001:0db8::1" }},
		{"status mapping", func(e *Envelope) { e.Status = 200 }},
		{"HTTP range", func(e *Envelope) { e.HTTP = 600 }},
		{"HTTP200RPCerror false success", func(e *Envelope) { e.Outcome = string(Success); e.Status = 200 }},
		{"success non2xx", func(e *Envelope) { e.Outcome = string(Success); e.Status = 200; e.RPCError = nil; e.HTTP = 503 }},
		{"unknown outcome", func(e *Envelope) { e.Outcome = "ok" }},
		{"zero sequence", func(e *Envelope) { e.BufferSeq = "0" }},
	} {
		t.Run(cell.name, func(t *testing.T) {
			v := e
			cell.edit(&v)
			b, _ := json.Marshal(v)
			if _, err := DecodeEnvelope(b); err == nil {
				t.Fatal("invalid variant accepted")
			}
		})
	}
	for _, b := range [][]byte{
		append(append([]byte{}, raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"v":1`, `"v":1,"v":1`, 1)),
		[]byte(strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1)),
		[]byte(strings.Replace(string(raw), `"v":1`, `"v":null`, 1)),
		[]byte(strings.Replace(string(raw), `"h":200`, `"h":2e2`, 1)),
		append(bytes.Repeat([]byte{' '}, MaxEncodedBytes), raw...),
	} {
		if _, err := DecodeEnvelope(b); err == nil {
			t.Fatal("noncanonical JSON accepted")
		}
	}
	// Principal without selected org and fully unattributed completions remain
	// metadata, but cannot satisfy any protected org/actor predicate.
	for _, actor := range []string{e.ActorID, ""} {
		v := e
		v.ActorID = actor
		v.DataOrg = ""
		v.Policy = ""
		b, _ := json.Marshal(v)
		if _, err := DecodeEnvelope(b); err != nil {
			t.Fatal("unattributed metadata rejected", err)
		}
	}
}

func TestSelectedPolicyWithoutOrganizationRoundTripsAndGrantsNoOrg(t *testing.T) {
	original, _ := normalEnvelope(t)
	for _, actor := range []string{original.ActorID, ""} {
		e := original
		e.ActorID, e.DataOrg = actor, ""
		raw, _ := json.Marshal(e)
		decoded, err := DecodeEnvelope(raw)
		if err != nil || decoded.ActorID != actor || decoded.DataOrg != "" || decoded.Policy != original.Policy {
			t.Fatal("selected org-free policy lost", decoded, err)
		}
		e.BufferSeq = ""
		record := toRecord(e)
		spool, err := EncodeSpool(record)
		if err != nil {
			t.Fatal(err)
		}
		round, err := DecodeSpool(spool)
		if err != nil || round.Fields().ActorID != actor || round.Fields().DataOrg != "" || round.Fields().Policy != original.Policy {
			t.Fatal("org-free spool changed authority", round.Fields(), err)
		}
		sealed, err := SealEnvelope(round, 1<<40+1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEnvelope(sealed); err != nil {
			t.Fatal(err)
		}
		for _, policy := range []string{"bad", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("1", 63), "sha256:" + original.Policy} {
			invalid := original
			invalid.ActorID, invalid.DataOrg, invalid.Policy = actor, "", policy
			raw, _ := json.Marshal(invalid)
			if _, err := DecodeEnvelope(raw); err == nil {
				t.Fatal("invalid policy admitted with empty org", policy)
			}
		}
	}
}
