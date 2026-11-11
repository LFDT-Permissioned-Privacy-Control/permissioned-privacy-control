package ssotransaction

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func publicRecord() Record {
	d := func(b byte) (v Digest) {
		for i := range v {
			v[i] = b
		}
		return
	}
	scope := Scope{d(0x11), "22222222-2222-4222-8222-222222222222", d(0x22), "33333333-3333-4333-8333-333333333333"}
	p := PendingRecord{ID: "11111111-1111-4111-8111-111111111111", Scope: scope, ClientID: "bank-explorer", ClientCatalogDigest: d(0x41), IdentityDigest: d(0x41), Recipient: d(0x41), StateHash: d(0x41), RedirectHash: d(0x41), PKCES256: d(0x41), ContextKeyID: "ctx1", ContextCiphertext: bytes.Repeat([]byte{0x31}, 28), CreatedAt: 1794000000000000, ExpiresAt: 1794000300000000}
	r := &ReadyFields{CodeHash: d(0x41), CodeExpiresAt: 1794000060000001, GrantKeyID: "grant1", GrantCiphertext: bytes.Repeat([]byte{0x32}, 28), ActorID: "ops:p1:" + strings.Repeat("Q", 42) + "E", ProfileID: "azure-bank", ProfileDigest: d(0x41), FamilyID: "44444444-4444-4444-8444-444444444444", FamilyGeneration: 7, FamilyHandleHash: d(0x41), AccessDigest: d(0x41), AccessExpiresAt: 1794000300000000, FamilyExpiresAt: 1794600000000000, PreparedAt: 1794000000000001, CodeResponseDigest: d(0x41), CodeResponseBytes: 256}
	retain := Micros(1794086460000001)
	return Record{Pending: p, Phase: Ready, Ready: r, RetainUntil: &retain}
}
func TestIndependentPublicCodecVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/codec-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Namespace struct {
			SHA256 string `json:"sha256"`
		}
		Vector struct {
			SHA256 string `json:"sha256"`
		}
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("fixture")
	}
	r := publicRecord()
	c, e := CaptureRecord(r)
	if e != nil || hex.EncodeToString(c.Binding[:]) != v.Vector.SHA256 {
		t.Fatal("capture golden", c, e)
	}
	d, e := NamespaceFor(r.Pending.Scope.BrokerNamespace, "https://ops.example.test")
	if e != nil || hex.EncodeToString(d[:]) != v.Namespace.SHA256 {
		t.Fatal("namespace golden", e)
	}
	changed := Clone(r)
	changed.Ready.GrantCiphertext[0]++
	next, _ := CaptureRecord(changed)
	if next == c {
		t.Fatal("cipher unbound")
	}
	if r.Ready.GrantCiphertext[0] != 0x32 {
		t.Fatal("alias")
	}
}
func TestClosedRecordGrammarAndCaps(t *testing.T) {
	for name, edit := range map[string]func(*Record){"oversized context": func(r *Record) { r.Pending.ContextCiphertext = make([]byte, 4097) }, "oversized grant": func(r *Record) { r.Ready.GrantCiphertext = make([]byte, 24577) }, "zero digest": func(r *Record) { r.Pending.Recipient = Digest{} }, "canonical actor": func(r *Record) { r.Ready.ActorID = "ops:p1:" + strings.Repeat("Q", 42) + "Z" }, "wrong ready epoch": func(r *Record) { r.Pending.Scope.Epoch = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }, "nil retention": func(r *Record) { r.RetainUntil = nil }, "overflow": func(r *Record) { r.Ready.CodeExpiresAt = MaxMicros + 1 }, "empty terminal cipher": func(r *Record) {
		r.Phase = Expired
		r.Pending.ContextCiphertext = []byte{}
		r.Ready.GrantCiphertext = nil
	}, "mixed pending": func(r *Record) { r.Phase = Pending }} {
		t.Run(name, func(t *testing.T) {
			r := publicRecord()
			edit(&r)
			if ValidateRecord(r) == nil {
				t.Fatal("invalid accepted")
			}
			if _, e := CaptureRecord(r); e == nil {
				t.Fatal("invalid captured")
			}
		})
	}
	r := publicRecord()
	r.Pending.ContextCiphertext = make([]byte, MaxContextCipherBytes)
	r.Ready.GrantCiphertext = make([]byte, MaxGrantCipherBytes)
	if ValidateRecord(r) != nil {
		t.Fatal("exact cap")
	}
	r.Phase = Expired
	r.Pending.ContextCiphertext = nil
	r.Ready.GrantCiphertext = nil
	if ValidateRecord(r) != nil {
		t.Fatal("terminal")
	}
	if _, e := Add(MaxMicros, 1); e == nil {
		t.Fatal("overflow")
	}
	if !DefaultLimits().Valid() {
		t.Fatal("limits")
	}
}
func TestNamespaceExactOrigin(t *testing.T) {
	d := Digest{1}
	for _, s := range []string{"https://OPS.test", "https://ops.test/", "https://ops.test:443", "https://ops.test?", "http://ops.test", "https://u@ops.test", "https://ops.test/#x", "https://ops.test:0444", "https://ops.test:", "https://[::ffff:127.0.0.1]"} {
		if _, e := NamespaceFor(d, s); e == nil {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"https://ops.test", "https://ops.test:8443", "https://[::1]:8443"} {
		if _, e := NamespaceFor(d, s); e != nil {
			t.Fatal(s, e)
		}
	}
}

func TestNamespacePreservesBrowserHostname(t *testing.T) {
	broker := Digest{1}
	tooLong := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)
	for _, host := range []string{"127.1", "2130706433", "0x7f000001", "0177.0.0.1", "127.0.0.01", "0x7f.1", "example.123", tooLong} {
		t.Run(host, func(t *testing.T) {
			if _, err := NamespaceFor(broker, "https://"+host); err == nil {
				t.Fatal("namespace accepts a noncanonical browser host")
			}
		})
	}
	maxDNS := strings.TrimSuffix(tooLong, "d")
	for _, host := range []string{"127.0.0.1", "[::1]", "example.test", maxDNS} {
		if _, err := NamespaceFor(broker, "https://"+host); err != nil {
			t.Fatal("canonical namespace origin rejected", host, err)
		}
	}
}
