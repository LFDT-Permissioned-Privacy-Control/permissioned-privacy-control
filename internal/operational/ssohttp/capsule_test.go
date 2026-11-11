package ssohttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	m "privacy-proxy/internal/ssotransaction"
	"reflect"
	"strings"
	"testing"
)

// These are public codec/protocol fixtures, not verified grants or families.
func codecFixture(t *testing.T) (*Handler, m.PendingRecord, m.ReadyFields) {
	t.Helper()
	cc, e := makeCipher(bytes.Repeat([]byte{1}, 32))
	if e != nil {
		t.Fatal(e)
	}
	gc, e := makeCipher(bytes.Repeat([]byte{2}, 32))
	if e != nil {
		t.Fatal(e)
	}
	h := &Handler{runtimeDigest: m.Digest{1}, contextCipher: cc, grantCipher: gc}
	p := m.PendingRecord{ID: "11111111-1111-1111-1111-111111111111", Scope: m.Scope{Namespace: m.Digest{2}, Epoch: "22222222-2222-2222-2222-222222222222", BrokerNamespace: m.Digest{3}, BrokerRecoveryEpoch: "33333333-3333-3333-3333-333333333333"}, ClientID: "client", ClientCatalogDigest: m.Digest{4}, IdentityDigest: m.Digest{5}, Recipient: m.Digest{6}, StateHash: m.Digest{7}, RedirectHash: m.Digest{8}, PKCES256: m.Digest{9}, ContextKeyID: "context", ContextCiphertext: bytes.Repeat([]byte{10}, 28), CreatedAt: 1000000, ExpiresAt: 301000000}
	v := m.ReadyFields{CodeHash: m.Digest{11}, CodeExpiresAt: 61000000, GrantKeyID: "grant", ActorID: "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)), ProfileID: "azure", ProfileDigest: m.Digest{13}, FamilyID: "44444444-4444-4444-4444-444444444444", FamilyGeneration: 2, FamilyHandleHash: m.Digest{14}, AccessDigest: m.Digest{15}, AccessExpiresAt: 301000000, FamilyExpiresAt: 86401000000, PreparedAt: 1000000, CodeResponseDigest: m.Digest{16}, CodeResponseBytes: 200}
	return h, p, v
}
func TestCapsuleAADGoldenAndEveryField(t *testing.T) {
	h, p, v := codecFixture(t)
	golden := map[string]string{"context": "897832aee461a96fcdcd00f89996d7d888b90691af24c5b326f1f68c9b07627f", "grant": "ee0e08ce1550a4190eb610ad270b017249d52132eddedb1afba638d2adeace2e"}
	for name, raw := range map[string][]byte{"context": h.contextAAD(p), "grant": h.grantAAD(p, v)} {
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != golden[name] {
			t.Fatalf("%s framing mismatch: %x", name, sum)
		}
	}
	contextCipher, e := seal(h.contextCipher, contextPayload{1, "client", "https://app.test/cb", "state"}, h.contextAAD(p), 4096)
	if e != nil {
		t.Fatal(e)
	}
	grantCipher, e := seal(h.grantCipher, grantPayload{1, "original.jwt.bytes", "actual-handle"}, h.grantAAD(p, v), 24576)
	if e != nil {
		t.Fatal(e)
	}
	// Every scalar (including each nested scope component) is bound; ciphertext
	// is excluded from context AAD but hashed into grant AAD.
	mutate := func(value reflect.Value) bool {
		switch value.Kind() {
		case reflect.String:
			value.SetString(value.String() + "x")
			return true
		case reflect.Int64:
			value.SetInt(value.Int() + 1)
			return true
		case reflect.Uint32:
			value.SetUint(value.Uint() + 1)
			return true
		case reflect.Array:
			if value.Type().Elem().Kind() == reflect.Uint8 {
				value.Index(0).SetUint(value.Index(0).Uint() ^ 1)
				return true
			}
		}
		return false
	}
	var walk func(reflect.Value, func())
	walk = func(value reflect.Value, check func()) {
		for i := 0; i < value.NumField(); i++ {
			f := value.Field(i)
			if f.Kind() == reflect.Struct {
				walk(f, check)
				continue
			}
			saved := reflect.New(f.Type()).Elem()
			saved.Set(f)
			if mutate(f) {
				check()
			}
			f.Set(saved)
		}
	}
	changedP := p
	walk(reflect.ValueOf(&changedP).Elem(), func() {
		var out contextPayload
		if open(h.contextCipher, contextCipher, h.contextAAD(changedP), &out, 4096) == nil {
			t.Fatal("changed pending scalar accepted")
		}
		var g grantPayload
		if open(h.grantCipher, grantCipher, h.grantAAD(changedP, v), &g, 24576) == nil {
			t.Fatal("changed pending scalar accepted by grant")
		}
	})
	changedV := v
	walk(reflect.ValueOf(&changedV).Elem(), func() {
		var out grantPayload
		if open(h.grantCipher, grantCipher, h.grantAAD(p, changedV), &out, 24576) == nil {
			t.Fatal("changed ready scalar accepted")
		}
	})
	p.ContextCiphertext[0] ^= 1
	var out grantPayload
	if open(h.grantCipher, grantCipher, h.grantAAD(p, v), &out, 24576) == nil {
		t.Fatal("context ciphertext swap accepted")
	}
	h.runtimeDigest[0] ^= 1
	var c contextPayload
	if open(h.contextCipher, contextCipher, h.contextAAD(p), &c, 4096) == nil {
		t.Fatal("runtime/source swap accepted")
	}
	for _, ciphertext := range [][]byte{contextCipher, grantCipher} {
		for i := range ciphertext {
			bad := bytes.Clone(ciphertext)
			bad[i] ^= 1
			var value any
			if open(h.contextCipher, bad, []byte("wrong-purpose"), &value, 24576) == nil {
				t.Fatal("tampered or swapped-purpose cipher accepted")
			}
		}
	}
}
func TestMaximumCapsulesAndPreparedBodies(t *testing.T) {
	h, p, v := codecFixture(t)
	client := strings.Repeat("a", 128)
	redirect := "https://app.test/" + strings.Repeat("a", 2048-len("https://app.test/"))
	token := strings.Repeat("A", 8190) + "." + strings.Repeat("B", 8191) + ".C"
	if len(token) != 16384 {
		t.Fatal(len(token))
	}
	handle := strings.Repeat("A", 3500)
	for _, state := range []string{strings.Repeat("&", 512), strings.Repeat("<", 512), strings.Repeat(">", 512), strings.Repeat(`"`, 512), strings.Repeat(`\`, 512), strings.Repeat(" ", 512)} {
		plain := contextPayload{1, client, redirect, state}
		raw, e := seal(h.contextCipher, plain, h.contextAAD(p), 4096)
		if e != nil {
			t.Fatal("legal maximum state rejected", e)
		}
		var restored contextPayload
		if open(h.contextCipher, raw, h.contextAAD(p), &restored, 4096) != nil || restored != plain {
			t.Fatal("exact state changed")
		}
		t.Logf("max context ciphertext=%d state=%q", len(raw), state[:1])
		callback, _ := url.Parse(redirect)
		q := callback.Query()
		q.Set("code", strings.Repeat("c", 43))
		q.Set("state", state)
		callback.RawQuery = q.Encode()
		response, e := body(CompleteResponse{callback.String()}, 8192)
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("prepared redirect JSON=%d", len(response))
	}
	for _, state := range []string{"\u2028", "\u2029"} {
		if ascii(state, 1, 512, true) {
			t.Fatal("non-ASCII state accepted")
		}
		raw, e := seal(h.contextCipher, contextPayload{1, client, redirect, state}, h.contextAAD(p), 4096)
		if e != nil {
			t.Fatal(e)
		}
		var plain contextPayload
		if open(h.contextCipher, raw, h.contextAAD(p), &plain, 4096) != nil || plain.State != state {
			t.Fatal("Unicode JSON escape changed value")
		}
	}
	raw, e := seal(h.grantCipher, grantPayload{1, token, handle}, h.grantAAD(p, v), 24576)
	if e != nil {
		t.Fatal(e)
	}
	var restored grantPayload
	if open(h.grantCipher, raw, h.grantAAD(p, v), &restored, 24576) != nil || restored.AccessToken != token || restored.RenewalHandle != handle {
		t.Fatal("maximum grant changed")
	}
	t.Logf("max grant ciphertext=%d", len(raw))
	response, e := body(TokenResponse{token, "Bearer", 299}, 24576)
	if e != nil {
		t.Fatal(e)
	}
	var got TokenResponse
	if json.Unmarshal(response, &got) != nil || got.AccessToken != token {
		t.Fatal("original maximum token changed")
	}
	t.Logf("max token JSON=%d", len(response))
}
func TestOAuthBasicOneFormDecode(t *testing.T) {
	id := "client"
	base := strings.Repeat("x", 32)
	for _, suffix := range []string{"+", "%", ":", "/", "=", "%2B", "!#$&'()*,-.;<>?@[\\]^_`{|}~"} {
		secret := base + suffix
		h := &Handler{secrets: map[string][32]byte{id: sha256.Sum256([]byte(secret))}, secretLengths: map[string]int{id: len(secret)}}
		r := httptest.NewRequest("POST", "https://ops.test/api/v2/sso/token", nil)
		r.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		if got, e := h.basic(r); e != nil || got != id {
			t.Fatal("valid punctuation rejected", suffix, e)
		}
	}
	h := &Handler{secrets: map[string][32]byte{id: sha256.Sum256([]byte(base + "+"))}, secretLengths: map[string]int{id: 33}}
	for _, wire := range []string{id + ":" + base + "+", id + ":" + base + "%", id + ":" + base + "%GG", id + ":" + base + "%252B", id + ":" + base + "%253A", "other:" + base + "%2B", id + ":" + strings.Repeat("x", 257)} {
		r := httptest.NewRequest("POST", "https://ops.test", nil)
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(wire)))
		if _, e := h.basic(r); e == nil {
			t.Fatal("bad Basic accepted", wire)
		}
	}
	r := httptest.NewRequest("POST", "https://ops.test", nil)
	r.SetBasicAuth(id, url.QueryEscape(base+"+"))
	r.Header.Add("Authorization", r.Header.Get("Authorization"))
	if _, e := h.basic(r); e == nil {
		t.Fatal("duplicate Basic accepted")
	}
}
