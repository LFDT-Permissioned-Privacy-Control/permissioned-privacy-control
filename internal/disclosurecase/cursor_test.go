package disclosurecase

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCursorEncryptionContextAndExpiry(t *testing.T) {
	actor := "ops:p1:h8r51EkUOmId9V9QsfRAB4s2CDMR3omEQA4OG8icGig"
	ring, err := newCursorRing(CursorKeys{Active: CursorKey{ID: "key1", Key: bytes.Repeat([]byte{3}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	payload := cursorPayload{Version: 1, Epoch: "epoch1", Actor: actor, Bundle: "bundle", Disclosure: "rules", Role: "recipient", Organization: "org", Query: "case-list", LastTime: 1800000000000000, LastID: "11111111-1111-1111-1111-111111111111", Expires: 1800000300}
	a, err := ring.seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ring.seal(payload)
	if err != nil || a == b || strings.Contains(a, payload.LastID) || strings.Contains(a, actor) {
		t.Fatal("cursor nonce/metadata hiding failed", err)
	}
	position, err := ring.open(a, payload, time.Unix(1800000000, 0))
	if err != nil || position.ID != payload.LastID || position.Time.UnixMicro() != payload.LastTime {
		t.Fatal("cursor round trip", err)
	}
	for _, field := range []string{"actor", "epoch", "bundle", "rules", "role", "org", "query"} {
		expected := payload
		switch field {
		case "actor":
			expected.Actor = "other"
		case "epoch":
			expected.Epoch = "other"
		case "bundle":
			expected.Bundle = "other"
		case "rules":
			expected.Disclosure = "other"
		case "role":
			expected.Role = "other"
		case "org":
			expected.Organization = "other"
		case "query":
			expected.Query = "case-audit"
		}
		if _, err := ring.open(a, expected, time.Unix(1800000000, 0)); !errors.Is(err, ErrConflict) {
			t.Fatal("context substitution accepted", field, err)
		}
	}
	if _, err := ring.open(a, payload, time.Unix(payload.Expires, 0)); err == nil {
		t.Fatal("expired cursor accepted")
	}
	for _, bad := range []string{a + "A", strings.Replace(a, "key1", "unknown", 1), strings.Repeat("x", 4097), "dc1.key1.AA"} {
		if _, err := ring.open(bad, payload, time.Unix(1800000000, 0)); err == nil {
			t.Fatal("tampered cursor accepted")
		}
	}
	rotated, err := newCursorRing(CursorKeys{Active: CursorKey{ID: "key2", Key: bytes.Repeat([]byte{4}, 32)}, Previous: &CursorKey{ID: "key1", Key: bytes.Repeat([]byte{3}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.open(a, payload, time.Unix(1800000000, 0)); err != nil {
		t.Fatal("explicit overlap key rejected", err)
	}
}
