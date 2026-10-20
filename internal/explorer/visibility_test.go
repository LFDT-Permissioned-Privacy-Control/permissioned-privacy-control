package explorer

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// pseudonymPattern matches a well-formed pseudonym: the "Address-" prefix
// followed by exactly four letters in A..P (the low-nibble alphabet the HMAC
// output is folded into). RD-1164 #8: the four letters are HMAC-derived, so
// their exact values are not predictable — tests assert the shape, not a value.
var pseudonymPattern = regexp.MustCompile(`^Address-[A-P]{4}$`)

func TestGeneratePseudonym(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		wantUnknown bool // if true, expect exactly "Address-Unknown"
	}{
		{
			name:    "all zeros (0x prefix)",
			address: "0x0000000000000000000000000000000000000000",
		},
		{
			name:    "all as",
			address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:    "all fs",
			address: "0xffffffffffffffffffffffffffffffffffffffff",
		},
		{
			name:    "mixed hex digits",
			address: "0x1234567890abcdef1234567890abcdef12345678",
		},
		{
			name:    "without 0x prefix",
			address: "abcd000000000000000000000000000000000000",
		},
		{
			name:    "uppercase address",
			address: "0xABCDEF0000000000000000000000000000000000",
		},
		{
			// RD-1164 #8: HMAC accepts any input >= 4 chars, including
			// bytes that are not valid hex. A 40-char all-G string is no
			// longer rejected — it hashes to a well-formed pseudonym.
			name:    "non-hex chars still produce a valid pseudonym",
			address: "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
		},
		{
			name:        "too short",
			address:     "0x12",
			wantUnknown: true,
		},
		{
			name:        "empty string",
			address:     "",
			wantUnknown: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GeneratePseudonym(tc.address, nil)
			if tc.wantUnknown {
				if got != "Address-Unknown" {
					t.Errorf("GeneratePseudonym(%q, nil) = %q, want %q", tc.address, got, "Address-Unknown")
				}
				return
			}
			if !pseudonymPattern.MatchString(got) {
				t.Errorf("GeneratePseudonym(%q, nil) = %q, want match %s", tc.address, got, pseudonymPattern)
			}
		})
	}
}

// TestGeneratePseudonym_NonReversible is the RD-1164 #8 security regression:
// the pseudonym must be derived from HMAC(key, address), never from the
// address's own leading nibbles, and must be keyed. It pins three properties
// the old reversible nibble-mapping scheme violated.
func TestGeneratePseudonym_NonReversible(t *testing.T) {
	// (a) Two DISTINCT addresses sharing the same first 4 hex nibbles must
	// produce DIFFERENT pseudonyms. Under the OLD scheme both mapped to
	// "Address-BCDE" (from the shared "1234" prefix); the HMAC scheme spreads
	// the whole address, so the leading bytes no longer determine the alias.
	addrShared1 := "0x1234aaaa00000000000000000000000000000000"
	addrShared2 := "0x1234bbbb00000000000000000000000000000000"
	p1 := GeneratePseudonym(addrShared1, nil)
	p2 := GeneratePseudonym(addrShared2, nil)
	if p1 == p2 {
		t.Errorf("addresses sharing the first 4 nibbles must not collide: both give %q "+
			"(pseudonym is leaking the leading address bytes)", p1)
	}

	// (b) The same address under two different keys must yield different
	// pseudonyms — proof the output is genuinely keyed (non-enumerable in prod).
	addr := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	keyed1 := GeneratePseudonym(addr, []byte("k1"))
	keyed2 := GeneratePseudonym(addr, []byte("k2"))
	if keyed1 == keyed2 {
		t.Errorf("same address under different keys must differ: both give %q", keyed1)
	}

	// (c) Determinism: same address + same key is stable across calls.
	k := []byte("stable-key")
	first := GeneratePseudonym(addr, k)
	for i := 0; i < 10; i++ {
		if got := GeneratePseudonym(addr, k); got != first {
			t.Errorf("not deterministic: got %q on iteration %d, want %q", got, i, first)
		}
	}
}

func TestGeneratePseudonym_Deterministic(t *testing.T) {
	addr := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	first := GeneratePseudonym(addr, nil)
	for i := 0; i < 10; i++ {
		if got := GeneratePseudonym(addr, nil); got != first {
			t.Errorf("not deterministic: got %q on iteration %d, want %q", got, i, first)
		}
	}
}

func TestGeneratePseudonym_StartsWithAddressPrefix(t *testing.T) {
	addr := "0x1234567890abcdef1234567890abcdef12345678"
	result := GeneratePseudonym(addr, nil)
	if !strings.HasPrefix(result, "Address-") {
		t.Errorf("pseudonym should start with 'Address-', got %q", result)
	}
}

func TestGeneratePseudonym_DifferentAddressesDifferentPseudonyms(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	p1 := GeneratePseudonym(addr1, nil)
	p2 := GeneratePseudonym(addr2, nil)
	if p1 == p2 {
		t.Errorf("different addresses should produce different pseudonyms: both give %q", p1)
	}
}

func TestGenerateAddressID_Deterministic(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	grantID := "grant-123"
	first := GenerateAddressID(addr, grantID)
	for i := 0; i < 5; i++ {
		if got := GenerateAddressID(addr, grantID); got != first {
			t.Errorf("not deterministic: got %q on iteration %d", got, i)
		}
	}
}

func TestGenerateAddressID_DifferentInputsDifferentIDs(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	id1 := GenerateAddressID(addr, "grant-1")
	id2 := GenerateAddressID(addr, "grant-2")
	if id1 == id2 {
		t.Errorf("different grant IDs should produce different address IDs")
	}

	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	id3 := GenerateAddressID(addr2, "grant-1")
	if id1 == id3 {
		t.Errorf("different addresses should produce different address IDs")
	}
}

func TestGenerateAddressID_Length(t *testing.T) {
	id := GenerateAddressID("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grant-1")
	if len(id) != 16 {
		t.Errorf("expected 16 hex chars, got %d: %q", len(id), id)
	}
}

// TestJSONString_MarshalJSON covers the MarshalJSON method on types.go.
func TestJSONString_MarshalJSON(t *testing.T) {
	type payload struct {
		Value JSONString `json:"value"`
	}
	p := payload{Value: "0x1234"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if got != `{"value":"0x1234"}` {
		t.Errorf("unexpected JSON: %s", got)
	}
}

func TestGenerateAddressID_CaseInsensitive(t *testing.T) {
	lower := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	upper := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	id1 := GenerateAddressID(lower, "grant")
	id2 := GenerateAddressID(upper, "grant")
	if id1 != id2 {
		t.Errorf("address IDs should be case-insensitive: %q vs %q", id1, id2)
	}
}
