package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// TestComputeChainHashStable pins the chain hash exactly so the
// verifier and writer cannot drift apart silently. If this test
// changes by accident, every existing chain breaks across the upgrade
// — be deliberate.
func TestComputeChainHashStable(t *testing.T) {
	prev := "abc"
	content := "v2|1|did:test|eth_chainId|127.0.0.1|200|200|2026-05-14T00:00:00Z||"
	got := computeChainHash(prev, content)

	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(content))
	want := hex.EncodeToString(h.Sum(nil))

	if got != want {
		t.Fatalf("computeChainHash drifted: got %s want %s", got, want)
	}
}

// TestAccessLogChainContentV2_FormatPinned ensures the v2 format
// string is exactly what writers in db.AccessLogChainContent emit.
// Format bumps must NEVER mutate v2 in place — add a v3 builder and
// bump hash_format_version on new rows. This pin enforces that.
func TestAccessLogChainContentV2_FormatPinned(t *testing.T) {
	got := AccessLogChainContentV2(
		42,
		"did:test:user",
		"eth_blockNumber",
		"203.0.113.4",
		200, 200,
		mustTime(t, "2026-05-14T11:22:33.456789Z"),
		"corr-xyz",
		`{"foo":"bar"}`,
	)
	want := `v2|42|did:test:user|eth_blockNumber|203.0.113.4|200|200|2026-05-14T11:22:33.456789Z|corr-xyz|{"foo":"bar"}`
	if got != want {
		t.Fatalf("v2 format drift:\n got:  %s\n want: %s", got, want)
	}
}

// TestRBACAuditChainContentV1_FormatPinned ditto for the rbac chain.
func TestRBACAuditChainContentV1_FormatPinned(t *testing.T) {
	got := RBACAuditChainContentV1(
		7,
		"did:admin:alice",
		"update",
		"group",
		"00000000-0000-0000-0000-000000000abc",
		"engineering",
		"00000000-0000-0000-0000-000000000def",
		"203.0.113.7",
		mustTime(t, "2026-05-14T08:00:00Z"),
		`{"name":"old"}`,
		`{"name":"new"}`,
	)
	want := `v1|7|did:admin:alice|update|group|00000000-0000-0000-0000-000000000abc|engineering|00000000-0000-0000-0000-000000000def|203.0.113.7|2026-05-14T08:00:00Z|{"name":"old"}|{"name":"new"}`
	if got != want {
		t.Fatalf("v1 format drift:\n got:  %s\n want: %s", got, want)
	}
}

// TestHashChainAppend_AdvancesOnSuccess verifies Append's commit path.
func TestHashChainAppend_AdvancesOnSuccess(t *testing.T) {
	chain := NewHashChain("")
	hash, err := chain.Append(func(prev string) (string, func(string) error, error) {
		if prev != "" {
			t.Fatalf("expected empty prev, got %q", prev)
		}
		return "row-1", func(_ string) error { return nil }, nil
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if chain.LastHash() != hash {
		t.Fatalf("chain head not advanced: head=%s hash=%s", chain.LastHash(), hash)
	}
}

// TestHashChainAppend_RollsBackOnError verifies the chain head does
// NOT advance when the write callback returns an error — closes the
// pre-RD-858 race where a failed DB write could leave the in-memory
// chain ahead of the durable state.
func TestHashChainAppend_RollsBackOnError(t *testing.T) {
	chain := NewHashChain("seed-x")
	_, err := chain.Append(func(prev string) (string, func(string) error, error) {
		return "row-fail", func(_ string) error { return context.DeadlineExceeded }, nil
	})
	if err == nil {
		t.Fatal("expected error from Append, got nil")
	}
	if chain.LastHash() != "seed-x" {
		t.Fatalf("chain advanced on failure: head=%s want=seed-x", chain.LastHash())
	}
}

// TestHashChainAppend_RollsBackOnBuilderError ditto when the builder
// itself fails (e.g. nextval() lookup).
func TestHashChainAppend_RollsBackOnBuilderError(t *testing.T) {
	chain := NewHashChain("seed-y")
	_, err := chain.Append(func(prev string) (string, func(string) error, error) {
		return "", nil, context.Canceled
	})
	if err == nil {
		t.Fatal("expected error from Append, got nil")
	}
	if chain.LastHash() != "seed-y" {
		t.Fatalf("chain advanced on builder failure: head=%s", chain.LastHash())
	}
}

// TestHashChainAppend_NilWriteRejected: the contract says write must
// be non-nil. Guard prevents silently-half-advanced chains.
func TestHashChainAppend_NilWriteRejected(t *testing.T) {
	chain := NewHashChain("")
	_, err := chain.Append(func(prev string) (string, func(string) error, error) {
		return "content", nil, nil
	})
	if err == nil {
		t.Fatal("expected error from Append with nil write, got nil")
	}
	if chain.LastHash() != "" {
		t.Fatalf("chain advanced with nil write: %s", chain.LastHash())
	}
}

// TestHashChainAppend_Sequence chains three writes and confirms each
// row's hash uses the previous row's hash. Mirrors what a verifier
// walking the same content sequence should compute.
func TestHashChainAppend_Sequence(t *testing.T) {
	chain := NewHashChain("")
	hashes := make([]string, 3)
	contents := []string{"a", "b", "c"}

	for i, content := range contents {
		var captured string
		c := content
		hash, err := chain.Append(func(prev string) (string, func(string) error, error) {
			captured = prev
			return c, func(_ string) error { return nil }, nil
		})
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		hashes[i] = hash
		if i == 0 && captured != "" {
			t.Fatalf("first prev should be empty, got %q", captured)
		}
		if i > 0 && captured != hashes[i-1] {
			t.Fatalf("row %d prev = %q want %q", i, captured, hashes[i-1])
		}
	}

	// Independent recomputation must match the chain's accepted hashes.
	prev := ""
	for i, content := range contents {
		expect := computeChainHash(prev, content)
		if expect != hashes[i] {
			t.Fatalf("row %d hash mismatch: chain=%s recomputed=%s", i, hashes[i], expect)
		}
		prev = expect
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tt, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tt
}
