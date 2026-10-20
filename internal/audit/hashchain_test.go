package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
)

func TestHashChain_BasicChaining(t *testing.T) {
	// Two chains seeded the same should produce identical hashes for the same input.
	chain1 := NewHashChain("seed")
	chain2 := NewHashChain("seed")

	h1 := chain1.ComputeNext("entry-1")
	h2 := chain2.ComputeNext("entry-1")

	if h1 != h2 {
		t.Fatalf("same seed + same input should produce same hash, got %s vs %s", h1, h2)
	}

	// Advance both chains with the same second entry.
	h1b := chain1.ComputeNext("entry-2")
	h2b := chain2.ComputeNext("entry-2")

	if h1b != h2b {
		t.Fatalf("second entry hash mismatch: %s vs %s", h1b, h2b)
	}

	// Second hash must differ from first (different previous hash input).
	if h1 == h1b {
		t.Fatal("different entries should produce different hashes")
	}
}

func TestHashChain_TamperDetection(t *testing.T) {
	// Build a chain: entry-A then entry-B.
	chain := NewHashChain("")
	chain.ComputeNext("entry-A")
	hashAfterB := chain.ComputeNext("entry-B")

	// Build a tampered chain: entry-A-TAMPERED then entry-B.
	tampered := NewHashChain("")
	tampered.ComputeNext("entry-A-TAMPERED")
	hashAfterBTampered := tampered.ComputeNext("entry-B")

	if hashAfterB == hashAfterBTampered {
		t.Fatal("tampering with a previous entry should change all subsequent hashes")
	}
}

func TestHashChain_EmptySeed(t *testing.T) {
	chain := NewHashChain("")
	hash := chain.ComputeNext("hello")

	// Manually compute expected: SHA-256("" + "hello")
	hasher := sha256.New()
	hasher.Write([]byte(""))
	hasher.Write([]byte("hello"))
	expected := hex.EncodeToString(hasher.Sum(nil))

	if hash != expected {
		t.Fatalf("expected %s, got %s", expected, hash)
	}
}

func TestHashChain_LastHash(t *testing.T) {
	chain := NewHashChain("init")

	if got := chain.LastHash(); got != "init" {
		t.Fatalf("expected initial last hash 'init', got %q", got)
	}

	h := chain.ComputeNext("data")
	if got := chain.LastHash(); got != h {
		t.Fatalf("LastHash should return tail hash %s, got %s", h, got)
	}
}

func TestHashChain_ThreadSafety(t *testing.T) {
	chain := NewHashChain("")

	var wg sync.WaitGroup
	const goroutines = 100

	hashes := make([]string, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			hashes[idx] = chain.ComputeNext("entry")
		}(i)
	}
	wg.Wait()

	// All hashes should be non-empty and unique (each builds on a different previous hash).
	seen := make(map[string]bool)
	for i, h := range hashes {
		if h == "" {
			t.Fatalf("hash %d is empty", i)
		}
		if seen[h] {
			t.Fatalf("duplicate hash at index %d: %s", i, h)
		}
		seen[h] = true
	}
}
