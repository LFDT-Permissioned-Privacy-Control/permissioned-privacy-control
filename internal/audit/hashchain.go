package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// errAppendNilWrite is returned by HashChain.Append when the build
// callback returns a nil write function. The chain head is not
// advanced.
var errAppendNilWrite = errors.New("hashchain: Append build callback returned nil write")

// HashChain provides cryptographic integrity for audit log entries.
// Each entry's hash is computed as SHA-256(previousHash | entryContent),
// creating a chain where tampering with any entry invalidates all subsequent hashes.
type HashChain struct {
	mu       sync.Mutex
	lastHash string
}

// NewHashChain creates a new hash chain seeded with the last known hash from the database.
// If lastKnownHash is empty (first entry or empty DB), the chain starts with a zero hash.
func NewHashChain(lastKnownHash string) *HashChain {
	return &HashChain{
		lastHash: lastKnownHash,
	}
}

// ComputeNext computes the hash for the next audit entry and advances the chain.
// The hash is SHA-256(previousHash | entryContent).
// This method is thread-safe.
func (h *HashChain) ComputeNext(entryContent string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	hasher := sha256.New()
	hasher.Write([]byte(h.lastHash))
	hasher.Write([]byte(entryContent))
	hash := hex.EncodeToString(hasher.Sum(nil))

	h.lastHash = hash
	return hash
}

// LastHash returns the current tail hash of the chain.
func (h *HashChain) LastHash() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastHash
}

// Append performs a chain advance under the chain mutex with a strict
// commit / rollback contract:
//
//   - build is invoked with the chain's current head. It MUST return
//     the entry's canonical content for hashing AND a write callback
//     that persists the row with the computed hash.
//   - The chain head advances to the new hash only if write returns
//     nil. A non-nil return rolls the chain back — the next Append
//     uses the same prev hash, and the chain stays consistent with
//     the DB.
//
// The mutex is held for the entire build+write window. This serializes
// audit writes against each other, which is exactly what we want:
// without serialization the chain order can diverge from the DB id
// order (two goroutines reserve ids N and N+1 but advance the chain
// in the opposite sequence), which breaks the verifier's id-ordered
// walk (RD-858).
//
// Returns the new hash on success, or "" + an error on failure.
func (h *HashChain) Append(build func(prevHash string) (content string, write func(hash string) error, err error)) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	prev := h.lastHash
	content, write, err := build(prev)
	if err != nil {
		return "", err
	}
	if write == nil {
		return "", errAppendNilWrite
	}

	hasher := sha256.New()
	hasher.Write([]byte(prev))
	hasher.Write([]byte(content))
	hash := hex.EncodeToString(hasher.Sum(nil))

	if err := write(hash); err != nil {
		return "", err
	}
	h.lastHash = hash
	return hash, nil
}
