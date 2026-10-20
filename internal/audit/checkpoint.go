package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Checkpoint is a signed roll-up of an audit chain's state at a point in time.
// It pins the chain head (id + hash) and the row count so the verifier can
// detect TAIL TRUNCATION — deletion of the most recent rows, which a plain
// hash-walk cannot catch because nothing downstream breaks (RD-1112 security
// review finding #1). For per-instance chains, one checkpoint exists per
// chain_name and the roll-up over all checkpoints is what proves no whole
// chain went missing.
//
// Checkpoints are SIGNED by a key that must live outside the app DB
// credential's blast radius (review finding #2): the Signer interface lets the
// key be an HMAC secret (MVP) or a KMS key (production) without changing
// callers. A signature the app can both write-the-DB and forge is decorative,
// so the key separation is the actual control.
type Checkpoint struct {
	ChainName string
	HeadID    int64
	HeadHash  string
	RowCount  int64
	CreatedAt time.Time
	KeyID     string
	Signature string // hex-encoded
}

// signedContent is the canonical, signature-covered serialization. Field order
// and formatting are fixed so Sign and Verify agree byte-for-byte across
// processes and key types. A leading version tag allows future format changes.
func (c Checkpoint) signedContent() []byte {
	return []byte(strings.Join([]string{
		"ckpt-v2",
		c.ChainName,
		strconv.FormatInt(c.HeadID, 10),
		c.HeadHash,
		strconv.FormatInt(c.RowCount, 10),
		// MICROSECOND precision: created_at is a Postgres TIMESTAMP (microsecond
		// resolution), so signing over UnixNano() breaks verification after the
		// DB round-trip on any host whose clock has sub-microsecond resolution
		// (e.g. Linux) — the sealed sub-µs digits are dropped on read-back and the
		// recomputed signature no longer matches. UnixMicro() is stable across the
		// round-trip on every platform. (v1 signed nanos; tag bumped to v2.)
		strconv.FormatInt(c.CreatedAt.UTC().UnixMicro(), 10),
	}, "|"))
}

// Signer signs and verifies checkpoint content. Implementations: HMACSigner
// (MVP) and a future KMS-backed signer. SECURITY: the signing key MUST NOT be
// writable by the same credential that can write the audit DB — otherwise a
// single compromise could truncate a chain AND re-sign the checkpoint to match
// (review finding #2). The interface exists precisely so the key can move to
// KMS (app holds Sign capability via a separate IAM role, never the key).
type Signer interface {
	Sign(content []byte) (sig string, keyID string, err error)
	Verify(content []byte, sig string, keyID string) error
}

// HMACSigner is a symmetric (HMAC-SHA256) Signer for the MVP. The key should be
// sourced from a secret distinct from the DB credential. keyID is recorded on
// each checkpoint so verification survives key rotation (the verifier selects
// the key by id).
type HMACSigner struct {
	keyID string
	key   []byte
}

// NewHMACSigner constructs an HMAC signer. keyID labels the key for rotation.
func NewHMACSigner(keyID string, key []byte) *HMACSigner {
	return &HMACSigner{keyID: keyID, key: key}
}

func (s *HMACSigner) Sign(content []byte) (string, string, error) {
	if len(s.key) == 0 {
		return "", "", fmt.Errorf("hmac signer: empty key")
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(content)
	return hex.EncodeToString(mac.Sum(nil)), s.keyID, nil
}

func (s *HMACSigner) Verify(content []byte, sig string, keyID string) error {
	if keyID != s.keyID {
		return fmt.Errorf("checkpoint key id %q does not match verifier key %q", keyID, s.keyID)
	}
	want, _, err := s.Sign(content)
	if err != nil {
		return err
	}
	wantB, err := hex.DecodeString(want)
	if err != nil {
		return fmt.Errorf("internal: bad recomputed signature: %w", err)
	}
	gotB, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("checkpoint signature is not valid hex: %w", err)
	}
	if !hmac.Equal(wantB, gotB) {
		return fmt.Errorf("checkpoint signature mismatch")
	}
	return nil
}

// SignCheckpoint signs c in place, filling Signature and KeyID.
func SignCheckpoint(s Signer, c *Checkpoint) error {
	sig, keyID, err := s.Sign(c.signedContent())
	if err != nil {
		return fmt.Errorf("sign checkpoint: %w", err)
	}
	c.Signature = sig
	c.KeyID = keyID
	return nil
}

// VerifyCheckpoint verifies c's signature. A failure means the checkpoint was
// forged or altered (or signed by an unknown key) — the chain's truncation
// guard cannot be trusted and must be treated as a tamper signal.
func VerifyCheckpoint(s Signer, c Checkpoint) error {
	return s.Verify(c.signedContent(), c.Signature, c.KeyID)
}
