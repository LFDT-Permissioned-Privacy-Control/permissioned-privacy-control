package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// ciphertextV1Prefix marks values produced by the current Encrypt. It lets
// Decrypt tell a value it MUST authenticate (versioned) apart from a legacy
// value that predates versioning (which may be plaintext or old ciphertext).
//
// RD-1164 #1: versioned values are decrypted fail-CLOSED — any failure
// (bad base64, short blob, GCM authentication failure) returns an error, never
// the input. That preserves AES-GCM integrity: a tampered or wrong-key value is
// rejected, not silently returned as "plaintext". Legacy (unprefixed) values
// stay backward-compatible (best-effort, see Decrypt). Migrate legacy rows with
// `privacy-cli reencrypt-rpc-keys` so the whole store is covered.
const ciphertextV1Prefix = "encv1:"

// Encrypt encrypts plaintext using AES-256-GCM with the given key and returns a
// versioned, base64-encoded ciphertext ("encv1:<base64(nonce||ciphertext)>").
// If key is empty, returns plaintext as-is (dev mode / encryption disabled).
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertextV1Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a value produced by Encrypt.
//
// If key is empty, returns the value as-is (dev mode / encryption disabled).
//
// Versioned values (carrying ciphertextV1Prefix) are fail-CLOSED: a decode,
// length, or authentication failure returns an error. This is the security
// guarantee — a tampered or wrong-key ciphertext is never accepted as data.
//
// Legacy (unprefixed) values are handled best-effort for backward compatibility:
// Decrypt attempts AES-GCM and, on failure, returns the value unchanged (it may
// be pre-versioning plaintext or ciphertext). Once a value has been migrated to
// the versioned form it is covered by the fail-closed path above.
func Decrypt(encoded string, key []byte) (string, error) {
	if len(key) == 0 {
		return encoded, nil
	}
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (AES-256)")
	}

	if blob, ok := strings.CutPrefix(encoded, ciphertextV1Prefix); ok {
		plaintext, err := decryptAESGCM(blob, key)
		if err != nil {
			// Fail closed: a versioned value asserts it is authenticated
			// ciphertext, so we must reject it rather than leak it as plaintext.
			return "", err
		}
		return plaintext, nil
	}

	// Legacy, unversioned value: tolerate plaintext / old ciphertext.
	plaintext, err := decryptAESGCM(encoded, key)
	if err != nil {
		return encoded, nil
	}
	return plaintext, nil
}

// IsEncrypted reports whether a stored value is in the current versioned
// ciphertext form. Useful for migration tooling that must distinguish an
// already-encrypted value from legacy plaintext.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, ciphertextV1Prefix)
}

// DecryptStrict decrypts a value and, unlike Decrypt, is fail-CLOSED for ALL
// inputs — versioned OR legacy unversioned: any decode/length/authentication
// failure returns an error, and it NEVER falls back to returning the input as
// "legacy plaintext". Migration tooling (privacy-cli reencrypt-rpc-keys) MUST
// use this rather than Decrypt: under Decrypt, a legacy unversioned ciphertext
// decrypted with the WRONG key fails the AES-GCM check and is returned verbatim
// with a nil error, which the tool would then treat as plaintext and
// re-encrypt — irreversibly double-encrypting existing ciphertext. With
// DecryptStrict a wrong key (or a genuinely non-ciphertext value) errors, so
// the caller can skip it instead of corrupting it. Handles both versioned
// (encv1:) and legacy unversioned base64(nonce||ciphertext) values.
func DecryptStrict(encoded string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (AES-256)")
	}
	// Strip the version marker if present; a legacy value has none. Either way
	// the underlying blob must decode + authenticate, with no fail-open.
	blob, _ := strings.CutPrefix(encoded, ciphertextV1Prefix)
	return decryptAESGCM(blob, key)
}

// decryptAESGCM decodes and AEAD-opens a base64(nonce||ciphertext) blob,
// returning an error on any failure (invalid base64, short blob, auth failure).
func decryptAESGCM(blob string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", errors.New("decryption failed: authentication error")
	}

	return string(plaintext), nil
}
