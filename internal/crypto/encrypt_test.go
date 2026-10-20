package crypto

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "sk-live-abc123"},
		{"empty", ""},
		{"long", "this-is-a-very-long-api-key-that-contains-many-characters-1234567890"},
		{"special chars", "key!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"unicode", "key-éèê"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}

			// Encrypted value should differ from plaintext (unless empty)
			if tt.plaintext != "" && encrypted == tt.plaintext {
				t.Error("encrypted value should differ from plaintext")
			}

			decrypted, err := Decrypt(encrypted, key)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEmptyKeyPassthrough(t *testing.T) {
	plaintext := "sk-live-abc123"

	encrypted, err := Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encrypted != plaintext {
		t.Errorf("empty key should passthrough: got %q, want %q", encrypted, plaintext)
	}

	decrypted, err := Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("empty key should passthrough: got %q, want %q", decrypted, plaintext)
	}
}

// TestVersionedCiphertextFormat verifies Encrypt emits the versioned prefix and
// IsEncrypted recognises it (RD-1164 #1/#16).
func TestVersionedCiphertextFormat(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	encrypted, err := Encrypt("sk-live-abc123", key)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if !strings.HasPrefix(encrypted, "encv1:") {
		t.Errorf("ciphertext should carry the version prefix, got %q", encrypted)
	}
	if !IsEncrypted(encrypted) {
		t.Error("IsEncrypted should be true for a versioned ciphertext")
	}
	if IsEncrypted("plain-text-api-key") {
		t.Error("IsEncrypted should be false for a legacy plaintext value")
	}
}

// TestWrongKeyFailsClosed is the RD-1164 #1 regression guard: decrypting a
// versioned ciphertext with the WRONG key must return an error (fail closed),
// never the raw ciphertext as "plaintext". Previously Decrypt returned the
// input verbatim on GCM auth failure, nullifying AEAD integrity.
func TestWrongKeyFailsClosed(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	encrypted, err := Encrypt("sk-live-abc123", key1)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	got, err := Decrypt(encrypted, key2)
	if err == nil {
		t.Fatalf("decrypting a versioned value with the wrong key must fail closed; got %q, nil error", got)
	}
	if got == encrypted {
		t.Error("Decrypt must not return the ciphertext as plaintext on auth failure")
	}
}

// TestTamperedCiphertextFailsClosed guards AEAD integrity: mutating a versioned
// ciphertext must cause Decrypt to error under the correct key (RD-1164 #1).
func TestTamperedCiphertextFailsClosed(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	encrypted, err := Encrypt("sk-live-secret", key)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Flip the final character of the base64 payload (part of the GCM tag).
	b := []byte(encrypted)
	last := len(b) - 1
	if b[last] == 'A' {
		b[last] = 'B'
	} else {
		b[last] = 'A'
	}

	if got, err := Decrypt(string(b), key); err == nil {
		t.Fatalf("tampered versioned ciphertext must fail closed; got %q, nil error", got)
	}
}

// TestLegacyPlaintextDecryption confirms backward compatibility: an unversioned
// value that is not decryptable is returned verbatim (pre-versioning plaintext).
func TestLegacyPlaintextDecryption(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// A plaintext value that is not valid base64 should be returned as-is.
	legacyPlaintext := "sk-live-abc123!@#"

	decrypted, err := Decrypt(legacyPlaintext, key)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if decrypted != legacyPlaintext {
		t.Errorf("legacy plaintext should passthrough: got %q, want %q", decrypted, legacyPlaintext)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16) // AES-128, not AES-256

	_, err := Encrypt("test", shortKey)
	if err == nil {
		t.Error("Encrypt() should reject non-32-byte key")
	}

	_, err = Decrypt("test", shortKey)
	if err == nil {
		t.Error("Decrypt() should reject non-32-byte key")
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "sk-live-abc123"

	enc1, _ := Encrypt(plaintext, key)
	enc2, _ := Encrypt(plaintext, key)

	if enc1 == enc2 {
		t.Error("encrypting same plaintext twice should produce different ciphertexts (random nonce)")
	}

	// Both should decrypt to the same plaintext
	dec1, _ := Decrypt(enc1, key)
	dec2, _ := Decrypt(enc2, key)

	if dec1 != plaintext || dec2 != plaintext {
		t.Error("both ciphertexts should decrypt to the original plaintext")
	}
}

// TestDecryptStrict guards the migration tool's fail-closed decrypt (mandrigin
// review): DecryptStrict must ERROR (never pass the input through) on a wrong
// key or a non-ciphertext value, for BOTH versioned and legacy unversioned
// formats. This is what stops privacy-cli reencrypt-rpc-keys from
// double-encrypting a legacy ciphertext when handed a wrong --old-key.
func TestDecryptStrict(t *testing.T) {
	key := make([]byte, 32)
	wrong := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal(err)
	}

	enc, err := Encrypt("sk-live-secret", key)
	if err != nil {
		t.Fatal(err)
	}

	// Versioned value, correct key -> plaintext.
	if got, err := DecryptStrict(enc, key); err != nil || got != "sk-live-secret" {
		t.Fatalf("versioned + correct key: got %q err %v", got, err)
	}
	// Versioned value, wrong key -> error (must not pass through).
	if got, err := DecryptStrict(enc, wrong); err == nil {
		t.Fatalf("versioned + wrong key must error, got %q", got)
	}

	// A legacy unversioned ciphertext is the base64 blob WITHOUT the version
	// prefix (the pre-versioning Encrypt output shape).
	legacy := strings.TrimPrefix(enc, "encv1:")
	if legacy == enc {
		t.Fatal("expected a version prefix to strip")
	}
	// Legacy + correct key -> plaintext (strict decrypt still migrates it fine).
	if got, err := DecryptStrict(legacy, key); err != nil || got != "sk-live-secret" {
		t.Fatalf("legacy + correct key: got %q err %v", got, err)
	}
	// Legacy + WRONG key -> error. mandrigin's scenario: under the fail-open
	// Decrypt this returned the ciphertext verbatim (which the migration tool
	// would then re-encrypt = irreversible double-encryption); DecryptStrict
	// must reject it so the tool skips instead.
	if got, err := DecryptStrict(legacy, wrong); err == nil {
		t.Fatalf("legacy unversioned + wrong key must error (else double-encryption), got %q", got)
	}

	// A genuinely non-ciphertext (plaintext) value -> error under strict decrypt.
	if got, err := DecryptStrict("not-a-ciphertext-value!@#", key); err == nil {
		t.Fatalf("plaintext must error under strict decrypt, got %q", got)
	}
}
