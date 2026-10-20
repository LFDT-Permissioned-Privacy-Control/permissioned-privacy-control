package audit

import (
	"testing"
	"time"
)

func sampleCheckpoint() Checkpoint {
	return Checkpoint{
		ChainName: "access_logs",
		HeadID:    1042,
		HeadHash:  "abc123def456",
		RowCount:  1042,
		CreatedAt: time.Unix(0, 1_750_000_000_000_000_000).UTC(),
	}
}

func TestCheckpointSignVerifyRoundTrip(t *testing.T) {
	s := NewHMACSigner("k1", []byte("super-secret-checkpoint-key"))
	c := sampleCheckpoint()
	if err := SignCheckpoint(s, &c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if c.Signature == "" || c.KeyID != "k1" {
		t.Fatalf("sign did not fill fields: %+v", c)
	}
	if err := VerifyCheckpoint(s, c); err != nil {
		t.Fatalf("verify of untouched checkpoint failed: %v", err)
	}
}

// TestCheckpointTamperDetected is the load-bearing test: altering ANY
// signature-covered field (especially RowCount / HeadHash, the truncation
// guard) must fail verification.
func TestCheckpointTamperDetected(t *testing.T) {
	s := NewHMACSigner("k1", []byte("super-secret-checkpoint-key"))
	base := sampleCheckpoint()
	if err := SignCheckpoint(s, &base); err != nil {
		t.Fatalf("sign: %v", err)
	}

	mutate := map[string]func(*Checkpoint){
		"RowCount (truncation)": func(c *Checkpoint) { c.RowCount = 10 },
		"HeadHash":              func(c *Checkpoint) { c.HeadHash = "deadbeef" },
		"HeadID":                func(c *Checkpoint) { c.HeadID = 1 },
		"ChainName":             func(c *Checkpoint) { c.ChainName = "rbac_audit_log" },
		"CreatedAt":             func(c *Checkpoint) { c.CreatedAt = c.CreatedAt.Add(time.Second) },
	}
	for name, mut := range mutate {
		c := base // copy (Signature/KeyID retained)
		mut(&c)
		if err := VerifyCheckpoint(s, c); err == nil {
			t.Errorf("tampering with %s was NOT detected", name)
		}
	}
}

func TestCheckpointWrongKeyRejected(t *testing.T) {
	signer := NewHMACSigner("k1", []byte("key-one"))
	c := sampleCheckpoint()
	if err := SignCheckpoint(signer, &c); err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Different key, same id → signature mismatch.
	if err := VerifyCheckpoint(NewHMACSigner("k1", []byte("key-two")), c); err == nil {
		t.Error("verification with a different key should fail")
	}
	// Different key id → rejected before comparing.
	if err := VerifyCheckpoint(NewHMACSigner("k2", []byte("key-one")), c); err == nil {
		t.Error("verification with a mismatched key id should fail")
	}
}

func TestHMACSignerEmptyKey(t *testing.T) {
	c := sampleCheckpoint()
	if err := SignCheckpoint(NewHMACSigner("k1", nil), &c); err == nil {
		t.Error("signing with an empty key should error")
	}
}
