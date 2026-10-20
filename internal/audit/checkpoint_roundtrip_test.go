package audit

import (
	"testing"
	"time"
)

// TestSignatureStableAcrossMicrosecondRoundTrip is the regression guard for the
// nanosecond-vs-microsecond signing bug (found by the RD-1112 write-path
// integration tests, which flaked only on Linux/CI). The checkpoint and
// re-anchor signatures cover CreatedAt, but the audit tables store it as a
// Postgres TIMESTAMP (MICROSECOND resolution). Signing over UnixNano() meant
// that on any host whose clock has sub-microsecond resolution (Linux), the
// sealed sub-µs digits were lost on read-back and the recomputed signature no
// longer matched — a false tamper alarm in production, not just a test flake.
// macOS hid it (microsecond-resolution time.Now()).
//
// This test is platform-independent: it simulates the DB round-trip by
// truncating CreatedAt to a microsecond and asserts the signature still
// verifies. It FAILS against the old UnixNano() content and PASSES with the
// UnixMicro() fix, on every platform.
func TestSignatureStableAcrossMicrosecondRoundTrip(t *testing.T) {
	signer := NewHMACSigner("test-key", []byte("checkpoint-hmac-secret-32bytes!!"))

	// CreatedAt carrying sub-microsecond nanoseconds (…789 ns past the µs),
	// exactly what time.Now() yields on a nanosecond-resolution clock.
	created := time.Unix(1_700_000_000, 123_456_789).UTC()

	t.Run("checkpoint", func(t *testing.T) {
		cp := Checkpoint{ChainName: "access_logs", HeadID: 42, HeadHash: "deadbeef", RowCount: 10, CreatedAt: created}
		if err := SignCheckpoint(signer, &cp); err != nil {
			t.Fatalf("sign: %v", err)
		}
		// Postgres TIMESTAMP truncates to microseconds on store+read-back.
		cp.CreatedAt = cp.CreatedAt.Truncate(time.Microsecond)
		if err := VerifyCheckpoint(signer, cp); err != nil {
			t.Fatalf("checkpoint signature must survive a microsecond DB round-trip: %v", err)
		}
	})

	t.Run("reanchor", func(t *testing.T) {
		ra := ReAnchor{
			ChainName: "access_logs", Reason: "break-glass", Actor: "did:test:op",
			FromHeadID: 5, FromHash: "aa", ToHeadID: 9, ToHash: "bb", CreatedAt: created,
		}
		if err := SignReAnchor(signer, &ra); err != nil {
			t.Fatalf("sign: %v", err)
		}
		ra.CreatedAt = ra.CreatedAt.Truncate(time.Microsecond)
		if err := VerifyReAnchor(signer, ra); err != nil {
			t.Fatalf("reanchor signature must survive a microsecond DB round-trip: %v", err)
		}
	})
}
