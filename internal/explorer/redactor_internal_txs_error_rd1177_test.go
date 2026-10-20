package explorer

import (
	"context"
	"testing"
)

// RD-1177 F2 / REDACTION_SPEC G4 — RedactInternalTransactions must nil the
// `error` field when either side of the internal call is Hidden or Redacted.
//
// A trace revert string can embed the hidden counterparty's address or a
// private reason (e.g. "execution reverted: caller 0xABCD... not authorized").
// The one-side-hidden branch masked From/To and stripped Input/Output/Value
// but left `error` untouched, while top-level RedactTransactions already nils
// it — so /transactions/:hash/internal leaked what /transactions did not.
//
// MUTATION CHECK: remove `redacted.Error = nil` from the one-side-hidden
// branch of RedactInternalTransactions → this test fails.
func TestRedactInternalTransactions_OneSideHidden_StripsError_RD1177(t *testing.T) {
	hiddenFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	visibleTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// A revert string that embeds a private address + reason — exactly the
	// class of leak G4 is about.
	revert := "execution reverted: caller " + hiddenFrom + " not authorized"

	engine := newEngine(VisibilityMap{
		hiddenFrom: VisibilityHidden,
		visibleTo:  VisibilityFull,
	})

	itxs := []InternalTransaction{{
		ID:     1,
		TxHash: "0xparent",
		From:   hiddenFrom,
		To:     strPtr(visibleTo),
		Value:  "100",
		Error:  strPtr(revert),
	}}

	// Non-participant viewer: the row survives (one side visible) but the
	// hidden side is masked. Error must be gone.
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer", RedactOpts{})
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected the one-side-hidden internal tx to survive, got %d rows", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("hidden From must be [PRIVATE], got %q", result[0].From)
	}
	if result[0].Error != nil {
		t.Fatalf("RD-1177/G4 regression: internal-tx Error must be nil on the one-side-hidden "+
			"branch (revert strings can embed the hidden counterparty), got %q", *result[0].Error)
	}
}

// Complement: when BOTH sides are fully visible to the viewer, the error is a
// legitimate part of the trace and is preserved (no over-stripping).
func TestRedactInternalTransactions_BothVisible_KeepsError_RD1177(t *testing.T) {
	a := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	revert := "execution reverted: insufficient balance"

	engine := newEngine(VisibilityMap{a: VisibilityFull, b: VisibilityFull})

	itxs := []InternalTransaction{{
		ID: 1, TxHash: "0xparent", From: a, To: strPtr(b), Value: "100", Error: strPtr(revert),
	}}

	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer", RedactOpts{})
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result))
	}
	if result[0].Error == nil || *result[0].Error != revert {
		t.Errorf("both-visible internal tx should keep its error, got %v", result[0].Error)
	}
}
