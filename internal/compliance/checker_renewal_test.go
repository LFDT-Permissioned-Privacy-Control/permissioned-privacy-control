package compliance

import (
	"context"
	"errors"
	"testing"
	"time"
)

// txClaimStore is the transaction-bound travel-rule store (the Reth path).
type txClaimStore struct {
	mockComplianceStore
	bound      *TravelRuleRecord
	boundErr   error
	boundCalls int
	txClaims   int
}

func (s *txClaimStore) ClaimTravelRuleRecordForTx(context.Context, uint64, string, string, string, string, string, string, float64) (*TravelRuleRecord, error) {
	s.txClaims++
	return s.claimedRecord, s.claimErr
}

func (s *txClaimStore) BoundTravelRuleRecordForTx(context.Context, uint64, string, string, string, string, string, string, float64) (*TravelRuleRecord, error) {
	s.boundCalls++
	return s.bound, s.boundErr
}

// G19 (plan §4.8.5): renewal mode re-evaluates every rule, satisfies the
// travel-rule step only with the record bound to this transaction (never
// claims or borrows another), and turns infrastructure failures — including
// an unwritable compliance log — into errors (retryable), never denials.
func TestRenewalRevalidatesOnlyItsBoundTravelRuleRecord(t *testing.T) {
	request := func() *CheckRequest {
		return &CheckRequest{OrgID: "org-1", UserID: "user-1", From: "0x0000000000000000000000000000000000000001", To: "0x0000000000000000000000000000000000000002", Value: "0x1bc16d674ec80000",
			Transaction: TransactionBinding{ChainID: 31337, DeploymentID: "d", Hash: "0x" + "ab", Renewal: true}}
	}
	newStore := func() *txClaimStore {
		return &txClaimStore{mockComplianceStore: mockComplianceStore{config: enabledConfig(1000), tokenPrice: nativePrice(1000), claimedRecord: &TravelRuleRecord{ID: "tr-unused"}}}
	}
	t.Run("bound_record_passes", func(t *testing.T) {
		store := newStore()
		store.bound = &TravelRuleRecord{ID: "tr-bound"}
		result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request())
		if err != nil || !result.Allowed || result.TravelRuleRecordID != "tr-bound" {
			t.Fatalf("renewal with its bound record: %+v %v", result, err)
		}
		if store.boundCalls != 1 || store.txClaims != 0 || store.claimCalls != 0 {
			t.Fatalf("renewal claimed a record: bound=%d tx=%d claim=%d", store.boundCalls, store.txClaims, store.claimCalls)
		}
	})
	t.Run("no_bound_record_is_denied_never_borrowed", func(t *testing.T) {
		store := newStore() // an unused covering record exists, but none is bound
		result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request())
		if err != nil || result.Allowed {
			t.Fatalf("renewal without a bound record: %+v %v", result, err)
		}
		if store.txClaims != 0 || store.claimCalls != 0 {
			t.Fatal("renewal borrowed an unused record")
		}
	})
	t.Run("lookup_error_is_retryable", func(t *testing.T) {
		store := newStore()
		store.boundErr = errors.New("database unavailable")
		if result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request()); err == nil {
			t.Fatalf("a lookup failure became a decision: %+v", result)
		}
	})
	t.Run("price_error_is_retryable", func(t *testing.T) {
		store := newStore()
		store.tokenPriceErr = errors.New("price service down")
		if result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request()); err == nil {
			t.Fatalf("a price failure became a decision: %+v", result)
		}
	})
	t.Run("log_failure_is_retryable", func(t *testing.T) {
		store := newStore()
		store.bound = &TravelRuleRecord{ID: "tr-bound"}
		store.logErr = errors.New("compliance log unavailable")
		if result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request()); err == nil {
			t.Fatalf("an unwritable log became a denial in renewal mode: %+v", result)
		}
	})
	t.Run("sanction_is_a_denial", func(t *testing.T) {
		store := newStore()
		store.bound = &TravelRuleRecord{ID: "tr-bound"}
		store.sanctionedAddrs = map[string]bool{"0x0000000000000000000000000000000000000002": true}
		if result, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request()); err != nil || result.Allowed {
			t.Fatalf("a sanction is a business refusal: %+v %v", result, err)
		}
	})
	t.Run("store_without_binding_support_is_an_error", func(t *testing.T) {
		store := &mockComplianceStore{config: enabledConfig(1000), tokenPrice: nativePrice(1000), claimedRecord: &TravelRuleRecord{ID: "tr-unused"}}
		if _, err := NewChecker(store, 24*time.Hour, 15*time.Minute).Check(context.Background(), request()); err == nil || store.claimCalls != 0 {
			t.Fatalf("renewal fell back to a per-call claim: %v claims=%d", err, store.claimCalls)
		}
	})
}
