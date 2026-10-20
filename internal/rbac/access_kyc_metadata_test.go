package rbac

import (
	"context"
	"testing"
	"time"
)

// TestKYCGateExemptsOrgFreeMetadataMethods is the RD-1197 regression guard:
// an authenticated-but-not-KYC'd user must not be stricter than anonymous for
// the org-free metadata methods. The anonymous allowlist (migration 044)
// serves the same methods with no user at all, so the blanket KYC deny used
// to make signing in strictly worse. Bans remain a blanket deny.
func TestKYCGateExemptsOrgFreeMetadataMethods(t *testing.T) {
	ctx := context.Background()

	newController := func() *AccessController {
		store := NewMockCrossOrgStore()
		store.CreateUser(ctx, &User{ID: "user-nokyc", ExternalID: "did:test:nokyc", KYC: false})
		store.CreateUser(ctx, &User{ID: "user-kyc", ExternalID: "did:test:kyc", KYC: true})
		store.CreateUser(ctx, &User{ID: "user-banned", ExternalID: "did:test:banned", KYC: true, Banned: true})
		return NewAccessController(store, 5*time.Minute)
	}

	t.Run("non-KYC user allowed on every org-free metadata method", func(t *testing.T) {
		controller := newController()
		for method := range orgFreeMetadataMethods {
			result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: "did:test:nokyc",
				Method:         method,
			})
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", method, err)
			}
			if !result.Allowed {
				t.Errorf("%s: non-KYC user denied (reason %q); must not be stricter than anonymous", method, result.Reason)
			}
		}
	})

	tests := []struct {
		name       string
		externalID string
		method     string
		allowed    bool
		reason     string
	}{
		{"non-KYC user still denied on state query", "did:test:nokyc", "eth_getBalance", false, "KYC verification required"},
		{"non-KYC user still denied on eth_call", "did:test:nokyc", "eth_call", false, "KYC verification required"},
		{"non-KYC user still denied on send", "did:test:nokyc", "eth_sendTransaction", false, "KYC verification required"},
		{"banned user denied even on metadata method", "did:test:banned", "eth_blockNumber", false, "user is banned"},
		{"metadata method is case-insensitive", "did:test:nokyc", "ETH_BlockNumber", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
				UserExternalID: tt.externalID,
				Method:         tt.method,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed != tt.allowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", result.Allowed, tt.allowed, result.Reason)
			}
			if tt.reason != "" && result.Reason != tt.reason {
				t.Errorf("reason = %q, want %q", result.Reason, tt.reason)
			}
		})
	}
}
