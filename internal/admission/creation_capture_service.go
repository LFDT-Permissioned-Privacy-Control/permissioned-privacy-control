package admission

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationcapture"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
)

func captureRequest(input TrustedRawInput) creationcapture.CaptureRequest {
	return creationcapture.CaptureRequest{Approved: input.ApprovedCheck, View: input.View, Organization: input.OrganizationID, Transaction: input.Transaction, Execution: input.Execution, Wallets: input.WalletSnapshot}
}

func (s *Service) validateObservedInput(input TrustedRawInput) error {
	if s == nil || !s.creationObserved || s.captureGate == nil || input.Execution == nil || !input.Transaction.Valid() || input.Transaction.ChainID() != s.network.ChainID || s.checkView(input.View, input.OrganizationID) != nil || input.ApprovedCheck.RequireMatches(input.View, input.OrganizationID, input.Execution, input.WalletSnapshot) != nil {
		return ErrInvalid
	}
	hash, known := input.Execution.TransactionHash()
	signer, signed := input.Execution.VerifiedSigner()
	a := input.Execution.Anchor()
	if !known || !signed || hash != input.Transaction.Hash() || signer != input.Transaction.Signer() || a.Hash == (common.Hash{}) || a.OrganizationID != input.OrganizationID || a.ChainID != s.network.ChainID || a.Profile != s.evidenceProfile {
		return ErrInvalid
	}
	if p := input.ApprovedCheck.Plan(); p != nil {
		d := p.Data()
		if d.Version != nativeadmission.CapturedCreationPlanVersion || d.CaptureProfile != creationfacts.CaptureProfile {
			return ErrInvalid
		}
	}
	return nil
}

// NeedsCreationCapture is an availability hint, never a permission verdict.
// Financial ALLOW independently derives the actual branches under its hash
// lock, and rolls back any eligible branch lacking sealed positive evidence.
func (s *Service) NeedsCreationCapture(ctx context.Context, input TrustedRawInput) (CaptureNeed, error) {
	if err := s.validateObservedInput(input); err != nil {
		return 0, err
	}
	plan := input.ApprovedCheck.Plan()
	if plan == nil {
		return NoEligible, nil
	}
	if plan.HasFactoryAuthority() {
		return NeedCapture, nil
	}
	if input.WalletSnapshot.ActorID() != input.View.ActorID() || !input.WalletSnapshot.Contains(input.Transaction.Signer()) {
		return NoEligible, nil
	}
	store, ok := s.store.(CreationCoveredStore)
	if !ok {
		return 0, ErrUnavailable
	}
	origin, found, err := store.ReadOriginBinding(ctx, s.networkKey, s.state, input.Transaction.Hash())
	if err != nil {
		return 0, err
	}
	if found && (origin.Actor != input.View.ActorID() || origin.Organization != input.OrganizationID) {
		return NoEligible, nil
	}
	return NeedCapture, nil
}
