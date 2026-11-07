package compliance

import (
	"context"
	"errors"
	"time"
)

type PreviewRecordRequest struct {
	Binding                                          TransactionBinding
	OrgID, ActorID, BeneficiaryAddress, TokenAddress string
	AmountFiat                                       float64
	DecisionAt                                       time.Time
}

// Implementations must recheck an existing binding's complete coverage; a
// mismatched bound record cannot borrow an unused record. Renewal is bound-only.
type SourcePreviewStore interface {
	CheckStore
	PreviewTravelRuleRecord(context.Context, PreviewRecordRequest) (*TravelRuleRecord, error)
}

var ErrSourcePreviewUnsupported = errors.New("source compliance preview unavailable")

type sourcePreviewStore struct {
	CheckStore
	reader SourcePreviewStore
	at     time.Time
}

func (s sourcePreviewStore) ClaimUnusedTravelRuleRecord(ctx context.Context, org, actor, beneficiary, token string, amount float64) (*TravelRuleRecord, error) {
	return s.FindUnusedTravelRuleRecord(ctx, org, actor, beneficiary, token, amount)
}
func (s sourcePreviewStore) CreateComplianceLog(context.Context, *ComplianceLog) (int64, error) {
	return 0, nil
}
func (s sourcePreviewStore) ClaimTravelRuleRecordForTx(ctx context.Context, chain uint64, deployment, hash, org, actor, beneficiary, token string, amount float64) (*TravelRuleRecord, error) {
	return s.reader.PreviewTravelRuleRecord(ctx, PreviewRecordRequest{Binding: TransactionBinding{ChainID: chain, DeploymentID: deployment, Hash: hash}, OrgID: org, ActorID: actor, BeneficiaryAddress: beneficiary, TokenAddress: token, AmountFiat: amount, DecisionAt: s.at})
}
func (s sourcePreviewStore) BoundTravelRuleRecordForTx(ctx context.Context, chain uint64, deployment, hash, org, actor, beneficiary, token string, amount float64) (*TravelRuleRecord, error) {
	return s.reader.PreviewTravelRuleRecord(ctx, PreviewRecordRequest{Binding: TransactionBinding{ChainID: chain, DeploymentID: deployment, Hash: hash, Renewal: true}, OrgID: org, ActorID: actor, BeneficiaryAddress: beneficiary, TokenAddress: token, AmountFiat: amount, DecisionAt: s.at})
}
