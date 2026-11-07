package admission

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
)

const SignedEvidenceProfile = "geth-prague-signed-call/v1"

type Config struct {
	Snapshot                *policybundle.CatalogSnapshot
	Clock                   identity.Clock
	NetworkBinding          NetworkBinding
	ExpectedState           ExpectedState
	Store                   Store
	QuoteProvider           QuoteProvider
	ExpectedEvidenceProfile string
	CursorKeyring           CursorKeyring
}
type Service struct {
	snapshot                         *policybundle.CatalogSnapshot
	factory                          *runtimepolicy.Factory
	catalog                          *compliancepolicy.Catalog
	clock                            identity.Clock
	network                          NetworkBinding
	networkKey                       Digest
	state                            ExpectedState
	store                            Store
	quotes                           QuoteProvider
	evidenceProfile                  string
	manifestDigest, complianceDigest Digest
	orgs                             map[string]*orgRuntime
	cursors                          *cursorRing
}
type Metadata struct {
	ManifestDigest, ComplianceDigest, NetworkKey Digest
	Network                                      NetworkBinding
	EvidenceProfile                              string
}

func (s *Service) Metadata() Metadata {
	return Metadata{s.manifestDigest, s.complianceDigest, s.networkKey, s.network, s.evidenceProfile}
}
func (s *Service) AdminReady() bool { return s != nil && s.cursors != nil }
func New(c Config) (*Service, error) {
	if c.Snapshot == nil || c.Clock == nil || c.Store == nil || !c.ExpectedState.Valid() || !supportedEvidenceProfile(c.ExpectedEvidenceProfile) {
		return nil, ErrInvalid
	}
	key, err := c.NetworkBinding.Key()
	if err != nil {
		return nil, err
	}
	meta := c.Snapshot.Metadata()
	if meta.Environment != c.NetworkBinding.Environment || meta.ChainID != c.NetworkBinding.ChainID {
		return nil, ErrInvalid
	}
	catalog, ok := c.Snapshot.Compliance()
	if !ok {
		return nil, ErrInvalid
	}
	for _, requirement := range catalog.Requirements() {
		if requirement == "inputs.price-quotes/v1" && c.QuoteProvider == nil {
			return nil, ErrInvalid
		}
	}
	factory, err := runtimepolicy.NewFactory(c.Snapshot, c.Clock)
	if err != nil {
		return nil, ErrInvalid
	}
	ring, err := newCursorRing(c.CursorKeyring)
	if err != nil {
		return nil, err
	}
	manifest, err := ParseDigest(string(meta.ManifestDigest))
	if err != nil {
		return nil, err
	}
	policy, err := ParseDigest(catalog.Digest())
	if err != nil {
		return nil, err
	}
	s := &Service{snapshot: c.Snapshot, factory: factory, catalog: catalog, clock: c.Clock, network: c.NetworkBinding, networkKey: key, state: c.ExpectedState, store: c.Store, quotes: c.QuoteProvider, evidenceProfile: c.ExpectedEvidenceProfile, manifestDigest: manifest, complianceDigest: policy, orgs: map[string]*orgRuntime{}, cursors: ring}
	for _, organization := range c.Snapshot.Organizations() {
		p, ok := catalog.OrgPolicy(organization.ID)
		if !ok {
			return nil, ErrInvalid
		}
		runtime := &orgRuntime{policy: p, prices: map[string]compliancepolicy.SourceTokenPrice{}, thresholds: map[string]compliancepolicy.SourceThreshold{}, quoteIDs: map[string]bool{}}
		for _, price := range p.Spec.TokenPrices {
			runtime.prices[price.TokenAddress] = price
			if price.CoingeckoID != "" {
				runtime.quoteIDs[price.CoingeckoID] = true
			}
		}
		if _, hasNative := runtime.prices["native"]; !hasNative {
			runtime.quoteIDs["ethereum"] = true
		}
		for _, threshold := range p.Spec.AddressThresholds {
			runtime.thresholds[threshold.Address] = threshold
		}
		s.orgs[organization.ID] = runtime
	}
	return s, nil
}
func (s *Service) view(token string) (*runtimepolicy.View, error) {
	v, err := s.factory.Build(token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return v, nil
}
func (s *Service) checkView(v *runtimepolicy.View, org string) error {
	if v == nil || v.RequireLive() != nil {
		return ErrUnauthorized
	}
	if string(v.Metadata().ManifestDigest) != s.manifestDigest.String() {
		return ErrInvalid
	}
	if _, ok := v.Org(org); !ok {
		return ErrForbidden
	}
	if s.orgs[org] == nil {
		return ErrInvalid
	}
	return nil
}
func (s *Service) captureQuotes(ctx context.Context) (QuoteSnapshot, error) {
	if s.quotes == nil {
		return NewQuoteSnapshot(nil)
	}
	snapshot, err := s.quotes.Capture(ctx)
	if err != nil || !snapshot.valid {
		return QuoteSnapshot{}, ErrUnavailable
	}
	return snapshot, nil
}
func (s *Service) newRequestStore(scope Scope, at time.Time, quotes QuoteSnapshot, read ReadTx, write RawTx) *requestStore {
	return &requestStore{service: s, org: s.orgs[scope.Organization], scope: scope, read: read, write: write, quotes: quotes, at: at, used: map[string]Quote{}}
}
func (s *Service) checkTime(v *runtimepolicy.View, org string, at time.Time, used map[string]Quote, newRecord *Record) error {
	if err := s.checkView(v, org); err != nil {
		return err
	}
	now := s.clock().UTC()
	if now.Before(at) {
		return ErrUnavailable
	}
	age := time.Duration(s.orgs[org].policy.PriceMaxAgeSeconds) * time.Second
	for _, q := range used {
		if !q.Fresh(now, age) {
			return ErrValuation
		}
	}
	if newRecord != nil && !now.Before(newRecord.EffectiveExpiry(s.orgs[org].policy.RecordMaxSeconds)) {
		return ErrConflict
	}
	return nil
}

type Decision struct {
	Allowed, Monitored bool
	Coverage, RecordID string
}
type CommittedResult struct {
	decision Decision
	receipt  *RawReceipt
}

func (r *CommittedResult) Decision() Decision { return r.decision }
func (r *CommittedResult) Receipt() (*RawReceipt, bool) {
	return r.receipt, r.receipt != nil && r.decision.Allowed
}

type RawReceipt struct {
	service                    *Service
	view                       *runtimepolicy.View
	scope                      Scope
	audience                   Digest
	anchor                     common.Hash
	execution                  *rpcexecution.CallExecution
	walletActor, walletVersion string
	at                         time.Time
	used                       map[string]Quote
	valid                      bool
}

func (r *RawReceipt) RequirePublishable() error {
	if r == nil || !r.valid || r.service == nil {
		return ErrInvalid
	}
	return r.service.checkTime(r.view, r.scope.Organization, r.at, r.used, nil)
}
func (r *RawReceipt) Matches(input TrustedRawInput) bool {
	if r == nil || !r.valid || input.View == nil || input.Execution == nil || !input.Transaction.Valid() {
		return false
	}
	_, digest, err := NormalizeRecipients(input.Audience)
	return err == nil && r.scope.Actor == input.View.ActorID() && r.scope.Organization == input.OrganizationID && r.scope.Hash == input.Transaction.Hash() && r.anchor == input.Execution.Anchor().Hash && r.execution == input.Execution && r.walletActor == input.WalletSnapshot.ActorID() && r.walletVersion == input.WalletSnapshot.Version() && r.audience == digest && string(input.View.Metadata().ManifestDigest) == r.service.manifestDigest.String()
}
func (s *Service) CheckAndRecordRaw(ctx context.Context, input TrustedRawInput) (*CommittedResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.checkView(input.View, input.OrganizationID); err != nil {
		return nil, err
	}
	if !input.Transaction.Valid() || input.Transaction.ChainID() != s.network.ChainID || input.Execution == nil || !input.Execution.Signed() {
		return nil, ErrInvalid
	}
	txHash, hashKnown := input.Execution.TransactionHash()
	signer, signerKnown := input.Execution.VerifiedSigner()
	anchor := input.Execution.Anchor()
	if !hashKnown || !signerKnown || txHash != input.Transaction.Hash() || signer != input.Transaction.Signer() || anchor.ChainID != s.network.ChainID || anchor.OrganizationID != input.OrganizationID || anchor.Profile != s.evidenceProfile || anchor.Hash == (common.Hash{}) {
		return nil, ErrInvalid
	}
	to, financialData, err := financialProjection(input.Transaction, s.evidenceProfile)
	if err != nil {
		return nil, err
	}
	audience, audienceDigest, err := NormalizeRecipients(input.Audience)
	if err != nil {
		return nil, err
	}
	qualified := input.WalletSnapshot.ActorID() == input.View.ActorID() && input.WalletSnapshot.Contains(signer)
	var walletVersion Digest
	if qualified {
		walletVersion, err = ParseDigest(input.WalletSnapshot.Version())
		if err != nil || input.WalletSnapshot.EvidenceAt().IsZero() || input.WalletSnapshot.EvidenceAt().After(s.clock()) {
			return nil, ErrInvalid
		}
	}
	if len(audience) > 0 && (!qualified || input.Transaction.Creation()) {
		return nil, ErrForbidden
	}
	if registered, found := input.View.Contract(to); found && registered.OwnerOrg() != input.OrganizationID {
		return nil, ErrForbidden
	}
	quotes, err := s.captureQuotes(ctx)
	if err != nil {
		return nil, err
	}
	scope := Scope{Network: s.networkKey, State: s.state, Organization: input.OrganizationID, Actor: input.View.ActorID(), Hash: txHash}
	var decision Decision
	var at time.Time
	used := map[string]Quote{}
	committed, err := s.store.WithRawTransaction(ctx, scope, func(raw RawTx) (CommitKind, error) {
		if err := s.checkView(input.View, input.OrganizationID); err != nil {
			return 0, err
		}
		at = s.clock().UTC()
		var origin Origin
		var exists bool
		// Reject immutable sharing conflicts before any financial record claim.
		// The same hash lock protects these facts through the eventual commit.
		if len(audience) > 0 {
			origin, exists, err = raw.GetOrigin()
			if err != nil {
				return 0, err
			}
			if exists && origin.Organization != scope.Organization {
				return 0, ErrConflict
			}
			share, shared, shareErr := raw.GetShare()
			if shareErr != nil {
				return 0, shareErr
			}
			if shared && !share.SameBinding(Share{Network: s.networkKey, Hash: txHash, Actor: scope.Actor, Organization: scope.Organization, Recipients: audience, RecipientDigest: audienceDigest}) {
				return 0, ErrConflict
			}
		}
		request := s.newRequestStore(scope, at, quotes, raw, raw)
		request.anchor.Anchor = anchor
		checker, err := compliance.NewSourceChecker(request, compliance.SourceCheckOptions{OrganizationID: scope.Organization, ActorID: scope.Actor, Currency: request.org.policy.Spec.Settings.Currency, DecisionAt: at, PriceMaxAge: time.Duration(request.org.policy.PriceMaxAgeSeconds) * time.Second})
		if err != nil {
			return 0, ErrInvalid
		}
		checked, err := checker.Check(ctx, request.checkRequest(txHash.Hex(), AddressString(signer), AddressString(to), financialData, "0x"+input.Transaction.Value().Text(16), false))
		if err != nil {
			return 0, err
		}
		if checked == nil {
			return 0, ErrUnavailable
		}
		decision = Decision{Allowed: checked.Allowed, Monitored: checked.Monitored, RecordID: checked.TravelRuleRecordID, Coverage: "not_detected"}
		if checked.TransferInfo != nil {
			decision.Coverage = "disabled"
			if request.org.policy.Spec.Settings.Enabled {
				decision.Coverage = "root_transfer"
				if request.lastEventID <= 0 {
					return 0, ErrUnavailable
				}
			}
		}
		if !checked.Allowed {
			if request.lastEventID <= 0 || request.newRecord != nil {
				return 0, ErrUnavailable
			}
			// This commits an observation at DecisionAt, never publication
			// authority. Later token/quote expiry must not erase a true denial.
			return CommitDeny, nil
		}
		if len(audience) == 0 {
			origin, exists, err = raw.GetOrigin()
			if err != nil {
				return 0, err
			}
		}
		ownProvenance := false
		if qualified && (!exists || (origin.Actor == scope.Actor && origin.Organization == scope.Organization)) {
			w := Witness{AnchorHash: anchor.Hash, AnchorNumber: anchor.Number, AnchorTimestamp: anchor.Timestamp, EvidenceProfile: anchor.Profile, WalletVersion: walletVersion, DecisionAt: at, ManifestDigest: s.manifestDigest, ComplianceDigest: s.complianceDigest, WalletEvidenceAt: input.WalletSnapshot.EvidenceAt()}
			w.ID = w.Digest()
			if !exists {
				if _, err := raw.PutOrigin(Origin{Network: s.networkKey, Hash: txHash, Actor: scope.Actor, Organization: scope.Organization, FirstAdmittedAt: at, Primary: w}); err != nil {
					return 0, err
				}
			} else {
				if err := raw.PutWitness(w); err != nil {
					return 0, err
				}
			}
			ownProvenance = true
		}
		if len(audience) > 0 {
			if exists && origin.Organization != scope.Organization {
				return 0, ErrConflict
			}
			w := Witness{AnchorHash: anchor.Hash, AnchorNumber: anchor.Number, AnchorTimestamp: anchor.Timestamp, EvidenceProfile: anchor.Profile, WalletVersion: walletVersion, DecisionAt: at, ManifestDigest: s.manifestDigest, ComplianceDigest: s.complianceDigest, WalletEvidenceAt: input.WalletSnapshot.EvidenceAt()}
			w.ID = w.Digest()
			if err := raw.PutShare(Share{Network: s.networkKey, Hash: txHash, Actor: scope.Actor, Organization: scope.Organization, Recipients: audience, RecipientDigest: audienceDigest, DeclaredAt: at, Witness: w}); err != nil {
				return 0, err
			}
			ownProvenance = true
		}
		if request.lastEventID == 0 && !ownProvenance {
			if _, err := raw.AppendEvent(Event{Scope: scope, Kind: "admission_only", Coverage: decision.Coverage, Decision: "allowed", DecisionAt: at, PolicyDigest: s.complianceDigest, Anchor: anchor}); err != nil {
				return 0, err
			}
		}
		if err := s.checkTime(input.View, scope.Organization, at, request.used, request.newRecord); err != nil {
			return 0, err
		}
		for id, q := range request.used {
			used[id] = q
		}
		return CommitAllow, nil
	})
	if err != nil {
		return nil, err
	}
	if !committed.Committed || (decision.Allowed && committed.Kind != CommitAllow) || (!decision.Allowed && committed.Kind != CommitDeny) {
		return nil, ErrUnavailable
	}
	out := &CommittedResult{decision: decision}
	if decision.Allowed {
		out.receipt = &RawReceipt{service: s, view: input.View, scope: scope, audience: audienceDigest, anchor: anchor.Hash, execution: input.Execution, walletActor: input.WalletSnapshot.ActorID(), walletVersion: input.WalletSnapshot.Version(), at: at, used: used, valid: true}
	}
	return out, nil
}
