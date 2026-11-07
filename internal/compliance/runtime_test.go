package compliance

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const sourceOrg = "11111111-1111-1111-1111-111111111111"
const sourceFrom = "0x1111111111111111111111111111111111111111"
const sourceTo = "0x2222222222222222222222222222222222222222"

func sourceActor(b byte) string {
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}
func sourceOptions() SourceCheckOptions {
	return SourceCheckOptions{OrganizationID: sourceOrg, ActorID: sourceActor(1), Currency: "eur", DecisionAt: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), PriceMaxAge: 10 * time.Minute}
}
func sourceRequest() *CheckRequest {
	return &CheckRequest{OrgID: sourceOrg, UserID: sourceActor(1), From: sourceFrom, To: sourceTo, Value: "0xde0b6b3a7640000"}
}

// Only the nine decision methods are implemented; no broad Store stubs.
type scopedCheckStore struct {
	config                                                                           *ComplianceConfig
	price                                                                            *TokenPrice
	quote                                                                            *SystemTokenPrice
	record, bound                                                                    *TravelRuleRecord
	boundExists                                                                      bool
	sanctions                                                                        map[string]bool
	logErr                                                                           error
	configCalls, findCalls, claimCalls, txClaims, boundCalls, previewCalls, logCalls int
	used                                                                             bool
	at                                                                               time.Time
}

func newScopedStore() *scopedCheckStore {
	return &scopedCheckStore{config: &ComplianceConfig{OrgID: sourceOrg, Enabled: true, ThresholdFiat: 100, Currency: "eur", UnknownPricePolicy: UnknownPriceForbidden, EnforcementMode: EnforcementEnforce}, price: &TokenPrice{Decimals: 18, PricesByCurrency: map[string]float64{"eur": 100}}, at: sourceOptions().DecisionAt}
}
func (s *scopedCheckStore) GetComplianceConfig(context.Context, string) (*ComplianceConfig, error) {
	s.configCalls++
	return s.config, nil
}
func (s *scopedCheckStore) GetTokenPrice(context.Context, string, string) (*TokenPrice, error) {
	return s.price, nil
}
func (s *scopedCheckStore) GetSystemTokenPrice(context.Context, string) (*SystemTokenPrice, error) {
	return s.quote, nil
}
func (s *scopedCheckStore) GetAddressThresholdOverride(context.Context, string, string) (*AddressThresholdOverride, error) {
	return nil, nil
}
func (s *scopedCheckStore) IsAddressSanctioned(_ context.Context, _, address string) (bool, error) {
	return s.sanctions[strings.ToLower(address)], nil
}
func (s *scopedCheckStore) GetSystemSetting(context.Context, string) (string, error) {
	panic("source currency fell back to mutable system setting")
}
func (s *scopedCheckStore) FindUnusedTravelRuleRecord(context.Context, string, string, string, string, float64) (*TravelRuleRecord, error) {
	s.findCalls++
	if s.used || s.record == nil || !s.record.ExpiresAt.After(s.at) {
		return nil, nil
	}
	return s.record, nil
}
func (s *scopedCheckStore) ClaimUnusedTravelRuleRecord(ctx context.Context, o, a, b, t string, n float64) (*TravelRuleRecord, error) {
	s.claimCalls++
	v, e := s.FindUnusedTravelRuleRecord(ctx, o, a, b, t, n)
	if v != nil {
		s.used = true
	}
	return v, e
}
func (s *scopedCheckStore) CreateComplianceLog(context.Context, *ComplianceLog) (int64, error) {
	s.logCalls++
	return 1, s.logErr
}
func (s *scopedCheckStore) ClaimTravelRuleRecordForTx(ctx context.Context, c uint64, d, h, o, a, b, t string, n float64) (*TravelRuleRecord, error) {
	s.txClaims++
	if s.boundExists {
		return s.BoundTravelRuleRecordForTx(ctx, c, d, h, o, a, b, t, n)
	}
	return s.ClaimUnusedTravelRuleRecord(ctx, o, a, b, t, n)
}
func (s *scopedCheckStore) BoundTravelRuleRecordForTx(ctx context.Context, c uint64, d, h, o, a, b, t string, n float64) (*TravelRuleRecord, error) {
	s.boundCalls++
	return s.previewBound(PreviewRecordRequest{Binding: TransactionBinding{ChainID: c, DeploymentID: d, Hash: h}, OrgID: o, ActorID: a, BeneficiaryAddress: b, TokenAddress: t, AmountFiat: n}), nil
}
func (s *scopedCheckStore) previewBound(r PreviewRecordRequest) *TravelRuleRecord {
	v := s.bound
	if v == nil || v.OrgID != r.OrgID || v.OriginatorUserID != r.ActorID || v.BeneficiaryAddress != r.BeneficiaryAddress || v.Currency != s.config.Currency || v.AmountFiat < r.AmountFiat {
		return nil
	}
	token := "native"
	if v.TokenAddress != nil {
		token = *v.TokenAddress
	}
	if token != r.TokenAddress {
		return nil
	}
	return v
}
func (s *scopedCheckStore) PreviewTravelRuleRecord(ctx context.Context, r PreviewRecordRequest) (*TravelRuleRecord, error) {
	s.previewCalls++
	if !r.DecisionAt.Equal(s.at) {
		return nil, fmt.Errorf("wrong decision time")
	}
	if s.boundExists {
		return s.previewBound(r), nil
	}
	if r.Binding.Renewal {
		return nil, nil
	}
	return s.FindUnusedTravelRuleRecord(ctx, r.OrgID, r.ActorID, r.BeneficiaryAddress, r.TokenAddress, r.AmountFiat)
}
func sourceChecker(t *testing.T, s CheckStore) *Checker {
	t.Helper()
	c, e := NewSourceChecker(s, sourceOptions())
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestSourceAuditFailureIsTypedOnEveryDecisionBranch(t *testing.T) {
	for _, name := range []string{"from sanctioned", "to sanctioned", "spender sanctioned", "unknown allowed", "unknown denied", "unknown monitor", "below threshold", "record missing", "record monitor", "record applied", "renewal applied"} {
		t.Run(name, func(t *testing.T) {
			s := newScopedStore()
			s.logErr = errors.New("disk unavailable")
			r := sourceRequest()
			switch name {
			case "from sanctioned":
				s.sanctions = map[string]bool{sourceFrom: true}
			case "to sanctioned":
				s.sanctions = map[string]bool{sourceTo: true}
			case "spender sanctioned":
				s.sanctions = map[string]bool{sourceFrom: true}
				r.To = "0x3333333333333333333333333333333333333333"
				r.Value = "0x0"
				r.Data = "0x23b872dd" + strings.Repeat("0", 24) + sourceTo[2:] + strings.Repeat("0", 24) + strings.Repeat("4", 40) + fmt.Sprintf("%064x", 100)
			case "unknown allowed":
				s.price = nil
				s.config.UnknownPricePolicy = UnknownPriceAllowed
			case "unknown denied":
				s.price = nil
			case "unknown monitor":
				s.price = nil
				s.config.EnforcementMode = EnforcementMonitor
			case "below threshold":
				s.config.ThresholdFiat = 101
			case "record monitor":
				s.config.EnforcementMode = EnforcementMonitor
			case "record applied":
				s.record = &TravelRuleRecord{ID: "r", ExpiresAt: s.at.Add(time.Hour)}
			case "renewal applied":
				s.boundExists = true
				s.bound = &TravelRuleRecord{ID: "bound", OrgID: sourceOrg, OriginatorUserID: r.UserID, BeneficiaryAddress: sourceTo, AmountFiat: 100, Currency: "eur", ExpiresAt: s.at.Add(-time.Hour)}
				r.Transaction = TransactionBinding{ChainID: 1, DeploymentID: "d", Hash: "0xabc", Renewal: true}
			}
			result, e := sourceChecker(t, s).Check(t.Context(), r)
			var typed *AuditUnavailableError
			if result != nil || !errors.Is(e, ErrAuditUnavailable) || !errors.As(e, &typed) || s.logCalls != 1 {
				t.Fatal("audit failure not typed/nil", result, e, s.logCalls)
			}
		})
	}
}

func TestSourceScopeConfigAndPriceSnapshots(t *testing.T) {
	for _, change := range []func(*scopedCheckStore, *CheckRequest){func(s *scopedCheckStore, r *CheckRequest) { r.UserID = sourceActor(2) }, func(s *scopedCheckStore, r *CheckRequest) { r.OrgID = "other" }, func(s *scopedCheckStore, r *CheckRequest) { s.config = nil }, func(s *scopedCheckStore, r *CheckRequest) { s.config.Currency = "usd" }, func(s *scopedCheckStore, r *CheckRequest) { s.config.EnforcementMode = "" }} {
		s := newScopedStore()
		r := sourceRequest()
		r.Value = "0x0"
		change(s, r)
		if result, e := sourceChecker(t, s).Check(t.Context(), r); e == nil || result != nil || s.logCalls != 0 || s.claimCalls != 0 {
			t.Fatal("scope/config bypassed early no-transfer")
		}
	}
	s := newScopedStore()
	s.config.ThresholdFiat = 101
	c := sourceChecker(t, s)
	c.SetDefaultEnforcementMode(EnforcementMonitor)
	result, e := c.Check(t.Context(), sourceRequest())
	if e != nil || !result.Allowed || s.configCalls != 1 {
		t.Fatal("source config read more than once", result, e, s.configCalls)
	}
	for _, system := range []bool{false, true} {
		s := newScopedStore()
		s.price.PriceFiat = 1
		s.price.PricesByCurrency = map[string]float64{"usd": 1}
		if system {
			id := "native-quote"
			s.price.CoingeckoID = &id
			s.quote = &SystemTokenPrice{PriceFiat: 1, PricesByCurrency: map[string]float64{"usd": 1}, UpdatedAt: s.at}
		}
		if result, e := sourceChecker(t, s).Check(t.Context(), sourceRequest()); e != nil || result.Allowed {
			t.Fatal("scalar USD fallback filled missing EUR", result, e)
		}
	}
	for _, offset := range []time.Duration{-10 * time.Minute, -10*time.Minute - time.Nanosecond, time.Nanosecond} {
		s := newScopedStore()
		s.config.ThresholdFiat = 101
		id := "quote"
		s.price.CoingeckoID = &id
		s.quote = &SystemTokenPrice{PricesByCurrency: map[string]float64{"eur": 100}, UpdatedAt: s.at.Add(offset)}
		result, e := sourceChecker(t, s).Check(t.Context(), sourceRequest())
		want := offset == -10*time.Minute
		if e != nil || result.Allowed != want {
			t.Fatal("fixed decision-time boundary", offset, result, e)
		}
	}
}

func TestSourcePreviewIsReadonlyAndBoundRecordCoverageMatters(t *testing.T) {
	for _, name := range []string{"bound expired", "bound mismatch", "unbound", "renewal no bound"} {
		t.Run(name, func(t *testing.T) {
			s := newScopedStore()
			r := sourceRequest()
			r.Transaction = TransactionBinding{ChainID: 1, DeploymentID: "d", Hash: "0xabc"}
			s.record = &TravelRuleRecord{ID: "unused", ExpiresAt: s.at.Add(time.Hour)}
			s.boundExists = true
			s.bound = &TravelRuleRecord{ID: "bound", OrgID: sourceOrg, OriginatorUserID: r.UserID, BeneficiaryAddress: sourceTo, AmountFiat: 100, Currency: "eur", ExpiresAt: s.at.Add(-time.Hour)}
			usedAt := s.at.Add(-2 * time.Hour)
			s.bound.UsedAt = &usedAt
			switch name {
			case "bound mismatch":
				s.bound.Currency = "usd"
			case "unbound":
				s.boundExists = false
			case "renewal no bound":
				s.boundExists = false
				r.Transaction.Renewal = true
			}
			result, e := sourceChecker(t, s).CheckPreview(t.Context(), r)
			want := name == "bound expired" || name == "unbound"
			if e != nil || result.Allowed != want || s.claimCalls+s.txClaims+s.boundCalls+s.logCalls != 0 || s.used || s.previewCalls != 1 {
				t.Fatal("preview consumed or lost binding", result, e)
			}
			if name != "unbound" && s.findCalls != 0 {
				t.Fatal("mismatched/renewal binding borrowed unused")
			}
		})
	}
}

type checkStoreOnly struct{ CheckStore }

func TestSourceConstructorAndReadonlyCapabilityAreExplicit(t *testing.T) {
	s := newScopedStore()
	for _, change := range []func(*SourceCheckOptions){func(o *SourceCheckOptions) { o.ActorID = "legacy-user" }, func(o *SourceCheckOptions) { o.OrganizationID = "" }, func(o *SourceCheckOptions) { o.Currency = "" }, func(o *SourceCheckOptions) { o.DecisionAt = time.Time{} }, func(o *SourceCheckOptions) { o.PriceMaxAge = 25 * time.Hour }} {
		o := sourceOptions()
		change(&o)
		if _, e := NewSourceChecker(s, o); e == nil {
			t.Fatal("invalid source scope accepted")
		}
	}
	c, e := NewSourceChecker(checkStoreOnly{s}, sourceOptions())
	if e != nil {
		t.Fatal(e)
	}
	if result, e := c.CheckPreview(t.Context(), sourceRequest()); result != nil || !errors.Is(e, ErrSourcePreviewUnsupported) {
		t.Fatal("missing readonly capability borrowed consuming store", result, e)
	}
}

func TestSourceParallelCurrencyScopesAndCallerOwnedRollback(t *testing.T) {
	var wg sync.WaitGroup
	for i, currency := range []string{"eur", "chf"} {
		wg.Add(1)
		go func(i int, currency string) {
			defer wg.Done()
			s := newScopedStore()
			s.config.Currency = currency
			s.price.PricesByCurrency = map[string]float64{currency: 100}
			s.config.ThresholdFiat = 101
			o := sourceOptions()
			o.ActorID = sourceActor(byte(i + 1))
			o.Currency = currency
			c, e := NewSourceChecker(s, o)
			if e != nil {
				t.Error(e)
				return
			}
			r := sourceRequest()
			r.UserID = o.ActorID
			result, e := c.Check(t.Context(), r)
			if e != nil || !result.Allowed {
				t.Error("scope leak", e)
			}
		}(i, currency)
	}
	wg.Wait()
	// The operational caller owns a transaction: shared Checker does not make
	// a record claim and audit write atomic by itself.
	parent := newScopedStore()
	parent.record = &TravelRuleRecord{ID: "r", ExpiresAt: parent.at.Add(time.Hour)}
	parent.logErr = errors.New("audit down")
	claimedInChild := false
	commits := 0
	transaction := func() error {
		child := *parent
		_, e := sourceChecker(t, &child).Check(t.Context(), sourceRequest())
		claimedInChild = child.used
		if e == nil {
			*parent = child
			commits++
		}
		return e
	}
	if e := transaction(); !errors.Is(e, ErrAuditUnavailable) || !claimedInChild || parent.used || commits != 0 {
		t.Fatal("typed failure did not roll back caller transaction", e)
	}
	parent.logErr = nil
	if e := transaction(); e != nil || !parent.used || commits != 1 {
		t.Fatal("valid caller transaction did not commit", e)
	}
}
