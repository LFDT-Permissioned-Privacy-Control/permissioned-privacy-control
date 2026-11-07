package admission

import (
	"context"
	"math/big"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
)

type orgRuntime struct {
	policy     compliancepolicy.OrganizationPolicy
	prices     map[string]compliancepolicy.SourceTokenPrice
	thresholds map[string]compliancepolicy.SourceThreshold
	quoteIDs   map[string]bool
}
type requestStore struct {
	service     *Service
	org         *orgRuntime
	scope       Scope
	read        ReadTx
	write       RawTx
	quotes      QuoteSnapshot
	at          time.Time
	used        map[string]Quote
	lastEventID int64
	newRecord   *Record
	anchor      Event
}

var _ compliance.CheckStore = (*requestStore)(nil)
var _ compliance.TransactionClaimer = (*requestStore)(nil)
var _ compliance.SourcePreviewStore = (*requestStore)(nil)

func (r *requestStore) orgMatches(org string) error {
	if org != r.scope.Organization {
		return ErrInvalid
	}
	return nil
}
func (r *requestStore) GetComplianceConfig(_ context.Context, org string) (*compliance.ComplianceConfig, error) {
	if err := r.orgMatches(org); err != nil {
		return nil, err
	}
	s := r.org.policy.Spec.Settings
	return &compliance.ComplianceConfig{OrgID: org, Enabled: s.Enabled, ThresholdFiat: s.ThresholdFiat, Currency: s.Currency, UnknownPricePolicy: compliance.UnknownPricePolicy(s.UnknownPricePolicy), EnforcementMode: compliance.EnforcementMode(s.EnforcementMode)}, nil
}
func (r *requestStore) GetTokenPrice(_ context.Context, org, address string) (*compliance.TokenPrice, error) {
	if err := r.orgMatches(org); err != nil {
		return nil, err
	}
	if address != "native" {
		a, err := ParseAddress(address)
		if err != nil || AddressString(a) != address {
			return nil, ErrInvalid
		}
	}
	p, ok := r.org.prices[address]
	if !ok {
		return nil, nil
	}
	prices := make(map[string]float64, len(p.PricesByCurrency))
	for currency, value := range p.PricesByCurrency {
		prices[currency] = value
	}
	out := &compliance.TokenPrice{ID: p.ID, OrgID: org, TokenAddress: p.TokenAddress, Symbol: p.Symbol, Decimals: p.Decimals, PricesByCurrency: prices}
	if p.CoingeckoID != "" {
		id := p.CoingeckoID
		out.CoingeckoID = &id
	}
	return out, nil
}
func (r *requestStore) GetSystemTokenPrice(_ context.Context, id string) (*compliance.SystemTokenPrice, error) {
	if !r.org.quoteIDs[id] || id == "" {
		return nil, ErrInvalid
	}
	q, found := r.quotes.Get(id, r.org.policy.Spec.Settings.Currency)
	if !found || !q.Fresh(r.at, time.Duration(r.org.policy.PriceMaxAgeSeconds)*time.Second) {
		return nil, nil
	}
	r.used[id] = q
	return &compliance.SystemTokenPrice{CoingeckoID: &id, Decimals: 18, PricesByCurrency: map[string]float64{q.Currency: q.Value}, UpdatedAt: q.Oldest(), Source: q.SourceID}, nil
}
func (r *requestStore) GetAddressThresholdOverride(_ context.Context, org, address string) (*compliance.AddressThresholdOverride, error) {
	if err := r.orgMatches(org); err != nil {
		return nil, err
	}
	a, err := ParseAddress(address)
	if err != nil || AddressString(a) != address {
		return nil, ErrInvalid
	}
	row, ok := r.org.thresholds[address]
	if !ok {
		return nil, nil
	}
	return &compliance.AddressThresholdOverride{ID: row.ID, OrgID: org, Address: address, ThresholdFiat: row.ThresholdFiat, Note: row.Note}, nil
}
func (r *requestStore) IsAddressSanctioned(_ context.Context, org, address string) (bool, error) {
	if err := r.orgMatches(org); err != nil {
		return false, err
	}
	a, err := ParseAddress(address)
	if err != nil {
		return false, err
	}
	return r.service.catalog.IsSanctioned(org, AddressString(a)), nil
}
func (r *requestStore) GetSystemSetting(context.Context, string) (string, error) {
	return "", ErrInvalid
}
func (r *requestStore) transferQuery(org, actor, beneficiary, token string, amount float64) (TransferQuery, error) {
	if org != r.scope.Organization || actor != r.scope.Actor {
		return TransferQuery{}, ErrInvalid
	}
	a, err := ParseAddress(beneficiary)
	if err != nil || AddressString(a) != beneficiary {
		return TransferQuery{}, ErrInvalid
	}
	if _, err := CanonicalFiat(amount); err != nil {
		return TransferQuery{}, err
	}
	q := TransferQuery{Beneficiary: a, AmountFiat: amount, Currency: r.org.policy.Spec.Settings.Currency, RecordMaxSeconds: r.org.policy.RecordMaxSeconds}
	if token != "native" {
		a, err := ParseAddress(token)
		if err != nil || AddressString(a) != token {
			return TransferQuery{}, ErrInvalid
		}
		q.Token = &a
	}
	return q, nil
}
func legacyRecord(record Record) *compliance.TravelRuleRecord {
	var token *string
	if record.Token != nil {
		s := AddressString(*record.Token)
		token = &s
	}
	var hash *string
	if record.UsedHash != nil {
		s := record.UsedHash.Hex()
		hash = &s
	}
	return &compliance.TravelRuleRecord{ID: record.ID, OrgID: record.Organization, OriginatorUserID: record.Actor, TransferType: record.TransferType, TokenAddress: token, BeneficiaryAddress: AddressString(record.Beneficiary), AmountWei: record.AmountWei, AmountFiat: record.AmountFiat, Currency: record.Currency, ExpiresAt: record.ExpiresAt, UsedAt: record.UsedAt, UsedTxHash: hash, CreatedAt: record.CreatedAt}
}
func (r *requestStore) find(q TransferQuery, boundOnly, claim bool) (*compliance.TravelRuleRecord, error) {
	record, binding, err := r.read.BoundRecord(q)
	if err != nil {
		return nil, err
	}
	if binding {
		if record.ID == "" || !q.Covers(record) {
			return nil, nil
		}
		if !r.sameRecordScope(record) || !record.ValidMetadata() || record.UsedHash == nil || *record.UsedHash != r.scope.Hash {
			return nil, ErrCoverage
		}
		return legacyRecord(record), nil
	}
	if boundOnly {
		return nil, nil
	}
	var found bool
	if claim {
		if r.write == nil {
			return nil, ErrInvalid
		}
		record, found, err = r.write.ClaimUnused(q, r.service.clock().UTC())
		if err == nil && found {
			copied := record
			r.newRecord = &copied
		}
	} else {
		record, found, err = r.read.FindUnused(q, r.at)
	}
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if !r.sameRecordScope(record) || !record.ValidMetadata() || !q.Covers(record) {
		return nil, ErrCoverage
	}
	return legacyRecord(record), nil
}
func (r *requestStore) sameRecordScope(record Record) bool {
	return record.Network == r.scope.Network && record.Organization == r.scope.Organization && record.Actor == r.scope.Actor
}
func (r *requestStore) FindUnusedTravelRuleRecord(_ context.Context, org, actor, beneficiary, token string, amount float64) (*compliance.TravelRuleRecord, error) {
	q, err := r.transferQuery(org, actor, beneficiary, token, amount)
	if err != nil {
		return nil, err
	}
	return r.find(q, false, false)
}
func (r *requestStore) ClaimUnusedTravelRuleRecord(context.Context, string, string, string, string, float64) (*compliance.TravelRuleRecord, error) {
	return nil, ErrInvalid
}
func (r *requestStore) transaction(chain uint64, deployment, hash string) error {
	if strconv.FormatUint(chain, 10) != r.service.network.ChainID || deployment != r.service.network.DeploymentID || hash != r.scope.Hash.Hex() {
		return ErrInvalid
	}
	return nil
}
func (r *requestStore) ClaimTravelRuleRecordForTx(_ context.Context, chain uint64, deployment, hash, org, actor, beneficiary, token string, amount float64) (*compliance.TravelRuleRecord, error) {
	if err := r.transaction(chain, deployment, hash); err != nil {
		return nil, err
	}
	q, err := r.transferQuery(org, actor, beneficiary, token, amount)
	if err != nil {
		return nil, err
	}
	return r.find(q, false, true)
}
func (r *requestStore) BoundTravelRuleRecordForTx(_ context.Context, chain uint64, deployment, hash, org, actor, beneficiary, token string, amount float64) (*compliance.TravelRuleRecord, error) {
	if err := r.transaction(chain, deployment, hash); err != nil {
		return nil, err
	}
	q, err := r.transferQuery(org, actor, beneficiary, token, amount)
	if err != nil {
		return nil, err
	}
	return r.find(q, true, false)
}
func (r *requestStore) PreviewTravelRuleRecord(_ context.Context, q compliance.PreviewRecordRequest) (*compliance.TravelRuleRecord, error) {
	if err := r.transaction(q.Binding.ChainID, q.Binding.DeploymentID, q.Binding.Hash); err != nil {
		return nil, err
	}
	if !q.DecisionAt.Equal(r.at) {
		return nil, ErrInvalid
	}
	query, err := r.transferQuery(q.OrgID, q.ActorID, q.BeneficiaryAddress, q.TokenAddress, q.AmountFiat)
	if err != nil {
		return nil, err
	}
	return r.find(query, q.Binding.Renewal, false)
}
func (r *requestStore) CreateComplianceLog(_ context.Context, entry *compliance.ComplianceLog) (int64, error) {
	if r.write == nil || entry == nil || entry.OrgID != r.scope.Organization || entry.UserID != r.scope.Actor || entry.Currency != r.org.policy.Spec.Settings.Currency || r.lastEventID != 0 {
		return 0, ErrInvalid
	}
	from, err := ParseAddress(entry.FromAddress)
	if err != nil {
		return 0, err
	}
	to, err := ParseAddress(entry.ToAddress)
	if err != nil {
		return 0, err
	}
	if _, err := ParseUint256(entry.AmountWei, false); err != nil {
		return 0, err
	}
	if entry.Decision != "allowed" && entry.Decision != "denied" {
		return 0, ErrInvalid
	}
	e := r.anchor
	e.Scope = r.scope
	e.Kind = "root_native"
	if entry.TransferType == compliance.TransferTypeERC20 {
		e.Kind = "root_erc20"
	} else if entry.TransferType != compliance.TransferTypeETH {
		return 0, ErrInvalid
	}
	e.Coverage = "root_transfer"
	e.From = &from
	e.To = &to
	e.AmountWei = &entry.AmountWei
	e.AmountFiat = entry.AmountFiat
	e.Threshold = entry.ThresholdFiat
	e.Currency = &entry.Currency
	e.Decision = entry.Decision
	e.Monitored = entry.WouldBlock
	e.RecordID = entry.TravelRuleRecordID
	e.DecisionAt = r.at
	e.PolicyDigest = r.service.complianceDigest
	if entry.TokenAddress != nil {
		a, err := ParseAddress(*entry.TokenAddress)
		if err != nil {
			return 0, err
		}
		e.Token = &a
	}
	if entry.DenialReason != nil {
		e.Reason = *entry.DenialReason
	}
	if !text(e.Reason, 2048, true) {
		return 0, ErrInvalid
	}
	for _, n := range []*float64{e.AmountFiat, e.Threshold} {
		if n != nil {
			if _, err := CanonicalFiat(*n); err != nil {
				return 0, err
			}
		}
	}
	// Only positively valued decisions use a quote. Unknown-price/monitor
	// paths must not acquire an expiry gate for an unusable observation.
	if e.AmountFiat != nil {
		for _, q := range r.used {
			q := q
			e.Quote = &q
			break
		}
	} else {
		r.used = map[string]Quote{}
	}
	id, err := r.write.AppendEvent(e)
	if err != nil {
		return 0, err
	}
	if id <= 0 {
		return 0, ErrUnavailable
	}
	r.lastEventID = id
	return id, nil
}

func (r *requestStore) checkRequest(txHash string, from, to, input, value string, renewal bool) *compliance.CheckRequest {
	chain, _ := new(big.Int).SetString(r.service.network.ChainID, 10)
	return &compliance.CheckRequest{OrgID: r.scope.Organization, UserID: r.scope.Actor, From: strings.ToLower(from), To: strings.ToLower(to), Data: input, Value: value, Transaction: compliance.TransactionBinding{ChainID: chain.Uint64(), DeploymentID: r.service.network.DeploymentID, Hash: txHash, Renewal: renewal}}
}
