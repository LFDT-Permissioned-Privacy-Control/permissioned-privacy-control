package admission

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/runtimepolicy"
)

type Response struct {
	body []byte
	gate func() error
}

func (r *Response) WriteTo(w io.Writer) (int64, error) {
	if err := r.gate(); err != nil {
		return 0, err
	}
	n, err := w.Write(r.body)
	return int64(n), err
}
func response(value any, gate func() error) (*Response, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > MaxResponseBytes {
		return nil, ErrUnavailable
	}
	return &Response{append(raw, '\n'), gate}, nil
}
func (s *Service) admin(v *runtimepolicy.View, org string, write bool) error {
	if err := s.checkView(v, org); err != nil {
		return err
	}
	o, _ := v.Org(org)
	if o.IsOrgAdmin() || (!write && o.IsOrgReadonlyAdmin()) {
		return nil
	}
	return ErrForbidden
}
func (s *Service) adminView(token, org string, write bool) (*runtimepolicy.View, error) {
	v, err := s.view(token)
	if err != nil {
		return nil, err
	}
	if err := s.admin(v, org, write); err != nil {
		return nil, err
	}
	return v, nil
}
func (s *Service) SelectedPolicy(ctx context.Context, token, org, section string) (*Response, error) {
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	v, err := s.adminView(token, org, false)
	if err != nil {
		return nil, err
	}
	policy, ok := s.catalog.OrgPolicy(org)
	if !ok {
		return nil, ErrNotFound
	}
	var data any
	switch section {
	case "config":
		data = policy
	case "tokens":
		data = policy.Spec.TokenPrices
	case "address-thresholds":
		data = policy.Spec.AddressThresholds
	case "sanctions":
		rows := []compliancepolicy.SourceSanction{}
		for _, row := range s.catalog.Sanctions() {
			if row.Scope == "global" || row.OrganizationID == org {
				rows = append(rows, row)
			}
		}
		data = rows
	case "quotes":
		snapshot, err := s.captureQuotes(ctx)
		if err != nil {
			return nil, err
		}
		rows := []Quote{}
		for _, q := range snapshot.Quotes() {
			if s.orgs[org].quoteIDs[q.ID] && q.Currency == policy.Spec.Settings.Currency {
				rows = append(rows, q)
			}
		}
		data = rows
	default:
		return nil, ErrInvalid
	}
	return response(struct {
		SourceDigest string `json:"sourceDigest"`
		Data         any    `json:"data"`
	}{s.complianceDigest.String(), data}, func() error { return s.admin(v, org, false) })
}

type CreateRecordRequest struct {
	OriginatorActorID  string                  `json:"originatorActorId"`
	OriginatorData     json.RawMessage         `json:"originatorData"`
	BeneficiaryData    json.RawMessage         `json:"beneficiaryData"`
	TransferType       compliance.TransferType `json:"transferType"`
	TokenAddress       string                  `json:"tokenAddress" optional:"true"`
	BeneficiaryAddress string                  `json:"beneficiaryAddress"`
	AmountWei          string                  `json:"amountWei"`
}
type RecordDTO struct {
	ID                 string                  `json:"id"`
	OrganizationID     string                  `json:"organizationId"`
	OriginatorActorID  string                  `json:"originatorActorId"`
	OriginatorData     json.RawMessage         `json:"originatorData,omitempty"`
	BeneficiaryData    json.RawMessage         `json:"beneficiaryData,omitempty"`
	TransferType       compliance.TransferType `json:"transferType"`
	TokenAddress       string                  `json:"tokenAddress"`
	BeneficiaryAddress string                  `json:"beneficiaryAddress"`
	AmountWei          string                  `json:"amountWei"`
	AmountFiat         float64                 `json:"amountFiat"`
	Currency           string                  `json:"currency"`
	CreatedAt          time.Time               `json:"createdAt"`
	ExpiresAt          time.Time               `json:"expiresAt"`
	UsedAt             *time.Time              `json:"usedAt,omitempty"`
	UsedTxHash         string                  `json:"usedTxHash,omitempty"`
}

func recordDTO(record Record, pii bool) RecordDTO {
	token := ""
	if record.Token != nil {
		token = AddressString(*record.Token)
	}
	out := RecordDTO{ID: record.ID, OrganizationID: record.Organization, OriginatorActorID: record.Actor, TransferType: record.TransferType, TokenAddress: token, BeneficiaryAddress: AddressString(record.Beneficiary), AmountWei: record.AmountWei, AmountFiat: record.AmountFiat, Currency: record.Currency, CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, UsedAt: record.UsedAt}
	if record.UsedHash != nil {
		out.UsedTxHash = record.UsedHash.Hex()
	}
	if pii {
		out.OriginatorData = record.OriginatorData
		out.BeneficiaryData = record.BeneficiaryData
	}
	return out
}
func (s *Service) CreateRecord(ctx context.Context, token, org string, req CreateRecordRequest) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.adminView(token, org, true)
	if err != nil {
		return nil, err
	}
	if !validActor(req.OriginatorActorID) {
		return nil, ErrInvalid
	}
	amount, err := ParseUint256(req.AmountWei, true)
	if err != nil {
		return nil, err
	}
	beneficiary, err := ParseAddress(req.BeneficiaryAddress)
	if err != nil {
		return nil, err
	}
	originator, err := NormalizePII(req.OriginatorData)
	if err != nil {
		return nil, err
	}
	beneficiaryData, err := NormalizePII(req.BeneficiaryData)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, ErrUnavailable
	}
	r := Record{ID: id.String(), Network: s.networkKey, Organization: org, Actor: req.OriginatorActorID, OriginatorData: originator, BeneficiaryData: beneficiaryData, TransferType: req.TransferType, Beneficiary: beneficiary, AmountWei: req.AmountWei, Currency: s.orgs[org].policy.Spec.Settings.Currency, CreatedBy: v.ActorID(), PolicyDigest: s.complianceDigest}
	tokenAddress := "native"
	if req.TransferType == compliance.TransferTypeERC20 {
		address, err := ParseAddress(req.TokenAddress)
		if err != nil {
			return nil, err
		}
		r.Token = &address
		tokenAddress = AddressString(address)
	} else if req.TransferType != compliance.TransferTypeETH || req.TokenAddress != "" {
		return nil, ErrInvalid
	}
	quotes, err := s.captureQuotes(ctx)
	if err != nil {
		return nil, err
	}
	used := map[string]Quote{}
	var decisionAt time.Time
	stored, err := s.store.CreateRecord(ctx, s.networkKey, s.state, r, func(row *Record) error {
		if err := s.admin(v, org, true); err != nil {
			return err
		}
		if !row.CreatedAt.IsZero() {
			return s.checkTime(v, org, decisionAt, used, nil)
		}
		decisionAt = s.clock().UTC().Truncate(time.Microsecond)
		request := s.newRequestStore(Scope{Network: s.networkKey, State: s.state, Organization: org, Actor: req.OriginatorActorID}, decisionAt, quotes, nil, nil)
		price, decimals, quote, err := request.recordPrice(tokenAddress)
		if err != nil {
			return err
		}
		fiat, err := compliance.WeiToFiat(amount, decimals, price)
		if err != nil || fiat <= 0 {
			return ErrValuation
		}
		if _, err := CanonicalFiat(fiat); err != nil {
			return err
		}
		row.AmountFiat = fiat
		row.CreatedAt = decisionAt
		row.ExpiresAt = decisionAt.Add(time.Duration(request.org.policy.RecordMaxSeconds) * time.Second)
		if quote != nil {
			row.QuoteDigest = quote.Digest
			used[quote.ID] = *quote
		}
		return s.checkTime(v, org, decisionAt, used, nil)
	})
	if err != nil {
		return nil, err
	}
	if !stored.Valid() {
		return nil, ErrUnavailable
	}
	return response(recordDTO(stored, true), func() error { return s.admin(v, org, true) })
}
func (r *requestStore) recordPrice(token string) (float64, int, *Quote, error) {
	price, ok := r.org.prices[token]
	id := ""
	decimals := 18
	if ok {
		decimals = price.Decimals
		if price.CoingeckoID != "" {
			id = price.CoingeckoID
		} else {
			v := price.PricesByCurrency[r.org.policy.Spec.Settings.Currency]
			if v <= 0 {
				return 0, 0, nil, ErrValuation
			}
			return v, decimals, nil, nil
		}
	} else if token == "native" {
		id = "ethereum"
	} else {
		return 0, 0, nil, ErrValuation
	}
	q, ok := r.quotes.Get(id, r.org.policy.Spec.Settings.Currency)
	if !ok || !q.Fresh(r.at, time.Duration(r.org.policy.PriceMaxAgeSeconds)*time.Second) {
		return 0, 0, nil, ErrValuation
	}
	return q.Value, decimals, &q, nil
}
func (s *Service) GetRecord(ctx context.Context, token, org, id string) (*Response, error) {
	v, err := s.adminView(token, org, false)
	if err != nil {
		return nil, err
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	record, err := s.store.GetRecord(ctx, s.networkKey, s.state, org, id)
	if err != nil {
		return nil, err
	}
	if record.Organization != org || record.Network != s.networkKey || !record.Valid() {
		return nil, ErrUnavailable
	}
	return response(recordDTO(record, true), func() error { return s.admin(v, org, false) })
}
func (s *Service) DeleteUnused(ctx context.Context, token, org, id string) (*Response, error) {
	v, err := s.adminView(token, org, true)
	if err != nil {
		return nil, err
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	found, err := s.store.DeleteUnused(ctx, s.networkKey, s.state, org, id, func() error { return s.admin(v, org, true) })
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return response(struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}{id, "deleted"}, func() error { return s.admin(v, org, true) })
}

type ListOptions struct {
	Limit  int
	Cursor string
}

func (s *Service) page(v *runtimepolicy.View, org, purpose string, opts ListOptions) (int, pageCursor, error) {
	if opts.Limit == 0 {
		opts.Limit = 50
	}
	if opts.Limit < 1 || opts.Limit > 100 || s.cursors == nil {
		return 0, pageCursor{}, ErrInvalid
	}
	c := pageCursor{Version: 1, Purpose: purpose, Network: s.networkKey.String(), Generation: s.state.Generation, Coverage: s.state.Coverage.String(), Org: org, Viewer: v.ActorID(), Manifest: s.manifestDigest.String(), Query: strconv.Itoa(opts.Limit)}
	if opts.Cursor != "" {
		opened, err := s.cursors.open(opts.Cursor, c, s.clock())
		return opts.Limit, opened, err
	}
	return opts.Limit, c, nil
}
func (s *Service) nextCursor(v *runtimepolicy.View, c pageCursor, position Position) (string, error) {
	c.At = position.At
	c.ID = position.ID
	expires := s.clock().Add(15 * time.Minute)
	if v.ExpiresAt().Before(expires) {
		expires = v.ExpiresAt()
	}
	c.Expires = expires.Unix()
	return s.cursors.seal(c)
}
func (s *Service) ListRecords(ctx context.Context, token, org string, opts ListOptions) (*Response, error) {
	v, err := s.adminView(token, org, false)
	if err != nil {
		return nil, err
	}
	limit, cursor, err := s.page(v, org, "records", opts)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.ListRecords(ctx, s.networkKey, s.state, org, Position{cursor.At, cursor.ID}, limit+1)
	if err != nil {
		return nil, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]RecordDTO, 0, len(rows))
	for _, row := range rows {
		if !row.ValidMetadata() || row.Organization != org || row.Network != s.networkKey {
			return nil, ErrUnavailable
		}
		out = append(out, recordDTO(row, false))
	}
	next := ""
	if more && len(rows) > 0 {
		last := rows[len(rows)-1]
		next, err = s.nextCursor(v, cursor, Position{last.CreatedAt, last.ID})
		if err != nil {
			return nil, err
		}
	}
	return response(struct {
		Records    []RecordDTO `json:"records"`
		NextCursor string      `json:"nextCursor,omitempty"`
	}{out, next}, func() error { return s.admin(v, org, false) })
}
