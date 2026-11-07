package disclosuredata

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"

	p "privacy-proxy/internal/disclosurepolicy"
)

var ErrNotFound = errors.New("protected data not found")

type page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"nextCursor"`
}
type singleton[T any] struct {
	Item T `json:"item"`
}
type Result struct {
	scope                      ReadScope
	readID                     string
	coverage                   CoverageDTO
	body                       any
	rows                       uint16
	total                      *Count
	sourceDigest, renderDigest Digest
}

func (r Result) ReturnedRows() uint16 { return r.rows }
func (r Result) QualifiedTotal() *Count {
	if r.total == nil {
		return nil
	}
	return ptr(*r.total)
}
func (r Result) SourceSetDigest() Digest { return r.sourceDigest }
func (r Result) RenderDigest() Digest    { return r.renderDigest }

// WithCursor creates a detached output; it cannot modify a sealed source position.
func (r Result) WithCursor(raw string) (Result, error) {
	if len(raw) > 2048 || raw == "" {
		return Result{}, ErrInvalid
	}
	switch body := r.body.(type) {
	case page[AddressDTO]:
		body.NextCursor = ptr(raw)
		r.body = body
	case page[TransactionDTO]:
		body.NextCursor = ptr(raw)
		r.body = body
	case page[ActivityDTO]:
		body.NextCursor = ptr(raw)
		r.body = body
	default:
		return Result{}, ErrInvalid
	}
	return r, nil
}
func envelope[T any](r Result, body T) ([]byte, error) {
	raw, e := json.Marshal(struct {
		Version  uint8       `json:"v"`
		ReadID   string      `json:"readId"`
		CaseID   string      `json:"caseId"`
		Resource p.Resource  `json:"resource"`
		View     View        `json:"view"`
		Level    p.Level     `json:"level"`
		DataTime p.Interval  `json:"dataTime"`
		Until    int64       `json:"effectiveUntil"`
		Coverage CoverageDTO `json:"coverage"`
		Result   T           `json:"result"`
	}{1, r.readID, r.scope.CaseID, r.scope.Query.resource, r.scope.Query.view, r.scope.Query.scope.Level, r.scope.Query.scope.DataTime, r.scope.EffectiveUntil.Unix(), r.coverage, body})
	if e != nil {
		return nil, ErrUnavailable
	}
	if len(raw)+1 > MaxResponseBytes {
		return nil, ErrTooBroad
	}
	return raw, nil
}
func (r Result) MarshalJSON() ([]byte, error) {
	if !uuidValid(r.readID) || !digestValid(r.sourceDigest) || !digestValid(r.renderDigest) {
		return nil, ErrInvalid
	}
	switch body := r.body.(type) {
	case page[AddressDTO]:
		if r.scope.Query.resource == p.AddressHistory && r.scope.Query.view == List {
			return envelope(r, body)
		}
	case singleton[AddressDTO]:
		if r.scope.Query.resource == p.AddressHistory && r.scope.Query.view == Resolve {
			return envelope(r, body)
		}
	case page[TransactionDTO]:
		if r.scope.Query.resource == p.Transactions && r.scope.Query.view == List {
			return envelope(r, body)
		}
	case singleton[TransactionDetailDTO]:
		if r.scope.Query.resource == p.Transactions && r.scope.Query.view == Detail {
			return envelope(r, body)
		}
	case page[ActivityDTO]:
		if r.scope.Query.resource == p.ActivityLogs && r.scope.Query.view == List {
			return envelope(r, body)
		}
	case SummaryDTO:
		if r.scope.Query.resource == p.ActivitySummary && r.scope.Query.view == Report {
			return envelope(r, body)
		}
	case SanctionsDTO:
		if r.scope.Query.resource == p.SanctionsReport && r.scope.Query.view == Report {
			return envelope(r, body)
		}
	case ComplianceDTO:
		if r.scope.Query.resource == p.ComplianceReport && r.scope.Query.view == Report {
			return envelope(r, body)
		}
	}
	return nil, ErrInvalid
}
func ValidateFacts(s ReadScope, ds []SourceDescriptor, f Facts, after *Position) error {
	_, e := validateFacts(s, ds, f, after)
	return e
}
func addressMAC(k Key, domain, caseID, org, recipient string, a [20]byte) []byte {
	h := hmac.New(sha256.New, k.Bytes)
	h.Write(framed([]byte(domain), []byte(k.ID), []byte(caseID), []byte(org), []byte(recipient), a[:]))
	return h.Sum(nil)[:16]
}
func locator(k Key, c RenderContext, a [20]byte) string {
	return "da1." + k.ID + "." + base64.RawURLEncoding.EncodeToString(addressMAC(k, "ops.disclosure.address-id/v1", c.CaseID, c.DataOrganizationID, c.RecipientActorID, a))
}
func locatorMatches(c RenderContext, id string, a [20]byte) bool {
	parts := strings.Split(id, ".")
	if len(parts) != 3 {
		return false
	}
	key := c.Keys.Active
	if parts[1] != key.ID {
		if c.Keys.Previous == nil || parts[1] != c.Keys.Previous.ID {
			return false
		}
		key = *c.Keys.Previous
	}
	got := locator(key, c, a)
	return hmac.Equal([]byte(got), []byte(id))
}
func display(c RenderContext, a [20]byte, external bool) string {
	if c.Query.scope.Level == p.Full {
		return addressString(a)
	}
	if c.Query.scope.Level == p.Redacted {
		return "[PRIVATE]"
	}
	domain := "ops.disclosure.display/v1"
	if external {
		domain = "ops.disclosure.external/v1"
	}
	return "Address-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(addressMAC(c.Keys.Active, domain, c.CaseID, c.DataOrganizationID, c.RecipientActorID, a))
}
func addressDTO(c RenderContext, fc factContext, a AddressFact) AddressDTO {
	out := AddressDTO{AddressID: locator(c.Keys.Active, c, a.Address), Display: display(c, a.Address, false)}
	if c.Query.scope.Level == p.Full {
		out.Address = ptr(addressString(a.Address))
		out.TargetActorIDs = append([]string{}, a.Provenance.TargetActorIDs...)
		if a.ENSName != nil {
			out.ENSName = ptr(*a.ENSName)
		}
	}
	if c.Query.scope.Level != p.Redacted {
		out.IsMine = ptr(fc.mine[a.Address])
	}
	return out
}
func txDTO(c RenderContext, fc factContext, t TransactionFact) TransactionDTO {
	out := TransactionDTO{BlockNumber: t.BlockNumber, TransactionIndex: t.TransactionIndex, BlockTime: t.BlockTime, GasUsed: t.GasUsed, Status: t.Status, Direction: t.Direction, From: display(c, t.From, len(fc.targets[t.From]) == 0)}
	if t.To != nil {
		out.To = ptr(display(c, *t.To, len(fc.targets[*t.To]) == 0))
	}
	if c.Query.scope.Level == p.Full {
		out.TransactionHash = ptr(hashString(t.Hash))
		out.Value = ptr(t.Value)
	}
	return out
}
func summaryDTO(s ActivityAggregate) SummaryDTO {
	out := SummaryDTO{s.Total, s.Successful, s.Failed, []MethodCountDTO{}}
	for _, m := range s.Methods {
		out.MethodBreakdown = append(out.MethodBreakdown, MethodCountDTO{m.Method, m.Total, m.Successful, m.Failed})
	}
	return out
}
func sanctionsDTO(c RenderContext, fc factContext, s SanctionsAggregate) SanctionsDTO {
	out := SanctionsDTO{s.Status, s.ScopedAddressCount, s.SourceDigest, s.CheckedAt.Unix(), []SanctionMatchDTO{}}
	for _, m := range s.Matches {
		a := AddressFact{Address: m.Address, Provenance: Provenance{TargetActorIDs: fc.targets[m.Address]}}
		entry := SanctionMatchDTO{Address: addressDTO(c, fc, a), SourceID: m.SourceID}
		if c.Query.scope.Level == p.Full && m.Reason != "" {
			entry.Reason = ptr(m.Reason)
		}
		out.Matches = append(out.Matches, entry)
	}
	return out
}

// This second preflight charges the expanded projection BEFORE creating aliases,
// repeated actor lists or DTO copies. Source bytes are a conservative baseline.
func emissionBudget(f Facts, fc factContext, c RenderContext) error {
	b := NewBudget()
	if e := valueBudget(reflect.ValueOf(f), b); e != nil {
		return e
	}
	if e := b.AddItems(2); e != nil {
		return e
	}
	if e := b.AddBytes(2048); e != nil {
		return e
	}
	addAddress := func(a [20]byte) error {
		if e := b.AddItems(1); e != nil {
			return e
		}
		if e := b.AddBytes(256); e != nil {
			return e
		}
		if c.Query.scope.Level == p.Full {
			ids := fc.targets[a]
			if e := b.AddItems(uint64(len(ids))); e != nil {
				return e
			}
			for _, id := range ids {
				if e := b.AddBytes(uint64(len(id))); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if c.Query.view == Resolve {
		if e := addAddress([20]byte{}); e != nil {
			return e
		}
	} else {
		for _, a := range f.Addresses {
			if e := addAddress(a.Address); e != nil {
				return e
			}
		}
	}
	for range f.Transactions {
		if e := b.AddBytes(512); e != nil {
			return e
		}
	}
	sanctions := f.Sanctions
	if f.Compliance != nil {
		sanctions = &f.Compliance.Sanctions
	}
	if sanctions != nil {
		for _, m := range sanctions.Matches {
			if e := addAddress(m.Address); e != nil {
				return e
			}
		}
	}
	return nil
}
func Render(s ReadScope, ds []SourceDescriptor, f Facts, c RenderContext, readID string) (Result, error) {
	return render(s, ds, f, c, readID, nil)
}

// afterBudget is a local stage-order spy for package tests, never configuration
// or a provider hook. Public Render always uses the actual serializer.
func render(s ReadScope, ds []SourceDescriptor, f Facts, c RenderContext, readID string, afterBudget func()) (Result, error) {
	var result Result
	if e := CheckFactsBudget(f); e != nil {
		return result, e
	}
	if !digestValid(s.Namespace) || !uuidValid(s.CaseID) || s.CaseVersion < 1 || !actor(s.RecipientActorID) || !uuidValid(s.DataOrganizationID) || !digestValid(s.BundleDigest) || !digestValid(s.RuleDigest) || !uuidValid(readID) || !utc(c.PreparedAt) || !s.EffectiveUntil.After(c.PreparedAt) || c.Namespace != s.Namespace || c.CaseID != s.CaseID || c.DataOrganizationID != s.DataOrganizationID || c.RecipientActorID != s.RecipientActorID || c.Query.digest != s.Query.digest || !c.EffectiveUntil.Equal(s.EffectiveUntil) {
		return result, ErrInvalid
	}
	set, e := SourceSetDigest(ds, s.Query.resource, s.Query.view)
	if e != nil {
		return result, e
	}
	keys, e := cloneKeys(c.Keys)
	if e != nil {
		return result, e
	}
	c.Keys = keys
	// The provider transfers detached immutable facts; copying after the cheap
	// preflight also prevents later reuse of its backing slices from changing output.
	f = cloneValue(reflect.ValueOf(f)).Interface().(Facts)
	fc, e := validateFacts(s, ds, f, nil)
	if e != nil {
		return result, e
	}
	if e := emissionBudget(f, fc, c); e != nil {
		return result, e
	}
	if afterBudget != nil {
		afterBudget()
	}
	rd, e := RenderContextDigest(c)
	if e != nil {
		return result, e
	}
	pops := []string{}
	for _, d := range ds {
		pops = append(pops, d.Population)
	}
	slices.Sort(pops)
	pops = slices.Compact(pops)
	result = Result{scope: s, readID: readID, coverage: CoverageDTO{"COMPLETE_AT_CUT", pops, set, c.PreparedAt.Unix()}, sourceDigest: set, renderDigest: rd}
	switch s.Query.resource {
	case p.AddressHistory:
		if s.Query.view == Resolve {
			var selected *AddressFact
			for i := range f.Addresses {
				if locatorMatches(c, s.Query.addressID, f.Addresses[i].Address) {
					if selected != nil {
						return Result{}, ErrConflict
					}
					selected = &f.Addresses[i]
				}
			}
			if selected == nil {
				return Result{}, ErrNotFound
			}
			result.body = singleton[AddressDTO]{addressDTO(c, fc, *selected)}
			result.rows = 1
		} else {
			body := page[AddressDTO]{Items: []AddressDTO{}}
			for _, a := range f.Addresses {
				body.Items = append(body.Items, addressDTO(c, fc, a))
			}
			result.body = body
			result.rows = uint16(len(body.Items))
		}
	case p.ActivityLogs:
		body := page[ActivityDTO]{Items: []ActivityDTO{}}
		for _, a := range f.Activities {
			item := ActivityDTO{RecordID: a.ID, Method: a.Method, StatusCode: a.StatusCode, Time: a.ObservedAt.Unix()}
			if s.Query.scope.Level == p.Full {
				item.ActorID = ptr(a.Provenance.TargetActorIDs[0])
				if a.TrustedIP != nil {
					item.IPAddress = ptr(*a.TrustedIP)
				}
			}
			body.Items = append(body.Items, item)
		}
		result.body = body
		result.rows = uint16(len(body.Items))
	case p.Transactions:
		if s.Query.view == Detail {
			t := f.Transactions[0]
			_, participants := fc.participants(t)
			matched := false
			for _, a := range participants {
				if locatorMatches(c, s.Query.addressID, a) {
					if matched {
						return Result{}, ErrConflict
					}
					matched = true
				}
			}
			if !matched {
				return Result{}, ErrNotFound
			}
			v := t.Full
			body := TransactionDetailDTO{TransactionDTO: txDTO(c, fc, t), GasPrice: v.EffectiveGasPrice, GasLimit: v.GasLimit, MaxFeePerGas: v.MaxFeePerGas, MaxPriorityFeePerGas: v.MaxPriorityFeePerGas, Nonce: v.Nonce, Type: v.Type, Input: v.Input, Error: v.Error, RevertReason: v.RevertReason}
			if v.ContractAddress != nil {
				body.ContractAddress = ptr(addressString(*v.ContractAddress))
			}
			result.body = singleton[TransactionDetailDTO]{body}
			result.rows = 1
		} else {
			body := page[TransactionDTO]{Items: []TransactionDTO{}}
			for _, t := range f.Transactions {
				body.Items = append(body.Items, txDTO(c, fc, t))
			}
			result.body = body
			result.rows = uint16(len(body.Items))
		}
	case p.ActivitySummary:
		result.body = summaryDTO(*f.ActivitySummary)
		result.rows = 1
		result.total = ptr(f.ActivitySummary.Total)
	case p.SanctionsReport:
		result.body = sanctionsDTO(c, fc, *f.Sanctions)
		result.rows = 1
	case p.ComplianceReport:
		v := f.Compliance
		body := ComplianceDTO{Activity: summaryDTO(v.Activity), Sanctions: sanctionsDTO(c, fc, v.Sanctions), KYC: "not_evaluated", Evidence: []ComplianceEvidenceDTO{}}
		for _, ev := range v.Evidence {
			entry := ComplianceEvidenceDTO{ID: ev.ID, Population: "ADMISSION_DECISION", Time: ev.DecisionAt.Unix(), Kind: ev.Kind, Decision: ev.Decision, Monitored: ev.Monitored, Coverage: ev.Coverage, PolicyDigest: ev.PolicyDigest, QuoteDigest: ev.QuoteDigest}
			if s.Query.scope.Level == p.Full {
				entry.TransactionHash = ptr(hashString(ev.TransactionHash))
				entry.RecordID = ev.RecordID
				if ev.Reason != "" {
					entry.Reason = ptr(ev.Reason)
				}
				if q := ev.Quote; q != nil {
					entry.Quote = &QuoteDTO{q.ID, q.Currency, q.SourceID, q.Value, q.ProviderAsOf.Unix(), q.FetchedAt.Unix(), q.Digest}
				}
			}
			body.Evidence = append(body.Evidence, entry)
		}
		result.body = body
		result.rows = 1
		result.total = ptr(v.Activity.Total)
	default:
		return Result{}, ErrUnsupported
	}
	return result, nil
}
