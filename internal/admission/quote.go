package admission

import (
	"context"
	"math"
	"sort"
	"strconv"
	"time"

	"privacy-proxy/internal/compliance"
)

type Quote struct {
	ID           string    `json:"id"`
	Currency     string    `json:"currency"`
	Value        float64   `json:"value"`
	FetchedAt    time.Time `json:"fetchedAt"`
	ProviderAsOf time.Time `json:"providerAsOf"`
	SourceID     string    `json:"sourceId"`
	Digest       Digest    `json:"-"`
}

func (q Quote) Valid() bool {
	return text(q.ID, 100, false) && text(q.SourceID, 128, false) && compliance.IsValidCurrency(q.Currency) && q.Value > 0 && q.Value < 1e12 && !math.IsNaN(q.Value) && !math.IsInf(q.Value, 0) && !q.FetchedAt.IsZero() && !q.ProviderAsOf.IsZero()
}
func (q Quote) Fresh(at time.Time, age time.Duration) bool {
	return q.Valid() && age > 0 && !q.FetchedAt.After(at) && !q.ProviderAsOf.After(at) && at.Sub(q.FetchedAt) <= age && at.Sub(q.ProviderAsOf) <= age
}
func (q Quote) Oldest() time.Time {
	if q.ProviderAsOf.Before(q.FetchedAt) {
		return q.ProviderAsOf
	}
	return q.FetchedAt
}
func quoteDigest(q Quote) Digest {
	return HashParts("ops-price-quote/v1", []byte(q.ID), []byte(q.Currency), []byte(strconv.FormatFloat(q.Value, 'g', -1, 64)), []byte(q.FetchedAt.UTC().Format(time.RFC3339Nano)), []byte(q.ProviderAsOf.UTC().Format(time.RFC3339Nano)), []byte(q.SourceID))
}

// QuoteSnapshot owns detached immutable observations. Missing and stale entries
// remain unknown; they do not become a fabricated current price or clear result.
type QuoteSnapshot struct {
	quotes map[string]Quote
	valid  bool
}

func NewQuoteSnapshot(quotes []Quote) (QuoteSnapshot, error) {
	if len(quotes) > 20000 {
		return QuoteSnapshot{}, ErrInvalid
	}
	s := QuoteSnapshot{quotes: make(map[string]Quote, len(quotes)), valid: true}
	for _, q := range quotes {
		if !q.Valid() {
			return QuoteSnapshot{}, ErrInvalid
		}
		q.FetchedAt = q.FetchedAt.UTC().Truncate(time.Microsecond)
		q.ProviderAsOf = q.ProviderAsOf.UTC().Truncate(time.Microsecond)
		if !q.Valid() {
			return QuoteSnapshot{}, ErrInvalid
		}
		key := q.ID + "/" + q.Currency
		if _, ok := s.quotes[key]; ok {
			return QuoteSnapshot{}, ErrInvalid
		}
		q.Digest = quoteDigest(q)
		s.quotes[key] = q
	}
	return s, nil
}
func (s QuoteSnapshot) Get(id, currency string) (Quote, bool) {
	q, ok := s.quotes[id+"/"+currency]
	return q, ok && s.valid
}
func (s QuoteSnapshot) Quotes() []Quote {
	out := make([]Quote, 0, len(s.quotes))
	for _, q := range s.quotes {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == out[j].ID {
			return out[i].Currency < out[j].Currency
		}
		return out[i].ID < out[j].ID
	})
	return out
}

type QuoteProvider interface {
	Capture(context.Context) (QuoteSnapshot, error)
}
