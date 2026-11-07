// Package quotefeed polls one approved price feed into immutable in-memory
// observations. Financial decisions remain in the existing compliance checker.
package quotefeed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/pricefeedpolicy"
)

const CycleTimeout = 10 * time.Second

var (
	ErrInvalid  = errors.New("invalid price feed binding")
	ErrResponse = errors.New("invalid price feed response")
	ErrClosed   = errors.New("price feed closed")
)

type CredentialBinding struct{ FromEnv, Header, Value string }
type Config struct {
	Source            pricefeedpolicy.Definition
	Plan              pricefeedpolicy.Plan
	Clock             identity.Clock
	Transport         http.RoundTripper
	CredentialBinding CredentialBinding
	AllowPrivate      bool
}
type Metadata struct {
	SourceDigest, PlanDigest, ComplianceDigest string
	IDs, Currencies, Requests                  int
	RefreshIntervalSeconds                     int64
}
type Service struct {
	metadata        Metadata
	clock           identity.Clock
	requests        []pricefeedpolicy.Request
	currencies      []string
	client          *http.Client
	header, value   string
	interval        time.Duration
	snapshot        atomic.Pointer[admission.QuoteSnapshot]
	mu              sync.Mutex
	started, closed bool
	cancel          context.CancelFunc
	done            chan struct{}
	ownedTransport  *http.Transport
}

var _ admission.QuoteProvider = (*Service)(nil)

func New(c Config) (*Service, error) {
	if !c.Source.Valid() || !c.Plan.Valid() || c.Source.Digest() != c.Plan.SourceDigest() || c.Clock == nil {
		return nil, ErrInvalid
	}
	source := c.Source.Source()
	requests := c.Plan.Requests()
	currencies := c.Plan.Currencies()
	if len(requests) == 0 || len(c.Plan.IDs()) == 0 || len(currencies) == 0 {
		return nil, ErrInvalid
	}
	if source.Credential == nil {
		if c.CredentialBinding != (CredentialBinding{}) {
			return nil, ErrInvalid
		}
	} else if source.Credential.FromEnv != c.CredentialBinding.FromEnv || !headerName(c.CredentialBinding.Header) || !headerValue(c.CredentialBinding.Value) {
		return nil, ErrInvalid
	}
	if err := validateDestination(source.URI, c.AllowPrivate); err != nil {
		return nil, err
	}
	transport := c.Transport
	var owned *http.Transport
	if transport == nil {
		owned = defaultTransport(source.URI, c.AllowPrivate)
		transport = owned
	}
	empty, err := admission.NewQuoteSnapshot(nil)
	if err != nil {
		return nil, ErrInvalid
	}
	s := &Service{metadata: Metadata{c.Source.Digest(), c.Plan.Digest(), c.Plan.CatalogDigest(), len(c.Plan.IDs()), len(currencies), len(requests), source.RefreshIntervalSeconds}, clock: c.Clock, requests: requests, currencies: currencies, client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, header: c.CredentialBinding.Header, value: c.CredentialBinding.Value, interval: time.Duration(source.RefreshIntervalSeconds) * time.Second, done: make(chan struct{}), ownedTransport: owned}
	s.snapshot.Store(&empty)
	return s, nil
}
func (s *Service) Metadata() Metadata { return s.metadata }
func (s *Service) Capture(ctx context.Context) (admission.QuoteSnapshot, error) {
	if ctx.Err() != nil {
		return admission.QuoteSnapshot{}, ctx.Err()
	}
	return *s.snapshot.Load(), nil
}
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.started {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	go func() {
		defer close(s.done)
		for {
			if ctx.Err() != nil {
				return
			}
			s.cycle(ctx)
			timer := time.NewTimer(s.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return nil
}
func (s *Service) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		if s.started {
			s.cancel()
		} else {
			close(s.done)
		}
	}
	done := s.done
	s.mu.Unlock()
	<-done
	if s.ownedTransport != nil {
		s.ownedTransport.CloseIdleConnections()
	}
}
func (s *Service) cycle(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, CycleTimeout)
	defer cancel()
	// One cycle owns this detached set. Failure never changes old timestamps.
	rows := map[string]admission.Quote{}
	for _, q := range s.snapshot.Load().Quotes() {
		rows[q.ID+"/"+q.Currency] = q
	}
	changed := false
	for _, batch := range s.requests {
		if ctx.Err() != nil {
			break
		}
		quotes, err := s.fetch(ctx, batch)
		if err != nil {
			continue
		}
		for _, q := range quotes {
			rows[q.ID+"/"+q.Currency] = q
			changed = true
		}
	}
	if !changed {
		return
	}
	quotes := make([]admission.Quote, 0, len(rows))
	for _, q := range rows {
		quotes = append(quotes, q)
	}
	updated, err := admission.NewQuoteSnapshot(quotes)
	if err == nil {
		s.snapshot.Store(&updated)
	}
}
func (s *Service) fetch(ctx context.Context, batch pricefeedpolicy.Request) ([]admission.Quote, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, batch.URI, nil)
	if err != nil {
		return nil, ErrResponse
	}
	req.Header.Set("Accept", "application/json")
	if s.header != "" {
		req.Header.Set(s.header, s.value)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, ErrResponse
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > MaxBodyBytes {
		return nil, ErrResponse
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil || len(raw) > MaxBodyBytes {
		return nil, ErrResponse
	}
	observed := s.clock().UTC()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return parseBatch(raw, batch.IDs, s.currencies, observed, "price-feed/"+s.metadata.SourceDigest)
}
func headerName(raw string) bool {
	if raw == "" || len(raw) > 128 {
		return false
	}
	for _, c := range []byte(raw) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	// These affect routing/framing rather than provider authentication.
	switch strings.ToLower(raw) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "trailer", "upgrade":
		return false
	}
	return true
}

func headerValue(raw string) bool {
	if raw == "" || len(raw) > 8192 {
		return false
	}
	for _, c := range []byte(raw) {
		if c < 0x20 && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}
