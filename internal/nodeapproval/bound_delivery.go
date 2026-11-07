package nodeapproval

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const MaxBoundEnvelopeBytes = 34 << 20
const MaxBoundRetain = 1_000_000
const MaxBoundTargets = 32

type DeliveryOptions struct {
	Targets                []string
	Timeout                time.Duration
	MaxInFlight, RetainMax int
}

type BoundDeliveryOptions struct {
	BoundPreflightOptions
	Seed     []byte
	KeyID    string
	TTL      time.Duration
	MaxBatch int
	Delivery DeliveryOptions
}

// ValidateBoundDelivery checks the finite trusted startup settings without
// opening a connection or starting a signer. A zero TTL selects the V1 default.
func ValidateBoundDelivery(o BoundDeliveryOptions) error {
	_, _, err := boundDeliveryConfig(o)
	return err
}

func boundDeliveryConfig(o BoundDeliveryOptions) (deliveryConfig, time.Duration, error) {
	bad := func() (deliveryConfig, time.Duration, error) {
		return deliveryConfig{}, 0, errors.New("invalid bound delivery configuration")
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = DefaultApprovalTTL
	}
	d := o.Delivery
	if len(o.Seed) != ed25519.SeedSize || !ValidKeyID(o.KeyID) || ttl < MinApprovalTTL || ttl > MaxApprovalTTL || o.MaxBatch < 1 || o.MaxBatch > MaxBatchApprovals || len(d.Targets) == 0 || len(d.Targets) > MaxBoundTargets || d.Timeout < time.Millisecond || d.Timeout > maxDeliveryTimeout || d.MaxInFlight < 1 || d.MaxInFlight > maxInFlightLimit || d.RetainMax < MaxBatchApprovals || d.RetainMax > MaxBoundRetain {
		return bad()
	}
	for _, target := range d.Targets {
		if strings.Contains(target, ",") {
			return bad()
		}
	}
	targets, err := parseTargets(strings.Join(d.Targets, ","))
	if err != nil {
		return bad()
	}
	return deliveryConfig{targets: targets, timeout: d.Timeout, maxInFlight: d.MaxInFlight, retainMax: d.RetainMax, statusEvery: statusEvery, readyWindow: readyWindow, drain: drainTimeout}, ttl, nil
}

// NewBoundDelivery reads no environment settings and uses the existing Guard1
// signer, retention and producer lanes. The response cap precedes RPC decoding.
func NewBoundDelivery(o BoundDeliveryOptions) (*Service, error) {
	cfg, ttl, err := boundDeliveryConfig(o)
	if err != nil {
		return nil, err
	}
	if o.Transport == nil {
		return nil, errors.New("invalid bound delivery configuration")
	}
	o.BoundPreflightOptions.Transport = envelopeTransport{base: o.Transport}
	s, err := NewBoundPreflight(o.BoundPreflightOptions)
	if err != nil {
		return nil, err
	}
	s.signer = NewEd25519Signer(o.KeyID, bytes.Clone(o.Seed))
	s.ttl, s.maxBatch, s.hops = ttl, o.MaxBatch, newHops()
	if err := s.startDelivery(cfg); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Ready is an admission-time observation. Enqueue repeats the live check.
func (s *Service) Ready(chain uint64) bool {
	if s == nil || chain == 0 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closing && s.queue != nil && s.ready(chain, time.Now())
}

type envelopeTransport struct{ base http.RoundTripper }

func (t envelopeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("bound node response unavailable")
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxBoundEnvelopeBytes {
		return nil, errors.New("bound node response exceeds limit")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBoundEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBoundEnvelopeBytes {
		return nil, errors.New("bound node response exceeds limit")
	}
	owned := *resp
	owned.Body = io.NopCloser(bytes.NewReader(raw))
	owned.ContentLength = int64(len(raw))
	return &owned, nil
}
