package nodeapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type boundRoundTripper func(*http.Request) (*http.Response, error)

func (f boundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type spaces struct{}

func (spaces) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

type trackedBody struct {
	io.Reader
	closed *atomic.Bool
}

func (b trackedBody) Close() error { b.closed.Store(true); return nil }

func TestBoundGuardRejectsOversizedEnvelopeBeforeRPCDecode(t *testing.T) {
	var closed atomic.Bool
	var calls atomic.Int64
	transport := boundRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		var q struct{ ID json.RawMessage }
		json.NewDecoder(r.Body).Decode(&q)
		prefix := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":"0x7a69"}`, q.ID)
		// The valid prefix would satisfy a one-value RPC decoder. The bounded
		// transport must inspect the complete envelope and reject this tail.
		body := trackedBody{Reader: io.MultiReader(strings.NewReader(prefix), io.LimitReader(spaces{}, MaxBoundEnvelopeBytes+1)), closed: &closed}
		return &http.Response{StatusCode: 200, Body: body, ContentLength: -1, Header: http.Header{}}, nil
	})
	t.Setenv("OPS_APPROVAL_NODE", "besu")
	t.Setenv("OPS_APPROVAL_HASH_MODE", "invalid-env")
	s, err := NewBoundDelivery(BoundDeliveryOptions{BoundPreflightOptions: BoundPreflightOptions{URL: "http://bound.test", Transport: transport, HashMode: HashCalls}, Seed: bytes.Repeat([]byte{7}, 32), KeyID: "test", MaxBatch: 32, Delivery: DeliveryOptions{Targets: []string{"127.0.0.1:1"}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, raw := signedCall(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := s.Prepare(ctx, raw); err == nil {
		t.Fatal("valid prefix hid oversized response")
	}
	if calls.Load() != 1 || !closed.Load() {
		t.Fatal("response not bounded/closed", calls.Load(), closed.Load())
	}
	if s.ttl != DefaultApprovalTTL {
		t.Fatal("default TTL changed")
	}
}

func TestBoundDeliveryUsesExistingProducerReadinessSignerAndDrain(t *testing.T) {
	p := newTCPProducer(t, "bound-boot")
	seed := bytes.Clone(testSeed)
	targets := []string{p.name}
	transport := boundRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("delivery readiness unexpectedly used node RPC")
		return nil, io.EOF
	})
	s, err := NewBoundDelivery(BoundDeliveryOptions{BoundPreflightOptions: BoundPreflightOptions{URL: "http://unused.test", Transport: transport, HashMode: HashCalls}, Seed: seed, KeyID: "default", MaxBatch: 32, Delivery: DeliveryOptions{Targets: targets, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seed[0] ^= 0xff
	targets[0] = "mutated.invalid:1"
	waitReady(t, s)
	if !s.Ready(31337) || s.Ready(1) || s.Ready(0) {
		t.Fatal("readiness chain not checked")
	}
	hash := common.HexToHash("0x1234")
	if err := s.Enqueue(approvalFor(hash)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.Ready(31337) {
		t.Fatal("closed sender remains ready")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	stored := p.stored[p.boot]
	if len(stored) != 1 || stored[0] != hash {
		t.Fatal("original queue/drain/signature path changed", stored)
	}
}
