package v2server

import (
	"context"
	"errors"
	"net/http"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/rpcexecution"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiagnosticsSeparateReadinessOwnNodeCacheAndCancellation(t *testing.T) {
	var calls atomic.Int32
	node := newObservedNode(func(context.Context) error { calls.Add(1); return nil }, time.Now)
	foreign := newObservedNode(func(context.Context) error { return errors.New("https://private.foreign.node credential failure") }, time.Now)
	ready := newReadiness(func() error { return nil }, []func(context.Context) error{func(context.Context) error { return errors.New("private database failure") }})
	sampler := newDiagnosticsSampler(ready, map[string][]*observedNode{"own": {node}, "foreign": {foreign}})
	for range 2 {
		sample := sampler.sample(t.Context(), "own")
		if sample.Readiness.State != "unavailable" || sample.Node.State != "connected" || sample.Node.SampledAt == nil || sample.Node.LatencyMS == nil {
			t.Fatal("readiness confused with own node", sample)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("node sample cache bypassed", calls.Load())
	}
	if sample := sampler.sample(t.Context(), "foreign"); sample.Node.State != "unavailable" {
		t.Fatal("cross-organization node sample alias", sample)
	}
	if sample := sampler.sample(t.Context(), "unconfigured"); sample.Node.State != "unknown" || sample.Node.SampledAt != nil {
		t.Fatal("unsampled node reported connected", sample)
	}
	started := make(chan struct{})
	cancelled := newObservedNode(func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() }, time.Now)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { _ = cancelled.observe(ctx); close(done) }()
	<-started
	cancel()
	<-done
	if sample := cancelled.snapshot(); sample.State != "unknown" || sample.SampledAt != nil {
		t.Fatal("caller cancellation cached as node failure", sample)
	}
}

func TestDiagnosticsAggregateUnknownAndFiniteConcurrentWorkers(t *testing.T) {
	unknown := newObservedNode(func(context.Context) error { return nil }, time.Now)
	known := newObservedNode(func(context.Context) error { return nil }, time.Now)
	_ = known.observe(t.Context())
	ready := newReadiness(func() error { return nil }, []func(context.Context) error{func(context.Context) error { return nil }})
	// A busy sampler may publish completed facts, but a partial organization
	// check must never be upgraded to Connected by a later healthy binding.
	s := newDiagnosticsSampler(ready, map[string][]*observedNode{"org": {unknown, known}})
	s.probe <- struct{}{}
	if sample := s.sample(t.Context(), "org"); sample.Node.State != "unknown" {
		t.Fatal("partial node population reported connected", sample)
	}
	<-s.probe
	var active, maximum atomic.Int32
	nodes := []*observedNode{}
	for range 10 {
		nodes = append(nodes, newObservedNode(func(ctx context.Context) error {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			<-ctx.Done()
			return ctx.Err()
		}, time.Now))
	}
	s = newDiagnosticsSampler(ready, map[string][]*observedNode{"org": nodes})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	sample := s.sample(ctx, "org")
	if maximum.Load() > 4 || maximum.Load() == 0 || active.Load() != 0 || sample.Node.State != "unknown" {
		t.Fatal("unbounded workers or cancellation cached", maximum.Load(), active.Load(), sample)
	}
}

func TestDiagnosticsEarlierProbeCannotReplaceNewerObservation(t *testing.T) {
	first, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	node := newObservedNode(func(context.Context) error {
		if calls.Add(1) == 1 {
			close(first)
			<-release
			return nil
		}
		return errors.New("newer measured failure")
	}, time.Now)
	done := make(chan struct{})
	go func() { _ = node.observe(t.Context()); close(done) }()
	<-first
	_ = node.observe(t.Context())
	close(release)
	<-done
	if sample := node.snapshot(); sample.State != "unavailable" {
		t.Fatal("late earlier success overwrote the newer result", sample)
	}
}

func TestDiagnosticsExactConfiguredOrgBindingsDespiteDeduplication(t *testing.T) {
	makeClient := func(endpoint, ref string) (*rpcexecution.MetadataClient, rpcexecution.Credential) {
		credential := rpcexecution.Credential{Header: "Authorization", Value: "Bearer private-" + ref}
		client, err := rpcexecution.NewMetadataClient(http.DefaultTransport, rpcexecution.MetadataSource{Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x" + strings.Repeat("1", 64), DeploymentID: "diagnostics"}, URL: endpoint, CredentialRef: ref, CredentialHeader: "Authorization"}, credential, rpcexecution.DefaultMetadataLimits())
		if err != nil {
			t.Fatal(err)
		}
		return client, credential
	}
	a, ca := makeClient("https://private-a.node/rpc", "A")
	b, cb := makeClient("https://private-b.node/rpc", "B")
	fallback, cf := makeClient("https://private-default.node/rpc", "DEFAULT")
	s := &Server{}
	s.addReadyNode(a, ca, false, "org-a")
	s.addReadyNode(a, ca, false, "org-a")
	s.addReadyNode(b, cb, false, "org-b")
	s.addReadyNode(fallback, cf, true, "")
	if len(s.readyChecks) != 3 || len(s.diagnosticNodes["org-a"]) != 1 || len(s.diagnosticNodes["org-b"]) != 1 || s.diagnosticNodes["org-a"][0] == s.diagnosticNodes["org-b"][0] || len(s.diagnosticNodes[""]) != 0 {
		t.Fatal("default or foreign node aliased into own organization")
	}
	// Sharing is allowed only when that exact binding is explicitly configured
	// for the second organization; a public/default check alone never adds it.
	s.addReadyNode(a, ca, false, "org-b")
	if len(s.readyChecks) != 3 || len(s.diagnosticNodes["org-b"]) != 2 || s.diagnosticNodes["org-b"][1] != s.diagnosticNodes["org-a"][0] {
		t.Fatal("explicit same-binding association lost")
	}
}
