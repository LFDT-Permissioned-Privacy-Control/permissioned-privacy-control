package v2server

import (
	"context"
	"sync"
	"time"

	"privacy-proxy/internal/selfhttp"
)

// Node samples contain only the outcome of the existing pinned readiness check.
// Their TTL is not used by public readiness, whose probe semantics stay intact.
type observedNode struct {
	check  func(context.Context) error
	clock  func() time.Time
	probe  chan struct{}
	mu     sync.Mutex
	serial uint64
	until  time.Time
	value  selfhttp.Observation
}

func newObservedNode(check func(context.Context) error, clock func() time.Time) *observedNode {
	return &observedNode{check: check, clock: clock, probe: make(chan struct{}, 1)}
}
func (n *observedNode) observe(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	n.mu.Lock()
	n.serial++
	serial := n.serial
	n.mu.Unlock()
	started := time.Now()
	err := n.check(ctx)
	if ctx.Err() != nil {
		return err
	}
	finished := n.clock().UTC()
	state := "connected"
	if err != nil {
		state = "unavailable"
	}
	var latency *int64
	if elapsed := time.Since(started).Milliseconds(); elapsed >= 0 && elapsed <= 3000 {
		latency = &elapsed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if ctx.Err() == nil && n.serial == serial {
		n.value = selfhttp.Observation{State: state, SampledAt: &finished, LatencyMS: latency}
		n.until = finished.Add(time.Second)
	}
	return err
}
func (n *observedNode) snapshot() selfhttp.Observation {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.clock().Before(n.until) {
		return n.value
	}
	return selfhttp.Observation{State: "unknown"}
}
func (n *observedNode) sample(ctx context.Context) {
	if ctx.Err() != nil || n.snapshot().State != "unknown" {
		return
	}
	select {
	case n.probe <- struct{}{}:
		defer func() { <-n.probe }()
	default:
		return
	}
	if n.snapshot().State == "unknown" {
		_ = n.observe(ctx)
	}
}

type diagnosticsSampler struct {
	ready *readiness
	nodes map[string][]*observedNode
	probe chan struct{}
}

func newDiagnosticsSampler(ready *readiness, nodes map[string][]*observedNode) *diagnosticsSampler {
	return &diagnosticsSampler{ready: ready, nodes: nodes, probe: make(chan struct{}, 1)}
}
func (s *diagnosticsSampler) sample(parent context.Context, org string) selfhttp.DiagnosticsSample {
	select {
	case s.probe <- struct{}{}:
		defer func() { <-s.probe }()
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		defer cancel()
		jobs := make(chan func(context.Context), len(s.nodes[org])+1)
		jobs <- func(ctx context.Context) { _ = s.ready.check(ctx) }
		for _, node := range s.nodes[org] {
			jobs <- node.sample
		}
		close(jobs)
		var workers sync.WaitGroup
		for range min(4, len(s.nodes[org])+1) {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for job := range jobs {
					if ctx.Err() == nil {
						job(ctx)
					}
				}
			}()
		}
		workers.Wait()
	default: // Another caller owns the finite sample; return only fresh facts.
	}
	result := selfhttp.DiagnosticsSample{Readiness: s.ready.observation(), Node: selfhttp.Observation{State: "unknown"}}
	allFresh := len(s.nodes[org]) > 0
	var oldest *time.Time
	var maximum int64
	allLatencies := true
	for _, node := range s.nodes[org] {
		value := node.snapshot()
		if value.State == "unavailable" {
			result.Node = value
		}
		if value.State == "unknown" {
			allFresh = false
			continue
		}
		if oldest == nil || value.SampledAt.Before(*oldest) {
			oldest = value.SampledAt
		}
		if value.LatencyMS == nil {
			allLatencies = false
		} else if *value.LatencyMS > maximum {
			maximum = *value.LatencyMS
		}
	}
	if result.Node.State != "unavailable" && allFresh {
		result.Node = selfhttp.Observation{State: "connected", SampledAt: oldest}
		if allLatencies {
			result.Node.LatencyMS = &maximum
		}
	}
	return result
}
func (p *readiness) observation() selfhttp.Observation {
	now := time.Now().UTC()
	if p.local == nil || p.local() != nil {
		return selfhttp.Observation{State: "unavailable", SampledAt: &now}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sampledAt.IsZero() || !now.Before(p.until) {
		return selfhttp.Observation{State: "unknown"}
	}
	state := "unavailable"
	if p.ready {
		state = "ready"
	}
	at := p.sampledAt
	return selfhttp.Observation{State: state, SampledAt: &at}
}
