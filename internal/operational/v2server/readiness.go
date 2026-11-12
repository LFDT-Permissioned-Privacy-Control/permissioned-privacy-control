package v2server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"privacy-proxy/internal/rpcexecution"
	"sync"
	"sync/atomic"
	"time"
)

// Readiness is a bounded dependency observation, never request authorization.
// At most one caller owns a probe; a completed sample lasts at most one second.
type readiness struct {
	checks []func(context.Context) error
	local  func() error
	probe  chan struct{}
	mu     sync.Mutex
	until  time.Time
	ready  bool
}

func newReadiness(local func() error, checks []func(context.Context) error) *readiness {
	return &readiness{local: local, checks: append([]func(context.Context) error{}, checks...), probe: make(chan struct{}, 1)}
}

func (p *readiness) check(parent context.Context) bool {
	if parent == nil || parent.Err() != nil || p.local == nil || p.local() != nil {
		return false
	}
	p.mu.Lock()
	cached, ready := time.Now().Before(p.until), p.ready
	p.mu.Unlock()
	if cached {
		return ready && p.local() == nil && parent.Err() == nil
	}
	select {
	case p.probe <- struct{}{}:
		defer func() { <-p.probe }()
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	var failed atomic.Bool
	jobs := make(chan func(context.Context) error, len(p.checks))
	for _, check := range p.checks {
		jobs <- check
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(4, len(p.checks)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for check := range jobs {
				if failed.Load() {
					continue
				}
				if ctx.Err() != nil || check == nil || check(ctx) != nil {
					failed.Store(true)
				}
			}
		}()
	}
	workers.Wait()
	ready = len(p.checks) > 0 && !failed.Load()
	if p.local() != nil || ctx.Err() != nil {
		return false
	}
	p.mu.Lock()
	if ctx.Err() != nil {
		p.mu.Unlock()
		return false
	}
	p.until = time.Now().Add(time.Second)
	p.ready = ready
	p.mu.Unlock()
	return ready && p.local() == nil && ctx.Err() == nil
}

func (s *Server) addReadyNode(client *rpcexecution.MetadataClient, credential rpcexecution.Credential, requireSync bool) {
	// Distinct credential bindings on the same URL are independent dependencies.
	// Hash private material for startup-only de-duplication; never log it.
	raw, _ := json.Marshal(struct {
		Source      rpcexecution.MetadataSourceMetadata
		Credential  rpcexecution.Credential
		RequireSync bool
	}{client.Source(), credential, requireSync})
	key := sha256.Sum256(raw)
	if s.readyNodes == nil {
		s.readyNodes = map[[32]byte]bool{}
	}
	if !s.readyNodes[key] {
		s.readyNodes[key] = true
		s.readyChecks = append(s.readyChecks, nodeReady(client, requireSync))
	}
}

func (p *readiness) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !p.check(r.Context()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func nodeReady(client *rpcexecution.MetadataClient, requireSync bool) func(context.Context) error {
	return func(ctx context.Context) error {
		method := rpcexecution.MetadataChainID
		if requireSync {
			method = rpcexecution.MetadataSyncing
		}
		q, err := rpcexecution.ParseMetadataQuery(method, []byte("[]"), client.Bounds())
		if err != nil {
			return err
		}
		result, err := client.Query(ctx, q)
		if err != nil {
			return err
		}
		if requireSync && !bytes.Equal(result.ResultJSON(), []byte("false")) {
			return ErrInvalid
		}
		return nil
	}
}
