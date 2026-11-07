package creationobserver

import (
	"context"
	"errors"
	"sync"
	"time"

	f "privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/rpcexecution"
)

type WorkStore interface {
	HeaderStore
	LoadNextCreationWork(context.Context, f.Network, f.ObserverSnapshot) (*WorkSnapshot, bool, error)
	AcknowledgeUnchangedInclusion(context.Context, *WorkSnapshot) (bool, error)
	RecordCreationRetry(context.Context, *WorkSnapshot, string) error
	PublishCreationObservation(context.Context, *QualifiedObservation) error
}
type Options struct {
	Network           f.Network
	State             f.State
	Owner             string
	SourceSet         f.Digest
	Reference         f.Source
	CaughtUpAssertion string
	HeaderClient      *rpcexecution.HeaderClient
	IncludedClient    *rpcexecution.IncludedClient
	Store             WorkStore
}
type Observer struct {
	mu       sync.Mutex
	headers  *HeaderWorker
	included *rpcexecution.IncludedClient
	store    WorkStore
}

// New owns both workers and one store binding. No externally advanced header
// worker or caller-supplied parsed included proof can be substituted.
func New(o Options) (*Observer, error) {
	if o.IncludedClient == nil || o.IncludedClient.Source() != o.Reference || o.Store == nil {
		return nil, ErrBinding
	}
	headers, err := NewHeaderWorker(HeaderOptions{Network: o.Network, State: o.State, Owner: o.Owner, SourceSet: o.SourceSet, Reference: o.Reference, CaughtUpAssertion: o.CaughtUpAssertion, Client: o.HeaderClient, Store: o.Store})
	if err != nil {
		return nil, err
	}
	return &Observer{headers: headers, included: o.IncludedClient, store: o.Store}, nil
}

// Step performs one header operation and at most one included transaction.
// The network proof runs after releasing the bounded SQL read snapshot. A
// renewed DB-clock lease precedes its15s budget; publication independently
// checks the remaining lease and exact prefix CAS through COMMIT.
func (o *Observer) Step(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrBinding
	}
	if !o.mu.TryLock() {
		return ErrUnavailable
	}
	defer o.mu.Unlock()
	if err := o.headers.Step(ctx); err != nil {
		return err
	}
	o.headers.mu.Lock()
	before := o.headers.current
	o.headers.mu.Unlock()
	if !before.State.Ready || before.State.Quarantine != "none" {
		return ErrUnavailable
	}
	work, found, err := o.store.LoadNextCreationWork(ctx, o.headers.options.Network, before)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if acknowledged, err := o.store.AcknowledgeUnchangedInclusion(ctx, work); err != nil {
		return err
	} else if acknowledged {
		return nil
	}
	if !work.HasEligibleCoverage() {
		return o.store.RecordCreationRetry(ctx, work, "uncovered")
	}
	before, err = o.store.RenewObserverLease(ctx, before.Lease)
	if err != nil {
		return ErrUnavailable
	}
	o.headers.mu.Lock()
	o.headers.current = before
	o.headers.lastRenew = time.Now()
	o.headers.mu.Unlock()
	proof, err := o.included.AcquireIncluded(ctx, work.Hash())
	if err != nil {
		outcome := "not-included"
		var typed *rpcexecution.Error
		if errors.As(err, &typed) && (typed.Code == rpcexecution.UnsupportedEvidence || typed.Code == rpcexecution.EvidenceLimit) {
			outcome = "unsupported"
		}
		if writeErr := o.store.RecordCreationRetry(ctx, work, outcome); writeErr != nil {
			return writeErr
		}
		if errors.Is(err, rpcexecution.ErrNotIncluded) {
			return nil
		}
		return ErrUnavailable
	}
	qualified, err := QualifyIncluded(work, proof)
	if err != nil {
		return err
	}
	return o.store.PublishCreationObservation(ctx, qualified)
}

// Run does not retry effects or spin when a source/store is unavailable.
// Process assembly owns the independent maximum of four configured networks.
func (o *Observer) Run(ctx context.Context) error {
	if o == nil || ctx == nil {
		return ErrBinding
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = o.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
