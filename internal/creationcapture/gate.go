// Package creationcapture pairs an approved native creation intent with bounded
// capture-time readiness. Its operational caught-up-source assumption is not a
// cryptographic proof of global noninclusion or historical wallet authorship.
package creationcapture

import (
	"context"
	"errors"
	"slices"
	"time"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

var ErrUnavailable = errors.New("creation capture unavailable")
var ErrBinding = errors.New("invalid creation capture binding")

type ReadinessStore interface {
	ReadCheckpoint(context.Context, creationfacts.Digest, creationfacts.State, creationfacts.Digest) (creationfacts.Checkpoint, error)
	ConfirmCapture(context.Context, creationfacts.Checkpoint, creationfacts.Header) (creationfacts.Checkpoint, error)
}
type Options struct {
	Network           creationfacts.Network
	State             creationfacts.State
	Reference         creationfacts.Source
	Sources           []creationfacts.Source
	CaughtUpAssertion string
	Store             ReadinessStore
}
type Metadata struct {
	Network              creationfacts.Network
	State                creationfacts.State
	Reference, SourceSet creationfacts.Digest
}
type Gate struct {
	metadata Metadata
	store    ReadinessStore
	sources  []creationfacts.Source
	allowed  map[creationfacts.Digest]creationfacts.Source
}

func New(o Options) (*Gate, error) {
	set, err := creationfacts.SourceSet(o.Sources)
	if err != nil || !o.Network.Valid() || !o.State.Valid() || o.Store == nil || o.CaughtUpAssertion != creationfacts.CaughtUpAssertion || !o.Reference.Valid() || o.Reference.Network != o.Network || o.Reference.Profile != "reth-prague-included-creations/v1" {
		return nil, ErrBinding
	}
	g := &Gate{metadata: Metadata{o.Network, o.State, o.Reference.Digest(), set}, store: o.Store, sources: slices.Clone(o.Sources), allowed: map[creationfacts.Digest]creationfacts.Source{}}
	for _, s := range g.sources {
		if s.Network != o.Network || s.Profile == "reth-prague-included-creations/v1" {
			return nil, ErrBinding
		}
		g.allowed[s.Digest()] = s
	}
	return g, nil
}
func (g *Gate) Metadata() Metadata {
	if g == nil {
		return Metadata{}
	}
	return g.metadata
}
func (g *Gate) Sources() []creationfacts.Source {
	if g == nil {
		return nil
	}
	return slices.Clone(g.sources)
}

type CaptureRequest struct {
	Approved     *nativeadmission.ApprovedSignedCheck
	View         *runtimepolicy.View
	Organization string
	Transaction  transactioninput.VerifiedTransaction
	Execution    *rpcexecution.CallExecution
	Wallets      nativeadmission.WalletSnapshot
}

// Probe is trusted startup/orchestration code returning ONLY opaque client
// evidence. Success is not trusted as a bool: Capture verifies all bindings.
type Probe func(context.Context, creationfacts.Checkpoint) (*rpcexecution.CaptureEvidence, error)

type Ticket struct {
	gate    *Gate
	request CaptureRequest
	record  creationfacts.CoverageRecord
}
type Result struct {
	gate    *Gate
	request CaptureRequest
	ticket  *Ticket
	mined   bool
}

func (r *Result) Ticket() (*Ticket, bool) {
	if r == nil || r.ticket == nil {
		return nil, false
	}
	return r.ticket, true
}
func (r *Result) KnownMined() bool { return r != nil && r.gate != nil && r.mined && r.ticket == nil }
func (t *Ticket) Record() creationfacts.CoverageRecord {
	if t == nil {
		return creationfacts.CoverageRecord{}
	}
	return t.record
}
func sameRequest(a, b CaptureRequest) bool {
	return a.Approved == b.Approved && a.View == b.View && a.Organization == b.Organization && a.Execution == b.Execution && a.Transaction.Valid() && b.Transaction.Valid() && a.Transaction.Hash() == b.Transaction.Hash() && a.Transaction.Signer() == b.Transaction.Signer() && a.Wallets.ActorID() == b.Wallets.ActorID() && a.Wallets.Version() == b.Wallets.Version()
}
func (g *Gate) validate(r CaptureRequest) error {
	if g == nil || r.View == nil || r.Execution == nil || !r.Transaction.Valid() || r.Transaction.ChainID() != g.metadata.Network.ChainID || r.Approved.RequireMatches(r.View, r.Organization, r.Execution, r.Wallets) != nil {
		return ErrBinding
	}
	p := r.Approved.Plan()
	if p == nil || p.Data().Version != nativeadmission.CapturedCreationPlanVersion || p.Data().CaptureProfile != creationfacts.CaptureProfile {
		return ErrBinding
	}
	return nil
}
func (r *Result) RequireMatches(g *Gate, request CaptureRequest) error {
	if r == nil || r.gate != g || !sameRequest(r.request, request) || g.validate(request) != nil || (r.mined == (r.ticket != nil)) {
		return ErrBinding
	}
	if r.ticket != nil && (r.ticket.gate != g || !sameRequest(r.ticket.request, request) || r.ticket.record.Digest() == (creationfacts.Digest{})) {
		return ErrBinding
	}
	return nil
}

func (g *Gate) Capture(ctx context.Context, request CaptureRequest, probe Probe) (*Result, error) {
	if g == nil || len(g.allowed) == 0 || g.validate(request) != nil || probe == nil {
		return nil, ErrBinding
	}
	ctx, cancel := context.WithTimeout(ctx, creationfacts.CaptureTimeout)
	defer cancel()
	started := time.Now()
	readAt := time.Now()
	cp, err := g.store.ReadCheckpoint(ctx, g.metadata.Network.Key, g.metadata.State, g.metadata.SourceSet)
	if err != nil || !cp.Valid() {
		return nil, ErrUnavailable
	}
	cp.RemainingTTL -= time.Since(readAt)
	if !cp.Valid() || cp.Network != g.metadata.Network.Key || cp.State != g.metadata.State || cp.SourceSet != g.metadata.SourceSet || cp.Reference != g.metadata.Reference {
		return nil, ErrUnavailable
	}
	evidence, err := probe(ctx, cp)
	if err != nil || evidence.RequireMatches(request.Transaction, request.Execution) != nil || evidence.Checkpoint() != cp {
		return nil, ErrUnavailable
	}
	source := evidence.Source()
	allowed, ok := g.allowed[source.Digest()]
	if !ok || source != allowed || source.Network != g.metadata.Network || source.Organization != request.Organization {
		return nil, ErrBinding
	}
	anchor := request.Execution.Anchor()
	a := creationfacts.Header{Number: anchor.Number, Hash: anchor.Hash, Timestamp: anchor.Timestamp}
	confirmAt := time.Now()
	confirmed, err := g.store.ConfirmCapture(ctx, cp, a)
	if err != nil || !confirmed.Valid() || !confirmed.SameTrust(cp) || confirmed.HighWater.Number > a.Number || (confirmed.HighWater.Number == a.Number && confirmed.HighWater.Hash != a.Hash) {
		return nil, ErrUnavailable
	}
	confirmed.RemainingTTL -= time.Since(confirmAt)
	if !confirmed.Valid() || ctx.Err() != nil || time.Since(started) > creationfacts.CaptureTimeout || g.validate(request) != nil {
		return nil, ErrUnavailable
	}
	result := &Result{gate: g, request: request, mined: evidence.KnownMined()}
	if result.mined {
		return result, nil
	}
	finished := time.Now().UTC()
	record := creationfacts.CoverageRecord{Version: 1, Policy: creationfacts.CaptureProfile, Network: cp.Network, State: cp.State, ObserverEpoch: cp.ObserverEpoch, CaptureEpoch: cp.CaptureEpoch, SourceSet: cp.SourceSet, Reference: cp.Reference, Ingress: source.Digest(), HighWater: confirmed.HighWater, Latest: evidence.Latest(), HeaderVersion: confirmed.HeaderVersion, LeaseFence: confirmed.LeaseFence, ProbeStarted: started.UTC(), ProbeFinished: finished, ValidUntil: finished.Add(confirmed.RemainingTTL)}
	if _, err := record.Canonical(); err != nil {
		return nil, ErrUnavailable
	}
	result.ticket = &Ticket{gate: g, request: request, record: record}
	return result, nil
}
