package nodepolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"time"
)

type FactSource interface {
	NodePolicyVersion(context.Context) (uint64, error)
	ExportNodePolicySnapshot(context.Context, Network, time.Time, time.Duration) (Snapshot, error)
	AcknowledgeNodePolicy(context.Context, string, AppliedState) error
}
type FactNode interface {
	PolicyStatus(context.Context) (NodeStatus, error)
	ApplyPolicy(context.Context, []byte) (AppliedState, error)
}

// FactRepublisher can force the next publication to be a full export, by
// recording a change the incremental export cannot describe.
type FactRepublisher interface {
	RequestFullNodePolicyExport(context.Context) error
}

type PublisherConfig struct {
	Network    Network
	ConsumerID string
	Signer     Signer
	Source     FactSource
	Node       FactNode
	Lifetime   time.Duration
	Now        func() time.Time
	// Wake, when set, makes Run publish at once instead of at the next
	// heartbeat. Senders fill it without blocking (capacity 1), so any number
	// of signals during a publication cause at most one more (RD-1411 §5.2).
	Wake <-chan struct{}
}
type Publisher struct {
	mu         sync.Mutex
	config     PublisherConfig
	last       *Snapshot
	lastDigest string
	deltaCount int
	deltaBytes int
	// lastFull is when facts were last read in full from the source.
	lastFull time.Time
	// anchorRequested: this publisher found the node holding facts it did not
	// publish itself (a restart or failover) and asked for a full export.
	anchorRequested bool
}

// ErrFactDivergence means the facts published incrementally differ from a
// full export of the same generation. The publisher requests a full
// republication, which corrects the node.
var ErrFactDivergence = errors.New("incrementally published facts differ from the full export")

// fullExportEvery bounds how long incrementally published facts go without
// being compared with, or replaced by, a full export (RD-1411 §5.6).
const fullExportEvery = 5 * time.Minute

// Keep replay checkpoints comfortably below the node's signed-history bounds.
const maxCheckpointDeltas = 128
const maxCheckpointDeltaBytes = 128 << 20

func NewPublisher(config PublisherConfig) (*Publisher, error) {
	if config.Source == nil || config.Node == nil || config.Network.ChainID == 0 || !identifier(config.Network.DeploymentID) || !identifier(config.ConsumerID) || !identifier(config.Signer.KeyID) || len(config.Signer.PrivateKey) != ed25519.PrivateKeySize || config.Lifetime < time.Second || config.Lifetime > MaxMessageLifetime {
		return nil, ErrEnvelope
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Publisher{config: config}, nil
}

// Tick publishes at most one coherent generation, then persists only its exact
// node acknowledgement. A failed/ambiguous send is recovered by the next status
// read; it is never recorded as applied based on a returned transaction hash.
func (p *Publisher) Tick(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.config
	version, err := c.Source.NodePolicyVersion(ctx)
	if err != nil {
		return err
	}
	if version == 0 {
		return ErrSnapshot
	}
	status, err := c.Node.PolicyStatus(ctx)
	if err != nil {
		return err
	}
	if status.ProtocolVersion != ProtocolVersion || status.Network != c.Network || !slices.Contains(status.Capabilities, "fact_stream_v1") {
		return ErrNodeResponse
	}
	if status.Version > version {
		return ErrFeedConflict
	}
	at := c.Now()
	header := Header{Network: c.Network, IssuedAt: at.Unix(), ExpiresAt: at.Add(c.Lifetime).Unix()}
	var kind string
	var payload any
	var snapshot *Snapshot
	var expected AppliedState
	fromFull := false // the published facts were read in full in this tick
	matchesNode := p.last != nil && p.last.Version == status.Version && p.lastDigest == status.Digest
	if status.Version == version {
		if !hexDigest(status.Digest) {
			return ErrNodeResponse
		}
		if matchesNode && at.Sub(p.lastFull) >= fullExportEvery {
			if err := p.verify(ctx, at); err != nil {
				return err
			}
		}
		if p.last == nil && !p.anchorRequested {
			// The node holds facts another publisher (or this process before
			// a restart) may have built incrementally; nothing here can
			// compare them, so the next publication reads every fact.
			if r, ok := c.Source.(FactRepublisher); ok {
				if _, incremental := c.Source.(IncrementalFactSource); incremental {
					if err := r.RequestFullNodePolicyExport(ctx); err != nil {
						return err
					}
				}
			}
			p.anchorRequested = true
		}
		kind = "heartbeat"
		payload = Heartbeat{Header: header, Version: version, Digest: status.Digest}
		expected = AppliedState{Version: version, Digest: status.Digest, ExpiresAt: header.ExpiresAt}
	} else {
		canDelta := matchesNode && p.deltaCount < maxCheckpointDeltas && p.deltaBytes < maxCheckpointDeltaBytes
		var next *Snapshot
		var delta *Delta
		if incremental, ok := c.Source.(IncrementalFactSource); ok && canDelta && at.Sub(p.lastFull) < fullExportEvery {
			patched, d, err := p.exportIncremental(ctx, incremental, header, version)
			if err != nil {
				// Never worse than the full export: read everything instead.
				slog.Warn("incremental fact export failed; exporting every fact", "error", err)
			} else if patched != nil {
				next, delta = patched, d
			}
		}
		if next == nil {
			exported, err := p.exportFull(ctx, at, header, version, status.Version)
			if err != nil {
				return err
			}
			next, fromFull = &exported, true
			if canDelta {
				d, err := BuildDelta(*p.last, p.lastDigest, exported)
				if err != nil {
					return err
				}
				delta = &d
			}
		}
		snapshot = next
		kind, payload = "snapshot", *next
		if delta != nil {
			kind, payload = "delta", *delta
		}
		expected = AppliedState{Version: next.Version, ExpiresAt: header.ExpiresAt}
	}
	wire, err := c.Signer.Seal(kind, payload)
	if err != nil {
		return err
	}
	if kind == "delta" && p.deltaBytes+len(wire) > maxCheckpointDeltaBytes {
		// The checkpoint re-anchors on a fresh full export.
		exported, err := p.exportFull(ctx, at, header, version, status.Version)
		if err != nil {
			return err
		}
		snapshot, kind, fromFull = &exported, "snapshot", true
		expected.Version = exported.Version
		wire, err = c.Signer.Seal(kind, exported)
		if err != nil {
			return err
		}
	}
	if kind != "heartbeat" {
		var envelope Envelope
		if err := decodeStrict(wire, &envelope); err != nil {
			return err
		}
		expected.Digest = PayloadDigest(envelope.Payload)
	}
	ack, err := c.Node.ApplyPolicy(ctx, wire)
	if errors.Is(err, ErrNodeResync) && kind == "delta" {
		// The rejected delta never advanced the node. Replace it with a fresh
		// full export: a strictly newer, coherent database generation.
		exported, exportErr := p.exportFull(ctx, at, header, version, status.Version)
		if exportErr != nil {
			return exportErr
		}
		snapshot, kind, fromFull = &exported, "snapshot", true
		wire, err = c.Signer.Seal(kind, exported)
		if err != nil {
			return err
		}
		var envelope Envelope
		if err := decodeStrict(wire, &envelope); err != nil {
			return err
		}
		expected = AppliedState{Version: exported.Version, Digest: PayloadDigest(envelope.Payload), ExpiresAt: header.ExpiresAt}
		ack, err = c.Node.ApplyPolicy(ctx, wire)
	}
	if err != nil {
		return err
	}
	if ack.Version != expected.Version || ack.Digest != expected.Digest || ack.ExpiresAt < expected.ExpiresAt {
		return ErrNodeResponse
	}
	if err := c.Source.AcknowledgeNodePolicy(ctx, c.ConsumerID, ack); err != nil {
		return err
	}
	if snapshot != nil {
		p.last = snapshot
		p.lastDigest = ack.Digest
		if kind == "snapshot" {
			p.deltaCount, p.deltaBytes = 0, 0
		}
		if fromFull {
			p.lastFull = at
		}
		if kind == "delta" {
			p.deltaCount++
			p.deltaBytes += len(wire)
		}
	}
	return nil
}

// exportIncremental reads the changes since p.last and patches them in. A nil
// snapshot without an error means the change log cannot describe the gap.
func (p *Publisher) exportIncremental(ctx context.Context, source IncrementalFactSource, header Header, version uint64) (*Snapshot, *Delta, error) {
	changes, err := source.ExportNodePolicyChanges(ctx, *p.last)
	if err != nil || changes.Full {
		return nil, nil, err
	}
	patched, d, err := ApplyChanges(*p.last, p.lastDigest, header, changes)
	if err != nil {
		return nil, nil, err
	}
	if patched.Version < version {
		return nil, nil, ErrSnapshot
	}
	if _, err := Pin(patched); err != nil {
		return nil, nil, err
	}
	return &patched, &d, nil
}

// exportFull reads every fact and checks the export is a coherent generation
// newer than the node's.
func (p *Publisher) exportFull(ctx context.Context, at time.Time, header Header, version, nodeVersion uint64) (Snapshot, error) {
	c := p.config
	exported, err := c.Source.ExportNodePolicySnapshot(ctx, c.Network, at, c.Lifetime)
	if err != nil {
		return Snapshot{}, err
	}
	if exported.Version < version || exported.Version <= nodeVersion || exported.Header != header {
		return Snapshot{}, ErrSnapshot
	}
	if _, err := Pin(exported); err != nil {
		return Snapshot{}, err
	}
	return exported, nil
}

// verify compares the facts the node holds (published incrementally) with a
// full export of the same generation. A difference is reported and a full
// republication requested, so a divergence lasts at most fullExportEvery
// plus one publication.
func (p *Publisher) verify(ctx context.Context, at time.Time) error {
	c := p.config
	if _, ok := c.Source.(IncrementalFactSource); !ok {
		p.lastFull = at
		return nil
	}
	full, err := c.Source.ExportNodePolicySnapshot(ctx, c.Network, at, c.Lifetime)
	if err != nil {
		return err
	}
	if full.Version != p.last.Version {
		return nil // a change landed meanwhile; its publication reads in full
	}
	if sameFacts(*p.last, full) {
		p.lastFull = at
		return nil
	}
	if r, ok := c.Source.(FactRepublisher); ok {
		if err := r.RequestFullNodePolicyExport(ctx); err != nil {
			return err
		}
	}
	p.lastFull = time.Time{}
	return ErrFactDivergence
}

// sameFacts reports whether two snapshots hold the same facts, whatever their
// order.
func sameFacts(a, b Snapshot) bool {
	a, b = cloneSnapshot(a), cloneSnapshot(b)
	empty := func(upserts any, deletes []string) bool {
		return reflect.ValueOf(upserts).Len() == 0 && len(deletes) == 0
	}
	if u, d := diffFacts(a.Principals, b.Principals, principalKey); !empty(u, d) {
		return false
	}
	if u, d := diffFacts(a.Groups, b.Groups, groupKey); !empty(u, d) {
		return false
	}
	if u, d := diffFacts(a.Contracts, b.Contracts, contractKey); !empty(u, d) {
		return false
	}
	if u, d := diffFacts(a.Policies, b.Policies, policyKey); !empty(u, d) {
		return false
	}
	u, d := diffFacts(a.Sanctions, b.Sanctions, sanctionKey)
	return empty(u, d)
}

// Run keeps retrying through transient outages. The node's lease enforces the
// staleness bound while unavailable; errors are reported without hiding them.
// It publishes on every Wake signal and, as heartbeat and fallback when
// notifications are lost, every interval.
func (p *Publisher) Run(ctx context.Context, interval time.Duration, report func(error)) error {
	if interval <= 0 || interval > p.config.Lifetime/3 {
		return errors.New("fact publish interval exceeds freshness budget")
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		err := p.Tick(ctx)
		if err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-p.config.Wake:
		}
	}
}
