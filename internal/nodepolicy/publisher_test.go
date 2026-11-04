package nodepolicy

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memorySource struct {
	snapshot Snapshot
	exports  int
	acks     []AppliedState
	failure  error
}

func (s *memorySource) NodePolicyVersion(context.Context) (uint64, error) {
	return s.snapshot.Version, s.failure
}
func (s *memorySource) ExportNodePolicySnapshot(_ context.Context, n Network, at time.Time, lifetime time.Duration) (Snapshot, error) {
	s.exports++
	out := cloneSnapshot(s.snapshot)
	out.Header = Header{Network: n, IssuedAt: at.Unix(), ExpiresAt: at.Add(lifetime).Unix()}
	return out, s.failure
}
func (s *memorySource) AcknowledgeNodePolicy(_ context.Context, _ string, state AppliedState) error {
	s.acks = append(s.acks, state)
	return s.failure
}

type memoryNode struct {
	feed        Feed
	verifier    Verifier
	kinds       []string
	lostAck     bool
	badAck      bool
	failure     error
	resyncDelta bool
}

func (n *memoryNode) PolicyStatus(context.Context) (NodeStatus, error) {
	s := NodeStatus{ProtocolVersion: 1, Network: n.verifier.Network, Capabilities: RequiredCapabilities()}
	if n.failure != nil {
		return s, n.failure
	}
	n.feed.mu.RLock()
	v := n.feed.current
	n.feed.mu.RUnlock()
	if v != nil {
		s.Version, s.Digest, s.ExpiresAt = v.Version(), v.Digest(), v.Lease().ExpiresAt
		s.Ready = s.ExpiresAt > n.verifier.clock().Unix()
	}
	return s, nil
}
func (n *memoryNode) ApplyPolicy(_ context.Context, wire []byte) (AppliedState, error) {
	if n.failure != nil {
		return AppliedState{}, n.failure
	}
	var e Envelope
	if err := decodeStrict(wire, &e); err != nil {
		return AppliedState{}, err
	}
	n.kinds = append(n.kinds, e.Kind)
	if n.resyncDelta && e.Kind == "delta" {
		return AppliedState{}, ErrNodeResync
	}
	if err := n.feed.Apply(n.verifier, wire); err != nil {
		return AppliedState{}, err
	}
	v, err := n.feed.Pin(n.verifier.clock())
	if err != nil {
		return AppliedState{}, err
	}
	if n.lostAck {
		n.lostAck = false
		return AppliedState{}, ErrNodeUnavailable
	}
	ack := AppliedState{Version: v.Version(), Digest: v.Digest(), ExpiresAt: v.Lease().ExpiresAt}
	if n.badAck {
		ack.Version++
	}
	return ack, nil
}

func TestPublisherCheckpointsBoundedDeltaHistory(t *testing.T) {
	p, s, n, _ := publisherFixture(t)
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 130; i++ {
		s.snapshot.Version++
		s.snapshot.Principals[0].Banned = i%2 == 0
		if err := p.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n.kinds[128] != "delta" || n.kinds[129] != "snapshot" || n.kinds[130] != "delta" {
		t.Fatalf("unbounded delta history: %v", n.kinds[127:])
	}
}

func TestPublisherResynchronizesRejectedDeltaBeforeAcknowledging(t *testing.T) {
	p, s, n, _ := publisherFixture(t)
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.snapshot.Version++
	s.snapshot.Principals[0].Banned = true
	n.resyncDelta = true
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.acks) != 2 || len(n.kinds) != 3 || n.kinds[1] != "delta" || n.kinds[2] != "snapshot" || s.acks[1].Version != s.snapshot.Version {
		t.Fatalf("resync did not acknowledge full replacement: %+v kinds=%v", s.acks, n.kinds)
	}
	v, err := n.feed.Pin(n.verifier.clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(identityFixture(), n.verifier.clock()); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("resync lost revocation: %v", err)
	}
}
func publisherFixture(t *testing.T) (*Publisher, *memorySource, *memoryNode, *time.Time) {
	t.Helper()
	now := time.Unix(1020, 0)
	s := &memorySource{snapshot: snapshotFixture()}
	n := &memoryNode{verifier: testVerifier()}
	n.verifier.Now = func() time.Time { return now }
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return p, s, n, &now
}
func TestPublisherBootstrapsDeltasAndHeartbeats(t *testing.T) {
	p, s, n, now := publisherFixture(t)
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.exports != 1 || len(s.acks) != 1 || n.kinds[0] != "snapshot" {
		t.Fatal("bootstrap was not acknowledged")
	}
	*now = now.Add(10 * time.Second)
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.exports != 1 || n.kinds[1] != "heartbeat" || s.acks[0].Digest != s.acks[1].Digest {
		t.Fatal("idle heartbeat rewrote facts or reexported directory")
	}
	s.snapshot.Version += 2
	s.snapshot.Principals[0].Banned = true
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.exports != 2 || n.kinds[2] != "delta" || s.acks[2].Version != s.snapshot.Version {
		t.Fatal("coalesced generation not published")
	}
	v, err := n.feed.Pin(*now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(identityFixture(), *now); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("published revocation missing: %v", err)
	}
}
func TestPublisherRecoversLostAcknowledgementAndProcessRestart(t *testing.T) {
	p, s, n, now := publisherFixture(t)
	n.lostAck = true
	if err := p.Tick(context.Background()); err == nil {
		t.Fatal("lost acknowledgement reported success")
	}
	if len(s.acks) != 0 {
		t.Fatal("unconfirmed version persisted")
	}
	*now = now.Add(time.Second)
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.kinds[1] != "heartbeat" || len(s.acks) != 1 {
		t.Fatal("lost acknowledgement did not recover by exact node digest")
	}
	restarted, err := NewPublisher(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.snapshot.Version++
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n.kinds[len(n.kinds)-1] != "snapshot" {
		t.Fatal("restart guessed missing delta baseline")
	}
}
func TestPublisherNeverAcknowledgesMismatchedOrUncommittedState(t *testing.T) {
	for _, failure := range []string{"wrong_ack", "database", "node", "ahead"} {
		t.Run(failure, func(t *testing.T) {
			p, s, n, _ := publisherFixture(t)
			switch failure {
			case "wrong_ack":
				n.badAck = true
			case "database":
				s.failure = errors.New("database down")
			case "node":
				n.failure = ErrNodeUnavailable
			case "ahead":
				future := snapshotFixture()
				future.Version++
				if err := applySigned(t, &n.feed, n.verifier, "snapshot", future); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Tick(context.Background()); err == nil {
				t.Fatal("invalid publication succeeded")
			}
			if len(s.acks) != 0 {
				t.Fatal("unconfirmed cursor advanced")
			}
		})
	}
}

// statusCountingNode counts the node status reads a publisher makes.
type statusCountingNode struct {
	*memoryNode
	statusReads int
}

func (n *statusCountingNode) PolicyStatus(ctx context.Context) (NodeStatus, error) {
	n.statusReads++
	return n.memoryNode.PolicyStatus(ctx)
}

// A fact change right after the node acknowledged a publication goes out as
// a delta on that base without another status read, and no heartbeat
// follows a publication within a second; a stale acknowledgement, or a
// refused publication, reads the status again (P7 L5, finding F8).
func TestPublisherPublishesAFreshChangeWithoutAStatusRead(t *testing.T) {
	_, s, mem, now := publisherFixture(t)
	n := &statusCountingNode{memoryNode: mem}
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	change := func() {
		s.snapshot.Version++
		s.snapshot.Principals[0].Banned = !s.snapshot.Principals[0].Banned
	}
	if err := p.Tick(ctx); err != nil || n.statusReads != 1 || mem.kinds[0] != "snapshot" {
		t.Fatalf("bootstrap: reads %d kinds %v %v", n.statusReads, mem.kinds, err)
	}
	change()
	*now = now.Add(500 * time.Millisecond)
	if err := p.Tick(ctx); err != nil || n.statusReads != 1 || mem.kinds[1] != "delta" {
		t.Fatalf("fresh change: reads %d kinds %v %v", n.statusReads, mem.kinds, err)
	}
	*now = now.Add(500 * time.Millisecond)
	if err := p.Tick(ctx); err != nil || len(mem.kinds) != 2 {
		t.Fatalf("a heartbeat right after a publication: kinds %v %v", mem.kinds, err)
	}
	*now = now.Add(heartbeatSkip)
	if err := p.Tick(ctx); err != nil || n.statusReads != 2 || mem.kinds[2] != "heartbeat" {
		t.Fatalf("heartbeat: reads %d kinds %v %v", n.statusReads, mem.kinds, err)
	}
	*now = now.Add(ackFresh)
	change()
	if err := p.Tick(ctx); err != nil || n.statusReads != 3 || mem.kinds[3] != "delta" {
		t.Fatalf("change after a stale acknowledgement: reads %d kinds %v %v", n.statusReads, mem.kinds, err)
	}
	// The node lost its facts (restarted empty) right after acknowledging:
	// the delta on the acknowledged base is refused, and the next tick reads
	// the status and republishes in full.
	mem.feed = Feed{}
	change()
	*now = now.Add(100 * time.Millisecond)
	if err := p.Tick(ctx); err == nil {
		t.Fatal("a delta to a node without its base was accepted")
	}
	if err := p.Tick(ctx); err != nil || mem.kinds[len(mem.kinds)-1] != "snapshot" {
		t.Fatalf("recovery: kinds %v %v", mem.kinds, err)
	}
	status, _ := mem.PolicyStatus(ctx)
	if status.Version != s.snapshot.Version {
		t.Fatalf("node at %d, want %d", status.Version, s.snapshot.Version)
	}
}
