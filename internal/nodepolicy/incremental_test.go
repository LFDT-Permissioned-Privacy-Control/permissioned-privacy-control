package nodepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func policyFixture(org, group string, code string) PolicyArtifact {
	sum := sha256.Sum256([]byte(code))
	return PolicyArtifact{OrgID: org, GroupID: group, Revision: 3, PolicyDigest: strings.Repeat("ab", 32), RuntimeDigest: hex.EncodeToString(sum[:]), Bytecode: []byte(code)}
}

func richSnapshot() Snapshot {
	s := snapshotFixture()
	s.Contracts = append(s.Contracts, Contract{Address: "0x" + strings.Repeat("33", 20), OrgID: "org-b"})
	s.Policies = []PolicyArtifact{policyFixture("org-a", "payments", "pay"), policyFixture("org-a", "readers", "read"), policyFixture("org-b", "", "org-b")}
	s.Sanctions = []Sanction{{Address: "0x" + strings.Repeat("44", 20)}, {OrgID: "org-a", Address: "0x" + strings.Repeat("55", 20)}}
	return s
}

// changesBetween is what a correct change log reports: every key whose facts
// differ, with the current facts for those keys.
func changesBetween(base, next Snapshot) FactChanges {
	c := FactChanges{Version: next.Version}
	diff := func(keys func(Snapshot) map[string]any) []string {
		a, b := keys(base), keys(next)
		var out []string
		for k, v := range a {
			if w, ok := b[k]; !ok || !reflect.DeepEqual(v, w) {
				out = append(out, k)
			}
		}
		for k := range b {
			if _, ok := a[k]; !ok {
				out = append(out, k)
			}
		}
		return out
	}
	c.Principals = diff(func(s Snapshot) map[string]any {
		m := map[string]any{}
		for _, p := range cloneSnapshot(s).Principals {
			m[p.ID] = p
		}
		return m
	})
	c.Groups = diff(func(s Snapshot) map[string]any {
		m := map[string]any{}
		for _, g := range cloneSnapshot(s).Groups {
			m[g.ID] = g
		}
		return m
	})
	c.Contracts = diff(func(s Snapshot) map[string]any {
		m := map[string]any{}
		for _, x := range s.Contracts {
			m[x.Address] = x
		}
		return m
	})
	c.PolicyOrgs = diff(func(s Snapshot) map[string]any {
		byOrg := map[string][]PolicyArtifact{}
		for _, p := range s.Policies {
			byOrg[p.OrgID] = append(byOrg[p.OrgID], p)
		}
		m := map[string]any{}
		for org, artifacts := range byOrg {
			m[org] = artifacts
		}
		return m
	})
	c.Sanctions = diff(func(s Snapshot) map[string]any {
		m := map[string]any{}
		for _, x := range s.Sanctions {
			m[sanctionKey(x)] = x
		}
		return m
	})
	in := func(keys []string, k string) bool {
		for _, v := range keys {
			if v == k {
				return true
			}
		}
		return false
	}
	for _, p := range next.Principals {
		if in(c.Principals, p.ID) {
			c.Current.Principals = append(c.Current.Principals, p)
		}
	}
	for _, g := range next.Groups {
		if in(c.Groups, g.ID) {
			c.Current.Groups = append(c.Current.Groups, g)
		}
	}
	for _, x := range next.Contracts {
		if in(c.Contracts, x.Address) {
			c.Current.Contracts = append(c.Current.Contracts, x)
		}
	}
	for _, p := range next.Policies {
		if in(c.PolicyOrgs, p.OrgID) {
			c.Current.Policies = append(c.Current.Policies, p)
		}
	}
	for _, x := range next.Sanctions {
		if in(c.Sanctions, sanctionKey(x)) {
			c.Current.Sanctions = append(c.Current.Sanctions, x)
		}
	}
	return c
}

func TestApplyChangesEqualsBuildDelta(t *testing.T) {
	base := richSnapshot()
	next := cloneSnapshot(base)
	next.Version = 12
	next.Principals[0].Banned = true                                         // updated
	next.Principals = next.Principals[:1]                                    // user-b deleted
	next.Groups = append(next.Groups, Group{ID: "auditors", OrgID: "org-b"}) // inserted
	next.Groups[1].ContractClaims = []ContractClaim{{Address: next.Contracts[0].Address, Claims: 0}}
	next.Contracts = next.Contracts[:1]                                                                               // org-b contract deleted
	next.Policies = []PolicyArtifact{policyFixture("org-a", "payments", "pay2"), policyFixture("org-b", "", "org-b")} // org-a replaced, one artifact gone
	next.Sanctions = next.Sanctions[1:]                                                                               // global sanction removed
	changes := changesBetween(base, next)
	// A key reported as changed whose facts did not change yields no delta entry.
	changes.Contracts = append(changes.Contracts, base.Contracts[0].Address)
	changes.Current.Contracts = append(changes.Current.Contracts, base.Contracts[0])
	digest := strings.Repeat("cd", 32)
	header := Header{Network: base.Network, IssuedAt: base.IssuedAt + 5, ExpiresAt: base.ExpiresAt + 5}
	got, delta, err := ApplyChanges(base, digest, header, changes)
	if err != nil {
		t.Fatal(err)
	}
	next.Header = header
	want, err := BuildDelta(base, digest, next)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(delta)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("delta differs from the full diff\n got %s\nwant %s", gotJSON, wantJSON)
	}
	// Applying the delta to the base reproduces the patched snapshot.
	applied, err := applyDelta(base, delta)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(applied)
	b, _ := json.Marshal(sortedSnapshot(got))
	if string(a) != string(b) {
		t.Fatalf("patched snapshot differs from base+delta\n got %s\nwant %s", b, a)
	}
	if _, err := Pin(got); err != nil {
		t.Fatal(err)
	}
}

func sortedSnapshot(s Snapshot) Snapshot {
	out, err := applyDelta(s, Delta{Header: s.Header, Version: s.Version})
	if err != nil {
		panic(err)
	}
	return out
}

func TestApplyChangesRefusesIncoherentChanges(t *testing.T) {
	base := richSnapshot()
	header := base.Header
	for name, c := range map[string]FactChanges{
		"row for a key not reported": {Version: 8, Current: FactSet{Principals: []Principal{{ID: "user-z"}}}},
		"duplicate row":              {Version: 8, Principals: []string{"user-a"}, Current: FactSet{Principals: []Principal{base.Principals[0], base.Principals[0]}}},
		"not newer":                  {Version: base.Version},
		"full":                       {Version: 8, Full: true},
		"policy of another org":      {Version: 8, PolicyOrgs: []string{"org-b"}, Current: FactSet{Policies: []PolicyArtifact{policyFixture("org-a", "payments", "x")}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ApplyChanges(base, strings.Repeat("cd", 32), header, c); err == nil {
				t.Fatal("incoherent change set applied")
			}
		})
	}
}

// incrementalSource is a FactSource that also exports changes.
type incrementalSource struct {
	mu       sync.Mutex
	snapshot Snapshot
	full     int
	partial  int
	versions int
	acks     []AppliedState
	forceAll bool
}

func (s *incrementalSource) NodePolicyVersion(context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions++
	return s.snapshot.Version, nil
}
func (s *incrementalSource) ExportNodePolicySnapshot(_ context.Context, n Network, at time.Time, lifetime time.Duration) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.full++
	out := cloneSnapshot(s.snapshot)
	out.Header = Header{Network: n, IssuedAt: at.Unix(), ExpiresAt: at.Add(lifetime).Unix()}
	return out, nil
}
func (s *incrementalSource) ExportNodePolicyChanges(_ context.Context, base Snapshot) (FactChanges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.partial++
	if s.forceAll {
		return FactChanges{Version: s.snapshot.Version, Full: true}, nil
	}
	return changesBetween(base, s.snapshot), nil
}
func (s *incrementalSource) AcknowledgeNodePolicy(_ context.Context, _ string, state AppliedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks = append(s.acks, state)
	return nil
}
func (s *incrementalSource) change(fn func(*Snapshot)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.snapshot)
	s.snapshot.Version++
}

func incrementalFixture(t *testing.T, wake <-chan struct{}) (*Publisher, *incrementalSource, *memoryNode) {
	t.Helper()
	now := time.Unix(1020, 0)
	s := &incrementalSource{snapshot: richSnapshot()}
	n := &memoryNode{verifier: testVerifier()}
	n.verifier.Now = func() time.Time { return now }
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return now }, Wake: wake})
	if err != nil {
		t.Fatal(err)
	}
	return p, s, n
}

func TestPublisherSendsIncrementalExportsAsDeltas(t *testing.T) {
	p, s, n := incrementalFixture(t, nil)
	ctx := context.Background()
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	s.change(func(x *Snapshot) { x.Principals[0].Banned = true })
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if s.full != 1 || s.partial != 1 || n.kinds[1] != "delta" {
		t.Fatalf("full=%d partial=%d kinds=%v", s.full, s.partial, n.kinds)
	}
	v, err := n.feed.Pin(n.verifier.clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(identityFixture(), n.verifier.clock()); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("incremental revocation not applied: %v", err)
	}
	// An incomplete change log falls back to the full export.
	s.forceAll = true
	s.change(func(x *Snapshot) { x.Principals[0].Banned = false })
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if s.full != 2 || n.kinds[2] != "delta" {
		t.Fatalf("fallback: full=%d kinds=%v", s.full, n.kinds)
	}
	if got := n.feed.current.Snapshot(); got.Principals[0].Banned {
		t.Fatal("fallback export not applied")
	}
}

// The checkpoint snapshot after the delta budget is a fresh full export, so
// a long incremental run re-anchors on the database every checkpoint.
func TestPublisherCheckpointIsAFreshFullExport(t *testing.T) {
	p, s, n := incrementalFixture(t, nil)
	ctx := context.Background()
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCheckpointDeltas+1; i++ {
		s.change(func(x *Snapshot) { x.Principals[0].KYC = !x.Principals[0].KYC })
		if err := p.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n.kinds[maxCheckpointDeltas+1] != "snapshot" || s.full != 2 {
		t.Fatalf("checkpoint kinds=%v full=%d", n.kinds[maxCheckpointDeltas-1:], s.full)
	}
}

// blockingNode lets a test hold a publication in flight.
type blockingNode struct {
	*memoryNode
	mu      sync.Mutex
	gate    chan struct{}
	arrived chan struct{}
	applied chan uint64
}

func (b *blockingNode) ApplyPolicy(ctx context.Context, wire []byte) (AppliedState, error) {
	b.mu.Lock()
	gate := b.gate
	b.mu.Unlock()
	if gate != nil {
		b.arrived <- struct{}{}
		<-gate
	}
	b.mu.Lock()
	ack, err := b.memoryNode.ApplyPolicy(ctx, wire)
	b.mu.Unlock()
	if err == nil {
		b.applied <- ack.Version
	}
	return ack, err
}
func (b *blockingNode) PolicyStatus(ctx context.Context) (NodeStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.memoryNode.PolicyStatus(ctx)
}

// G3: a notification publishes at once, without waiting for the heartbeat
// timer, and any number of notifications during a publication cause at most
// one more.
func TestPublisherPublishesOnNotifyAndCoalesces(t *testing.T) {
	wake := make(chan struct{}, 1)
	notify := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	now := time.Unix(1020, 0)
	s := &incrementalSource{snapshot: richSnapshot()}
	node := &blockingNode{memoryNode: &memoryNode{verifier: testVerifier()}, applied: make(chan uint64, 16), arrived: make(chan struct{}, 1)}
	node.verifier.Now = func() time.Time { return now }
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: node, Lifetime: time.Minute, Now: func() time.Time { return now }, Wake: wake})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx, 20*time.Second, nil) }()
	defer func() { cancel(); <-done }()
	applied := func(what string) uint64 {
		t.Helper()
		select {
		case v := <-node.applied:
			return v
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: not published without the timer", what)
			return 0
		}
	}
	applied("bootstrap")

	s.change(func(x *Snapshot) { x.Principals[0].Banned = true })
	started := time.Now()
	notify()
	if v := applied("notified change"); v != s.snapshot.Version {
		t.Fatalf("published %d", v)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("notification took %v", took)
	}

	// Hold the next publication, then notify many times.
	gate := make(chan struct{})
	node.mu.Lock()
	node.gate = gate
	node.mu.Unlock()
	s.change(func(x *Snapshot) { x.Principals[0].Banned = false })
	notify()
	select {
	case <-node.arrived: // the tick is now waiting at the gate
	case <-time.After(2 * time.Second):
		t.Fatal("the notified publication did not start")
	}
	s.mu.Lock()
	ticksBefore := s.versions
	s.mu.Unlock()
	for i := 0; i < 50; i++ {
		s.change(func(x *Snapshot) { x.Principals[0].KYC = !x.Principals[0].KYC })
		notify()
	}
	node.mu.Lock()
	node.gate = nil
	node.mu.Unlock()
	close(gate)
	applied("held publication")
	if v := applied("coalesced follow-up"); v != s.snapshot.Version {
		t.Fatalf("coalesced publication carried %d, want %d", v, s.snapshot.Version)
	}
	time.Sleep(300 * time.Millisecond)
	s.mu.Lock()
	ticks := s.versions - ticksBefore
	s.mu.Unlock()
	if ticks != 1 {
		t.Fatalf("50 notifications during one publication caused %d further ticks, want 1", ticks)
	}
	select {
	case v := <-node.applied:
		t.Fatalf("extra publication %d", v)
	default:
	}
}

// divergingSource drops one change from its change log, as a defective
// trigger would, and records republication requests.
type divergingSource struct {
	incrementalSource
	dropNext    bool
	republished int
}

func (s *divergingSource) ExportNodePolicyChanges(ctx context.Context, base Snapshot) (FactChanges, error) {
	c, err := s.incrementalSource.ExportNodePolicyChanges(ctx, base)
	if s.dropNext {
		s.dropNext = false
		c.Principals, c.Current.Principals = nil, nil
	}
	return c, err
}
func (s *divergingSource) RequestFullNodePolicyExport(context.Context) error {
	s.republished++
	s.change(func(*Snapshot) {})
	s.forceAll = true
	return nil
}

// A divergence between the incrementally published facts and the database
// is found by the periodic full comparison and corrected by a full export.
func TestPublisherDetectsIncrementalDivergenceAndRepublishes(t *testing.T) {
	now := time.Unix(1020, 0)
	s := &divergingSource{incrementalSource: incrementalSource{snapshot: richSnapshot()}}
	n := &memoryNode{verifier: testVerifier()}
	n.verifier.Now = func() time.Time { return now }
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	s.dropNext = true
	s.change(func(x *Snapshot) { x.Principals[0].Banned = true; x.Sanctions = x.Sanctions[:1] })
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, principal := range p.last.Principals {
		if principal.ID == "user-a" && principal.Banned {
			t.Fatal("fixture did not diverge")
		}
	}
	now = now.Add(fullExportEvery)
	if err := p.Tick(ctx); !errors.Is(err, ErrFactDivergence) || s.republished != 1 {
		t.Fatalf("divergence not detected: %v (republished %d)", err, s.republished)
	}
	if err := p.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	v, err := n.feed.Pin(now)
	if err != nil {
		t.Fatal(err)
	}
	identity := identityFixture()
	identity.IssuedAt, identity.ExpiresAt = now.Unix(), now.Unix()+60
	if _, err := v.Resolve(identity, now); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("the republication did not correct the node: %v", err)
	}
}

// failingSource fails its incremental export.
type failingSource struct {
	incrementalSource
}

func (s *failingSource) ExportNodePolicyChanges(context.Context, Snapshot) (FactChanges, error) {
	return FactChanges{}, errors.New("change log unreadable")
}

// An incremental export that fails is replaced by a full export in the same
// publication, so facts never wait for the next checkpoint.
func TestPublisherFallsBackToAFullExportWhenTheIncrementalOneFails(t *testing.T) {
	now := time.Unix(1020, 0)
	s := &failingSource{incrementalSource{snapshot: richSnapshot()}}
	n := &memoryNode{verifier: testVerifier()}
	n.verifier.Now = func() time.Time { return now }
	p, err := NewPublisher(PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.change(func(x *Snapshot) { x.Principals[0].Banned = true })
	if err := p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.full != 2 || n.kinds[1] != "delta" || !n.feed.current.Snapshot().Principals[0].Banned {
		t.Fatalf("full=%d kinds=%v", s.full, n.kinds)
	}
}

// A publisher that starts against a node already holding facts (a restart or
// a failover) cannot know whether they were built incrementally and match the
// database, so it asks for a full export once.
func TestNewPublisherReanchorsANodeItDidNotPublish(t *testing.T) {
	now := time.Unix(1020, 0)
	s := &divergingSource{incrementalSource: incrementalSource{snapshot: richSnapshot()}}
	n := &memoryNode{verifier: testVerifier()}
	n.verifier.Now = func() time.Time { return now }
	config := PublisherConfig{Network: identityFixture().Network, ConsumerID: "producer", Signer: testSigner(), Source: s, Node: n, Lifetime: time.Minute, Now: func() time.Time { return now }}
	first, err := NewPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewPublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := restarted.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.republished != 1 || n.kinds[1] != "heartbeat" || n.kinds[2] != "snapshot" || n.kinds[3] != "heartbeat" {
		t.Fatalf("republished=%d kinds=%v", s.republished, n.kinds)
	}
}
