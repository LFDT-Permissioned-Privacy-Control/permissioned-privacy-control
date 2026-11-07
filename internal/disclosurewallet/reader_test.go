package disclosurewallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	w "privacy-proxy/internal/walletops"
)

type testStore struct {
	facts  []w.OwnershipFact
	calls  int
	actors []string
	err    error
}

func (s *testStore) LoadActiveMany(_ context.Context, _ w.Namespace, _ w.ExpectedState, actors []string) ([]w.OwnershipFact, error) {
	s.calls++
	s.actors = slices.Clone(actors)
	return s.facts, s.err
}
func testActor(b byte) string {
	return "ops:p1:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}
func testConfig(store w.MultiReader, clock *time.Time) Config {
	binding := w.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: fmt.Sprintf("0x%064x", 1), DeploymentID: "b0-public-fixture"}
	net, _ := (d.NetworkBinding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}).Key()
	var plan [32]byte
	copy(plan[:], bytes.Repeat([]byte{0x22}, 32))
	return Config{Store: store, Binding: binding, ExpectedState: w.ExpectedState{Generation: "11111111-1111-4111-8111-111111111111", Coverage: sha256.Sum256([]byte("ops.wallet.empty-source/v1"))}, Plan: d.SourcePlan{Version: 1, Profile: "ops.disclosure.data-sources/v1", NetworkKey: digest(net), BundleDigest: digest([32]byte{3}), PlanDigest: digest(plan), Resources: []p.Resource{p.ActivityLogs, p.ActivitySummary, p.AddressHistory, p.ComplianceReport, p.SanctionsReport, p.Transactions}}, Clock: func() time.Time { return *clock }}
}
func testScope(t *testing.T, c Config, targets []string, recipient string, resource p.Resource) d.ReadScope {
	t.Helper()
	s := p.Scope{TargetActors: targets, Resources: []p.Resource{resource}, Addresses: p.Addresses{Mode: "all-target-addresses", Values: []string{}}, DataTime: p.Interval{Start: 1600000000, End: 1900000000}, Level: p.Full}
	view := d.List
	if resource == p.ActivitySummary || resource == p.ComplianceReport || resource == p.SanctionsReport {
		view = d.Report
	}
	n, err := d.Normalize(d.Query{Version: 1, Resource: resource, View: view}, s)
	if err != nil {
		t.Fatal(err)
	}
	return d.ReadScope{Namespace: digest([32]byte{4}), CaseID: "22222222-2222-4222-8222-222222222222", CaseVersion: 1, RecipientActorID: recipient, DataOrganizationID: "33333333-3333-4333-8333-333333333333", BundleDigest: c.Plan.BundleDigest, RuleDigest: digest([32]byte{5}), EffectiveUntil: time.Unix(1900000000, 0).UTC(), Query: n}
}
func testFact(c Config, actor string, n byte) w.OwnershipFact {
	ns, _ := c.Binding.Namespace()
	return w.OwnershipFact{Namespace: ns, Actor: actor, Address: common.BytesToAddress([]byte{n}), ProofVersion: 2, VerifiedAt: time.UnixMicro(1700000000123456).UTC()}
}

func TestColdConfigurationAndScopeFailBeforeRead(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	for _, cell := range []struct {
		name string
		edit func(*Config)
	}{
		{"nil reader", func(c *Config) { c.Store = nil }},
		{"typed nil reader", func(c *Config) { var s *testStore; c.Store = s }},
		{"nil clock", func(c *Config) { c.Clock = nil }},
		{"invalid clock", func(c *Config) { c.Clock = func() time.Time { return time.Time{} } }},
		{"generation", func(c *Config) { c.ExpectedState.Generation = "bad" }},
		{"origin", func(c *Config) { c.Binding.ServiceOrigin = "http://ops.test" }},
		{"network pairing", func(c *Config) { c.Binding.DeploymentID = "different" }},
		{"oversized chain", func(c *Config) { c.Binding.ChainID = "18446744073709551616" }},
		{"bundle", func(c *Config) { c.Plan.BundleDigest = "invalid" }},
		{"plan", func(c *Config) { c.Plan.PlanDigest = "invalid" }},
		{"profile", func(c *Config) { c.Plan.Profile = "unknown" }},
		{"resource order", func(c *Config) { c.Plan.Resources = []p.Resource{p.Transactions, p.AddressHistory} }},
		{"resource duplicate", func(c *Config) { c.Plan.Resources = []p.Resource{p.Transactions, p.Transactions} }},
		{"empty resources", func(c *Config) { c.Plan.Resources = nil }},
	} {
		t.Run(cell.name, func(t *testing.T) {
			store := &testStore{}
			c := testConfig(store, &now)
			cell.edit(&c)
			if _, err := New(c); !errors.Is(err, d.ErrInvalid) || store.calls != 0 {
				t.Fatal(err, store.calls)
			}
		})
	}
	store := &testStore{}
	c := testConfig(store, &now)
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range []struct {
		name string
		edit func(*d.ReadScope)
	}{
		{"namespace", func(s *d.ReadScope) { s.Namespace = "bad" }},
		{"case", func(s *d.ReadScope) { s.CaseID = "bad" }},
		{"version", func(s *d.ReadScope) { s.CaseVersion = 0 }},
		{"recipient", func(s *d.ReadScope) { s.RecipientActorID = "bad" }},
		{"data org", func(s *d.ReadScope) { s.DataOrganizationID = "bad" }},
		{"bundle", func(s *d.ReadScope) { s.BundleDigest = digest([32]byte{9}) }},
		{"rule", func(s *d.ReadScope) { s.RuleDigest = "bad" }},
		{"query", func(s *d.ReadScope) { s.Query = d.NormalizedQuery{} }},
		{"expiry", func(s *d.ReadScope) { s.EffectiveUntil = time.Time{} }},
	} {
		t.Run(cell.name, func(t *testing.T) {
			scope := testScope(t, c, []string{testActor(1)}, testActor(2), p.AddressHistory)
			cell.edit(&scope)
			if _, err := r.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrInvalid) || store.calls != 0 {
				t.Fatal(err, store.calls)
			}
		})
	}
	for _, resource := range []p.Resource{p.ActivityLogs, p.ActivitySummary} {
		scope := testScope(t, c, []string{testActor(1)}, testActor(2), resource)
		if _, err := r.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnsupported) || store.calls != 0 {
			t.Fatal(resource, err, store.calls)
		}
	}
	scope := testScope(t, c, []string{testActor(1)}, testActor(2), p.AddressHistory)
	for _, ref := range []d.SourceRef{{Kind: d.HistorySource, ID: digest([32]byte{1})}, {Kind: d.WalletSource, ID: "bad"}} {
		if _, err := r.Open(t.Context(), scope, &ref); !errors.Is(err, d.ErrInvalid) || store.calls != 0 {
			t.Fatal(err, store.calls)
		}
	}
}

func TestExactIndependentReferenceVectorsAndCurrentness(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	store := &testStore{}
	c := testConfig(store, &now)
	store.facts = []w.OwnershipFact{testFact(c, testActor(2), 1), testFact(c, testActor(1), 1)}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope(t, c, []string{testActor(1)}, testActor(2), p.AddressHistory)
	s, err := r.Open(t.Context(), scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := d.Digest("sha256:cf371c562c64c8b993c1af2e3ca668d9a63b6c4ab921048cdc519ea68a69cfd6")
	if s.Descriptor().Reference != want || s.Descriptor().NetworkKey != "sha256:5b88ce92db9ce0580c5851312b42a2ea38b7d32a76a2befcd995bb443f887a0f" || s.Descriptor().Epoch != "sha256:6ee64b56586d72490687d370d4196f22e7cace5e80a711942d13d111ec447339" || s.Descriptor().FormatDigest != "sha256:091e5911965ee71da9464ec726d5a6e99e0332206889983c83f6ddee5c7df646" {
		t.Fatal(s.Descriptor())
	}
	if _, err := d.SourceReferences([]d.SourceDescriptor{s.Descriptor()}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(store.actors, []string{testActor(1), testActor(2)}) || s.Wallets()[0].ActorID != testActor(1) {
		t.Fatal(store.actors, s.Wallets())
	}
	old := s.Descriptor()
	now = time.Unix(1600000000, 0).UTC() // even earlier than stored acceptance
	if err := s.CheckCurrent(t.Context()); err != nil || s.Descriptor() != old {
		t.Fatal("rollback changed immutable observation", err)
	}
	ref := d.SourceRef{Kind: d.WalletSource, ID: want}
	resumed, err := r.Open(t.Context(), scope, &ref)
	if err != nil || resumed.Descriptor().Reference != want || !resumed.Descriptor().AsOf.Equal(now) {
		t.Fatal("stable resume", err)
	}
	// Root independently checked this EXACT delta: original sorted tuple0 +1 microsecond.
	store.facts[1].VerifiedAt = store.facts[1].VerifiedAt.Add(time.Microsecond)
	changed, err := r.Open(t.Context(), scope, nil)
	if err != nil || changed.Descriptor().Reference != "sha256:aba203d833e1100489fa907f23a015ffe284a7bac9a0c871fbc9942aad78eaae" {
		t.Fatal("changed timestamp vector", err)
	}
	if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := r.Open(t.Context(), scope, &ref); !errors.Is(err, d.ErrConflict) {
		t.Fatal(err)
	}
	store.facts = nil
	empty, err := r.Open(t.Context(), scope, nil)
	if err != nil || empty.Wallets() == nil || len(empty.Wallets()) != 0 || empty.Descriptor().Reference != "sha256:7e3ae1a77a255ea2b667c9639b8ead9d1ebf20988dbafb0e57b3cf330f6a749b" {
		t.Fatal("zero snapshot", err)
	}
	store.facts = []w.OwnershipFact{testFact(c, testActor(1), 1)}
	withZero, _ := r.Open(t.Context(), scope, nil)
	if withZero.Descriptor().Reference != "sha256:e9e35fd0fe4649d7d73e4fef690d327fb4f9555e3efa9419a5ffc3de84f2de78" {
		t.Fatal(withZero.Descriptor())
	}
	one, _ := r.Open(t.Context(), testScope(t, c, []string{testActor(1)}, testActor(1), p.AddressHistory), nil)
	if one.Descriptor().Reference != "sha256:769ee53f1435c22fb093bf0da5e5a5b70b16475cd78442f23fd4ea181736c399" {
		t.Fatal(one.Descriptor())
	}
	// Every getter is detached; no recheck or caller mutation rewrites the sample.
	wallets := one.Wallets()
	wallets[0].ActorID = "bad"
	if one.Wallets()[0].ActorID != testActor(1) {
		t.Fatal("aliased wallets")
	}
	one.Close()
	one.Close()
}

func TestFactsBoundsValidationAndUnion(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	store := &testStore{}
	c := testConfig(store, &now)
	r, _ := New(c)
	scope := testScope(t, c, []string{testActor(1)}, testActor(2), p.AddressHistory)
	for _, cell := range []struct {
		name string
		edit func(*w.OwnershipFact)
	}{
		{"namespace", func(f *w.OwnershipFact) { f.Namespace[0] ^= 1 }},
		{"unselected actor", func(f *w.OwnershipFact) { f.Actor = testActor(3) }},
		{"proof", func(f *w.OwnershipFact) { f.ProofVersion = 1 }},
		{"zero time", func(f *w.OwnershipFact) { f.VerifiedAt = time.Time{} }},
		{"pre epoch", func(f *w.OwnershipFact) { f.VerifiedAt = time.Unix(-1, 0) }},
		{"submicro time", func(f *w.OwnershipFact) { f.VerifiedAt = f.VerifiedAt.Add(time.Nanosecond) }},
		{"beyond time", func(f *w.OwnershipFact) { f.VerifiedAt = time.Unix(p.MaxUnixSeconds+1, 0) }},
	} {
		t.Run(cell.name, func(t *testing.T) {
			f := testFact(c, testActor(1), 1)
			cell.edit(&f)
			store.facts = []w.OwnershipFact{f}
			if _, err := r.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
	fact := testFact(c, testActor(1), 1)
	store.facts = []w.OwnershipFact{fact, fact}
	if _, err := r.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("duplicate", err)
	}
	store.facts = make([]w.OwnershipFact, 4097)
	if _, err := r.Open(t.Context(), scope, nil); !errors.Is(err, d.ErrTooBroad) {
		t.Fatal("sentinel must fail before tuple work", err)
	}
	store.facts = make([]w.OwnershipFact, 4096)
	for i := range store.facts {
		f := fact
		f.Address = common.HexToAddress(fmt.Sprintf("0x%040x", i))
		store.facts[i] = f
	}
	s, err := r.Open(t.Context(), scope, nil)
	if err != nil || len(s.Wallets()) != 4096 {
		t.Fatal("exact bound", err)
	}
	store.err = w.ErrUnavailable
	if err := s.CheckCurrent(t.Context()); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal(err)
	}
	store.err = nil
	store.facts = nil
	actors := make([]string, 256)
	for i := range actors {
		raw := sha256.Sum256([]byte(fmt.Sprint(i)))
		actors[i] = "ops:p1:" + base64.RawURLEncoding.EncodeToString(raw[:])
	}
	_, err = r.Open(t.Context(), testScope(t, c, actors, testActor(2), p.AddressHistory), nil)
	if err != nil || len(store.actors) != 257 {
		t.Fatal("one257 actor union", len(store.actors), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := store.calls
	if _, err := r.Open(ctx, scope, nil); !errors.Is(err, d.ErrUnavailable) || store.calls != calls {
		t.Fatal("cancel before read", err)
	}
	// A configured plan is detached, and timestamps in a non-UTC location retain
	// the exact microsecond instant rather than acquiring an observation time.
	c.Plan.Resources[2] = p.Events
	fact.VerifiedAt = fact.VerifiedAt.In(time.FixedZone("test", 3600))
	store.facts = []w.OwnershipFact{fact}
	normalized, err := r.Open(t.Context(), scope, nil)
	if err != nil || normalized.Wallets()[0].AcceptedAt.Location() != time.UTC || !normalized.Wallets()[0].AcceptedAt.Equal(fact.VerifiedAt) {
		t.Fatal("UTC normalization/config alias", err)
	}
}

func TestExistingCursorBindsCurrentWalletReference(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	store := &testStore{}
	c := testConfig(store, &now)
	store.facts = []w.OwnershipFact{testFact(c, testActor(1), 1)}
	r, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	scope := testScope(t, c, []string{testActor(1)}, testActor(2), p.AddressHistory)
	s, err := r.Open(t.Context(), scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	// This synthetic history descriptor tests ONLY A cursor composition. It is
	// not history evidence or an implemented serving source.
	history := s.Descriptor()
	history.Kind = d.HistorySource
	history.Reference = digest([32]byte{0x70})
	history.Population = "CURRENT_SCOPED_WALLET_HISTORY"
	descriptors := []d.SourceDescriptor{history, s.Descriptor()}
	set, err := d.SourceSetDigest(descriptors, p.AddressHistory, d.List)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := d.SourceReferences(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	renderGeneration, err := d.RenderGeneration(d.Keys{Active: d.Key{ID: "render", Bytes: bytes.Repeat([]byte{0x33}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	binding := d.CursorBinding{Namespace: scope.Namespace, CaseID: scope.CaseID, CaseVersion: scope.CaseVersion, RecipientActorID: scope.RecipientActorID, BundleDigest: scope.BundleDigest, RuleDigest: scope.RuleDigest, QueryDigest: scope.Query.Digest(), SourcePlanDigest: c.Plan.PlanDigest, RenderGeneration: renderGeneration}
	cursor, err := d.NewCursor(d.Keys{Active: d.Key{ID: "data", Bytes: bytes.Repeat([]byte{0x55}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	position := d.Position{Kind: d.WalletSource, Address: &d.AddressPosition{Address: [20]byte(common.BytesToAddress([]byte{1}))}}
	raw, err := cursor.Seal(binding, set, refs, position, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	continuation, err := cursor.Open(raw, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := continuation.References()[1]
	resumed, err := r.Open(t.Context(), scope, &expected)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := []d.SourceDescriptor{history, resumed.Descriptor()}
	stable, err := d.SourceSetDigest(unchanged, p.AddressHistory, d.List)
	if err != nil || continuation.VerifySourceSet(stable) != nil {
		t.Fatal("fresh observation broke A source-set identity", err)
	}
	store.facts = nil
	if _, err := r.Open(t.Context(), scope, &expected); !errors.Is(err, d.ErrConflict) {
		t.Fatal("cursor retained an unlinked wallet", err)
	}
	store.err = w.ErrUnavailable
	if _, err := r.Open(t.Context(), scope, &expected); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("unready source became valid zero", err)
	}
}
