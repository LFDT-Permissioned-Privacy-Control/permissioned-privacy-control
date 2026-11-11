package historyfacts

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/explorerdata"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/readprivacy"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
)

type walletStore struct {
	facts []walletops.OwnershipFact
	loads int
	after func()
}

func (s *walletStore) WithActorTransaction(context.Context, walletops.Namespace, walletops.ExpectedState, string, func(walletops.ActorTx) error) error {
	return ErrUnavailable
}
func (s *walletStore) ResolveActiveActors(context.Context, walletops.Namespace, walletops.ExpectedState, common.Address, int) ([]string, error) {
	return nil, ErrUnavailable
}
func (s *walletStore) LoadActive(_ context.Context, ns walletops.Namespace, _ walletops.ExpectedState, actor string, _ int) ([]walletops.OwnershipFact, error) {
	s.loads++
	if s.after != nil {
		s.after()
	}
	return append([]walletops.OwnershipFact{}, s.facts...), nil
}

type shareSource struct {
	meta  ShareMetadata
	rows  []a.Share
	reads int
}

type shareTrap struct{ meta ShareMetadata }

func (s shareTrap) Metadata() ShareMetadata { return s.meta }
func (s shareTrap) Read(context.Context, ShareQuery) (*SharePass, error) {
	panic("strict called unused share reader")
}
func (s shareTrap) Recheck(context.Context, *SharePass) error {
	panic("strict rechecked unused share reader")
}

func (s *shareSource) Metadata() ShareMetadata { return s.meta }
func (s *shareSource) Read(ctx context.Context, q ShareQuery) (*SharePass, error) {
	s.reads++
	fence, err := q.OperationFence(ctx)
	if err != nil {
		return nil, err
	}
	return NewSharePass(s.meta.Identity, s.meta.Binding, q, s.rows, fence)
}
func (s *shareSource) Recheck(ctx context.Context, p *SharePass) error {
	if p.ValidateFor(s.meta.Identity, s.meta.Binding) != nil {
		return ErrUnavailable
	}
	next, err := s.Read(ctx, p.Query())
	if err != nil || !p.SamePositives(next) {
		return ErrUnavailable
	}
	return nil
}

type fixture struct {
	config    Config
	wallets   *walletStore
	shares    *shareSource
	clock     atomic.Int64
	a, b, own common.Address
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	x := &fixture{a: common.HexToAddress("0x1234"), b: common.HexToAddress("0x5678"), own: common.HexToAddress("0x9876")}
	x.clock.Store(f.Now)
	src := f.DefaultStateFixture(t)
	ca := f.ReadContract(x.a.Hex())
	ca.ReadGrants[0].EventRules.Mode = "all"
	cb := f.ReadContract(x.b.Hex())
	cb.ID = "99999999-9999-9999-9999-999999999998"
	cb.ReadGrants = []policybundle.ReadGrant{}
	src.Contracts[f.Org] = []policybundle.Contract{ca}
	src.Contracts[f.OtherOrg] = []policybundle.Contract{cb}
	for i := range src.Groups[f.OtherOrg] {
		src.Groups[f.OtherOrg][i].AllowedMethods = []string{"eth_getBalance"}
	}
	snapshot := f.StateSnapshot(t, src)
	x.config = Config{Snapshot: snapshot, Clock: func() time.Time { return time.Unix(x.clock.Load(), 0) }, Network: networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: common.HexToHash("0x1").Hex(), DeploymentID: "history-test"}}
	x.config.WalletBinding = walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: x.config.Network.GenesisHash, DeploymentID: "history-test"}
	x.config.WalletState = walletops.ExpectedState{Generation: "11111111-1111-1111-1111-111111111111"}
	ns, _ := x.config.WalletBinding.Namespace()
	x.wallets = &walletStore{facts: []walletops.OwnershipFact{{Namespace: ns, Actor: f.Actor(f.Subject), Address: x.own, ProofVersion: 2, VerifiedAt: time.Unix(f.Now, 0)}}}
	x.config.Wallets, _ = walletadapter.New(x.wallets, ns, x.config.WalletState, x.config.Clock)
	x.config.ShareExpected = ShareBinding{Network: x.config.Network, State: a.ExpectedState{Generation: "22222222-2222-2222-2222-222222222222"}, SchemaProfile: ShareSchemaProfile}
	x.shares = &shareSource{meta: ShareMetadata{Binding: x.config.ShareExpected, Mode: "reader", Identity: NewReaderIdentity()}}
	x.config.Shares = x.shares
	return x
}
func (x *fixture) begin(t *testing.T, roles ...string) *Current {
	t.Helper()
	factory, err := New(x.config)
	if err != nil {
		t.Fatal(err)
	}
	c, err := factory.Begin(t.Context(), f.Token(t, x.config.Snapshot, f.Subject, roles...), f.Org, "eth_getCode")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func fixtureShare(t *testing.T, b ShareBinding, hash common.Hash, recipient string) a.Share {
	t.Helper()
	recipients, digest, err := a.NormalizeRecipients([]string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := b.Network.Key()
	return a.Share{Network: a.Digest(key), Hash: hash, Actor: f.Actor(f.AdminSubject), Organization: f.Org, Recipients: recipients, RecipientDigest: digest, DeclaredAt: time.Unix(f.Now, 0), Witness: a.Witness{AnchorHash: common.Hash{1}, ManifestDigest: a.Digest{2}, WalletVersion: a.Digest{3}, WalletEvidenceAt: time.Unix(f.Now, 0)}}
}

func TestCurrentSelectedOrgPlainAddressAndEventAuthority(t *testing.T) {
	x := newFixture(t)
	c := x.begin(t, "Auditor", "Foreign")
	if c.Address(x.a).Reason != explorerdata.ReasonRBACGroupMember || !c.Emitter(x.a).HasGrant || c.Emitter(x.a).VisibleToUnlock || c.Emitter(x.a).Admin || !c.Emitter(x.a).Rules.IsWildcard() {
		t.Fatal("approved current read grant lost")
	}
	if c.Address(x.b).Level != explorerdata.VisibilityRedacted || c.Emitter(x.b).HasGrant || c.AdminForDataset(x.b) {
		t.Fatal("BankA method borrowed BankB authority")
	}
	if c.Address(x.own).Reason != explorerdata.ReasonOwnAddress || c.Emitter(x.own).HasGrant || c.AdminForDataset(x.own) {
		t.Fatal("own/plain Full became event/admin authority")
	}
	if c.Address(common.Address{19: 18}).Level != explorerdata.VisibilityHidden || c.Address(common.Address{}).Level != explorerdata.VisibilityHidden || c.Address(common.Address{19: 9}).Reason != explorerdata.ReasonPublicAddress {
		t.Fatal("sparse/unknown address became public")
	}
	for n := byte(10); n <= 17; n++ {
		if c.Address(common.Address{19: n}).Level != explorerdata.VisibilityHidden || c.Emitter(common.Address{19: n}).HasGrant {
			t.Fatal("unqualified later native precompile widened history visibility", n)
		}
	}
	admin := x.begin(t, "Admin", "Foreign")
	if !admin.AdminForDataset(x.a) || admin.AdminForDataset(x.b) || admin.AdminForDataset(x.own) || admin.AdminForDataset(common.Address{19: 22}) {
		t.Fatal("admin dataset owner fence")
	}
	readonly := x.begin(t, "Readonly")
	if readonly.Emitter(x.a).HasGrant || readonly.AdminForDataset(x.a) || readonly.Address(x.a).Level == explorerdata.VisibilityFull {
		t.Fatal("readonly admin manufactured association")
	}
	if err := c.Recheck(t.Context()); err != nil {
		t.Fatal("unchanged original wallet", err)
	}
	before := x.wallets.loads
	factory, _ := New(x.config)
	if _, err := factory.Begin(t.Context(), f.Token(t, x.config.Snapshot, f.Subject, "Auditor", "Foreign"), f.OtherOrg, "eth_getCode"); err == nil || x.wallets.loads != before {
		t.Fatal("denied selected method performed wallet I/O")
	}
}

func TestCurrentIndependentColdBindingsAndOriginalTokenCapture(t *testing.T) {
	x := newFixture(t)
	for _, change := range []func(*Config){func(c *Config) { c.WalletBinding.ServiceOrigin = "https://other.test" }, func(c *Config) { c.WalletState.Generation = "33333333-3333-3333-3333-333333333333" }, func(c *Config) { c.ShareExpected.State.Coverage[0] = 1 }, func(c *Config) { c.ShareExpected.SchemaProfile = "other" }, func(c *Config) { c.Network.DeploymentID = "other" }} {
		config := x.config
		change(&config)
		if _, err := New(config); err == nil {
			t.Fatal("wrong independent binding accepted")
		}
	}
	if x.wallets.loads != 0 || x.shares.reads != 0 {
		t.Fatal("cold mismatch made source I/O")
	}
	factory, _ := New(x.config)
	raw := f.Token(t, x.config.Snapshot, f.Subject, "Auditor")
	c, err := factory.Begin(t.Context(), raw, f.Org, "eth_getCode")
	if err != nil {
		t.Fatal(err)
	}
	if c.AuthCapture() != sha256.Sum256([]byte(raw)) || !factory.UsesSnapshot(x.config.Snapshot) {
		t.Fatal("original auth capture/snapshot missing")
	}
	for _, raw := range []string{"", raw + "bad"} {
		if _, err := factory.Begin(t.Context(), raw, f.Org, "eth_getCode"); err == nil {
			t.Fatal("invalid bearer accepted")
		}
	}
	x.wallets.facts = nil
	if c.Recheck(t.Context()) == nil {
		t.Fatal("unlinked wallet accepted")
	}
}

func TestCurrentSharesOriginalFenceExpiryAndNoRecipientTransfer(t *testing.T) {
	x := newFixture(t)
	hash := common.Hash{9}
	x.shares.rows = []a.Share{fixtureShare(t, x.config.ShareExpected, hash, f.Actor(f.Subject))}
	c := x.begin(t, "Auditor")
	with, err := c.WithShares(t.Context(), []common.Hash{hash})
	if err != nil || !with.Listed(hash) {
		t.Fatal("actual immutable recipient", err)
	}
	if err := with.Recheck(t.Context()); err != nil {
		t.Fatal("temporary acquisition child canceled pass", err)
	}
	mutated, _ := with.shares.Share(hash)
	mutated.Recipients[0] = f.Actor(f.AdminSubject)
	if !with.Listed(hash) {
		t.Fatal("getter mutated immutable recipients")
	}
	strict := *with
	factory := *with.owner
	factory.profile = readprivacy.ReadProfileStrict
	strict.owner = &factory
	if strict.Listed(hash) {
		t.Fatal("strict used share")
	}
	strict.shares = nil
	reads := x.shares.reads
	strictCopy, err := strict.WithShares(t.Context(), []common.Hash{hash})
	if err != nil || strictCopy.shares != nil || strictCopy.Listed(hash) || x.shares.reads != reads {
		t.Fatal("strict acquired or fabricated a share pass", err)
	}
	x.shares.meta.Identity = NewReaderIdentity()
	if with.Recheck(t.Context()) == nil {
		t.Fatal("source replacement accepted")
	}
	x.shares.meta.Identity = with.owner.shareIdentity
	x.wallets.after = func() { x.clock.Store(f.Now + 300) }
	if with.Recheck(t.Context()) == nil {
		t.Fatal("original View expired during final source reload")
	}
	// A short independent operation deadline survives Background and the
	// canceled acquisition child; it never starts another final budget.
	x = newFixture(t)
	x.config.Timeout = 200 * time.Millisecond
	backgroundFactory, _ := New(x.config)
	c, err = backgroundFactory.Begin(context.Background(), f.Token(t, x.config.Snapshot, f.Subject, "Auditor"), f.Org, "eth_getCode")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(210 * time.Millisecond)
	if c.Recheck(context.Background()) == nil {
		t.Fatal("Background renewed original deadline")
	}
	x = newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	factory2, _ := New(x.config)
	c, err = factory2.Begin(ctx, f.Token(t, x.config.Snapshot, f.Subject, "Auditor"), f.Org, "eth_getCode")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if c.Recheck(context.Background()) == nil {
		t.Fatal("Background lost original cancellation")
	}
}

func TestSharePassExactQueryAbsentAndWholeBudget(t *testing.T) {
	x := newFixture(t)
	fence, _ := NewFence(t.Context(), time.Second)
	hash := common.Hash{1}
	next := common.Hash{2}
	row := fixtureShare(t, x.config.ShareExpected, hash, f.Actor(f.Subject))
	q := ShareQuery{Hashes: []common.Hash{hash, next}}
	p, err := NewSharePass(x.shares.meta.Identity, x.config.ShareExpected, q, []a.Share{row}, fence)
	if err != nil {
		t.Fatal(err)
	}
	late := fixtureShare(t, x.config.ShareExpected, next, f.Actor(f.Subject))
	current, _ := NewSharePass(x.shares.meta.Identity, x.config.ShareExpected, q, []a.Share{row, late}, fence)
	if !p.SamePositives(current) {
		t.Fatal("late absent listing invalidated prior result")
	}
	if _, ok := p.Share(next); ok {
		t.Fatal("late listing widened decided pass")
	}
	row.Witness.AnchorNumber++
	changed, _ := NewSharePass(x.shares.meta.Identity, x.config.ShareExpected, q, []a.Share{row}, fence)
	if p.SamePositives(changed) || p.ValidateFor(NewReaderIdentity(), x.config.ShareExpected) == nil {
		t.Fatal("immutable binding/reader changed")
	}
	for _, q := range []ShareQuery{{Hashes: []common.Hash{hash, hash}}, {Hashes: []common.Hash{{}}}, {Hashes: make([]common.Hash, MaxShareHashes+1)}} {
		if _, err := NormalizeShareQuery(q); err == nil {
			t.Fatal("unbounded/ambiguous query")
		}
	}
	x.config.MaxBytes = 1100
	c := x.begin(t, "Auditor")
	if _, err := c.WithShares(t.Context(), []common.Hash{hash}); err == nil {
		t.Fatal("shares escaped whole lower observation budget")
	}
}

func TestCurrentStableApprovedGrantFoldAndNewRevisionRevocation(t *testing.T) {
	x := newFixture(t)
	source := f.DefaultStateFixture(t)
	contract := f.ReadContract(x.a.Hex())
	contract.ABI = json.RawMessage(`[{"type":"event","name":"Notice","anonymous":false,"inputs":[{"indexed":true,"name":"who","type":"address"}]}]`)
	topic := crypto.Keccak256Hash([]byte("Notice(address)")).Hex()
	for i, group := range []string{f.AuditorGroup, f.ReadonlyGroup} {
		id, must := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", "self"
		if i == 1 {
			id, must = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", x.a.Hex()
		}
		grant := policybundle.ReadGrant{ID: id, GroupID: group, EventRules: policybundle.EventRules{Mode: "allowlist", Rules: []policybundle.EventRule{{Topic0: topic, Name: "Notice", ParamRules: []policybundle.ParamRule{{Index: 0, MustBe: must}}}}}}
		if i == 0 {
			contract.ReadGrants = []policybundle.ReadGrant{grant}
		} else {
			contract.ReadGrants = append(contract.ReadGrants, grant)
		}
	}
	source.Contracts[f.Org] = []policybundle.Contract{contract}
	x.config.Snapshot = f.StateSnapshot(t, source)
	c := x.begin(t, "Auditor", "Readonly")
	e := c.Emitter(x.a)
	if !e.HasGrant || e.Admin || len(e.Rules.Rules) != 1 || e.Rules.Rules[0].ParamRules[0].MustBe != strings.ToLower(x.a.Hex()) {
		t.Fatal("did not fold sorted current grant IDs with preserved first-constraint rule", e)
	}
	e.Rules.Rules[0].ParamRules[0].MustBe = "mutated"
	if c.Emitter(x.a).Rules.Rules[0].ParamRules[0].MustBe == "mutated" {
		t.Fatal("mutable event facts changed snapshot")
	}
	contract.ReadGrants = []policybundle.ReadGrant{}
	source.Contracts[f.Org] = []policybundle.Contract{contract}
	x.config.Snapshot = f.StateSnapshot(t, source)
	revoked := x.begin(t, "Auditor", "Readonly")
	if revoked.Emitter(x.a).HasGrant || revoked.Address(x.a).Level == explorerdata.VisibilityFull {
		t.Fatal("new approved revision retained old grant")
	}
}

func TestSharePassMaximumFinitePopulationAndMalformedShapes(t *testing.T) {
	x := newFixture(t)
	fence, _ := NewFence(t.Context(), time.Second)
	actors := make([]string, a.MaxRecipients)
	for i := range actors {
		sum := sha256.Sum256([]byte{byte(i)})
		actors[i] = "ops:p1:" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	slices.Sort(actors)
	actors, digest, err := a.NormalizeRecipients(actors)
	if err != nil {
		t.Fatal(err)
	}
	q := ShareQuery{Hashes: make([]common.Hash, MaxShareHashes)}
	rows := make([]a.Share, MaxShareHashes)
	for i := range rows {
		binary.BigEndian.PutUint64(q.Hashes[i][24:], uint64(i+1))
		rows[i] = fixtureShare(t, x.config.ShareExpected, q.Hashes[i], actors[0])
		rows[i].Recipients = actors
		rows[i].RecipientDigest = digest
	}
	p, err := NewSharePass(x.shares.meta.Identity, x.config.ShareExpected, q, rows, fence)
	if err != nil || p.ChargedBytes() > MaxChargedBytes {
		t.Fatal("supported maximum exact population", err)
	}
	q.Hashes[0] = common.Hash{77}
	rows[0].Recipients = append(slices.Clone(actors), actors[0])
	for _, change := range []func(*a.Share){func(s *a.Share) { s.Recipients = append(slices.Clone(actors), actors[0]) }, func(s *a.Share) { s.Recipients = nil }, func(s *a.Share) { s.DeclaredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }} {
		row, _ := p.Share(p.Query().Hashes[0])
		change(&row)
		if _, err := NewSharePass(x.shares.meta.Identity, x.config.ShareExpected, p.Query(), []a.Share{row}, fence); err == nil {
			t.Fatal("malformed trusted projection accepted")
		}
	}
}

func TestStrictCurrentFactsNeedNoShareSource(t *testing.T) {
	x := newFixture(t)
	standard := x.config
	standard.Shares = nil
	if _, err := New(standard); err == nil || x.wallets.loads != 0 {
		t.Fatal("standard missing source did not fail cold")
	}
	source := f.DefaultStateFixture(t)
	source.ReadProfile = "strict"
	x.config.Snapshot = f.StateSnapshot(t, source)
	for _, shares := range []ShareReader{nil, shareTrap{x.shares.meta}} {
		config := x.config
		config.Shares = shares
		if shares == nil {
			config.ShareExpected = ShareBinding{}
		}
		factory, err := New(config)
		if err != nil {
			t.Fatal("strict startup needs no live shares", err)
		}
		c, err := factory.Begin(t.Context(), f.Token(t, config.Snapshot, f.Subject, "Auditor"), f.Org, "eth_getCode")
		if err != nil {
			t.Fatal(err)
		}
		c, err = c.WithShares(t.Context(), []common.Hash{{1}})
		if err != nil || c.shares != nil || c.Listed(common.Hash{1}) || c.Address(x.own).Reason != explorerdata.ReasonOwnAddress || c.Recheck(t.Context()) != nil {
			t.Fatal("strict own wallet depends on unused shares", err)
		}
	}
}
