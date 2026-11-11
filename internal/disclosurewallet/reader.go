// Package disclosurewallet qualifies a bounded sampled set of current
// operational wallet associations. It does not qualify historical ownership,
// historical data organization, transaction authorship or a complete report.
package disclosurewallet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
	w "privacy-proxy/internal/walletops"
)

type Config struct {
	Store         w.MultiReader // borrowed; assembly supplies walletsql.OpenReader
	Binding       w.ServiceBinding
	ExpectedState w.ExpectedState
	Plan          d.SourcePlan // exact detached whole Sources assembly plan
	Clock         identity.Clock
}

type Reader struct {
	store     w.MultiReader
	namespace w.Namespace
	state     w.ExpectedState
	plan      d.SourcePlan
	planRaw   [32]byte
	network   [32]byte
	clock     identity.Clock
}

// Snapshot holds no database transaction, connection, row lock or remote cursor.
// The initial observation remains immutable during later currentness checks.
type Snapshot struct {
	reader     *Reader
	actors     []string
	wallets    []d.WalletFact
	descriptor d.SourceDescriptor
}

func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	x := reflect.ValueOf(v)
	switch x.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return x.IsNil()
	}
	return false
}

func parseDigest(v d.Digest) ([32]byte, bool) {
	var out [32]byte
	if len(v) != 71 || !strings.HasPrefix(string(v), "sha256:") {
		return out, false
	}
	raw, err := hex.DecodeString(string(v)[7:])
	if err != nil || hex.EncodeToString(raw) != string(v)[7:] {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

func digest(raw [32]byte) d.Digest { return d.Digest("sha256:" + hex.EncodeToString(raw[:])) }
func validUUID(v string) bool {
	id, err := uuid.Parse(v)
	return err == nil && id != uuid.Nil && id.String() == v
}
func validTime(v time.Time) bool {
	return !v.IsZero() && v.Location() == time.UTC && v.Unix() >= 0 && v.Unix() <= p.MaxUnixSeconds && v.Nanosecond()%1000 == 0
}

func New(c Config) (*Reader, error) {
	return newReader(c, false)
}

// NewRetained selects the separately qualified whole retained source plan.
// Wallet facts and their meaning remain current operational associations.
func NewRetained(c Config) (*Reader, error) {
	return newReader(c, true)
}

func newReader(c Config, retained bool) (*Reader, error) {
	if nilInterface(c.Store) || c.Clock == nil || !c.ExpectedState.Valid() {
		return nil, d.ErrInvalid
	}
	ns, err := c.Binding.Namespace()
	if err != nil {
		return nil, d.ErrInvalid
	}
	net, err := (d.NetworkBinding{Environment: c.Binding.Environment, ChainID: c.Binding.ChainID, GenesisHash: c.Binding.GenesisHash, DeploymentID: c.Binding.DeploymentID}).Key()
	profileOK := c.Plan.Version == 1 && c.Plan.Profile == "ops.disclosure.data-sources/v1"
	if retained {
		profileOK = d.ValidRetainedPlan(c.Plan)
	}
	if err != nil || !profileOK || c.Plan.NetworkKey != digest(net) || len(c.Plan.Resources) < 1 || len(c.Plan.Resources) > 6 {
		return nil, d.ErrInvalid
	}
	if _, ok := parseDigest(c.Plan.BundleDigest); !ok {
		return nil, d.ErrInvalid
	}
	planRaw, ok := parseDigest(c.Plan.PlanDigest)
	if !ok {
		return nil, d.ErrInvalid
	}
	for i, resource := range c.Plan.Resources {
		if _, err := d.RequiredKinds(resource); err != nil || i > 0 && c.Plan.Resources[i-1] >= resource {
			return nil, d.ErrInvalid
		}
	}
	if !validTime(c.Clock().UTC().Truncate(time.Microsecond)) {
		return nil, d.ErrInvalid
	}
	c.Plan.Resources = slices.Clone(c.Plan.Resources)
	return &Reader{store: c.Store, namespace: ns, state: c.ExpectedState, plan: c.Plan, planRaw: planRaw, network: net, clock: c.Clock}, nil
}

func scopeActors(s d.ReadScope, plan d.SourcePlan) ([]string, error) {
	if _, ok := parseDigest(s.Namespace); !ok {
		return nil, d.ErrInvalid
	}
	if _, ok := parseDigest(s.RuleDigest); !ok {
		return nil, d.ErrInvalid
	}
	if _, ok := parseDigest(s.Query.Digest()); !ok {
		return nil, d.ErrInvalid
	}
	if !validUUID(s.CaseID) || s.CaseVersion < 1 || !validUUID(s.DataOrganizationID) || !identity.ValidActorID(s.RecipientActorID) || !validTime(s.EffectiveUntil) || s.BundleDigest != plan.BundleDigest {
		return nil, d.ErrInvalid
	}
	kinds, err := d.RequiredKinds(s.Query.Resource())
	if err != nil || !slices.Contains(plan.Resources, s.Query.Resource()) || !slices.Contains(kinds, d.WalletSource) {
		return nil, d.ErrUnsupported
	}
	targets := s.Query.Scope().TargetActors
	if len(targets) < 1 || len(targets) > 256 {
		return nil, d.ErrInvalid
	}
	for i, actor := range targets {
		if !identity.ValidActorID(actor) || i > 0 && targets[i-1] >= actor {
			return nil, d.ErrInvalid
		}
	}
	actors := append(targets, s.RecipientActorID)
	sort.Strings(actors)
	return slices.Compact(actors), nil
}

// Open derives the exact case target plus recipient union itself. The recipient
// can contribute Mine metadata; it cannot expand the authorized target scope.
func (r *Reader) Open(ctx context.Context, scope d.ReadScope, expected *d.SourceRef) (*Snapshot, error) {
	if r == nil {
		return nil, d.ErrInvalid
	}
	actors, err := scopeActors(scope, r.plan)
	if err != nil {
		return nil, err
	}
	var want d.SourceRef
	if expected != nil {
		want = *expected
		if _, ok := parseDigest(want.ID); !ok || want.Kind != d.WalletSource {
			return nil, d.ErrInvalid
		}
	}
	wallets, ref, err := r.read(ctx, actors)
	if err != nil {
		return nil, err
	}
	if expected != nil && want.ID != ref {
		return nil, d.ErrConflict
	}
	asOf := r.clock().UTC().Truncate(time.Microsecond)
	if !validTime(asOf) {
		return nil, d.ErrUnavailable
	}
	descriptor := d.SourceDescriptor{Version: 1, Kind: d.WalletSource, Reference: ref, NetworkKey: digest(r.network), Epoch: d.Digest(r.namespace.String()), Generation: r.state.Generation, PlanDigest: r.plan.PlanDigest, FormatDigest: digest(formatDigest), CoverageDigest: digest(r.state.Coverage), AsOf: asOf, Population: "CURRENT_PROVED_ASSOCIATIONS"}
	return &Snapshot{reader: r, actors: actors, wallets: wallets, descriptor: descriptor}, nil
}

func (r *Reader) read(ctx context.Context, actors []string) ([]d.WalletFact, d.Digest, error) {
	if ctx.Err() != nil {
		return nil, "", d.ErrUnavailable
	}
	facts, err := r.store.LoadActiveMany(ctx, r.namespace, r.state, slices.Clone(actors))
	if err != nil || ctx.Err() != nil {
		return nil, "", d.ErrUnavailable
	}
	if len(facts) > d.MaxWalletFacts {
		return nil, "", d.ErrTooBroad
	}
	out := make([]d.WalletFact, 0, len(facts))
	for _, fact := range facts {
		at := fact.VerifiedAt.UTC()
		if _, selected := slices.BinarySearch(actors, fact.Actor); !selected || !fact.Valid(r.namespace, fact.Actor) || !validTime(at) {
			return nil, "", d.ErrUnavailable
		}
		out = append(out, d.WalletFact{ActorID: fact.Actor, Address: [20]byte(fact.Address), AcceptedAt: at})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ActorID < out[j].ActorID || out[i].ActorID == out[j].ActorID && bytes.Compare(out[i].Address[:], out[j].Address[:]) < 0
	})
	for i := 1; i < len(out); i++ {
		if out[i].ActorID == out[i-1].ActorID && out[i].Address == out[i-1].Address {
			return nil, "", d.ErrUnavailable
		}
	}
	return out, r.reference(actors, out), nil
}

func (s *Snapshot) Descriptor() d.SourceDescriptor {
	if s == nil {
		return d.SourceDescriptor{}
	}
	return s.descriptor
}
func (s *Snapshot) Wallets() []d.WalletFact {
	if s == nil {
		return nil
	}
	return append([]d.WalletFact{}, s.wallets...)
}

// CheckCurrent samples again before exposure. An unlink after this sampled
// check may race with later audit/HTTP output; no cross-store fence is implied.
func (s *Snapshot) CheckCurrent(ctx context.Context) error {
	if s == nil || s.reader == nil {
		return d.ErrUnavailable
	}
	_, ref, err := s.reader.read(ctx, s.actors)
	if err != nil {
		return err
	}
	if ref != s.descriptor.Reference {
		return d.ErrConflict
	}
	return nil
}
func (s *Snapshot) Close() {}

func part(h hash.Hash, raw []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	h.Write(n[:])
	h.Write(raw)
}
func domainHash(domain string) [32]byte {
	h := sha256.New()
	part(h, []byte(domain))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

var formatDigest = domainHash("ops.disclosure.wallet-current-format/v1")

func (r *Reader) reference(actors []string, facts []d.WalletFact) d.Digest {
	a := sha256.New()
	part(a, []byte("ops.disclosure.wallet-current-actors/v1"))
	part(a, []byte(strconv.Itoa(len(actors))))
	for _, actor := range actors {
		part(a, []byte(actor))
	}
	h := sha256.New()
	for _, raw := range [][]byte{[]byte("ops.disclosure.wallet-current/v1"), r.network[:], r.namespace[:], []byte(r.state.Generation), r.state.Coverage[:], r.planRaw[:], formatDigest[:], a.Sum(nil), []byte(strconv.Itoa(len(facts)))} {
		part(h, raw)
	}
	for _, fact := range facts {
		part(h, []byte(fact.ActorID))
		part(h, fact.Address[:])
		part(h, []byte(strconv.FormatInt(fact.AcceptedAt.UnixMicro(), 10)))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return digest(out)
}
