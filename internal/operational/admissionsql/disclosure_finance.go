package admissionsql

import (
	"context"
	"encoding/hex"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
)

const (
	MaxFinanceEvents         = 100
	MaxFinanceRowBytes       = 8 << 10
	MaxFinanceDecodedBytes   = 1 << 20
	MaxFinanceHashInputBytes = 2 << 20
)

type FinanceReaderConfig struct {
	Store         *Store // borrowed, already opened with OpenReader
	Network       a.NetworkBinding
	ExpectedState a.ExpectedState
	Plan          d.SourcePlan // exact whole assembly plan; does not itself confer authority
	Clock         identity.Clock
}

type FinanceReader struct {
	store      *Store
	binding    a.NetworkBinding
	network    a.Digest
	state      a.ExpectedState
	plan       d.SourcePlan
	planDigest a.Digest
	clock      identity.Clock
}

// FinanceSnapshot is an immutable retained-row sample, not an execution ledger
// or database-wide commit frontier. It owns no transaction or connection.
type FinanceSnapshot struct {
	reader     *FinanceReader
	scope      d.ReadScope
	descriptor d.SourceDescriptor
	evidence   []d.ComplianceEvidence
	closed     atomic.Bool
}

func financeTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Unix() >= 0 && t.Unix() <= p.MaxUnixSeconds && t.Nanosecond()%1000 == 0
}
func financeDigest(v d.Digest) (a.Digest, bool) {
	x, err := a.ParseDigest(string(v))
	return x, err == nil
}
func NewFinanceReader(c FinanceReaderConfig) (*FinanceReader, error) {
	return newFinanceReader(c, false)
}

// NewRetainedFinanceReader accepts only the separate retained assembly plan.
// The source still reports retained admission decisions, capped at 100 events;
// it does not turn them into a complete execution or compliance ledger.
func NewRetainedFinanceReader(c FinanceReaderConfig) (*FinanceReader, error) {
	return newFinanceReader(c, true)
}

func newFinanceReader(c FinanceReaderConfig, retained bool) (*FinanceReader, error) {
	network, err := c.Network.Key()
	if err != nil || c.Store == nil || c.Store.pool == nil || c.Store.mode != "reader" || c.Store.schemaVersion < 1 || c.Store.schemaVersion > 3 || c.Clock == nil || !c.ExpectedState.Valid() || c.ExpectedState.Coverage == (a.Digest{}) {
		return nil, d.ErrInvalid
	}
	plan, ok := financeDigest(c.Plan.PlanDigest)
	_, bundleOK := financeDigest(c.Plan.BundleDigest)
	profileOK := c.Plan.Version == 1 && c.Plan.Profile == "ops.disclosure.data-sources/v1"
	if retained {
		profileOK = d.ValidRetainedPlan(c.Plan)
	}
	if !ok || !bundleOK || !profileOK || c.Plan.NetworkKey != d.Digest(network.String()) || len(c.Plan.Resources) < 1 || len(c.Plan.Resources) > 6 || !slices.Contains(c.Plan.Resources, p.ComplianceReport) || !financeTime(c.Clock().UTC().Truncate(time.Microsecond)) {
		return nil, d.ErrInvalid
	}
	for i, r := range c.Plan.Resources {
		if _, err := d.RequiredKinds(r); err != nil || i > 0 && c.Plan.Resources[i-1] >= r {
			return nil, d.ErrInvalid
		}
	}
	c.Plan.Resources = slices.Clone(c.Plan.Resources)
	return &FinanceReader{store: c.Store, binding: c.Network, network: network, state: c.ExpectedState, plan: c.Plan, planDigest: plan, clock: c.Clock}, nil
}

func (r *FinanceReader) validateScope(s d.ReadScope) (p.Scope, error) {
	if r == nil {
		return p.Scope{}, d.ErrInvalid
	}
	for _, x := range []d.Digest{s.Namespace, s.RuleDigest, s.Query.Digest()} {
		if _, ok := financeDigest(x); !ok {
			return p.Scope{}, d.ErrInvalid
		}
	}
	if !a.ValidUUID(s.CaseID) || s.CaseVersion < 1 || !a.ValidUUID(s.DataOrganizationID) || !identity.ValidActorID(s.RecipientActorID) || !financeTime(s.EffectiveUntil) || s.BundleDigest != r.plan.BundleDigest {
		return p.Scope{}, d.ErrInvalid
	}
	if s.Query.Resource() != p.ComplianceReport || s.Query.View() != d.Report || !slices.Contains(r.plan.Resources, p.ComplianceReport) {
		return p.Scope{}, d.ErrUnsupported
	}
	sc := s.Query.Scope()
	if len(sc.TargetActors) < 1 || len(sc.TargetActors) > 256 || len(sc.Addresses.Values) > 1024 {
		return p.Scope{}, d.ErrInvalid
	}
	// NormalizeScope checks every actor, address, interval and cardinality. The
	// normalized query already owns its slices; equality forbids silent repair.
	canonical, err := p.NormalizeScope(sc, p.DefaultLimits())
	if err != nil || !reflect.DeepEqual(sc, canonical) {
		return p.Scope{}, d.ErrInvalid
	}
	return sc, nil
}

func (r *FinanceReader) Open(ctx context.Context, s d.ReadScope, expected *d.SourceRef) (*FinanceSnapshot, error) {
	sc, err := r.validateScope(s)
	if err != nil {
		return nil, err
	}
	if expected != nil {
		if _, ok := financeDigest(expected.ID); !ok || expected.Kind != d.FinanceSource {
			return nil, d.ErrInvalid
		}
	}
	events, ref, coverage, err := r.read(ctx, s.DataOrganizationID, sc)
	if err != nil {
		return nil, err
	}
	if expected != nil && expected.ID != d.Digest(ref.String()) {
		return nil, d.ErrConflict
	}
	asOf := r.clock().UTC().Truncate(time.Microsecond)
	if !financeTime(asOf) {
		return nil, d.ErrUnavailable
	}
	epoch := a.HashParts("ops.disclosure.finance-epoch/v1", r.network[:], []byte(r.state.Generation), r.state.Coverage[:])
	format := a.HashParts("ops.disclosure.finance-retained-format/v1")
	desc := d.SourceDescriptor{Version: 1, Kind: d.FinanceSource, Reference: d.Digest(ref.String()), NetworkKey: d.Digest(r.network.String()), Epoch: d.Digest(epoch.String()), Generation: r.state.Generation, PlanDigest: r.plan.PlanDigest, FormatDigest: d.Digest(format.String()), CoverageDigest: d.Digest(coverage.String()), AsOf: asOf, Population: "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT"}
	evidence := make([]d.ComplianceEvidence, 0, len(events))
	for _, e := range events {
		out := d.ComplianceEvidence{ID: d.Count(strconv.FormatInt(e.ID, 10)), Provenance: d.Provenance{Source: desc.Reference, DataOrganizationID: e.Scope.Organization, TargetActorIDs: []string{e.Scope.Actor}, Kind: "ADMISSION_DECISION"}, TransactionHash: [32]byte(e.Scope.Hash), DecisionAt: e.DecisionAt, Decision: e.Decision, Monitored: e.Monitored, Kind: e.Kind, Reason: e.Reason, PolicyDigest: d.Digest(e.PolicyDigest.String()), Coverage: e.Coverage, RecordID: e.RecordID}
		if q := e.Quote; q != nil {
			value, _ := a.CanonicalFiat(q.Value)
			digest := d.Digest(q.Digest.String())
			out.QuoteDigest = &digest
			out.Quote = &d.QuoteFact{ID: q.ID, Currency: q.Currency, SourceID: q.SourceID, Value: value, ProviderAsOf: q.ProviderAsOf, FetchedAt: q.FetchedAt, Digest: digest}
		}
		evidence = append(evidence, out)
	}
	return &FinanceSnapshot{reader: r, scope: s, descriptor: desc, evidence: evidence}, nil
}

func (s *FinanceSnapshot) Descriptor() d.SourceDescriptor {
	if s == nil || s.closed.Load() {
		return d.SourceDescriptor{}
	}
	return s.descriptor
}
func (s *FinanceSnapshot) Evidence() []d.ComplianceEvidence {
	if s == nil || s.closed.Load() {
		return nil
	}
	out := slices.Clone(s.evidence)
	for i := range out {
		out[i].Provenance.TargetActorIDs = slices.Clone(out[i].Provenance.TargetActorIDs)
		if out[i].RecordID != nil {
			x := *out[i].RecordID
			out[i].RecordID = &x
		}
		if out[i].QuoteDigest != nil {
			x := *out[i].QuoteDigest
			out[i].QuoteDigest = &x
		}
		if out[i].Quote != nil {
			x := *out[i].Quote
			out[i].Quote = &x
		}
	}
	return out
}
func (s *FinanceSnapshot) CheckCurrent(ctx context.Context) error {
	if s == nil || s.closed.Load() {
		return d.ErrUnavailable
	}
	sc, err := s.reader.validateScope(s.scope)
	if err != nil {
		return err
	}
	_, ref, _, err := s.reader.read(ctx, s.scope.DataOrganizationID, sc)
	if err != nil {
		return err
	}
	if ref.String() != string(s.descriptor.Reference) {
		return d.ErrConflict
	}
	return nil
}
func (s *FinanceSnapshot) Close() {
	if s != nil {
		s.closed.Store(true)
	}
}

func financeScopeParts(org string, sc p.Scope) ([][]byte, [][]byte, error) {
	parts := [][]byte{[]byte(org), []byte(strconv.Itoa(len(sc.TargetActors)))}
	for _, actor := range sc.TargetActors {
		parts = append(parts, []byte(actor))
	}
	parts = append(parts, []byte(strconv.FormatInt(sc.DataTime.Start, 10)), []byte(strconv.FormatInt(sc.DataTime.End, 10)), []byte(sc.Addresses.Mode), []byte(strconv.Itoa(len(sc.Addresses.Values))))
	addresses := make([][]byte, 0, len(sc.Addresses.Values))
	size := 0
	for _, v := range sc.Addresses.Values {
		address, err := a.ParseAddress(v)
		if err != nil {
			return nil, nil, d.ErrInvalid
		}
		raw := address.Bytes()
		addresses = append(addresses, raw)
		parts = append(parts, raw)
	}
	for _, v := range parts {
		if len(v) > 65536-size {
			return nil, nil, d.ErrTooBroad
		}
		size += len(v)
	}
	return parts, addresses, nil
}
func (r *FinanceReader) read(ctx context.Context, org string, sc p.Scope) ([]a.Event, a.Digest, a.Digest, error) {
	parts, addresses, err := financeScopeParts(org, sc)
	if err != nil {
		return nil, a.Digest{}, a.Digest{}, err
	}
	_ = parts // validated before database acquisition; hashed with the complete set below
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, r.store.pool, true)
	if err != nil {
		return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
	}
	defer rollback(tx)
	genesis, _ := hex.DecodeString(r.binding.GenesisHash[2:])
	rows, err := tx.Query(ctx, financeQuery, r.network[:], r.state.Generation, r.state.Coverage[:], r.binding.Environment, r.binding.ChainID, genesis, r.binding.DeploymentID, org, sc.TargetActors, time.Unix(sc.DataTime.Start, 0).UTC(), time.Unix(sc.DataTime.End, 0).UTC(), sc.Addresses.Mode == "all-target-addresses", addresses)
	if err != nil {
		return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
	}
	defer rows.Close()
	events := make([]a.Event, 0, MaxFinanceEvents)
	total := 0
	for rows.Next() {
		var gate bool
		var present, shape *bool
		// Nullable lateral sentinel is decoded separately; the event scanner is
		// reused without allowing guarded invalid optional fields to become nil.
		var values []any
		values, err = rows.Values()
		if err != nil || len(values) != 32 {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		if v, ok := values[0].(bool); ok {
			gate = v
		}
		if !gate {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		if values[1] == nil {
			if len(events) != 0 {
				return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
			}
			continue
		}
		if v, ok := values[1].(bool); ok {
			present = &v
		}
		if v, ok := values[2].(bool); ok {
			shape = &v
		}
		if present == nil || !*present || shape == nil || !*shape {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		if len(events) == MaxFinanceEvents {
			return nil, a.Digest{}, a.Digest{}, d.ErrTooBroad
		}
		row := financeEventRow{Rows: rows}
		e, err := scanEvent(row, r.network, r.state)
		if err != nil {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		if e.Scope.Organization != org || !slices.Contains(sc.TargetActors, e.Scope.Actor) {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		if !financeNormalizeEvent(&e) {
			return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		_, size, err := financeEventParts(e)
		if err != nil {
			return nil, a.Digest{}, a.Digest{}, err
		}
		if size > MaxFinanceDecodedBytes-total {
			return nil, a.Digest{}, a.Digest{}, d.ErrTooBroad
		}
		total += size
		events = append(events, e)
	}
	if rows.Err() != nil {
		return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, a.Digest{}, a.Digest{}, d.ErrUnavailable
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
	ref, coverage, err := r.reference(org, sc, events)
	return events, ref, coverage, err
}

// financeEventRow scans only the already bounded SQL scalar projection. pgx's
// codec remains responsible for exact nullable conversions, including sentinels.
type financeEventRow struct{ pgx.Rows }

func (r financeEventRow) Scan(dest ...any) error {
	return r.Rows.Scan(append([]any{nil, nil, nil}, dest...)...)
}

func financeNormalizeEvent(e *a.Event) bool {
	e.DecisionAt = e.DecisionAt.UTC()
	if !financeTime(e.DecisionAt) {
		return false
	}
	if e.Quote != nil {
		e.Quote.ProviderAsOf = e.Quote.ProviderAsOf.UTC()
		e.Quote.FetchedAt = e.Quote.FetchedAt.UTC()
		if !financeTime(e.Quote.ProviderAsOf) || !financeTime(e.Quote.FetchedAt) {
			return false
		}
	}
	return e.Valid()
}
func financeEventParts(e a.Event) ([][]byte, int, error) {
	str := func(v string) []byte { return []byte(v) }
	optional := func(v *string) []byte {
		if v == nil {
			return nil
		}
		return str(*v)
	}
	money := func(v *float64) []byte {
		if v == nil {
			return nil
		}
		s, _ := a.CanonicalFiat(*v)
		return str(s)
	}
	addr := func(v *common.Address) []byte {
		if v == nil {
			return nil
		}
		return v.Bytes()
	}
	parts := [][]byte{str(strconv.FormatInt(e.ID, 10)), e.Scope.Hash[:], str(e.Scope.Actor), str(e.Scope.Organization), str(e.Kind), str(e.Coverage), addr(e.From), addr(e.To), addr(e.Token), optional(e.AmountWei), money(e.AmountFiat), money(e.Threshold), optional(e.Currency), str(e.Decision), str(map[bool]string{false: "0", true: "1"}[e.Monitored]), str(e.Reason), optional(e.RecordID), str(strconv.FormatInt(e.DecisionAt.UnixMicro(), 10)), e.PolicyDigest[:]}
	if q := e.Quote; q != nil {
		parts = append(parts, q.Digest[:], str(q.ID), str(q.Currency), str(q.SourceID), money(&q.Value), str(strconv.FormatInt(q.ProviderAsOf.UnixMicro(), 10)), str(strconv.FormatInt(q.FetchedAt.UnixMicro(), 10)))
	} else {
		parts = append(parts, nil, nil, nil, nil, nil, nil, nil)
	}
	parts = append(parts, e.Anchor.Hash[:], str(strconv.FormatUint(e.Anchor.Number, 10)), str(strconv.FormatUint(e.Anchor.Timestamp, 10)), str(e.Anchor.Profile))
	total := 0
	for _, v := range parts {
		if len(v) > MaxFinanceRowBytes-total {
			return nil, 0, d.ErrTooBroad
		}
		total += len(v)
	}
	return parts, total, nil
}

func (r *FinanceReader) reference(org string, sc p.Scope, events []a.Event) (a.Digest, a.Digest, error) {
	parts, _, err := financeScopeParts(org, sc)
	if err != nil {
		return a.Digest{}, a.Digest{}, err
	}
	scopeDigest := a.HashParts("ops.disclosure.finance-scope/v1", parts...)
	hashBytes := 65536 + 16384 // conservative scope and fixed framing/descriptor overhead
	coverageParts := [][]byte{r.network[:], []byte(r.state.Generation), r.state.Coverage[:], scopeDigest[:], []byte(strconv.Itoa(len(events)))}
	for i, e := range events {
		if i > 0 && events[i-1].ID >= e.ID {
			return a.Digest{}, a.Digest{}, d.ErrUnavailable
		}
		row, size, err := financeEventParts(e)
		if err != nil {
			return a.Digest{}, a.Digest{}, err
		}
		framed := size + 4*(len(row)+1) + len("ops.disclosure.finance-event/v1")
		if framed > MaxFinanceHashInputBytes-hashBytes {
			return a.Digest{}, a.Digest{}, d.ErrTooBroad
		}
		hashBytes += framed
		digest := a.HashParts("ops.disclosure.finance-event/v1", row...)
		coverageParts = append(coverageParts, digest[:])
	}
	coverage := a.HashParts("ops.disclosure.finance-retained-coverage/v1", coverageParts...)
	epoch := a.HashParts("ops.disclosure.finance-epoch/v1", r.network[:], []byte(r.state.Generation), r.state.Coverage[:])
	format := a.HashParts("ops.disclosure.finance-retained-format/v1")
	ref := a.HashParts("ops.disclosure.finance-retained/v1", r.network[:], epoch[:], r.planDigest[:], format[:], coverage[:])
	return ref, coverage, nil
}
