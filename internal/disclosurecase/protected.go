package disclosurecase

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/runtimepolicy"
)

type DataConfig struct {
	Network    d.NetworkBinding
	Sources    d.Sources
	RenderKeys d.Keys
	CursorKeys d.Keys
}

// RetainedDataConfig selects the separately validated live retained assembly.
// It cannot enter the legacy immutable Sources.Open/cursor path.
type RetainedDataConfig struct {
	Network    d.NetworkBinding
	Sources    d.RetainedSources
	RenderKeys d.Keys
	CursorKeys d.Keys
}

type dataState struct {
	sources    d.Sources
	retained   d.RetainedSources
	plan       d.SourcePlan
	network    d.Digest
	render     d.Keys
	cursors    *d.Cursor
	generation d.Digest
	slots      chan struct{}
}
type ExposureSummary struct {
	Version         uint8      `json:"v"`
	Resource        p.Resource `json:"resource"`
	View            d.View     `json:"view"`
	QueryDigest     string     `json:"queryDigest"`
	SourceSetDigest string     `json:"sourceSetDigest"`
	RenderDigest    string     `json:"renderDigest"`
	OutputDigest    string     `json:"outputDigest"`
	OutputBytes     uint32     `json:"outputBytes"`
	ReturnedRows    uint16     `json:"returnedRows"`
	QualifiedTotal  *d.Count   `json:"qualifiedTotal,omitempty"`
}

func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func NewWithData(config Config, dc DataConfig) (*Service, error) {
	return newWithData(config, dc, nil)
}

func NewWithRetainedData(config Config, dc RetainedDataConfig) (*Service, error) {
	if nilInterface(dc.Sources) {
		return nil, ErrInvalid
	}
	return newWithData(config, DataConfig{Network: dc.Network, RenderKeys: dc.RenderKeys, CursorKeys: dc.CursorKeys}, dc.Sources)
}

func newWithData(config Config, dc DataConfig, retained d.RetainedSources) (*Service, error) {
	s, e := New(config)
	if e != nil {
		return nil, e
	}
	if retained == nil && nilInterface(dc.Sources) {
		return nil, ErrInvalid
	}
	metadata := config.Snapshot.Metadata()
	if dc.Network.Environment != metadata.Environment || dc.Network.ChainID != metadata.ChainID {
		return nil, ErrInvalid
	}
	network, e := dc.Network.Key()
	if e != nil {
		return nil, ErrInvalid
	}
	netID := d.Digest("sha256:" + hex.EncodeToString(network[:]))
	var plan d.SourcePlan
	if retained == nil {
		plan = dc.Sources.Plan()
		if plan.Version != 1 || plan.Profile != "ops.disclosure.data-sources/v1" {
			return nil, ErrInvalid
		}
	} else {
		plan = retained.Plan()
		if !d.ValidRetainedPlan(plan) {
			return nil, ErrInvalid
		}
	}
	if plan.BundleDigest != d.Digest(metadata.ManifestDigest) || plan.NetworkKey != netID || !ValidDigest(string(plan.PlanDigest)) || plan.Resources == nil || len(plan.Resources) > 6 {
		return nil, ErrInvalid
	}
	for i, r := range plan.Resources {
		if _, e := d.RequiredKinds(r); e != nil || i > 0 && plan.Resources[i-1] >= r {
			return nil, d.ErrUnsupported
		}
	}
	plan.Resources = append([]p.Resource{}, plan.Resources...)
	for _, id := range s.catalog.RuleIDs() {
		rule, _ := s.catalog.Rule(id)
		src := rule.Source()
		for _, r := range src.Resources {
			if !slices.Contains(plan.Resources, r) {
				return nil, d.ErrUnsupported
			}
			if src.Addresses.Mode == "list" && (r == p.ActivityLogs || r == p.ActivitySummary || r == p.ComplianceReport) {
				return nil, d.ErrUnsupported
			}
		}
	}
	render, e := d.CopyKeys(dc.RenderKeys)
	if e != nil {
		return nil, ErrInvalid
	}
	cursorKeys, e := d.CopyKeys(dc.CursorKeys)
	if e != nil {
		return nil, ErrInvalid
	}
	adminKeys := d.Keys{Active: d.Key{ID: config.CursorKeys.Active.ID, Bytes: config.CursorKeys.Active.Key}}
	if config.CursorKeys.Previous != nil {
		adminKeys.Previous = &d.Key{ID: config.CursorKeys.Previous.ID, Bytes: config.CursorKeys.Previous.Key}
	}
	adminKeys, e = d.CopyKeys(adminKeys)
	if e != nil {
		return nil, ErrInvalid
	}
	all := [][]d.Key{}
	for _, ring := range []d.Keys{render, cursorKeys, adminKeys} {
		keys := []d.Key{ring.Active}
		if ring.Previous != nil {
			keys = append(keys, *ring.Previous)
		}
		all = append(all, keys)
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			for _, a := range all[i] {
				for _, b := range all[j] {
					if hmac.Equal(a.Bytes, b.Bytes) {
						return nil, ErrInvalid
					}
				}
			}
		}
	}
	cursors, e := d.NewCursor(cursorKeys)
	if e != nil {
		return nil, ErrInvalid
	}
	generation, e := d.RenderGeneration(render)
	if e != nil {
		return nil, ErrInvalid
	}
	strong, e := d.StrongNamespace(s.epoch, network)
	if e != nil {
		return nil, ErrInvalid
	}
	s.epoch = string(strong)
	s.data = &dataState{sources: dc.Sources, retained: retained, plan: plan, network: netID, render: render, cursors: cursors, generation: generation, slots: make(chan struct{}, 8)}
	return s, nil
}
func (s *Service) DataEnabled() bool { return s != nil && s.data != nil }
func (s *Service) TryAdmitHTTP() (func(), bool) {
	if !s.DataEnabled() {
		return nil, false
	}
	select {
	case s.data.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-s.data.slots }) }, true
	default:
		return nil, false
	}
}
func (s *Service) protected(v *runtimepolicy.View, c Case) (time.Time, error) {
	if v.RequireLive() != nil {
		return time.Time{}, ErrUnauthorized
	}
	if c.Epoch != s.epoch || ValidateCase(c) != nil || c.Status != "open" || c.RecipientActor != v.ActorID() {
		return time.Time{}, ErrNotFound
	}
	r, ok := s.catalog.Rule(c.RuleID)
	if !ok || r.Source().DataOrganizationID != c.DataOrg || !s.eligible(v, r) || !r.Covers(c.Scope) {
		return time.Time{}, ErrNotFound
	}
	until := r.ProtectedUntil(c.CreatedAt, c.ExpiresAt)
	if !s.clock().Before(until) {
		return time.Time{}, ErrNotFound
	}
	return until, nil
}
func dataError(e error) error {
	switch {
	case errors.Is(e, d.ErrNotFound):
		return ErrNotFound
	case errors.Is(e, d.ErrConflict):
		return ErrConflict
	case errors.Is(e, d.ErrTooBroad), errors.Is(e, d.ErrUnsupported):
		return e
	case errors.Is(e, d.ErrInvalid):
		return ErrInvalid
	}
	return ErrUnavailable
}
func sourceError(e error) error {
	if errors.Is(e, d.ErrInvalid) {
		return ErrUnavailable
	}
	return dataError(e)
}

func (s *Service) Read(ctx context.Context, token, id string, q d.Query) (*Response, error) {
	if !s.DataEnabled() {
		return nil, d.ErrUnsupported
	}
	fence, e := newDataReadFence(ctx)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithDeadline(ctx, fence.deadline)
	defer cancel()
	v, e := s.view(token)
	if e != nil {
		return nil, e
	}
	if !ValidUUID(id) {
		return nil, ErrNotFound
	}
	c, e := s.store.Get(ctx, id, s.epoch)
	if e != nil {
		return nil, e
	}
	until, e := s.protected(v, c)
	if e != nil {
		return nil, e
	}
	expires := v.ExpiresAt()
	if until.Before(expires) {
		expires = until
	}
	remaining := expires.Sub(s.clock())
	if remaining <= 0 {
		return nil, ErrUnauthorized
	}
	fence.clip(remaining)
	ctx, clipCancel := context.WithDeadline(ctx, fence.deadline)
	defer clipCancel()
	if q.Resource == p.Transactions && q.View == d.Detail && (c.Scope.Level != p.Full || q.Level != nil && *q.Level != p.Full) {
		return nil, ErrNotFound
	}
	query, e := d.Normalize(q, c.Scope)
	if e != nil {
		return nil, dataError(e)
	}
	rule, _ := s.catalog.Rule(c.RuleID)
	scope := d.ReadScope{Namespace: d.Digest(s.epoch), CaseID: c.ID, CaseVersion: c.Version, RecipientActorID: v.ActorID(), DataOrganizationID: c.DataOrg, BundleDigest: d.Digest(s.snapshot.Metadata().ManifestDigest), RuleDigest: d.Digest(rule.Digest()), EffectiveUntil: until, Query: query}
	binding := d.CursorBinding{Namespace: scope.Namespace, CaseID: c.ID, CaseVersion: c.Version, RecipientActorID: v.ActorID(), BundleDigest: scope.BundleDigest, RuleDigest: scope.RuleDigest, QueryDigest: query.Digest(), RenderGeneration: s.data.generation, SourcePlanDigest: s.data.plan.PlanDigest}
	var continuation *d.Continuation
	var retainedContinuation *d.RetainedContinuation
	var originalBasis *d.RetainedBasis
	var selectedBasis d.RetainedBasis
	var after *d.Position
	var refs []d.SourceRef
	if q.Cursor != nil {
		if s.data.retained == nil {
			got, err := s.data.cursors.Open(*q.Cursor, binding, s.clock())
			if err != nil {
				return nil, dataError(err)
			}
			continuation = &got
			refs = got.References()
			pos := got.Position()
			after = &pos
		} else {
			got, err := s.data.cursors.OpenRetained(*q.Cursor, s.data.plan, binding, query.Resource(), s.clock())
			if err != nil {
				return nil, dataError(err)
			}
			retainedContinuation = &got
			refs = got.References()
			pos, basis := got.Position(), got.Basis()
			after, originalBasis = &pos, &basis
		}
		if e := d.PositionForQuery(query, after); e != nil {
			return nil, dataError(e)
		}
	}
	var snap d.Snapshot
	if s.data.retained == nil {
		snap, e = s.data.sources.Open(ctx, scope, refs)
	} else {
		var owned d.RetainedSnapshot
		owned, e = s.data.retained.OpenRetained(ctx, scope, refs, originalBasis, d.ClonePosition(after))
		if e != nil && !nilInterface(owned) {
			owned.Close()
		}
		if e == nil && !nilInterface(owned) {
			selectedBasis = owned.Basis().Clone()
			if d.BasisForResource(query.Resource(), selectedBasis) != nil || selectedBasis.Valid() && selectedBasis.NetworkKey != s.data.network {
				owned.Close()
				return nil, ErrUnavailable
			}
			if originalBasis != nil && !selectedBasis.Equal(*originalBasis) {
				owned.Close()
				return nil, ErrConflict
			}
			snap = owned
		}
	}
	if e != nil {
		return nil, sourceError(e)
	}
	if nilInterface(snap) {
		return nil, ErrUnavailable
	}
	defer snap.Close()
	descriptors := snap.Descriptors()
	var actualRefs []d.SourceRef
	if s.data.retained == nil {
		actualRefs, e = d.SourceReferences(descriptors)
	} else {
		actualRefs, e = d.SourceReferencesRetained(s.data.plan, descriptors)
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	for _, desc := range descriptors {
		if desc.NetworkKey != s.data.network || desc.PlanDigest != s.data.plan.PlanDigest {
			return nil, ErrUnavailable
		}
	}
	if (continuation != nil || retainedContinuation != nil) && !slices.Equal(refs, actualRefs) {
		return nil, ErrConflict
	}
	var set d.Digest
	if s.data.retained == nil {
		set, e = d.SourceSetDigest(descriptors, query.Resource(), query.View())
	} else {
		set, e = d.SourceSetDigestRetained(s.data.plan, descriptors, query.Resource(), query.View())
	}
	if e != nil {
		return nil, dataError(e)
	}
	if continuation != nil {
		if e := continuation.VerifySourceSet(set); e != nil {
			return nil, dataError(e)
		}
	}
	if retainedContinuation != nil {
		if e := retainedContinuation.VerifySourceSet(set); e != nil {
			return nil, dataError(e)
		}
	}
	facts, e := snap.Read(ctx, scope, d.ClonePosition(after))
	if e != nil {
		return nil, sourceError(e)
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	facts, e = d.DetachFacts(facts)
	if e != nil {
		return nil, dataError(e)
	}
	if s.data.retained == nil {
		e = d.ValidateFacts(scope, descriptors, facts, after)
	} else {
		e = d.ValidateFactsRetained(s.data.plan, scope, descriptors, facts, after)
	}
	if e != nil {
		return nil, dataError(e)
	}
	if _, e := s.protected(v, c); e != nil {
		return nil, e
	}
	readID, e := uuid.NewRandom()
	if e != nil {
		return nil, ErrUnavailable
	}
	prepared := s.clock().UTC().Truncate(time.Microsecond)
	rc := d.RenderContext{PreparedAt: prepared, Namespace: scope.Namespace, CaseID: c.ID, DataOrganizationID: c.DataOrg, RecipientActorID: v.ActorID(), Keys: s.data.render, Query: query, EffectiveUntil: until}
	var result d.Result
	if s.data.retained == nil {
		result, e = d.Render(scope, descriptors, facts, rc, readID.String())
	} else {
		result, e = d.RenderRetained(s.data.plan, scope, descriptors, facts, rc, readID.String())
	}
	if e != nil {
		return nil, sourceError(e)
	}
	if result.SourceSetDigest() != set {
		return nil, ErrUnavailable
	}
	if !facts.End {
		expires := prepared.Add(300 * time.Second)
		if v.ExpiresAt().Before(expires) {
			expires = v.ExpiresAt()
		}
		if until.Before(expires) {
			expires = until
		}
		if !expires.After(s.clock()) {
			return nil, ErrUnauthorized
		}
		var raw string
		if s.data.retained == nil {
			raw, e = s.data.cursors.Seal(binding, set, actualRefs, *facts.Next, expires)
		} else {
			raw, e = s.data.cursors.SealRetained(s.data.plan, binding, query.Resource(), selectedBasis, set, actualRefs, *facts.Next, expires)
		}
		if e != nil {
			return nil, dataError(e)
		}
		result, e = result.WithCursor(raw)
		if e != nil {
			return nil, dataError(e)
		}
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return nil, dataError(e)
	}
	if len(raw)+1 > MaxResponseBytes {
		return nil, d.ErrTooBroad
	}
	response := &Response{body: append(raw, '\n'), status: 200, download: query.View() == d.Report, gate: func() error {
		if err := fence.check(); err != nil {
			return err
		}
		_, err := s.protected(v, c)
		return err
	}}
	if e := snap.CheckCurrent(ctx); e != nil {
		return nil, sourceError(e)
	}
	sum := sha256.Sum256(response.body)
	eventID, e := uuid.NewRandom()
	if e != nil {
		return nil, ErrUnavailable
	}
	event := Event{ID: eventID.String(), CaseID: c.ID, Epoch: c.Epoch, Actor: v.ActorID(), Action: "exposure_prepared", Outcome: "allowed", RuleID: c.RuleID, RuleDigest: rule.Digest(), BundleDigest: string(scope.BundleDigest), AttemptID: readID.String(), CaseVersion: c.Version, PreparedAt: prepared, Summary: EventSummary{Count: int(result.ReturnedRows()), RuleContext: "current", Exposure: &ExposureSummary{Version: 1, Resource: query.Resource(), View: query.View(), QueryDigest: string(query.Digest()), SourceSetDigest: string(set), RenderDigest: string(result.RenderDigest()), OutputDigest: "sha256:" + hex.EncodeToString(sum[:]), OutputBytes: uint32(len(response.body)), ReturnedRows: result.ReturnedRows(), QualifiedTotal: result.QualifiedTotal()}}}
	if ValidateExposureEvent(event) != nil {
		return nil, ErrUnavailable
	}
	receipt, e := s.store.WithLockedCase(ctx, c.ID, c.Epoch, c.Version, func(actual Case) (Event, error) {
		if _, e := s.protected(v, actual); e != nil {
			return Event{}, e
		}
		if actual.RuleID != c.RuleID || actual.DataOrg != c.DataOrg || actual.RecipientActor != c.RecipientActor || p.Digest(actual.Scope) != p.Digest(c.Scope) || !actual.CreatedAt.Equal(c.CreatedAt) || !actual.ExpiresAt.Equal(c.ExpiresAt) {
			return Event{}, ErrConflict
		}
		return event, nil
	})
	if e != nil {
		return nil, e
	}
	if receipt.AttemptID != event.AttemptID {
		return nil, ErrUnavailable
	}
	if e := response.gate(); e != nil {
		return nil, e
	}
	return response, nil
}

// Legacy nil summaries remain metadata. Only this dedicated validator qualifies
// a NEW output preparation event; action text alone is not an exposure receipt.
func ValidateExposureEvent(e Event) error {
	base := e
	base.Summary.Exposure = nil
	if ValidateEvent(base) != nil || e.PreparedAt.Location() != time.UTC || e.PreparedAt.Nanosecond()%1000 != 0 {
		return ErrInvalid
	}
	x := e.Summary.Exposure
	if x == nil || e.Action != "exposure_prepared" || e.Outcome != "allowed" || e.Summary.RuleContext != "current" || x.Version != 1 || x.ReturnedRows > 100 || e.Summary.Count != int(x.ReturnedRows) || x.OutputBytes < 1 || x.OutputBytes > MaxResponseBytes || !ValidDigest(x.QueryDigest) || !ValidDigest(x.SourceSetDigest) || !ValidDigest(x.RenderDigest) || !ValidDigest(x.OutputDigest) {
		return ErrInvalid
	}
	switch x.Resource {
	case p.AddressHistory:
		if x.View != d.List && x.View != d.Resolve {
			return ErrInvalid
		}
	case p.Transactions:
		if x.View != d.List && x.View != d.Detail {
			return ErrInvalid
		}
	case p.ActivityLogs:
		if x.View != d.List {
			return ErrInvalid
		}
	case p.ActivitySummary, p.SanctionsReport, p.ComplianceReport:
		if x.View != d.Report {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if x.View != d.List && x.ReturnedRows != 1 {
		return ErrInvalid
	}
	if x.QualifiedTotal != nil {
		if x.Resource != p.ActivitySummary && x.Resource != p.ComplianceReport {
			return ErrInvalid
		}
		if !d.ValidCount(*x.QualifiedTotal) {
			return ErrInvalid
		}
	}
	return nil
}
