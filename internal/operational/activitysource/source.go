// Package activitysource is the concrete SEALED-only protected activity source.
// It does not mount an endpoint or collect Core completion metadata.
package activitysource

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"time"

	a "privacy-proxy/internal/activitylog"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/operational/activitysql"
)

type source struct {
	reader *activitysql.Reader
	plan   d.SourcePlan
}
type snapshot struct {
	owner      *source
	read       *activitysql.ReadSnapshot
	scope      d.ReadScope
	descriptor d.SourceDescriptor
}

func digestValid(v d.Digest) bool {
	if len(v) != 71 || string(v[:7]) != "sha256:" {
		return false
	}
	_, err := a.ParseDigestHex(string(v[7:]))
	return err == nil
}
func New(reader *activitysql.Reader, plan d.SourcePlan) (d.Sources, error) {
	if reader == nil {
		return nil, d.ErrInvalid
	}
	metadata := reader.Metadata()
	if !a.CanonicalUUID(metadata.SourceID) || !a.CanonicalUUID(metadata.Generation) || metadata.Format != a.Format() {
		return nil, d.ErrInvalid
	}
	if plan.Version != 1 || plan.Profile != "ops.disclosure.data-sources/v1" || !digestValid(plan.BundleDigest) || !digestValid(plan.PlanDigest) || plan.NetworkKey != d.Digest("sha256:"+hex.EncodeToString(metadata.NetworkKey[:])) || len(plan.Resources) < 1 || len(plan.Resources) > 2 {
		return nil, d.ErrInvalid
	}
	for i, r := range plan.Resources {
		if r != p.ActivityLogs && r != p.ActivitySummary || i > 0 && plan.Resources[i-1] >= r {
			return nil, d.ErrInvalid
		}
	}
	plan.Resources = slices.Clone(plan.Resources)
	return &source{reader, plan}, nil
}
func (s *source) Plan() d.SourcePlan { p := s.plan; p.Resources = slices.Clone(p.Resources); return p }
func sourceError(err error) error {
	if errors.Is(err, a.ErrTooBroad) {
		return d.ErrTooBroad
	}
	return d.ErrUnavailable
}
func query(scope d.ReadScope) (activitysql.ReadQuery, error) {
	n := scope.Query
	sc := n.Scope()
	if n.Resource() != p.ActivityLogs && n.Resource() != p.ActivitySummary || n.Resource() == p.ActivityLogs && n.View() != d.List || n.Resource() == p.ActivitySummary && n.View() != d.Report || sc.Addresses.Mode != "all-target-addresses" || sc.DataTime.Start < 0 || sc.DataTime.End < sc.DataTime.Start || sc.DataTime.End > a.MaxObservedMicros/1000000 {
		return activitysql.ReadQuery{}, d.ErrUnsupported
	}
	return activitysql.ReadQuery{Organization: scope.DataOrganizationID, Actors: slices.Clone(sc.TargetActors), FromMicros: sc.DataTime.Start * 1000000, ThroughMicros: sc.DataTime.End * 1000000, Limit: int(n.Limit())}, nil
}
func (s *source) Open(ctx context.Context, scope d.ReadScope, refs []d.SourceRef) (d.Snapshot, error) {
	if scope.BundleDigest != s.plan.BundleDigest || !slices.Contains(s.plan.Resources, scope.Query.Resource()) || len(refs) > 1 {
		return nil, d.ErrUnavailable
	}
	q, err := query(scope)
	if err != nil {
		return nil, err
	}
	reference := ""
	if len(refs) == 1 {
		if refs[0].Kind != d.ActivitySource || !digestValid(refs[0].ID) {
			return nil, d.ErrInvalid
		}
		reference = string(refs[0].ID)
	}
	r, err := s.reader.Open(ctx, reference, q.FromMicros)
	if err != nil {
		return nil, sourceError(err)
	}
	cut := r.Cut()
	desc := d.SourceDescriptor{Version: 1, Kind: d.ActivitySource, Reference: d.Digest(cut.Reference), NetworkKey: s.plan.NetworkKey, Epoch: d.Digest(cut.Epoch), Generation: cut.Metadata.Generation, PlanDigest: s.plan.PlanDigest, FormatDigest: d.Digest("sha256:" + hex.EncodeToString(cut.Metadata.Format[:])), CoverageDigest: d.Digest(cut.Coverage), AsOf: cut.AsOf, Population: "SEALED_RPC_COMPLETIONS_AS_OF_CHAIN_HEAD"}
	if _, err := d.SourceReferences([]d.SourceDescriptor{desc}); err != nil {
		r.Close()
		return nil, d.ErrUnavailable
	}
	return &snapshot{s, r, scope, desc}, nil
}
func (s *snapshot) Descriptors() []d.SourceDescriptor { return []d.SourceDescriptor{s.descriptor} }
func sameScope(a, b d.ReadScope) bool {
	return a.Namespace == b.Namespace && a.CaseID == b.CaseID && a.CaseVersion == b.CaseVersion && a.RecipientActorID == b.RecipientActorID && a.DataOrganizationID == b.DataOrganizationID && a.BundleDigest == b.BundleDigest && a.RuleDigest == b.RuleDigest && a.EffectiveUntil.Equal(b.EffectiveUntil) && a.Query.Digest() == b.Query.Digest()
}
func (s *snapshot) Read(ctx context.Context, scope d.ReadScope, after *d.Position) (d.Facts, error) {
	if !sameScope(scope, s.scope) {
		return d.Facts{}, d.ErrUnavailable
	}
	defer s.read.Close() // release SQL snapshot BEFORE the case receipt transaction
	q, err := query(scope)
	if err != nil {
		return d.Facts{}, err
	}
	if scope.Query.Resource() == p.ActivitySummary {
		if after != nil {
			return d.Facts{}, d.ErrInvalid
		}
		methods, err := s.read.Summary(ctx, q)
		if err != nil {
			return d.Facts{}, sourceError(err)
		}
		aggregate := d.ActivityAggregate{Total: "0", Successful: "0", Failed: "0", Methods: []d.MethodCount{}}
		var total, success, failed uint64
		for _, m := range methods {
			if m.Total > ^uint64(0)-total || m.Successful > ^uint64(0)-success || m.Failed > ^uint64(0)-failed {
				return d.Facts{}, d.ErrTooBroad
			}
			total += m.Total
			success += m.Successful
			failed += m.Failed
			aggregate.Methods = append(aggregate.Methods, d.MethodCount{Method: m.Method, Total: d.Count(strconv.FormatUint(m.Total, 10)), Successful: d.Count(strconv.FormatUint(m.Successful, 10)), Failed: d.Count(strconv.FormatUint(m.Failed, 10))})
		}
		aggregate.Total = d.Count(strconv.FormatUint(total, 10))
		aggregate.Successful = d.Count(strconv.FormatUint(success, 10))
		aggregate.Failed = d.Count(strconv.FormatUint(failed, 10))
		return d.Facts{ActivitySummary: &aggregate, End: true}, nil
	}
	var key *activitysql.PageKey
	if after != nil {
		if after.Kind != d.ActivitySource || after.Activity == nil || after.Address != nil || after.Transaction != nil {
			return d.Facts{}, d.ErrInvalid
		}
		p := after.Activity
		n, err := strconv.ParseInt(string(p.CompletionOrdinal), 10, 64)
		if err != nil || n < 1 || strconv.FormatInt(n, 10) != string(p.CompletionOrdinal) {
			return d.Facts{}, d.ErrInvalid
		}
		key = &activitysql.PageKey{ObservedMicros: p.ObservedAtMicros, ProducerID: p.ProducerID, RunID: p.RunID, Ordinal: n, RecordID: p.RecordID}
	}
	rows, end, err := s.read.ReadPage(ctx, q, key)
	if err != nil {
		return d.Facts{}, sourceError(err)
	}
	facts := d.Facts{Activities: []d.ActivityFact{}, End: end}
	for _, row := range rows {
		e := row.Envelope
		var ip *string
		if e.IP != "" {
			v := e.IP
			ip = &v
		}
		facts.Activities = append(facts.Activities, d.ActivityFact{Provenance: d.Provenance{Source: s.descriptor.Reference, DataOrganizationID: e.DataOrg, TargetActorIDs: []string{e.ActorID}, Kind: "AUTHENTICATED_RECORDED_REQUEST_DATA_ORG"}, ID: e.RecordID, ProducerID: e.ProducerID, RunID: e.RunID, CompletionOrdinal: d.Count(e.Ordinal), ObservedAt: time.UnixMicro(e.ObservedMicros).UTC(), Method: e.Method, StatusCode: e.Status, TrustedIP: ip})
	}
	if !end {
		if len(rows) == 0 {
			return d.Facts{}, d.ErrUnavailable
		}
		e := rows[len(rows)-1].Envelope
		facts.Next = &d.Position{Kind: d.ActivitySource, Activity: &d.ActivityPosition{ObservedAtMicros: e.ObservedMicros, ProducerID: e.ProducerID, RunID: e.RunID, CompletionOrdinal: d.Count(e.Ordinal), RecordID: e.RecordID}}
	}
	return facts, nil
}
func (s *snapshot) CheckCurrent(ctx context.Context) error {
	if err := s.read.CheckCurrent(ctx); err != nil {
		return sourceError(err)
	}
	return nil
}
func (s *snapshot) Close() { s.read.Close() }
