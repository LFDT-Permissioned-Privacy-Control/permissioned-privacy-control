package activitysource

import (
	"context"
	"encoding/hex"
	"net"
	"slices"
	"strconv"
	"time"

	a "privacy-proxy/internal/activitylog"
	m "privacy-proxy/internal/activitymethoddata"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/operational/activitysql"
)

// RetainedPart is a concrete activity component of the separately selected
// whole retained plan. It cannot impersonate the complete six-source assembly.
type RetainedPart struct {
	reader *activitysql.Reader
	plan   d.SourcePlan
}
type RetainedPartSnapshot struct {
	read       *activitysql.ReadSnapshot
	descriptor d.SourceDescriptor
	facts      d.Facts
}

func NewRetainedPart(reader *activitysql.Reader, plan d.SourcePlan) (*RetainedPart, error) {
	if reader == nil || !d.ValidRetainedPlan(plan) {
		return nil, d.ErrInvalid
	}
	metadata := reader.Metadata()
	if !a.CanonicalUUID(metadata.SourceID) || !a.CanonicalUUID(metadata.Generation) || metadata.Format != a.Format() || plan.NetworkKey != d.Digest("sha256:"+hex.EncodeToString(metadata.NetworkKey[:])) {
		return nil, d.ErrInvalid
	}
	plan.Resources = slices.Clone(plan.Resources)
	return &RetainedPart{reader, plan}, nil
}

func retainedQuery(scope d.ReadScope) (activitysql.ReadQuery, error) {
	n := scope.Query
	sc := n.Scope()
	if n.Resource() != p.ActivityLogs && n.Resource() != p.ActivitySummary && n.Resource() != p.ComplianceReport || n.Resource() == p.ActivityLogs && n.View() != d.List || n.Resource() != p.ActivityLogs && n.View() != d.Report || sc.Addresses.Mode != "all-target-addresses" || sc.DataTime.Start < 0 || sc.DataTime.End < sc.DataTime.Start || sc.DataTime.End > a.MaxObservedMicros/1000000 {
		return activitysql.ReadQuery{}, d.ErrUnsupported
	}
	return activitysql.ReadQuery{Organization: scope.DataOrganizationID, Actors: slices.Clone(sc.TargetActors), FromMicros: sc.DataTime.Start * 1000000, ThroughMicros: sc.DataTime.End * 1000000, Limit: int(n.Limit())}, nil
}

func activityAfter(position *d.Position) (*activitysql.PageKey, error) {
	if position == nil {
		return nil, nil
	}
	if position.Kind != d.ActivitySource || position.Activity == nil || position.Address != nil || position.Transaction != nil {
		return nil, d.ErrInvalid
	}
	p := position.Activity
	ordinal, err := strconv.ParseInt(string(p.CompletionOrdinal), 10, 64)
	if err != nil || ordinal < 1 || strconv.FormatInt(ordinal, 10) != string(p.CompletionOrdinal) {
		return nil, d.ErrInvalid
	}
	return &activitysql.PageKey{ObservedMicros: p.ObservedAtMicros, ProducerID: p.ProducerID, RunID: p.RunID, Ordinal: ordinal, RecordID: p.RecordID}, nil
}

func activityAggregate(methods []activitysql.MethodCount) (d.ActivityAggregate, error) {
	out := d.ActivityAggregate{Total: "0", Successful: "0", Failed: "0", Methods: []d.MethodCount{}}
	var total, successful, failed uint64
	for _, method := range methods {
		if method.Total > ^uint64(0)-total || method.Successful > ^uint64(0)-successful || method.Failed > ^uint64(0)-failed {
			return out, d.ErrTooBroad
		}
		total += method.Total
		successful += method.Successful
		failed += method.Failed
		out.Methods = append(out.Methods, d.MethodCount{Method: method.Method, Total: d.Count(strconv.FormatUint(method.Total, 10)), Successful: d.Count(strconv.FormatUint(method.Successful, 10)), Failed: d.Count(strconv.FormatUint(method.Failed, 10))})
	}
	out.Total = d.Count(strconv.FormatUint(total, 10))
	out.Successful = d.Count(strconv.FormatUint(successful, 10))
	out.Failed = d.Count(strconv.FormatUint(failed, 10))
	return out, nil
}

// Open eagerly reads the exact authenticated page/summary and closes its actual
// RR before returning. Later wallet/node work cannot hold this transaction.
func (part *RetainedPart) Open(ctx context.Context, scope d.ReadScope, expected *d.SourceRef, after *d.Position) (*RetainedPartSnapshot, error) {
	if part == nil || scope.BundleDigest != part.plan.BundleDigest || !slices.Contains(part.plan.Resources, scope.Query.Resource()) || d.PositionForQuery(scope.Query, after) != nil {
		return nil, d.ErrInvalid
	}
	query, err := retainedQuery(scope)
	if err != nil {
		return nil, err
	}
	reference := ""
	if expected != nil {
		if expected.Kind != d.ActivitySource || !digestValid(expected.ID) {
			return nil, d.ErrInvalid
		}
		reference = string(expected.ID)
	}
	read, err := part.reader.OpenRequests(ctx, reference, query.FromMicros)
	if err != nil {
		return nil, sourceError(err)
	}
	defer read.Close()
	if read.Population() != m.PopulationRequests {
		return nil, d.ErrUnavailable
	}
	cut := read.Cut()
	desc := d.SourceDescriptor{Version: 2, Kind: d.ActivitySource, Reference: d.Digest(cut.Reference), NetworkKey: part.plan.NetworkKey, Epoch: d.Digest(cut.Epoch), Generation: cut.Metadata.Generation, PlanDigest: part.plan.PlanDigest, FormatDigest: d.Digest("sha256:" + hex.EncodeToString(cut.Metadata.Format[:])), CoverageDigest: d.Digest(cut.Coverage), AsOf: cut.AsOf, Population: d.SealedRequestPopulation}
	if _, err = d.SourceReferencesRetained(part.plan, []d.SourceDescriptor{desc}); err != nil {
		return nil, d.ErrUnavailable
	}
	facts := d.Facts{End: true}
	if scope.Query.Resource() != p.ActivityLogs {
		if after != nil {
			return nil, d.ErrInvalid
		}
		methods, err := read.Summary(ctx, query)
		if err != nil {
			return nil, sourceError(err)
		}
		aggregate, err := activityAggregate(methods)
		if err != nil {
			return nil, err
		}
		facts.ActivitySummary = &aggregate
	} else {
		key, err := activityAfter(after)
		if err != nil {
			return nil, err
		}
		rows, end, err := read.ReadPage(ctx, query, key)
		if err != nil {
			return nil, sourceError(err)
		}
		facts.Activities = []d.ActivityFact{}
		facts.End = end
		for _, row := range rows {
			e := row.Envelope
			if m.Classify(e.Method) == m.Unknown {
				return nil, d.ErrUnavailable
			}
			var ip *string
			if e.IP != "" {
				parsed := net.ParseIP(e.IP)
				if parsed == nil {
					return nil, d.ErrUnavailable
				}
				canonical := parsed.String()
				ip = &canonical
			}
			facts.Activities = append(facts.Activities, d.ActivityFact{Provenance: d.Provenance{Source: desc.Reference, DataOrganizationID: e.DataOrg, TargetActorIDs: []string{e.ActorID}, Kind: "AUTHENTICATED_RECORDED_REQUEST_DATA_ORG"}, ID: e.RecordID, ProducerID: e.ProducerID, RunID: e.RunID, CompletionOrdinal: d.Count(e.Ordinal), ObservedAt: time.UnixMicro(e.ObservedMicros).UTC(), Method: e.Method, StatusCode: e.Status, TrustedIP: ip})
		}
		if !end {
			if len(rows) == 0 {
				return nil, d.ErrUnavailable
			}
			e := rows[len(rows)-1].Envelope
			facts.Next = &d.Position{Kind: d.ActivitySource, Activity: &d.ActivityPosition{ObservedAtMicros: e.ObservedMicros, ProducerID: e.ProducerID, RunID: e.RunID, CompletionOrdinal: d.Count(e.Ordinal), RecordID: e.RecordID}}
		}
	}
	if ctx.Err() != nil {
		return nil, d.ErrUnavailable
	}
	return &RetainedPartSnapshot{read: read, descriptor: desc, facts: facts}, nil
}

func (s *RetainedPartSnapshot) Descriptor() d.SourceDescriptor {
	if s == nil {
		return d.SourceDescriptor{}
	}
	return s.descriptor
}
func (s *RetainedPartSnapshot) Facts() (d.Facts, error) {
	if s == nil {
		return d.Facts{}, d.ErrUnavailable
	}
	return d.DetachFacts(s.facts)
}
func (s *RetainedPartSnapshot) CheckCurrent(ctx context.Context) error {
	if s == nil {
		return d.ErrUnavailable
	}
	if err := s.read.CheckCurrent(ctx); err != nil {
		return sourceError(err)
	}
	return nil
}
func (s *RetainedPartSnapshot) Close() {
	if s != nil {
		s.read.Close()
	}
}
