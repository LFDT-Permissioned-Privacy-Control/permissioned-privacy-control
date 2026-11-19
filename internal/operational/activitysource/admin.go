package activitysource

import (
	"context"
	"errors"
	"privacy-proxy/internal/accesslog"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/operational/activitysql"
)

type AdminReader struct{ Store *activitysql.Reader }

func (r AdminReader) OpenAdmin(ctx context.Context, ref string, from int64) (accesslog.Snapshot, error) {
	if r.Store == nil {
		return nil, accesslog.ErrUnavailable
	}
	s, e := r.Store.OpenAdmin(ctx, ref, from)
	if e != nil {
		return nil, adminError(e)
	}
	return adminSnapshot{s}, nil
}

type adminSnapshot struct{ snapshot *activitysql.ReadSnapshot }

func (s adminSnapshot) Cut() accesslog.Cut {
	c := s.snapshot.Cut()
	return accesslog.Cut{Metadata: c.Metadata, Reference: c.Reference, Coverage: c.Coverage, Population: s.snapshot.Population(), RetainedFromMicros: c.RetainedFromMicros, AsOfMicros: c.AsOf.UnixMicro()}
}
func (s adminSnapshot) Close() { s.snapshot.Close() }
func (s adminSnapshot) CheckCurrent(ctx context.Context) error {
	return adminError(s.snapshot.CheckCurrent(ctx))
}
func (s adminSnapshot) ReadOrgPage(ctx context.Context, org string, q accesslog.Query, p *accesslog.Position) ([]a.Envelope, bool, error) {
	var key *activitysql.PageKey
	if p != nil {
		key = &activitysql.PageKey{ObservedMicros: p.ObservedMicros, ProducerID: p.ProducerID, RunID: p.RunID, Ordinal: p.Ordinal, RecordID: p.RecordID}
	}
	rows, end, e := s.snapshot.ReadOrgPage(ctx, activitysql.AdminReadQuery{Organization: org, Actor: q.ActorID, Method: q.Method, Outcome: q.Outcome, RequestReference: q.RequestReference, FromMicros: q.FromMicros, ToMicros: q.ToMicros, Limit: q.Limit}, key)
	if e != nil {
		return nil, false, adminError(e)
	}
	out := make([]a.Envelope, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Envelope)
	}
	return out, end, nil
}
func adminError(e error) error {
	if e == nil {
		return nil
	}
	var floor *activitysql.RetentionFloorError
	if errors.As(e, &floor) {
		return &accesslog.RetentionError{FromMicros: floor.RetainedFromMicros}
	}
	if errors.Is(e, a.ErrInvalid) {
		return accesslog.ErrInvalid
	}
	return accesslog.ErrUnavailable
}
