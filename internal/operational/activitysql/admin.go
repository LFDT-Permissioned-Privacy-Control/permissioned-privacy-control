package activitysql

import (
	"context"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/activitymethoddata"
	"privacy-proxy/internal/identity"
)

// AdminReadQuery is intentionally separate: disclosure ReadQuery still requires
// explicit target actors. Empty Actor selects all rows of exactly Organization.
type AdminReadQuery struct {
	Organization, Actor, Method, Outcome, RequestReference string
	FromMicros, ToMicros                                   int64
	Limit                                                  int
}
type RetentionFloorError struct{ RetainedFromMicros int64 }

func (*RetentionFloorError) Error() string { return "requested activity history was pruned" }
func (r *Reader) OpenAdmin(ctx context.Context, reference string, from int64) (*ReadSnapshot, error) {
	return r.openPopulation(ctx, reference, from, true, true)
}
func validAdmin(q AdminReadQuery) bool {
	outcome := q.Outcome == ""
	for _, v := range []a.Outcome{a.Success, a.Invalid, a.Unauthenticated, a.Denied, a.EvaluationFailed, a.Unavailable, a.Unconfirmed} {
		outcome = outcome || q.Outcome == string(v)
	}
	return a.CanonicalUUID(q.Organization) && (q.Actor == "" || identity.ValidActorID(q.Actor)) && (q.Method == "" || a.ValidMethod(q.Method) && activitymethoddata.Classify(q.Method) != activitymethoddata.Unknown) && outcome && (q.RequestReference == "" || a.CanonicalUUID(q.RequestReference)) && q.FromMicros >= 0 && q.ToMicros > q.FromMicros && q.ToMicros <= a.MaxObservedMicros+1 && q.Limit >= 1 && q.Limit <= 100
}
func (s *ReadSnapshot) ReadOrgPage(ctx context.Context, q AdminReadQuery, after *PageKey) ([]ActivityRow, bool, error) {
	if s == nil || !s.admin || !validAdmin(q) || !validKey(after) || q.FromMicros != s.from || after != nil && (after.ObservedMicros < q.FromMicros || after.ObservedMicros >= q.ToMicros) {
		return nil, false, a.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil || ctx.Err() != nil {
		return nil, false, a.ErrUnavailable
	}
	k := PageKey{ProducerID: "00000000-0000-0000-0000-000000000000", RunID: "00000000-0000-0000-0000-000000000000", RecordID: "00000000-0000-0000-0000-000000000000"}
	if after != nil {
		k = *after
	}
	var request any
	if q.RequestReference != "" {
		request = q.RequestReference
	}
	predicate, popArgs := s.populationPredicate(17)
	args := []any{s.reader.state.chain, s.cut.HeadID, q.Organization, q.FromMicros, q.ToMicros, q.Actor, q.Method, q.Outcome, request, after == nil, k.ObservedMicros, k.ProducerID, k.RunID, k.Ordinal, k.RecordID, q.Limit + 1}
	args = append(args, popArgs...)
	rows, e := s.tx.Query(s.ctx, `SELECT `+logColumns+` FROM ops_activity_v1.qualified_logs WHERE chain_name=$1 AND id<=$2 AND activity_kind=1 AND org_id=$3 AND activity_observed_us>=$4 AND activity_observed_us<$5 AND ($6::text='' OR external_id=$6) AND ($7::text='' OR method=$7) AND ($8::text='' OR activity_outcome=$8) AND ($9::uuid IS NULL OR activity_record_id=$9) AND `+predicate+` AND ($10::boolean OR (activity_observed_us,activity_producer_id,activity_run_id,activity_ordinal,activity_record_id)<($11,$12::uuid,$13::uuid,$14,$15::uuid)) ORDER BY activity_observed_us DESC,activity_producer_id DESC,activity_run_id DESC,activity_ordinal DESC,activity_record_id DESC LIMIT $16`, args...)
	if e != nil {
		return nil, false, a.ErrUnavailable
	}
	page := make([]logRow, 0, q.Limit+1)
	ids := []string{}
	for rows.Next() {
		l, e := scanLog(rows)
		if e != nil {
			rows.Close()
			return nil, false, e
		}
		page = append(page, l)
		ids = append(ids, l.run)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, false, a.ErrUnavailable
	}
	if len(page) > 0 {
		runs, e := loadRuns(s.ctx, s.tx, ids)
		if e != nil {
			return nil, false, e
		}
		for _, l := range page {
			if !registered(runs[l.run], l.envelope, uint64(l.seq), s.reader.state) {
				return nil, false, a.ErrUnavailable
			}
		}
	}
	out := make([]ActivityRow, 0, min(q.Limit, len(page)))
	for _, l := range page[:min(q.Limit, len(page))] {
		out = append(out, ActivityRow{l.envelope})
	}
	return out, len(page) <= q.Limit, nil
}
