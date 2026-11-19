package admissionsql

import (
	"context"
	"encoding/hex"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
)

// Same selected network/table and scope gates as the original finance source.
// An aggregate selects no row bodies and makes no immutable-cohort claim.
const financeNativeGate = `WITH gate AS (SELECT
 COALESCE((SELECT n.ready AND n.generation=$2::uuid AND n.coverage_digest=$3
  AND n.environment=$4 AND n.chain_id=$5 AND n.genesis_hash=$6 AND n.deployment_id=$7
  FROM ops_admission_v2.network_state n WHERE n.network_key=$1),false)
 AND (SELECT count(*)=2 AND bool_and(c.relkind='r' AND c.relpersistence='p'
  AND NOT c.relispartition AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity)
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='ops_admission_v2' AND c.relname IN('network_state','compliance_events')) AS ok)
`
const financeNativePredicate = `network_key=$1 AND org_id=$8::uuid AND actor_id=ANY($9::text[])
 AND decision_at>=$10::timestamptz AND decision_at<=$11::timestamptz
 AND ($12::boolean OR from_address=ANY($13::bytea[]) OR to_address=ANY($13::bytea[]))`
const financeNativeCount = financeNativeGate + `SELECT gate.ok,
 (SELECT count(*) FROM ops_admission_v2.compliance_events WHERE gate.ok AND ` + financeNativePredicate + `) FROM gate`
const financeNativeContext = financeNativeGate + `SELECT gate.ok FROM gate`
const financeNativePage = financeQueryPrefix + `
 AND ($14::boolean OR (decision_at,id)<($15::timestamptz,$16::bigint))
 ORDER BY decision_at DESC,id DESC LIMIT $17
 ) e ON true ORDER BY e.decision_at DESC NULLS LAST,e.id DESC NULLS LAST;`
const financeNativeIDs = financeQueryPrefix + `
 AND id=ANY($14::bigint[]) ORDER BY decision_at DESC,id DESC LIMIT 101
 ) e ON true ORDER BY e.decision_at DESC NULLS LAST,e.id DESC NULLS LAST;`

func (r *FinanceReader) nativeArgs(org string, sc p.Scope) ([]any, error) {
	_, addresses, err := financeScopeParts(org, sc)
	if err != nil {
		return nil, err
	}
	genesis, _ := hex.DecodeString(r.binding.GenesisHash[2:])
	return []any{r.network[:], r.state.Generation, r.state.Coverage[:], r.binding.Environment, r.binding.ChainID, genesis, r.binding.DeploymentID, org, sc.TargetActors, time.Unix(sc.DataTime.Start, 0).UTC(), time.Unix(sc.DataTime.End, 0).UTC(), sc.Addresses.Mode == "all-target-addresses", addresses}, nil
}

func (r *FinanceReader) nativeBegin(ctx context.Context) (pgx.Tx, error) {
	if r == nil || !d.NativeFinancePlan(r.plan) || r.store.CheckReady(ctx, r.network, r.state) != nil {
		return nil, d.ErrUnavailable
	}
	tx, err := begin(ctx, r.store.pool, true)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	return tx, nil
}

func (r *FinanceReader) nativeDescriptor(kind d.View, reference a.Digest, observed time.Time) d.SourceDescriptor {
	epoch := a.HashParts("ops.disclosure.finance-epoch/v1", r.network[:], []byte(r.state.Generation), r.state.Coverage[:])
	format := d.FinanceSummaryFormat()
	if kind == d.List {
		format = d.FinanceLiveFormat()
	}
	coverage := a.HashParts("ops.disclosure.finance-native-coverage/v1", r.network[:], []byte(r.state.Generation), r.state.Coverage[:])
	return d.SourceDescriptor{Version: 2, Kind: d.FinanceSource, Reference: d.Digest(reference.String()), NetworkKey: d.Digest(r.network.String()), Epoch: d.Digest(epoch.String()), Generation: r.state.Generation, PlanDigest: r.plan.PlanDigest, FormatDigest: format, CoverageDigest: d.Digest(coverage.String()), AsOf: observed, Population: "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT"}
}

func (r *FinanceReader) OpenSummary(ctx context.Context, scope d.ReadScope) (*FinanceSnapshot, error) {
	sc, err := r.validateScope(scope)
	if err != nil {
		return nil, err
	}
	if !d.NativeFinancePlan(r.plan) || scope.Query.View() != d.Report {
		return nil, d.ErrUnsupported
	}
	args, err := r.nativeArgs(scope.DataOrganizationID, sc)
	if err != nil {
		return nil, err
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := r.nativeBegin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	var gate bool
	var count int64
	if err = tx.QueryRow(ctx, financeNativeCount, args...).Scan(&gate, &count); err != nil || !gate || count < 0 {
		return nil, d.ErrUnavailable
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, d.ErrUnavailable
	}
	observed := r.clock().UTC().Truncate(time.Microsecond)
	if !financeTime(observed) {
		return nil, d.ErrUnavailable
	}
	parts, _, _ := financeScopeParts(scope.DataOrganizationID, sc)
	parts = append(parts, []byte(strconv.FormatInt(count, 10)))
	ref := a.HashParts("ops.disclosure.finance-summary-observation/v1", parts...)
	descriptor := r.nativeDescriptor(d.Report, ref, observed)
	return &FinanceSnapshot{reader: r, scope: scope, descriptor: descriptor, summary: &d.FinanceSummary{MatchingRetainedCount: d.Count(strconv.FormatInt(count, 10)), ObservedAt: observed}}, nil
}

func (s *FinanceSnapshot) Summary() *d.FinanceSummary {
	if s == nil || s.closed.Load() || s.summary == nil {
		return nil
	}
	out := *s.summary
	return &out
}

func (r *FinanceReader) OpenLivePage(ctx context.Context, scope d.ReadScope, expected *d.SourceRef, after *d.Position) (*FinanceSnapshot, error) {
	sc, err := r.validateScope(scope)
	if err != nil {
		return nil, err
	}
	if !d.LiveFinanceRead(r.plan, scope.Query) || after != nil && (after.FinanceLive == nil || d.PositionForQuery(scope.Query, after) != nil) {
		return nil, d.ErrInvalid
	}
	// Stable source identity is authenticated by df1. It is not a row frontier.
	stub := r.nativeDescriptor(d.List, a.HashParts("ops.disclosure.finance-native-empty/v1"), r.clock().UTC().Truncate(time.Microsecond))
	identity, err := d.FinanceLiveIdentity(r.plan, stub)
	if err != nil {
		return nil, err
	}
	if expected != nil && (expected.Kind != d.FinanceSource || expected.ID != identity) {
		return nil, d.ErrConflict
	}
	args, err := r.nativeArgs(scope.DataOrganizationID, sc)
	if err != nil {
		return nil, err
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := r.nativeBegin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	var gate bool
	var count int64
	if err = tx.QueryRow(ctx, financeNativeCount, args...).Scan(&gate, &count); err != nil || !gate || count < 0 {
		return nil, d.ErrUnavailable
	}
	at, id := time.Unix(0, 0).UTC(), int64(0)
	if after != nil {
		at = time.UnixMicro(after.FinanceLive.ObservedAtMicros).UTC()
		id, err = strconv.ParseInt(string(after.FinanceLive.ID), 10, 64)
		if err != nil {
			return nil, d.ErrInvalid
		}
	}
	rows, err := tx.Query(ctx, financeNativePage, append(args, after == nil, at, id, int(scope.Query.Limit())+1)...)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	events, digests, err := r.nativeRows(rows, scope.DataOrganizationID, sc, int(scope.Query.Limit())+1)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, d.ErrUnavailable
	}
	end := len(events) <= int(scope.Query.Limit())
	if !end {
		events = events[:scope.Query.Limit()]
		digests = digests[:scope.Query.Limit()]
	}
	observed := r.clock().UTC().Truncate(time.Microsecond)
	if !financeTime(observed) {
		return nil, d.ErrUnavailable
	}
	parts, _, _ := financeScopeParts(scope.DataOrganizationID, sc)
	parts = append(parts, []byte(strconv.FormatInt(count, 10)))
	for _, digest := range digests {
		parts = append(parts, digest[:])
	}
	ref := a.HashParts("ops.disclosure.finance-live-observation/v1", parts...)
	descriptor := r.nativeDescriptor(d.List, ref, observed)
	evidence := financeEvidence(events, descriptor.Reference)
	return &FinanceSnapshot{reader: r, scope: scope, descriptor: descriptor, liveEvents: events, liveDigests: digests, pageEnd: end, live: &d.FinanceLivePage{Items: evidence, MatchingRetainedCount: d.Count(strconv.FormatInt(count, 10)), ObservedAt: observed}}, nil
}

func (r *FinanceReader) nativeRows(rows pgx.Rows, org string, sc p.Scope, maximum int) ([]a.Event, []a.Digest, error) {
	defer rows.Close()
	events, digests := []a.Event{}, []a.Digest{}
	bytes := 0
	for rows.Next() {
		values, err := rows.Values()
		if err != nil || len(values) != 32 {
			return nil, nil, d.ErrUnavailable
		}
		gate, ok := values[0].(bool)
		if !ok || !gate {
			return nil, nil, d.ErrUnavailable
		}
		if values[1] == nil {
			if len(events) != 0 {
				return nil, nil, d.ErrUnavailable
			}
			continue
		}
		present, pok := values[1].(bool)
		shape, sok := values[2].(bool)
		if !pok || !present || !sok || !shape || len(events) >= maximum {
			return nil, nil, d.ErrUnavailable
		}
		e, err := scanEvent(financeEventRow{Rows: rows}, r.network, r.state)
		if err != nil || e.Scope.Organization != org || !financeActorInScope(sc, e.Scope.Actor) || !financeNormalizeEvent(&e) {
			return nil, nil, d.ErrUnavailable
		}
		parts, size, err := financeEventParts(e)
		if err != nil {
			return nil, nil, err
		}
		if size > MaxFinanceDecodedBytes-bytes {
			return nil, nil, d.ErrTooBroad
		}
		bytes += size
		if len(events) > 0 {
			prev := events[len(events)-1]
			if e.DecisionAt.After(prev.DecisionAt) || e.DecisionAt.Equal(prev.DecisionAt) && e.ID >= prev.ID {
				return nil, nil, d.ErrUnavailable
			}
		}
		events = append(events, e)
		digests = append(digests, a.HashParts("ops.disclosure.finance-event/v1", parts...))
	}
	if rows.Err() != nil {
		return nil, nil, d.ErrUnavailable
	}
	return events, digests, nil
}

func (s *FinanceSnapshot) LivePage() *d.FinanceLivePage {
	if s == nil || s.closed.Load() || s.live == nil {
		return nil
	}
	out := *s.live
	out.Items = financeEvidence(s.liveEvents, s.descriptor.Reference)
	return &out
}

func (s *FinanceSnapshot) checkNativeCurrent(ctx context.Context) error {
	sc, err := s.reader.validateScope(s.scope)
	if err != nil {
		return err
	}
	args, err := s.reader.nativeArgs(s.scope.DataOrganizationID, sc)
	if err != nil {
		return err
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := s.reader.nativeBegin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if s.summary != nil {
		var gate bool
		if err = tx.QueryRow(ctx, financeNativeContext, args[:7]...).Scan(&gate); err != nil || !gate {
			return d.ErrUnavailable
		}
	} else {
		ids := make([]int64, len(s.liveEvents))
		for i, e := range s.liveEvents {
			ids[i] = e.ID
		}
		rows, err := tx.Query(ctx, financeNativeIDs, append(args, ids)...)
		if err != nil {
			return d.ErrUnavailable
		}
		_, digests, err := s.reader.nativeRows(rows, s.scope.DataOrganizationID, sc, 100)
		if err != nil {
			return err
		}
		if !slices.Equal(digests, s.liveDigests) {
			return d.ErrConflict
		}
	}
	if tx.Commit(ctx) != nil {
		return d.ErrUnavailable
	}
	return nil
}
