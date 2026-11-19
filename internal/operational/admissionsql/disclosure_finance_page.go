package admissionsql

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	a "privacy-proxy/internal/admission"
	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
)

// The scan ceiling is independent of the <=100 returned body rows. The original
// cumulative canonical hash-byte ceiling usually stops rich cohorts earlier.
const MaxFinanceScanEvents = d.MaxEntries

type financePageObservation struct {
	events              []a.Event
	count, before       uint64
	end                 bool
	reference, coverage a.Digest
}

// OpenPage never treats an event ID as a commit frontier. Every read validates
// and fingerprints the entire bounded cohort, even rows outside this page.
func (r *FinanceReader) OpenPage(ctx context.Context, scope d.ReadScope, expected *d.SourceRef, after *d.Position) (*FinanceSnapshot, error) {
	sc, err := r.validateScope(scope)
	if err != nil {
		return nil, err
	}
	if scope.Query.View() != d.List || d.PositionForQuery(scope.Query, after) != nil {
		return nil, d.ErrInvalid
	}
	if expected != nil {
		if _, ok := financeDigest(expected.ID); !ok || expected.Kind != d.FinanceSource {
			return nil, d.ErrInvalid
		}
	}
	got, err := r.readPage(ctx, scope.DataOrganizationID, sc, after, scope.Query.Limit())
	if err != nil {
		return nil, err
	}
	if expected != nil && expected.ID != d.Digest(got.reference.String()) {
		return nil, d.ErrConflict
	}
	asOf := r.clock().UTC().Truncate(time.Microsecond)
	if !financeTime(asOf) {
		return nil, d.ErrUnavailable
	}
	epoch := a.HashParts("ops.disclosure.finance-epoch/v1", r.network[:], []byte(r.state.Generation), r.state.Coverage[:])
	format := a.HashParts("ops.disclosure.finance-retained-format/v1")
	desc := d.SourceDescriptor{Version: 1, Kind: d.FinanceSource, Reference: d.Digest(got.reference.String()), NetworkKey: d.Digest(r.network.String()), Epoch: d.Digest(epoch.String()), Generation: r.state.Generation, PlanDigest: r.plan.PlanDigest, FormatDigest: d.Digest(format.String()), CoverageDigest: d.Digest(got.coverage.String()), AsOf: asOf, Population: "RETAINED_ADMISSION_DECISIONS_AS_OF_SNAPSHOT"}
	return &FinanceSnapshot{reader: r, scope: scope, descriptor: desc, evidence: financeEvidence(got.events, desc.Reference), page: &d.FinanceEvidencePage{MatchingRetainedCount: d.Count(strconv.FormatUint(got.count, 10)), BeforeCount: d.Count(strconv.FormatUint(got.before, 10))}, after: d.ClonePosition(after), pageEnd: got.end}, nil
}

func (s *FinanceSnapshot) Page() *d.FinanceEvidencePage {
	if s == nil || s.closed.Load() || s.page == nil {
		return nil
	}
	return &d.FinanceEvidencePage{Items: s.Evidence(), MatchingRetainedCount: s.page.MatchingRetainedCount, BeforeCount: s.page.BeforeCount}
}
func (s *FinanceSnapshot) End() bool {
	return s != nil && !s.closed.Load() && s.page != nil && s.pageEnd
}

func (r *FinanceReader) readPage(ctx context.Context, org string, sc p.Scope, after *d.Position, limit uint16) (financePageObservation, error) {
	var out financePageObservation
	parts, addresses, err := financeScopeParts(org, sc)
	if err != nil {
		return out, err
	}
	var afterID int64
	if after != nil {
		afterID, err = strconv.ParseInt(string(after.Finance.ID), 10, 64)
		if err != nil || afterID <= 0 {
			return out, d.ErrInvalid
		}
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, r.store.pool, true)
	if err != nil {
		return out, d.ErrUnavailable
	}
	defer rollback(tx)
	genesis, _ := hex.DecodeString(r.binding.GenesisHash[2:])
	rows, err := tx.Query(ctx, financePageQuery, r.network[:], r.state.Generation, r.state.Coverage[:], r.binding.Environment, r.binding.ChainID, genesis, r.binding.DeploymentID, org, sc.TargetActors, time.Unix(sc.DataTime.Start, 0).UTC(), time.Unix(sc.DataTime.End, 0).UTC(), sc.Addresses.Mode == "all-target-addresses", addresses, MaxFinanceScanEvents+1)
	if err != nil {
		return out, d.ErrUnavailable
	}
	defer rows.Close()
	digests := []a.Digest{}
	// Same accounting/framing as the original complete report. Never charge only
	// retained page bodies or only the compact digest bytes.
	hashBytes, bodyBytes, lastID := 65536+16384, 0, int64(0)
	afterFound := after == nil
	out.events = []a.Event{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil || len(values) != 32 {
			return financePageObservation{}, d.ErrUnavailable
		}
		gate, ok := values[0].(bool)
		if !ok || !gate {
			return financePageObservation{}, d.ErrUnavailable
		}
		if values[1] == nil {
			if out.count != 0 {
				return financePageObservation{}, d.ErrUnavailable
			}
			continue
		}
		present, ok := values[1].(bool)
		shape, shapeOK := values[2].(bool)
		if !ok || !present || !shapeOK || !shape {
			return financePageObservation{}, d.ErrUnavailable
		}
		if out.count == MaxFinanceScanEvents {
			return financePageObservation{}, d.ErrTooBroad
		}
		e, err := scanEvent(financeEventRow{Rows: rows}, r.network, r.state)
		if err != nil || e.Scope.Organization != org || !financeActorInScope(sc, e.Scope.Actor) || !financeNormalizeEvent(&e) || e.ID <= lastID {
			return financePageObservation{}, d.ErrUnavailable
		}
		lastID = e.ID
		row, size, err := financeEventParts(e)
		if err != nil {
			return financePageObservation{}, err
		}
		framed := size + 4*(len(row)+1) + len("ops.disclosure.finance-event/v1")
		if framed > MaxFinanceHashInputBytes-hashBytes {
			return financePageObservation{}, d.ErrTooBroad
		}
		hashBytes += framed
		digests = append(digests, a.HashParts("ops.disclosure.finance-event/v1", row...))
		out.count++
		if e.ID == afterID {
			afterFound = true
		}
		if e.ID <= afterID {
			out.before++
			continue
		}
		if len(out.events) < int(limit) {
			if size > MaxFinanceDecodedBytes-bodyBytes {
				return financePageObservation{}, d.ErrTooBroad
			}
			bodyBytes += size
			out.events = append(out.events, e)
		}
	}
	if rows.Err() != nil {
		return financePageObservation{}, d.ErrUnavailable
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return financePageObservation{}, d.ErrUnavailable
	}
	if !afterFound {
		return financePageObservation{}, d.ErrConflict
	}
	out.end = out.count-out.before == uint64(len(out.events))
	scopeDigest := a.HashParts("ops.disclosure.finance-scope/v1", parts...)
	out.reference, out.coverage, err = r.referenceDigests(scopeDigest, digests)
	if err != nil {
		return financePageObservation{}, err
	}
	return out, nil
}

func financeActorInScope(sc p.Scope, actor string) bool {
	for _, value := range sc.TargetActors {
		if value == actor {
			return true
		}
	}
	return false
}
