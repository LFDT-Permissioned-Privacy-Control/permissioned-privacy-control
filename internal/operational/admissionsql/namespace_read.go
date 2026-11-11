package admissionsql

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	h "privacy-proxy/internal/historynamespace"
)

// Every root/address chunk is read in this ONE RR. The query budget includes
// BEGIN, setup and COMMIT; it cannot reset at a chunk boundary.
type namespaceReadTx struct {
	pgx.Tx
	queries, max int
	err          error
}

func (q *namespaceReadTx) take() error {
	if q.err != nil {
		return q.err
	}
	if q.queries >= q.max {
		q.err = h.ErrTooBroad
		return q.err
	}
	q.queries++
	return nil
}
func (q *namespaceReadTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := q.take(); err != nil {
		return nil, err
	}
	return q.Tx.Query(ctx, sql, args...)
}

type namespaceErrorRow struct{ err error }

func (r namespaceErrorRow) Scan(...any) error { return r.err }
func (q *namespaceReadTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if err := q.take(); err != nil {
		return namespaceErrorRow{err}
	}
	return q.Tx.QueryRow(ctx, sql, args...)
}
func (q *namespaceReadTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := q.take(); err != nil {
		return pgconn.CommandTag{}, err
	}
	return q.Tx.Exec(ctx, sql, args...)
}
func (r *NamespaceReader) DiscoverRequirements(ctx context.Context, input h.TrustedRootScope) (*h.Requirements, error) {
	if r == nil || ctx == nil || !r.limits.Valid() {
		return nil, h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	scope, err := h.PrepareRootScope(input, r.limits)
	if err != nil {
		return nil, err
	}
	var result *h.Requirements
	err = r.namespaceSnapshot(ctx, scope, func(ctx context.Context, facts h.Snapshot) error {
		var err error
		result, err = h.DiscoverRequirements(ctx, scope, facts, r.limits)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (r *NamespaceReader) ResolvePass(ctx context.Context, input h.TrustedRootPass) (*h.NamespacePass, error) {
	if r == nil || ctx == nil || !r.limits.Valid() {
		return nil, h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	pass, err := h.PrepareRootPass(input, r.limits)
	if err != nil {
		return nil, err
	}
	var result *h.NamespacePass
	err = r.namespaceSnapshot(ctx, pass.Scope(), func(ctx context.Context, facts h.Snapshot) error {
		var err error
		result, err = h.ResolvePass(ctx, pass, facts, r.limits)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// This callback is private pure computation only. No node, file, mutable
// provider or caller callback runs while the read transaction is open.
func (r *NamespaceReader) namespaceSnapshot(ctx context.Context, scope *h.RootScope, resolve func(context.Context, h.Snapshot) error) error {
	if r == nil || r.pool == nil || ctx == nil || scope == nil || !r.limits.Valid() || scope.Network() != r.network || scope.Era() != r.era {
		return h.ErrUnavailable
	}
	if ctx.Err() != nil {
		return h.ErrUnavailable
	}
	// BEGIN and its eventual COMMIT or ROLLBACK each need one physical
	// command. Reserve the completion slot before dispatching any SQL.
	if r.limits.MaxQueries < 2 {
		return h.ErrTooBroad
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return h.ErrUnavailable
	}
	defer rollback(tx)
	q := &namespaceReadTx{Tx: tx, queries: 1, max: r.limits.MaxQueries - 1}
	if _, err = q.Exec(ctx, `SELECT set_config('lock_timeout','500ms',true)`); err != nil {
		return namespaceReadError(q, err)
	}
	m, err := readNamespaceMetadata(ctx, q, r.network)
	if err != nil || !m.Ready || m.State.Generation != r.generation || m.Era != r.era {
		return namespaceReadError(q, h.ErrUnavailable)
	}
	facts := h.Snapshot{Network: r.network, Era: r.era, Generation: r.generation, NamespaceRevision: m.State.Revision, Completeness: m.Completeness, Ready: true}
	var coverage []byte
	if q.QueryRow(ctx, `SELECT coverage_digest FROM ops_admission_v2.network_state WHERE network_key=$1`, r.network[:]).Scan(&coverage) != nil {
		return namespaceReadError(q, h.ErrUnavailable)
	}
	var ok bool
	facts.AdmissionCoverage, ok = namespaceDigest(coverage)
	if !ok {
		return h.ErrUnavailable
	}
	facts.Observer, err = readNamespaceObserver(ctx, q, r.network)
	if err != nil {
		return namespaceReadError(q, err)
	}
	addresses := scope.Addresses()
	budget := namespaceCandidateBudget{limits: r.limits}
	for first := 0; first < len(addresses); first += 64 {
		chunk := addresses[first:min(first+64, len(addresses))]
		values := make([][]byte, len(chunk))
		for i, a := range chunk {
			values[i] = append([]byte(nil), a[:]...)
		}
		if err := readNamespaceLifetimes(ctx, q, &facts, values, &budget); err != nil {
			return namespaceReadError(q, err)
		}
		if err := readNamespaceTransfers(ctx, q, &facts, values, &budget); err != nil {
			return namespaceReadError(q, err)
		}
		if err := readNamespaceAutomatic(ctx, q, &facts, values, &budget); err != nil {
			return namespaceReadError(q, err)
		}
	}
	if err := resolve(ctx, facts); err != nil {
		return err
	}
	// Completion uses the slot reserved before BEGIN, including a real
	// deferred rollback when an earlier SQL or pure qualification fails.
	if ctx.Err() != nil || tx.Commit(ctx) != nil {
		return h.ErrUnavailable
	}
	return nil
}
func namespaceReadError(q *namespaceReadTx, err error) error {
	if q.err != nil {
		return q.err
	}
	if errors.Is(err, h.ErrTooBroad) || errors.Is(err, h.ErrInvalid) {
		return err
	}
	return h.ErrUnavailable
}

type namespaceCandidateBudget struct {
	limits      h.ReadLimits
	rows, bytes int
}

func (b *namespaceCandidateBudget) sentinel() int { return b.limits.MaxCandidates - b.rows + 1 }
func (b *namespaceCandidateBudget) add(value any) error {
	if b.rows >= b.limits.MaxCandidates {
		return h.ErrTooBroad
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return h.ErrUnavailable
	}
	if len(raw) > b.limits.MaxCandidateBytes-b.bytes {
		return h.ErrTooBroad
	}
	b.rows++
	b.bytes += len(raw)
	return nil
}
func namespaceQualifiedColumns(columns, alias string) string {
	parts := strings.Split(columns, ",")
	for i, p := range parts {
		parts[i] = alias + "." + p
	}
	return strings.Join(parts, ",")
}

type namespaceJoinedRow struct {
	row   namespaceScanner
	extra []any
}

func (r namespaceJoinedRow) Scan(fields ...any) error {
	return r.row.Scan(append(fields, r.extra...)...)
}

func readNamespaceLifetimes(ctx context.Context, q *namespaceReadTx, facts *h.Snapshot, addresses [][]byte, budget *namespaceCandidateBudget) error {
	rows, err := q.Query(ctx, `SELECT `+namespaceQualifiedColumns(namespaceLifetimeColumns, "l")+`,c.semantic_digest,d.cohort_id IS NOT NULL FROM ops_history_namespace_v1.legacy_contract_lifetimes l
 JOIN ops_history_namespace_v1.namespace_cohorts c USING(network_key,cohort_id)
 LEFT JOIN ops_history_namespace_v1.revoked_namespace_cohorts d USING(network_key,cohort_id)
 WHERE l.network_key=$1 AND l.address=ANY($2::bytea[])ORDER BY l.address,l.statement_digest LIMIT $3`, facts.Network[:], addresses, budget.sentinel())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var semantic []byte
		var revoked bool
		l, id, cohort, err := scanNamespaceLifetime(namespaceJoinedRow{rows, []any{&semantic, &revoked}}, facts.Network, facts.Era)
		if err != nil {
			return err
		}
		digest, ok := namespaceDigest(semantic)
		if !ok {
			return h.ErrUnavailable
		}
		f := h.LifetimeFact{ID: id, CohortID: cohort, CohortDigest: digest, Revoked: revoked, Lifetime: l}
		if err := budget.add(f); err != nil {
			return err
		}
		facts.Lifetimes = append(facts.Lifetimes, f)
	}
	return rows.Err()
}
func readNamespaceTransfers(ctx context.Context, q *namespaceReadTx, facts *h.Snapshot, addresses [][]byte, budget *namespaceCandidateBudget) error {
	rows, err := q.Query(ctx, `SELECT `+namespaceQualifiedColumns(namespaceTransferColumns, "t")+`,c.semantic_digest,d.cohort_id IS NOT NULL FROM ops_history_namespace_v1.namespace_transfers t
 JOIN ops_history_namespace_v1.namespace_cohorts c USING(network_key,cohort_id)
 LEFT JOIN ops_history_namespace_v1.revoked_namespace_cohorts d USING(network_key,cohort_id)
 WHERE t.network_key=$1 AND t.address=ANY($2::bytea[])ORDER BY t.address,t.transfer_digest LIMIT $3`, facts.Network[:], addresses, budget.sentinel())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var semantic []byte
		var revoked bool
		t, id, cohort, err := scanNamespaceTransfer(namespaceJoinedRow{rows, []any{&semantic, &revoked}}, facts.Network, facts.Era)
		if err != nil {
			return err
		}
		digest, ok := namespaceDigest(semantic)
		if !ok {
			return h.ErrUnavailable
		}
		f := h.TransferFact{ID: id, CohortID: cohort, CohortDigest: digest, Revoked: revoked, Transfer: t}
		if err := budget.add(f); err != nil {
			return err
		}
		facts.Transfers = append(facts.Transfers, f)
	}
	return rows.Err()
}

func readNamespaceObserver(ctx context.Context, q *namespaceReadTx, network h.Digest) (*h.ObserverTrust, error) {
	var out h.ObserverTrust
	var floorHash, floorParent, headHash, headParent, source, reference []byte
	var floorTime, headTime string
	err := q.QueryRow(ctx, `SELECT o.observer_epoch::text,o.ready,o.quarantine,f.number,f.hash,f.parent_hash,f.timestamp::text,h.number,h.hash,h.parent_hash,h.timestamp::text,o.reorg_epoch,o.source_set_digest,o.reference_binding_digest
 FROM ops_admission_v2.creation_observer_state o
 JOIN ops_admission_v2.creation_headers f ON f.network_key=o.network_key AND f.number=o.floor_number AND f.hash=o.floor_hash
 JOIN ops_admission_v2.creation_headers h ON h.network_key=o.network_key AND h.number=o.head_number AND h.hash=o.head_hash WHERE o.network_key=$1`, network[:]).Scan(&out.Epoch, &out.Ready, &out.Quarantine, &out.Floor.Number, &floorHash, &floorParent, &floorTime, &out.Head.Number, &headHash, &headParent, &headTime, &out.ReorgEpoch, &source, &reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !h.UUID(out.Epoch) || len(floorTime) > 20 || len(headTime) > 20 || len(floorParent) != 32 || len(headParent) != 32 {
		return nil, h.ErrUnavailable
	}
	var ok bool
	if out.Floor.Hash, ok = namespaceHash(floorHash); !ok {
		return nil, h.ErrUnavailable
	}
	copy(out.Floor.ParentHash[:], floorParent)
	if out.Head.Hash, ok = namespaceHash(headHash); !ok {
		return nil, h.ErrUnavailable
	}
	copy(out.Head.ParentHash[:], headParent)
	if out.SourceSet, ok = namespaceDigest(source); !ok {
		return nil, h.ErrUnavailable
	}
	if out.Reference, ok = namespaceDigest(reference); !ok {
		return nil, h.ErrUnavailable
	}
	out.Floor.Timestamp, err = strconv.ParseUint(floorTime, 10, 64)
	if err != nil {
		return nil, h.ErrUnavailable
	}
	out.Head.Timestamp, err = strconv.ParseUint(headTime, 10, 64)
	if err != nil {
		return nil, h.ErrUnavailable
	}
	return &out, nil
}

func readNamespaceAutomatic(ctx context.Context, q *namespaceReadTx, facts *h.Snapshot, addresses [][]byte, budget *namespaceCandidateBudget) error {
	rows, err := q.Query(ctx, `SELECT b.address,b.output_hash,b.output_length,b.inclusion_number,b.inclusion_hash,b.tx_hash,b.tx_index,b.actual_creation_record,b.proof_digest,b.evidence_profile,
 a.namespace::text,a.seed_digest,a.planned_entry,a.qualification_digest,a.kind,
 r.anchor_hash,r.anchor_number::text,r.anchor_timestamp::text,r.evidence_profile,r.plan_digest,r.manifest_digest,r.runtime_digest,r.branch,
 (a.kind=r.kind AND((a.kind='WALLET'AND a.wallet_actor=r.wallet_actor AND a.namespace=r.wallet_org AND a.factory_root IS NULL)OR(a.kind='FACTORY'AND a.wallet_actor IS NULL AND a.factory_root IS NOT NULL))),
 `+namespaceQualifiedColumns(coverageColumns, "c")+`,
 d.capture_epoch IS NOT NULL,ah.parent_hash,(ah.hash IS NOT NULL AND ah.timestamp=r.anchor_timestamp),bh.hash IS NOT NULL
 FROM ops_admission_v2.creation_births b
 JOIN ops_admission_v2.creation_authority_associations a USING(network_key,tx_hash,inclusion_hash,actual_creation_record)
 JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash,seed_digest)
 JOIN ops_admission_v2.creation_capture_coverage c USING(network_key,tx_hash,seed_digest)
 LEFT JOIN ops_admission_v2.revoked_creation_capture_epochs d ON d.network_key=c.network_key AND d.capture_epoch=c.capture_epoch
 LEFT JOIN ops_admission_v2.creation_headers ah ON ah.network_key=r.network_key AND ah.number=r.anchor_number AND ah.hash=r.anchor_hash
 LEFT JOIN ops_admission_v2.creation_headers bh ON bh.network_key=b.network_key AND bh.number=b.inclusion_number AND bh.hash=b.inclusion_hash
 WHERE b.network_key=$1 AND b.address=ANY($2::bytea[])ORDER BY b.address,b.inclusion_hash,b.actual_creation_record,a.seed_digest,a.planned_entry LIMIT $3`, facts.Network[:], addresses, budget.sentinel())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f h.AutomaticFact
		var address, runtime, birthHash, txHash, proof, seed, qualification, anchorHash, plan, manifest, runtimeSource, parent []byte
		var number, timestamp, profile string
		var originalBound bool
		var coverage coverageScan
		dest := []any{&address, &runtime, &f.RuntimeLength, &f.Birth.Number, &birthHash, &txHash, &f.Birth.Index, &f.Birth.Record, &proof, &profile,
			&f.Namespace, &seed, &f.PlannedEntry, &qualification, &f.Kind, &anchorHash, &number, &timestamp, &f.OriginalProfile, &plan, &manifest, &runtimeSource, &f.Branch, &originalBound}
		dest = append(dest, coverage.destinations()...)
		dest = append(dest, &f.Revoked, &parent, &f.StoredAnchorCanonical, &f.StoredBirthCanonical)
		if rows.Scan(dest...) != nil || len(address) != 20 || len(number) > 20 || len(timestamp) > 20 || profile != "reth-prague-included-creations/v1" || !originalBound {
			return h.ErrUnavailable
		}
		copy(f.Address[:], address)
		var ok bool
		for _, field := range []struct {
			dst *h.Hash
			raw []byte
		}{{&f.RuntimeHash, runtime}, {&f.Birth.Hash, birthHash}, {&f.Birth.TransactionHash, txHash}, {&f.Proof, proof}, {&f.Anchor.Hash, anchorHash}} {
			if *field.dst, ok = namespaceHash(field.raw); !ok {
				return h.ErrUnavailable
			}
		}
		for _, field := range []struct {
			dst *h.Digest
			raw []byte
		}{{&f.Seed, seed}, {&f.Qualification, qualification}, {&f.Plan, plan}, {&f.Manifest, manifest}, {&f.Runtime, runtimeSource}} {
			if *field.dst, ok = namespaceDigest(field.raw); !ok {
				return h.ErrUnavailable
			}
		}
		f.Anchor.Number, err = strconv.ParseUint(number, 10, 64)
		if err != nil {
			return h.ErrUnavailable
		}
		f.Anchor.Timestamp, err = strconv.ParseUint(timestamp, 10, 64)
		if err != nil {
			return h.ErrUnavailable
		}
		if len(parent) != 0 && len(parent) != 32 {
			return h.ErrUnavailable
		}
		copy(f.Anchor.ParentHash[:], parent)
		c, err := coverage.finish()
		if err != nil || h.Digest(c.Network) != facts.Network ||
			c.HighWater.Number > f.Anchor.Number || c.Latest.Number < f.Anchor.Number || c.HighWater.Number == f.Anchor.Number && h.Hash(c.HighWater.Hash) != f.Anchor.Hash {
			return h.ErrUnavailable
		}
		f.Coverage = h.Digest(c.Digest())
		f.OriginalGeneration = c.State.Generation
		f.OriginalStateCoverage = h.Digest(c.State.Coverage)
		if err := budget.add(f); err != nil {
			return err
		}
		facts.Automatic = append(facts.Automatic, f)
	}
	return rows.Err()
}
