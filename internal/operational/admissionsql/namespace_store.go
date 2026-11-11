package admissionsql

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationfacts"
	h "privacy-proxy/internal/historynamespace"
)

type NamespaceExpectedState struct {
	Generation string
	Revision   int64
}

func (s NamespaceExpectedState) valid() bool { return h.UUID(s.Generation) && s.Revision >= 1 }

// NamespaceMetadata describes source readiness and archive restoration, not
// completeness of on-chain history or a historical namespace verdict.
type NamespaceMetadata struct {
	Network        h.Digest
	State          NamespaceExpectedState
	Era            h.ModelEra
	Limits         h.CapacityLimits
	Ready          bool
	SourceReady    bool
	BaseReady      bool
	BaseGeneration string
	Completeness   h.Digest
}

type NamespaceReader struct {
	pool       *pgxpool.Pool
	binding    a.NetworkBinding
	network    h.Digest
	generation string
	era        h.ModelEra
	limits     h.ReadLimits
}

func OpenNamespaceReader(ctx context.Context, dsn string, binding a.NetworkBinding, generation string, era h.ModelEra) (*NamespaceReader, error) {
	return OpenNamespaceReaderWithLimits(ctx, dsn, binding, generation, era, h.DefaultReadLimits())
}

// OpenNamespaceReaderWithLimits permits lower-only whole-pass ceilings. It
// changes neither source grants nor the C1 startup readiness/catalog checks.
func OpenNamespaceReaderWithLimits(ctx context.Context, dsn string, binding a.NetworkBinding, generation string, era h.ModelEra, limits h.ReadLimits) (*NamespaceReader, error) {
	if ctx == nil || !h.UUID(generation) || !era.Valid() || !limits.Valid() {
		return nil, h.ErrInvalid
	}
	key, genesis, err := bindingValues(binding)
	if err != nil {
		return nil, h.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil || config.ConnConfig.ValidateConnect != nil {
		// target_session_attrs modes other than default/any install
		// connection-validation SQL outside the bounded read counter.
		// Reject them without silently changing their target-selection meaning.
		return nil, h.ErrUnavailable
	}
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	// One budgeted operation uses one protocol roundtrip per SQL command.
	// Preparing statements or an implicit pool Ping would consume additional
	// synchronization boundaries outside the read transaction's counter.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ShouldPing = func(context.Context, pgxpool.ShouldPingParams) bool { return false }
	config.MaxConns = 4
	config.MinConns = 0
	config.MinIdleConns = 0
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, h.ErrUnavailable
	}
	r := &NamespaceReader{pool: pool, binding: binding, network: h.Digest(key), generation: generation, era: era, limits: limits}
	fail := func(tx pgx.Tx) (*NamespaceReader, error) {
		if tx != nil {
			rollback(tx)
		}
		pool.Close()
		return nil, h.ErrUnavailable
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return fail(nil)
	}
	defer rollback(tx)
	if version, err := schemaVersion(ctx, tx); err != nil || version != 3 || checkSchema(ctx, tx) != nil || checkNamespaceSchema(ctx, tx) != nil || checkNamespacePrivileges(ctx, tx) != nil || verifyBinding(ctx, tx, key, binding, genesis) != nil {
		return fail(tx)
	}
	metadata, err := readNamespaceMetadata(ctx, tx, r.network)
	if err != nil || !metadata.Ready || metadata.State.Generation != generation || metadata.Era != era {
		return fail(tx)
	}
	if tx.Commit(ctx) != nil {
		return fail(tx)
	}
	return r, nil
}

func (r *NamespaceReader) Close() {
	if r != nil && r.pool != nil {
		r.pool.Close()
	}
}

func (r *NamespaceReader) Metadata(ctx context.Context) (NamespaceMetadata, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return NamespaceMetadata{}, h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m, err := readNamespaceMetadata(ctx, r.pool, r.network)
	if err != nil || !m.Ready || m.State.Generation != r.generation || m.Era != r.era {
		return NamespaceMetadata{}, h.ErrUnavailable
	}
	return m, nil
}

func readNamespaceMetadata(ctx context.Context, q querier, network h.Digest) (NamespaceMetadata, error) {
	m := NamespaceMetadata{Network: network}
	var version int
	var model string
	var entry, completeness []byte
	if q.QueryRow(ctx, `SELECT s.schema_version,s.expected_admission_generation::text,s.revision,s.ready,s.completeness_digest,s.model_id,s.era_entry_number,s.era_entry_hash,s.era_entry_timestamp,s.era_end_timestamp_exclusive,
 s.max_lifetimes,s.max_transfers,s.max_cohorts,s.max_revoked_cohorts,s.max_lifetimes_per_address,s.max_transfers_per_segment,n.generation::text,n.ready
 FROM ops_history_namespace_v1.namespace_network_state s JOIN ops_admission_v2.network_state n USING(network_key)WHERE s.network_key=$1`, network[:]).Scan(&version, &m.State.Generation, &m.State.Revision, &m.SourceReady, &completeness, &model, &m.Era.EntryNumber, &entry, &m.Era.EntryTimestamp, &m.Era.EndTimestampExclusive,
		&m.Limits.Lifetimes, &m.Limits.Transfers, &m.Limits.Cohorts, &m.Limits.RevokedCohorts, &m.Limits.LifetimesPerAddress, &m.Limits.TransfersPerSegment, &m.BaseGeneration, &m.BaseReady) != nil || version != 1 || model != h.ModelID || len(entry) != 32 || !m.State.valid() || !h.UUID(m.BaseGeneration) || !m.Limits.Valid() {
		return NamespaceMetadata{}, h.ErrUnavailable
	}
	copy(m.Era.EntryHash[:], entry)
	if !m.Era.Valid() || len(completeness) != 0 && len(completeness) != 32 {
		return NamespaceMetadata{}, h.ErrUnavailable
	}
	copy(m.Completeness[:], completeness)
	m.Ready = m.SourceReady && m.BaseReady && m.BaseGeneration == m.State.Generation && m.Completeness != (h.Digest{})
	return m, nil
}

// Owner operations use the existing global offline lock before this exclusive
// network fence. They never perform node/file I/O while either lock is held.
func namespaceOffline(ctx context.Context, dsn string, binding a.NetworkBinding, timeout time.Duration, callback func(context.Context, pgx.Tx, h.Digest) error) error {
	if ctx == nil || timeout <= 0 || timeout > 30*time.Minute {
		return h.ErrInvalid
	}
	key, genesis, err := bindingValues(binding)
	if err != nil {
		return h.ErrInvalid
	}
	err = offlineConnection(ctx, dsn, timeout, func(ctx context.Context, tx pgx.Tx) error {
		if version, err := schemaVersion(ctx, tx); err != nil || version != 3 || checkSchema(ctx, tx) != nil || checkNamespaceSchema(ctx, tx) != nil {
			return h.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','2s',true),pg_advisory_xact_lock($1)`, creationfacts.CaptureFence(creationfacts.Digest(key))); err != nil {
			return h.ErrUnavailable
		}
		if verifyBinding(ctx, tx, key, binding, genesis) != nil {
			return h.ErrUnavailable
		}
		return callback(ctx, tx, h.Digest(key))
	})
	if err != nil {
		if err == h.ErrConflict || err == h.ErrInvalid || err == h.ErrTooBroad {
			return err
		}
		return h.ErrUnavailable
	}
	return nil
}

func lockNamespaceState(ctx context.Context, tx pgx.Tx, network h.Digest, expected NamespaceExpectedState) (NamespaceMetadata, error) {
	if !expected.valid() {
		return NamespaceMetadata{}, h.ErrInvalid
	}
	var locked bool
	if tx.QueryRow(ctx, `SELECT true FROM ops_history_namespace_v1.namespace_network_state WHERE network_key=$1 AND expected_admission_generation=$2::uuid AND revision=$3 FOR UPDATE`, network[:], expected.Generation, expected.Revision).Scan(&locked) != nil || !locked {
		return NamespaceMetadata{}, h.ErrConflict
	}
	return readNamespaceMetadata(ctx, tx, network)
}
