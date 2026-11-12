package admissionsql

import (
	"context"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/historynamespace"
	"time"
)

func (s *Store) CheckReady(ctx context.Context, network a.Digest, expected a.ExpectedState) error {
	if s == nil || s.pool == nil || ctx == nil || !expected.Valid() {
		return a.ErrUnavailable
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	if s.CheckSchema(ctx) != nil || s.checkPrivileges(ctx) != nil {
		return a.ErrUnavailable
	}
	err := s.readReady(ctx, network, expected, func(context.Context, pgx.Tx) error { return nil })
	if err != nil || ctx.Err() != nil {
		return a.ErrUnavailable
	}
	return nil
}

func (r *NamespaceReader) CheckReady(ctx context.Context) error {
	if r == nil || r.pool == nil || ctx == nil {
		return h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return h.ErrUnavailable
	}
	defer rollback(tx)
	m, err := readNamespaceMetadata(ctx, tx, r.network)
	if err != nil || !m.Ready || m.State.Generation != r.generation || m.Era != r.era || checkSchema(ctx, tx) != nil || checkNamespaceSchema(ctx, tx) != nil || checkNamespacePrivileges(ctx, tx) != nil {
		return h.ErrUnavailable
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return h.ErrUnavailable
	}
	return nil
}

// CheckReady checks the observer's declared readiness/quarantine and exact
// binding, without inventing an address or admitting an ownership association.
// A request still checks observer progress against its actual node anchor.
func (r *AddressReader) CheckReady(ctx context.Context) error {
	if r == nil || r.store == nil || ctx == nil {
		return a.ErrUnavailable
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	b := r.meta.Binding
	var current addressCurrentScan
	err := r.store.pool.QueryRow(ctx, `SELECT n.environment,n.chain_id,n.genesis_hash,n.deployment_id,n.generation::text,n.coverage_digest,n.ready,
 o.ready,o.observer_epoch::text,o.quarantine,o.reorg_epoch,o.source_set_digest,o.reference_binding_digest,
 fh.number,fh.hash,fh.timestamp::text,hh.number,hh.hash,hh.timestamp::text
 FROM ops_admission_v2.network_state n JOIN ops_admission_v2.creation_observer_state o USING(network_key)
 JOIN ops_admission_v2.creation_headers fh ON fh.network_key=o.network_key AND fh.number=o.floor_number AND fh.hash=o.floor_hash
 JOIN ops_admission_v2.creation_headers hh ON hh.network_key=o.network_key AND hh.number=o.head_number AND hh.hash=o.head_hash
 WHERE n.network_key=$1`, b.Network.Key[:]).Scan(current.destinations()...)
	if err != nil || !current.valid(b) || ctx.Err() != nil {
		return a.ErrUnavailable
	}
	return nil
}
