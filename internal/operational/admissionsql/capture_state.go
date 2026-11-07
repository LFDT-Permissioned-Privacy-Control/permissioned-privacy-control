package admissionsql

import (
	"context"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/identity"
)

var _ creationcapture.ReadinessStore = (*Store)(nil)

func captureLock(ctx context.Context, tx pgx.Tx, network a.Digest, shared bool) error {
	sql := `SELECT pg_catalog.pg_advisory_xact_lock($1::bigint)`
	if shared {
		sql = `SELECT pg_catalog.pg_advisory_xact_lock_shared($1::bigint)`
	}
	if _, err := tx.Exec(ctx, sql, creationfacts.CaptureFence(creationfacts.Digest(network))); err != nil {
		return a.ErrUnavailable
	}
	return nil
}

// captureDurable intentionally does NOT inspect capture_ready, heartbeat,
// moving header/head or lease state. A valid snapshot may commit afterC.
// The shared advisory fence prevents an invalidating exclusive transition
// from committing after this check but before the financial COMMIT.
func captureDurable(ctx context.Context, q querier, scope a.Scope, b a.CaptureCommitBinding) error {
	var good bool
	err := q.QueryRow(ctx, `SELECT n.ready AND n.generation=$2::uuid AND n.coverage_digest=$3
 AND o.ready AND o.quarantine='none'AND o.observer_epoch=$4::uuid AND o.capture_epoch=$5::uuid AND o.source_set_digest=$6
 AND NOT EXISTS(SELECT 1 FROM ops_admission_v2.revoked_creation_capture_epochs r WHERE r.network_key=o.network_key AND r.capture_epoch=o.capture_epoch)
 FROM ops_admission_v2.network_state n JOIN ops_admission_v2.creation_observer_state o USING(network_key)WHERE n.network_key=$1`, scope.Network[:], scope.State.Generation, scope.State.Coverage[:], b.ObserverEpoch, b.CaptureEpoch, b.SourceSet[:]).Scan(&good)
	if err != nil || !good {
		return a.ErrUnavailable
	}
	return nil
}

func (s *Store) ReadOriginBinding(ctx context.Context, network a.Digest, state a.ExpectedState, hash common.Hash) (a.CreationOriginBinding, bool, error) {
	if s.mode != "app" || s.schemaVersion != 3 || !state.Valid() || hash == (common.Hash{}) {
		return a.CreationOriginBinding{}, false, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	var ready bool
	var actor, org *string
	err := s.pool.QueryRow(ctx, `SELECT n.ready AND n.generation=$2::uuid AND n.coverage_digest=$3,o.actor_id,o.org_id::text FROM ops_admission_v2.network_state n LEFT JOIN ops_admission_v2.qualified_tx_origins o ON o.network_key=n.network_key AND o.tx_hash=$4 WHERE n.network_key=$1`, network[:], state.Generation, state.Coverage[:], hash[:]).Scan(&ready, &actor, &org)
	if err != nil || !ready {
		return a.CreationOriginBinding{}, false, a.ErrUnavailable
	}
	if actor == nil && org == nil {
		return a.CreationOriginBinding{}, false, nil
	}
	if actor == nil || org == nil || !identity.ValidActorID(*actor) || !a.ValidUUID(*org) {
		return a.CreationOriginBinding{}, false, a.ErrCoverage
	}
	return a.CreationOriginBinding{Actor: *actor, Organization: *org}, true, nil
}

func (s *Store) ReadCheckpoint(ctx context.Context, network creationfacts.Digest, state creationfacts.State, sourceSet creationfacts.Digest) (creationfacts.Checkpoint, error) {
	if s.mode != "app" || s.schemaVersion != 3 || !state.Valid() {
		return creationfacts.Checkpoint{}, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	cp := creationfacts.Checkpoint{Network: network, State: state}
	var source, reference, hash, parent []byte
	var timestamp, ttl string
	err := s.pool.QueryRow(ctx, `SELECT o.observer_epoch::text,o.capture_epoch::text,o.source_set_digest,o.reference_binding_digest,h.number,h.hash,h.parent_hash,h.timestamp::text,o.header_version,o.lease_fence,trunc(extract(epoch FROM(o.capture_heartbeat_until-clock_timestamp()))*1000000000)::text
 FROM ops_admission_v2.network_state n JOIN ops_admission_v2.creation_observer_state o USING(network_key)JOIN ops_admission_v2.creation_headers h ON h.network_key=o.network_key AND h.number=o.head_number AND h.hash=o.head_hash
 WHERE n.network_key=$1 AND n.ready AND n.generation=$2::uuid AND n.coverage_digest=$3 AND o.ready AND o.quarantine='none'AND o.capture_ready AND o.source_set_digest=$4
 AND o.known_tip_number=o.head_number AND o.known_tip_hash=o.head_hash AND o.lease_owner IS NOT NULL AND o.lease_expires>clock_timestamp()AND o.capture_heartbeat_until>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM ops_admission_v2.revoked_creation_capture_epochs r WHERE r.network_key=o.network_key AND r.capture_epoch=o.capture_epoch)`, network[:], state.Generation, state.Coverage[:], sourceSet[:]).Scan(&cp.ObserverEpoch, &cp.CaptureEpoch, &source, &reference, &cp.HighWater.Number, &hash, &parent, &timestamp, &cp.HeaderVersion, &cp.LeaseFence, &ttl)
	if err != nil || len(source) != 32 || len(reference) != 32 || len(hash) != 32 || len(parent) != 32 || len(timestamp) > 20 || len(ttl) > 10 {
		return creationfacts.Checkpoint{}, a.ErrUnavailable
	}
	cp.HighWater.Timestamp, err = strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		return creationfacts.Checkpoint{}, a.ErrUnavailable
	}
	nanos, err := strconv.ParseInt(ttl, 10, 64)
	if err != nil || nanos <= 0 || nanos > int64(creationfacts.HeartbeatTTL) {
		return creationfacts.Checkpoint{}, a.ErrUnavailable
	}
	copy(cp.SourceSet[:], source)
	copy(cp.Reference[:], reference)
	copy(cp.HighWater.Hash[:], hash)
	copy(cp.HighWater.Parent[:], parent)
	cp.RemainingTTL = time.Duration(nanos)
	if !cp.Valid() || cp.SourceSet != sourceSet {
		return creationfacts.Checkpoint{}, a.ErrUnavailable
	}
	return cp, nil
}

func (s *Store) ConfirmCapture(ctx context.Context, prior creationfacts.Checkpoint, anchor creationfacts.Header) (creationfacts.Checkpoint, error) {
	if !prior.Valid() || !anchor.Valid() {
		return creationfacts.Checkpoint{}, a.ErrInvalid
	}
	cp, err := s.ReadCheckpoint(ctx, prior.Network, prior.State, prior.SourceSet)
	if err != nil || !cp.SameTrust(prior) || cp.HighWater.Number > anchor.Number || (cp.HighWater.Number == anchor.Number && cp.HighWater.Hash != anchor.Hash) {
		return creationfacts.Checkpoint{}, a.ErrUnavailable
	}
	return cp, nil
}
