package admissionsql

import (
	"context"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/creationfacts"
)

func validateRestoredObserver(ctx context.Context, tx pgx.Tx, network a.Digest) error {
	var bad bool
	if err := tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_refs r JOIN ops_admission_v2.creation_plans p USING(network_key,tx_hash,plan_digest)LEFT JOIN ops_admission_v2.creation_capture_coverage c USING(network_key,tx_hash,seed_digest)WHERE r.network_key=$1 AND((p.version=2)<>(c.seed_digest IS NOT NULL)OR c.plan_version IS NOT NULL AND c.plan_version<>p.version OR c.h_number>r.anchor_number OR c.latest_number<r.anchor_number OR(c.h_number=r.anchor_number AND c.h_hash<>r.anchor_hash)))
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_capacity c WHERE c.network_key=$1 AND(
 capture_coverage_count<>(SELECT count(*)FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1)
 OR capture_coverage_bytes<>(SELECT coalesce(sum(logical_bytes::bigint),0)FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1)
 OR revoked_epoch_count<>(SELECT count(*)FROM ops_admission_v2.revoked_creation_capture_epochs WHERE network_key=$1)
 OR header_count<>(SELECT count(*)FROM ops_admission_v2.creation_headers WHERE network_key=$1)
 OR birth_count<>(SELECT count(*)FROM ops_admission_v2.creation_births WHERE network_key=$1)
 OR association_count<>(SELECT count(*)FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1)))
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND NOT EXISTS(SELECT 1 FROM ops_admission_v2.creation_observer_state WHERE network_key=$1))`, network[:]).Scan(&bad); err != nil || bad {
		return a.ErrCoverage
	}
	var lastHash, lastSeed []byte
	for {
		rows, err := tx.Query(ctx, `SELECT tx_hash,seed_digest,`+coverageColumns+` FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND($2::bytea IS NULL OR(tx_hash,seed_digest)>($2::bytea,$3::bytea))ORDER BY tx_hash,seed_digest LIMIT 256`, network[:], lastHash, lastSeed)
		if err != nil {
			return a.ErrUnavailable
		}
		count := 0
		for rows.Next() {
			var hash, seed []byte
			var scan coverageScan
			dest := []any{&hash, &seed}
			dest = append(dest, scan.destinations()...)
			if rows.Scan(dest...) != nil || len(hash) != 32 || len(seed) != 32 {
				rows.Close()
				return a.ErrCoverage
			}
			record, err := scan.finish()
			if err != nil || record.Network != f.Digest(network) {
				rows.Close()
				return a.ErrCoverage
			}
			lastHash, lastSeed = hash, seed
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return a.ErrUnavailable
		}
		if count == 0 {
			break
		}
	}
	var observed bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_observer_state WHERE network_key=$1)`, network[:]).Scan(&observed) != nil {
		return a.ErrCoverage
	}
	if !observed {
		return nil
	}
	current, _, err := scanObserver(tx.QueryRow(ctx, `SELECT `+observerStateColumns+` `+observerStateJoin, network[:]), f.Digest(network))
	if err != nil {
		return err
	}
	// Present-row consistency cannot establish absent backup facts or past
	// caught-up trust. Both remain explicit offline completeness attestations.
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM(SELECT number,hash,parent_hash,timestamp,lag(number)OVER(ORDER BY number)n,lag(hash)OVER(ORDER BY number)h,lag(timestamp)OVER(ORDER BY number)t FROM ops_admission_v2.creation_headers WHERE network_key=$1)x WHERE(n IS NOT NULL AND(number<>n+1 OR parent_hash<>h OR timestamp<=t))OR number<$2 OR number>$3)
 OR(SELECT count(*)FROM ops_admission_v2.creation_headers WHERE network_key=$1)<>($3::numeric-$2::numeric+1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_capture_coverage c JOIN ops_admission_v2.creation_authority_refs r USING(network_key,tx_hash,seed_digest)WHERE c.network_key=$1 AND r.anchor_number<$2)`, network[:], current.Floor.Number, current.Head.Number).Scan(&bad) != nil || bad {
		return a.ErrCoverage
	}
	return nil
}

// RevokeCaptureEpochs appends a bounded deny-only cohort selection. It requires
// drained recovery and an explicit sticky quarantine; ordinary workers/roles
// cannot insert these rows. Duplicate requests preserve the first stored row.
func RevokeCaptureEpochs(ctx context.Context, dsn string, binding a.NetworkBinding, generation, observerEpoch, reason string, epochs []string, acknowledgeDrained bool) error {
	key, genesis, err := bindingValues(binding)
	if err != nil || !a.ValidUUID(generation) || !f.UUID(observerEpoch) || !acknowledgeDrained || len(epochs) == 0 || len(epochs) > 256 || (reason != "freshness-unproven" && reason != "source-binding-compromise" && reason != "restore-coverage-gap") {
		return a.ErrInvalid
	}
	epochs = slices.Clone(epochs)
	slices.Sort(epochs)
	for i, e := range epochs {
		if !f.UUID(e) || i > 0 && epochs[i-1] == e {
			return a.ErrInvalid
		}
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		version, err := schemaVersion(ctx, tx)
		if err != nil || version != 3 {
			return a.ErrUnavailable
		}
		if err := captureLock(ctx, tx, key, false); err != nil {
			return err
		}
		if err := verifyBinding(ctx, tx, key, binding, genesis); err != nil {
			return err
		}
		var permitted bool
		if tx.QueryRow(ctx, `SELECT NOT n.ready AND n.generation=$2::uuid AND NOT o.ready AND o.observer_epoch=$3::uuid AND o.quarantine NOT IN('none','awaiting-canonical') FROM ops_admission_v2.network_state n JOIN ops_admission_v2.creation_observer_state o USING(network_key)WHERE n.network_key=$1 FOR UPDATE OF n,o`, key[:], generation, observerEpoch).Scan(&permitted) != nil || !permitted {
			return a.ErrConflict
		}
		var count, covered int64
		if tx.QueryRow(ctx, `SELECT revoked_epoch_count,capture_coverage_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1 FOR UPDATE`, key[:]).Scan(&count, &covered) != nil {
			return a.ErrCoverage
		}
		added := int64(0)
		for _, epoch := range epochs {
			var hash, seed []byte
			if tx.QueryRow(ctx, `SELECT tx_hash,seed_digest FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1 AND capture_epoch=$2::uuid ORDER BY tx_hash,seed_digest LIMIT 1`, key[:], epoch).Scan(&hash, &seed) != nil || len(hash) != 32 || len(seed) != 32 {
				return a.ErrCoverage
			}
			tag, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.revoked_creation_capture_epochs(network_key,capture_epoch,witness_tx_hash,witness_seed_digest,reason,revoked_at)VALUES($1,$2::uuid,$3,$4,$5,clock_timestamp())ON CONFLICT(network_key,capture_epoch)DO NOTHING`, key[:], epoch, hash, seed, reason)
			if err != nil {
				return dbError(err)
			}
			added += tag.RowsAffected()
		}
		if count < 0 || count > f.DefaultLimits().RevokedEpochs-added || count > covered-added {
			return a.ErrCoverage
		}
		if added > 0 {
			if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_capacity SET revoked_epoch_count=revoked_epoch_count+$2 WHERE network_key=$1`, key[:], added); err != nil {
				return a.ErrUnavailable
			}
		}
		return nil
	})
}

// FinalizeCreationObserverRecovery is the explicit operator boundary for a
// sticky quarantine. Current node catch-up cannot establish original trust.
// The second acknowledgement includes complete affected-epoch selection and
// permanent preservation of prior revocations; it does not prove completeness.
func FinalizeCreationObserverRecovery(ctx context.Context, dsn string, binding a.NetworkBinding, expected a.ExpectedState, observerEpoch string, acknowledgeComplete, acknowledgeCaptureTrustResolved bool, timeout time.Duration) error {
	if !f.UUID(observerEpoch) || !acknowledgeCaptureTrustResolved {
		return a.ErrInvalid
	}
	return finalizeRecovery(ctx, dsn, binding, expected, acknowledgeComplete, timeout, observerEpoch)
}
func resetRestoredObserver(ctx context.Context, tx pgx.Tx, network a.Digest, expectedObserverEpoch string) error {
	var exists bool
	if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_observer_state WHERE network_key=$1)`, network[:]).Scan(&exists) != nil {
		return a.ErrUnavailable
	}
	if !exists {
		if expectedObserverEpoch != "" {
			return a.ErrConflict
		}
		return nil
	}
	current, _, err := scanObserver(tx.QueryRow(ctx, `SELECT `+observerStateColumns+` `+observerStateJoin+` FOR UPDATE OF o`, network[:]), f.Digest(network))
	if err != nil {
		return err
	}
	if current.HeaderVersion == math.MaxInt64 || current.LeaseFence == math.MaxInt64 {
		return a.ErrCoverage
	}
	if expectedObserverEpoch != "" && current.ObserverEpoch != expectedObserverEpoch {
		return a.ErrConflict
	}
	if current.Quarantine != "none" && current.Quarantine != "awaiting-canonical" && expectedObserverEpoch == "" {
		return a.ErrCoverage
	}
	_, err = tx.Exec(ctx, `UPDATE ops_admission_v2.creation_observer_state SET ready=false,capture_ready=false,quarantine='awaiting-canonical',observer_epoch=$2::uuid,capture_epoch=$3::uuid,lease_fence=lease_fence+1,header_version=header_version+1,lease_owner=NULL,lease_expires=NULL,capture_heartbeat_until=NULL WHERE network_key=$1`, network[:], uuid.NewString(), uuid.NewString())
	return dbError(err)
}

// readUnsignedNumeric bounds numeric conversion before allocation/conversion.
func readUnsignedNumeric(raw string) (uint64, error) {
	if len(raw) == 0 || len(raw) > 20 {
		return 0, a.ErrCoverage
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != raw {
		return 0, a.ErrCoverage
	}
	return n, nil
}
