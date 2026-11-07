package admissionsql

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	h "privacy-proxy/internal/historynamespace"
)

// BootstrapNamespace accepts only a genuinely new supplemental archive. The
// operator attests that no earlier namespace archive was lost; row absence
// cannot establish that historical fact. The source starts unready.
func BootstrapNamespace(ctx context.Context, dsn string, binding a.NetworkBinding, generation string, era h.ModelEra, limits h.CapacityLimits, acknowledgeDrained, acknowledgeNeverInitialized bool) error {
	if !acknowledgeDrained || !acknowledgeNeverInitialized || !h.UUID(generation) || !era.Valid() || !limits.Valid() {
		return h.ErrInvalid
	}
	return namespaceOffline(ctx, dsn, binding, 60*time.Second, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		var matches bool
		if tx.QueryRow(ctx, `SELECT generation=$2::uuid AND ready FROM ops_admission_v2.network_state WHERE network_key=$1`, network[:], generation).Scan(&matches) != nil || !matches {
			return h.ErrConflict
		}
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_network_state WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_cohorts WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.legacy_contract_lifetimes WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.namespace_transfers WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_history_namespace_v1.revoked_namespace_cohorts WHERE network_key=$1)`, network[:]).Scan(&exists) != nil || exists {
			return h.ErrConflict
		}
		_, err := tx.Exec(ctx, `INSERT INTO ops_history_namespace_v1.namespace_network_state(network_key,schema_version,expected_admission_generation,revision,ready,model_id,era_entry_number,era_entry_hash,era_entry_timestamp,era_end_timestamp_exclusive,
 max_lifetimes,max_transfers,max_cohorts,max_revoked_cohorts,max_lifetimes_per_address,max_transfers_per_segment,lifetime_count,transfer_count,cohort_count,revoked_cohort_count)
 VALUES($1,1,$2::uuid,1,false,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,0,0,0,0)`, network[:], generation, h.ModelID, era.EntryNumber, era.EntryHash[:], era.EntryTimestamp, era.EndTimestampExclusive,
			limits.Lifetimes, limits.Transfers, limits.Cohorts, limits.RevokedCohorts, limits.LifetimesPerAddress, limits.TransfersPerSegment)
		if err != nil {
			return h.ErrUnavailable
		}
		return nil
	})
}

func ReadNamespaceOwnerMetadata(ctx context.Context, dsn string, binding a.NetworkBinding) (NamespaceMetadata, error) {
	var metadata NamespaceMetadata
	err := namespaceOffline(ctx, dsn, binding, 30*time.Second, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		var err error
		metadata, err = readNamespaceMetadata(ctx, tx, network)
		return err
	})
	return metadata, err
}

// BeginNamespaceRecovery persists the unready boundary before imports or
// restore validation. A global admission-generation change never certifies the
// supplemental archive; only its own later finalize may do so.
func BeginNamespaceRecovery(ctx context.Context, dsn string, binding a.NetworkBinding, expected NamespaceExpectedState, newGeneration string, acknowledgeDrained bool) error {
	if !acknowledgeDrained || !expected.valid() || !h.UUID(newGeneration) {
		return h.ErrInvalid
	}
	return namespaceOffline(ctx, dsn, binding, 60*time.Second, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		m, err := lockNamespaceState(ctx, tx, network, expected)
		if err != nil {
			return err
		}
		if m.BaseGeneration != newGeneration {
			return h.ErrConflict
		}
		if !m.SourceReady && m.State.Generation == newGeneration {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_history_namespace_v1.namespace_network_state SET ready=false,completeness_digest=NULL,expected_admission_generation=$2::uuid,revision=revision+1 WHERE network_key=$1 AND revision=$3`, network[:], newGeneration, expected.Revision)
		if err != nil || tag.RowsAffected() != 1 {
			return h.ErrUnavailable
		}
		return nil
	})
}

func RevokeNamespaceCohorts(ctx context.Context, dsn string, binding a.NetworkBinding, expected NamespaceExpectedState, cohortIDs []string, reason string, acknowledgeDrained bool) error {
	if !acknowledgeDrained || !expected.valid() || len(cohortIDs) == 0 || len(cohortIDs) > 256 || reason != "source-compromise" && reason != "restore-gap" {
		return h.ErrInvalid
	}
	cohortIDs = append([]string(nil), cohortIDs...)
	slices.Sort(cohortIDs)
	for i, id := range cohortIDs {
		if !h.UUID(id) || i > 0 && cohortIDs[i-1] == id {
			return h.ErrInvalid
		}
	}
	return namespaceOffline(ctx, dsn, binding, 60*time.Second, func(ctx context.Context, tx pgx.Tx, network h.Digest) error {
		m, err := lockNamespaceState(ctx, tx, network, expected)
		if err != nil {
			return err
		}
		if m.SourceReady || m.State.Generation != m.BaseGeneration {
			return h.ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT c.cohort_id::text,r.reason FROM ops_history_namespace_v1.namespace_cohorts c LEFT JOIN ops_history_namespace_v1.revoked_namespace_cohorts r USING(network_key,cohort_id)WHERE c.network_key=$1 AND c.cohort_id=ANY($2::uuid[])ORDER BY c.cohort_id`, network[:], cohortIDs)
		if err != nil {
			return h.ErrUnavailable
		}
		newIDs := []string{}
		count := 0
		for rows.Next() {
			var id string
			var oldReason *string
			if rows.Scan(&id, &oldReason) != nil || oldReason != nil && *oldReason != reason {
				rows.Close()
				return h.ErrConflict
			}
			count++
			if oldReason == nil {
				newIDs = append(newIDs, id)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil || count != len(cohortIDs) {
			return h.ErrConflict
		}
		if len(newIDs) == 0 {
			return nil
		}
		var current int64
		if tx.QueryRow(ctx, `SELECT revoked_cohort_count FROM ops_history_namespace_v1.namespace_network_state WHERE network_key=$1`, network[:]).Scan(&current) != nil {
			return h.ErrUnavailable
		}
		if current > m.Limits.RevokedCohorts-int64(len(newIDs)) {
			return h.ErrTooBroad
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_history_namespace_v1.revoked_namespace_cohorts(network_key,cohort_id,reason,recorded_at)SELECT $1,id,$3,$4 FROM unnest($2::uuid[])id`, network[:], newIDs, reason, time.Now().UTC()); err != nil {
			return h.ErrUnavailable
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_history_namespace_v1.namespace_network_state SET revoked_cohort_count=revoked_cohort_count+$2,revision=revision+1 WHERE network_key=$1 AND revision=$3`, network[:], len(newIDs), expected.Revision)
		if err != nil || tag.RowsAffected() != 1 {
			return h.ErrUnavailable
		}
		return nil
	})
}
