package admissionsql

import (
	"context"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	"privacy-proxy/internal/creationfacts"
)

// BootstrapCreationObserver accepts only a fresh observer over empty/A1v1
// journal history. The header is trusted offline orchestration input: the CLI
// must acquire/verify it against its selected node BEFORE this SQL transaction.
// Existing schema3 histories require drained recovery, never fresh blessing.
func BootstrapCreationObserver(ctx context.Context, dsn string, binding a.NetworkBinding, expected a.ExpectedState, metadata creationcapture.Metadata, floor creationfacts.Header) error {
	key, genesis, err := bindingValues(binding)
	if err != nil || !expected.Valid() || !floor.Valid() {
		return a.ErrInvalid
	}
	network := creationfacts.Network{Key: creationfacts.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: common.HexToHash(binding.GenesisHash), Deployment: binding.DeploymentID}
	state := creationfacts.State{Generation: expected.Generation, Coverage: creationfacts.Digest(expected.Coverage)}
	if !network.Valid() || metadata.Network != network || metadata.State != state || metadata.SourceSet == (creationfacts.Digest{}) || metadata.Reference == (creationfacts.Digest{}) {
		return a.ErrInvalid
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
		var generation bool
		if err := tx.QueryRow(ctx, `SELECT generation=$2::uuid FROM ops_admission_v2.network_state WHERE network_key=$1 FOR UPDATE`, key[:], expected.Generation).Scan(&generation); err != nil || !generation {
			return a.ErrConflict
		}
		var previous bool
		if err := tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM ops_admission_v2.creation_observer_state WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_headers WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_births WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_capture_coverage WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.revoked_creation_capture_epochs WHERE network_key=$1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_plans WHERE network_key=$1 AND version<>1)
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_work WHERE network_key=$1 AND(processed_generation<>0 OR next_attempt_at IS NOT NULL OR retry_count<>0 OR outcome<>'pending'OR inclusion_hash IS NOT NULL OR inclusion_number IS NOT NULL OR last_reorg_epoch<>0))
 OR EXISTS(SELECT 1 FROM ops_admission_v2.creation_capacity WHERE network_key=$1 AND(capture_coverage_count<>0 OR capture_coverage_bytes<>0 OR revoked_epoch_count<>0 OR header_count<>0 OR birth_count<>0 OR association_count<>0))`, key[:]).Scan(&previous); err != nil || previous {
			return a.ErrConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.creation_observer_state(network_key,observer_epoch,ready,quarantine,floor_number,floor_hash,head_number,head_hash,header_version,capture_epoch,capture_ready,source_set_digest,reference_binding_digest,caught_up_assertion)VALUES($1,$2::uuid,false,'awaiting-canonical',$3,$4,$3,$4,1,$5::uuid,false,$6,$7,$8)`, key[:], uuid.NewString(), floor.Number, floor.Hash[:], uuid.NewString(), metadata.SourceSet[:], metadata.Reference[:], creationfacts.CaughtUpAssertion); err != nil {
			return a.ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.creation_headers(network_key,number,hash,parent_hash,timestamp)VALUES($1,$2,$3,$4,$5::numeric)`, key[:], floor.Number, floor.Hash[:], floor.Parent[:], strconv.FormatUint(floor.Timestamp, 10)); err != nil {
			return a.ErrUnavailable
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_capacity SET header_count=1 WHERE network_key=$1 AND header_count=0`, key[:])
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrCoverage
		}
		return nil
	})
}
