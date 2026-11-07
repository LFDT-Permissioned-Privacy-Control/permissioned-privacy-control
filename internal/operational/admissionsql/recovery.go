package admissionsql

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
)

func EmptyCoverage() a.Digest { return a.HashParts("ops-admission-empty-source/v1") }
func offline(ctx context.Context, dsn string, callback func(context.Context, pgx.Tx) error) error {
	return offlineConnection(ctx, dsn, 60*time.Second, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		return callback(ctx, tx)
	})
}
func bindingValues(binding a.NetworkBinding) (a.Digest, []byte, error) {
	key, err := binding.Key()
	if err != nil {
		return key, nil, err
	}
	genesis, _ := hex.DecodeString(binding.GenesisHash[2:])
	return key, genesis, nil
}
func verifyBinding(ctx context.Context, tx pgx.Tx, key a.Digest, binding a.NetworkBinding, genesis []byte) error {
	var equal bool
	if err := tx.QueryRow(ctx, `SELECT environment=$2 AND chain_id=$3 AND genesis_hash=$4 AND deployment_id=$5 FROM ops_admission_v2.network_state WHERE network_key=$1`, key[:], binding.Environment, binding.ChainID, genesis, binding.DeploymentID).Scan(&equal); err != nil || !equal {
		return a.ErrConflict
	}
	return nil
}

// BootstrapEmpty cannot bless a restore. It accepts only a new, empty network.
func BootstrapEmpty(ctx context.Context, dsn string, binding a.NetworkBinding, generation string) error {
	key, genesis, err := bindingValues(binding)
	if err != nil || !a.ValidUUID(generation) {
		return a.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.network_state WHERE network_key=$1)OR EXISTS(SELECT 1 FROM ops_admission_v2.travel_records WHERE network_key=$1)OR EXISTS(SELECT 1 FROM ops_admission_v2.compliance_events WHERE network_key=$1)OR EXISTS(SELECT 1 FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1)OR EXISTS(SELECT 1 FROM ops_admission_v2.tx_shares WHERE network_key=$1)OR EXISTS(SELECT 1 FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1)`, key[:]).Scan(&exists); err != nil {
			return a.ErrUnavailable
		}
		if exists {
			return a.ErrConflict
		}
		coverage := EmptyCoverage()
		_, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.network_state(network_key,environment,chain_id,genesis_hash,deployment_id,generation,ready,coverage_digest)VALUES($1,$2,$3,$4,$5,$6::uuid,true,$7)`, key[:], binding.Environment, binding.ChainID, genesis, binding.DeploymentID, generation, coverage[:])
		return dbError(err)
	})
}

// BeginRecovery requires the operator to drain all writers/readers and workers.
// It changes readiness only, never invalidates stable per-transaction facts.
func BeginRecovery(ctx context.Context, dsn string, binding a.NetworkBinding, generation string) error {
	key, genesis, err := bindingValues(binding)
	if err != nil || !a.ValidUUID(generation) {
		return a.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		var zero a.Digest
		tag, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.network_state(network_key,environment,chain_id,genesis_hash,deployment_id,generation,ready,coverage_digest)VALUES($1,$2,$3,$4,$5,$6::uuid,false,$7)ON CONFLICT(network_key)DO UPDATE SET ready=false,generation=EXCLUDED.generation,coverage_digest=EXCLUDED.coverage_digest WHERE ops_admission_v2.network_state.generation<>EXCLUDED.generation OR NOT ops_admission_v2.network_state.ready`, key[:], binding.Environment, binding.ChainID, genesis, binding.DeploymentID, generation, zero[:])
		if err != nil {
			return a.ErrUnavailable
		}
		if tag.RowsAffected() != 1 {
			return a.ErrConflict
		}
		return verifyBinding(ctx, tx, key, binding, genesis)
	})
}

// FinalizeRecovery publishes an explicit operator completeness attestation. It
// does not infer missing history from existing rows, mint receipts or resubmit.
// Restoring five data tables, their constraints and the identity sequence is an
// offline database operation; incompatible schemas never become ready.
func FinalizeRecovery(ctx context.Context, dsn string, binding a.NetworkBinding, expected a.ExpectedState, acknowledgeComplete bool) error {
	key, genesis, err := bindingValues(binding)
	if err != nil || !expected.Valid() || expected.Coverage == (a.Digest{}) || !acknowledgeComplete {
		return a.ErrInvalid
	}
	return offline(ctx, dsn, func(ctx context.Context, tx pgx.Tx) error {
		if err := verifyBinding(ctx, tx, key, binding, genesis); err != nil {
			return err
		}
		var unready bool
		if err := tx.QueryRow(ctx, `SELECT NOT ready AND generation=$2::uuid FROM ops_admission_v2.network_state WHERE network_key=$1 FOR UPDATE`, key[:], expected.Generation).Scan(&unready); err != nil || !unready {
			return a.ErrConflict
		}
		if err := validateRestored(ctx, tx, key, expected); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_admission_v2.network_state SET ready=true,coverage_digest=$3 WHERE network_key=$1 AND generation=$2::uuid AND NOT ready`, key[:], expected.Generation, expected.Coverage[:])
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrUnavailable
		}
		return nil
	})
}

func validateRestored(ctx context.Context, tx pgx.Tx, key a.Digest, expected a.ExpectedState) error {
	// These checks detect inconsistent present rows, not missing absent facts.
	var bad bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.compliance_events e JOIN ops_admission_v2.travel_records r ON r.id=e.record_id WHERE e.network_key=$1 AND(e.network_key<>r.network_key OR e.org_id<>r.org_id OR e.actor_id<>r.actor_id OR e.tx_hash IS DISTINCT FROM r.used_tx_hash OR r.used_at IS NULL))OR EXISTS(SELECT 1 FROM ops_admission_v2.extra_privacy_witnesses w JOIN ops_admission_v2.qualified_tx_origins o USING(network_key,tx_hash) WHERE w.network_key=$1 AND w.witness_id=o.witness_id)OR EXISTS(SELECT 1 FROM ops_admission_v2.tx_shares s JOIN ops_admission_v2.qualified_tx_origins o USING(network_key,tx_hash) WHERE s.network_key=$1 AND s.sender_org_id<>o.org_id)`, key[:]).Scan(&bad); err != nil || bad {
		return a.ErrCoverage
	}
	rows, err := tx.Query(ctx, `SELECT `+recordFullColumns+` FROM ops_admission_v2.travel_records WHERE network_key=$1`, key[:])
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		if _, _, err := scanRecord(rows, true, nil); err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a.ErrUnavailable
	}
	rows, err = tx.Query(ctx, `SELECT `+eventColumns+` FROM ops_admission_v2.compliance_events WHERE network_key=$1`, key[:])
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		if _, err := scanEvent(rows, key, expected); err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a.ErrUnavailable
	}
	rows, err = tx.Query(ctx, `SELECT `+witnessColumns+` FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1 UNION ALL SELECT `+witnessColumns+` FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1`, key[:])
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		var w witnessScan
		if rows.Scan(w.destinations()...) != nil {
			rows.Close()
			return a.ErrUnavailable
		}
		if _, err := w.finish(); err != nil {
			rows.Close()
			return err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a.ErrUnavailable
	}
	// Recheck recipient digests using the exact Go canonical representation.
	rows, err = tx.Query(ctx, `SELECT recipients,recipient_digest FROM ops_admission_v2.tx_shares WHERE network_key=$1`, key[:])
	if err != nil {
		return a.ErrUnavailable
	}
	for rows.Next() {
		var recipients []string
		var stored []byte
		if rows.Scan(&recipients, &stored) != nil {
			rows.Close()
			return a.ErrUnavailable
		}
		_, digest, err := a.NormalizeRecipients(recipients)
		if err != nil || len(recipients) == 0 || len(stored) != 32 || string(digest[:]) != string(stored) {
			rows.Close()
			return a.ErrCoverage
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a.ErrUnavailable
	}
	return nil
}
