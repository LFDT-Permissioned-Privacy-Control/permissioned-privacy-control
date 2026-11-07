package admissionsql

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationobserver"
	"privacy-proxy/internal/rpcexecution"
)

// insertObservationRows issues at most16 statements per table. Identifiers
// are fixed internal literals; all observed data remains parameterized.
func insertObservationRows(ctx context.Context, tx pgx.Tx, table, columns string, rows [][]any) (int64, error) {
	var inserted int64
	for start := 0; start < len(rows); start += 128 {
		end := min(start+128, len(rows))
		args := []any{}
		values := []string{}
		for _, row := range rows[start:end] {
			params := make([]string, len(row))
			for i, v := range row {
				args = append(args, v)
				params[i] = fmt.Sprintf("$%d", len(args))
			}
			values = append(values, "("+strings.Join(params, ",")+")")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO ops_admission_v2.`+table+`(`+columns+`)VALUES`+strings.Join(values, ",")+` ON CONFLICT DO NOTHING`, args...)
		if err != nil {
			return 0, dbError(err)
		}
		inserted += tag.RowsAffected()
	}
	return inserted, nil
}

func putObservedBirths(ctx context.Context, tx pgx.Tx, work *creationobserver.WorkSnapshot, data creationobserver.ObservationData, wanted map[int]creationobserver.Birth) (int64, error) {
	rows := make([][]any, 0, len(wanted))
	network, hash := work.Network().Key, work.Hash()
	for _, b := range data.Births {
		if _, ok := wanted[b.Record]; !ok {
			continue
		}
		var parent any
		if b.Parent >= 0 {
			parent = b.Parent
		}
		rows = append(rows, []any{network[:], b.Address[:], data.Inclusion.Hash[:], data.Inclusion.Number, hash[:], data.Index, b.Record, b.Creator[:], b.Kind, b.TupleDigest[:], parent, b.OutputHash[:], b.OutputLength, rpcexecution.IncludedProfileID, data.Proof[:], nil})
	}
	// Observation time is first audit metadata only. A single DB clock value
	// is used for the batch and is excluded from all equality/digest checks.
	var observedAt any
	if tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observedAt) != nil {
		return 0, a.ErrUnavailable
	}
	for _, row := range rows {
		row[len(row)-1] = observedAt
	}
	inserted, err := insertObservationRows(ctx, tx, "creation_births", "network_key,address,inclusion_hash,inclusion_number,tx_hash,tx_index,actual_creation_record,creator,kind,tuple_digest,creation_parent,output_hash,output_length,evidence_profile,proof_digest,observed_at", rows)
	if err != nil {
		return 0, err
	}
	read, err := tx.Query(ctx, `SELECT address,inclusion_number,tx_index,actual_creation_record,creator,kind,tuple_digest,creation_parent,output_hash,output_length,evidence_profile,proof_digest FROM ops_admission_v2.creation_births WHERE network_key=$1 AND tx_hash=$2 AND inclusion_hash=$3 ORDER BY actual_creation_record LIMIT 2049`, network[:], hash[:], data.Inclusion.Hash[:])
	if err != nil {
		return 0, a.ErrUnavailable
	}
	defer read.Close()
	seen := map[int]bool{}
	count := 0
	for read.Next() {
		count++
		if count > 2048 {
			return 0, a.ErrCoverage
		}
		var address, creator, tuple, output, proof []byte
		var number uint64
		var index uint32
		var record, length int
		var parent *int
		var kind, profile string
		if read.Scan(&address, &number, &index, &record, &creator, &kind, &tuple, &parent, &output, &length, &profile, &proof) != nil || len(address) != 20 || len(creator) != 20 || len(tuple) != 32 || len(output) != 32 || len(proof) != 32 {
			return 0, a.ErrCoverage
		}
		// Every birth in one transaction/inclusion belongs to the SAME full
		// included proof, including previously stored entries outside this
		// generation's newly eligible subset. Never accumulate mixed traces.
		if number != data.Inclusion.Number || index != data.Index || profile != rpcexecution.IncludedProfileID || common.BytesToHash(proof) != data.Proof {
			return 0, a.ErrConflict
		}
		b, ok := wanted[record]
		if !ok {
			continue
		}
		p := -1
		if parent != nil {
			p = *parent
		}
		if common.BytesToAddress(address) != b.Address || common.BytesToAddress(creator) != b.Creator || kind != b.Kind || common.BytesToHash(tuple) != b.TupleDigest || p != b.Parent || common.BytesToHash(output) != b.OutputHash || length != b.OutputLength {
			return 0, a.ErrConflict
		}
		seen[record] = true
	}
	if read.Err() != nil {
		return 0, a.ErrUnavailable
	}
	if len(seen) != len(wanted) {
		return 0, a.ErrConflict
	}
	return inserted, nil
}

func putObservedAssociations(ctx context.Context, tx pgx.Tx, work *creationobserver.WorkSnapshot, data creationobserver.ObservationData, associations []creationobserver.Association) (int64, error) {
	network, hash := work.Network().Key, work.Hash()
	rows := make([][]any, 0, len(associations))
	type key struct {
		record, entry int
		seed          a.Digest
	}
	wanted := map[key]creationobserver.Association{}
	for _, as := range associations {
		var actor, root any
		if as.Kind == "WALLET" {
			actor = as.WalletActor
		} else {
			root = as.FactoryRoot
		}
		rows = append(rows, []any{network[:], hash[:], data.Inclusion.Hash[:], as.Record, as.Seed[:], as.Entry, as.Namespace, as.Kind, actor, root, as.Qualification[:]})
		wanted[key{as.Record, as.Entry, as.Seed}] = as
	}
	inserted, err := insertObservationRows(ctx, tx, "creation_authority_associations", "network_key,tx_hash,inclusion_hash,actual_creation_record,seed_digest,planned_entry,namespace,kind,wallet_actor,factory_root,qualification_digest", rows)
	if err != nil {
		return 0, err
	}
	read, err := tx.Query(ctx, `SELECT actual_creation_record,seed_digest,planned_entry,namespace::text,kind,wallet_actor,factory_root,qualification_digest FROM ops_admission_v2.creation_authority_associations WHERE network_key=$1 AND tx_hash=$2 AND inclusion_hash=$3 ORDER BY actual_creation_record,seed_digest,planned_entry LIMIT 2049`, network[:], hash[:], data.Inclusion.Hash[:])
	if err != nil {
		return 0, a.ErrUnavailable
	}
	defer read.Close()
	seen := 0
	count := 0
	for read.Next() {
		count++
		if count > 2048 {
			return 0, a.ErrCoverage
		}
		var as creationobserver.Association
		var seed, digest []byte
		var actor *string
		var root *int
		if read.Scan(&as.Record, &seed, &as.Entry, &as.Namespace, &as.Kind, &actor, &root, &digest) != nil || len(seed) != 32 || len(digest) != 32 {
			return 0, a.ErrCoverage
		}
		copy(as.Seed[:], seed)
		copy(as.Qualification[:], digest)
		as.FactoryRoot = -1
		if actor != nil {
			as.WalletActor = *actor
		}
		if root != nil {
			as.FactoryRoot = *root
		}
		want, ok := wanted[key{as.Record, as.Entry, as.Seed}]
		if !ok {
			continue
		}
		if as != want {
			return 0, a.ErrConflict
		}
		seen++
	}
	if read.Err() != nil {
		return 0, a.ErrUnavailable
	}
	if seen != len(wanted) {
		return 0, a.ErrConflict
	}
	return inserted, nil
}

// PublishCreationObservation rechecks the immutable subset and all canonical
// and lease fences inside one commit. New refs remain due at their generation;
// a newly revoked original epoch is filtered individually under this fence.
func (s *Store) PublishCreationObservation(ctx context.Context, q *creationobserver.QualifiedObservation) error {
	if q == nil || q.Work() == nil {
		return a.ErrInvalid
	}
	work, data := q.Work(), q.Data()
	before := work.Before()
	immutableConflict := false
	err := s.observerWrite(ctx, before.Lease.Network, false, func(ctx context.Context, tx pgx.Tx) error {
		current, err := observationLock(ctx, tx, work)
		if err != nil {
			return err
		}
		latest, err := readCreationWork(ctx, tx, work.Network(), before, work.Hash())
		if err != nil {
			return err
		}
		if err := work.RequireCurrent(latest); err != nil {
			return err
		}
		var processed int64
		if tx.QueryRow(ctx, `SELECT processed_generation FROM ops_admission_v2.creation_work WHERE network_key=$1 AND tx_hash=$2`, current.Network[:], work.Hash().Bytes()).Scan(&processed) != nil {
			return a.ErrCoverage
		}
		if processed > work.Generation() {
			return nil
		} // an older duplicate cannot regress a newer terminal generation
		var canonical bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.creation_headers WHERE network_key=$1 AND number=$2 AND hash=$3 AND parent_hash=$4 AND timestamp=$5::numeric)`, current.Network[:], data.Inclusion.Number, data.Inclusion.Hash[:], data.Inclusion.Parent[:], data.Inclusion.Timestamp).Scan(&canonical) != nil {
			return a.ErrUnavailable
		}
		if !canonical || data.Inclusion.Number < current.Floor.Number || data.Inclusion.Number > current.Head.Number {
			return a.ErrConflict
		}
		birthByRecord := map[int]creationobserver.Birth{}
		for _, b := range data.Births {
			birthByRecord[b.Record] = b
		}
		wanted := map[int]creationobserver.Birth{}
		associations := []creationobserver.Association{}
		for _, as := range data.Associations {
			if latest.CurrentlyEligible(as.Seed) {
				b, ok := birthByRecord[as.Record]
				if !ok {
					return a.ErrCoverage
				}
				wanted[b.Record] = b
				associations = append(associations, as)
			}
		}
		births, err := putObservedBirths(ctx, tx, work, data, wanted)
		if err != nil {
			immutableConflict = errors.Is(err, a.ErrConflict)
			return err
		}
		added, err := putObservedAssociations(ctx, tx, work, data, associations)
		if err != nil {
			immutableConflict = errors.Is(err, a.ErrConflict)
			return err
		}
		if births > 0 || added > 0 {
			var oldBirths, oldAssociations int64
			if tx.QueryRow(ctx, `SELECT birth_count,association_count FROM ops_admission_v2.creation_capacity WHERE network_key=$1 FOR UPDATE`, current.Network[:]).Scan(&oldBirths, &oldAssociations) != nil {
				return a.ErrUnavailable
			}
			if oldBirths < 0 || oldAssociations < 0 || oldBirths > s.observerLimits.Births-births || oldAssociations > s.observerLimits.Associations-added {
				return a.ErrCoverage
			}
			if _, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_capacity SET birth_count=birth_count+$2,association_count=association_count+$3 WHERE network_key=$1`, current.Network[:], births, added); err != nil {
				return a.ErrUnavailable
			}
		}
		outcome := "uncovered"
		if len(associations) > 0 {
			outcome = "covered"
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_admission_v2.creation_work SET processed_generation=$3,outcome=$4,retry_count=0,next_attempt_at=NULL,inclusion_hash=$5,inclusion_number=$6,last_reorg_epoch=$7 WHERE network_key=$1 AND tx_hash=$2 AND generation>=$3`, current.Network[:], work.Hash().Bytes(), work.Generation(), outcome, data.Inclusion.Hash[:], data.Inclusion.Number, current.ReorgEpoch)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrUnavailable
		}
		// DB-clock expiry is checked again immediately before COMMIT. The
		// observer row lock plus shared advisory fence holds every other CAS.
		_, err = observerLeaseState(ctx, tx, before.Lease, false)
		return err
	})
	if immutableConflict {
		// Never upgrade shared to exclusive. A conflict first rolls back the
		// complete observation, then may quarantine only the same current CAS.
		_ = s.QuarantineObserver(ctx, before, "coverage-gap")
	}
	return err
}
