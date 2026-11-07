package activitysql

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
)

// SourceStatus is an owner diagnostic, not an independently recounted history.
// Runtime serving still performs the selected generation/readiness/cut gates.
type SourceStatus struct {
	Metadata           a.StoreMetadata
	Ready              bool
	RetainedFromMicros int64
	HeadID             int64
	HeadHash           string
	Rows, Bytes, Runs  int64
	Limits             StorageLimits
	Roles              RoleNames
	PendingPrune       bool
}

func Status(ctx context.Context, dsn string, network [32]byte, sourceID string) (SourceStatus, error) {
	if !a.CanonicalUUID(sourceID) {
		return SourceStatus{}, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := ownerConnection(ctx, dsn)
	if err != nil {
		return SourceStatus{}, err
	}
	defer closeOwner(c)
	tx, err := c.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return SourceStatus{}, a.ErrUnavailable
	}
	defer rollback(tx)
	s, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM ops_activity_v1.sources WHERE network_key=$1`, network[:]))
	if err != nil || s.metadata.SourceID != sourceID {
		return SourceStatus{}, a.ErrUnavailable
	}
	if err := checkSchema(ctx, tx); err != nil {
		return SourceStatus{}, err
	}
	if err := checkRole(ctx, tx, s.roles, "owner"); err != nil {
		return SourceStatus{}, err
	}
	var runs int64
	if tx.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.runs WHERE network_key=$1`, network[:]).Scan(&runs) != nil {
		return SourceStatus{}, a.ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return SourceStatus{}, a.ErrUnavailable
	}
	return SourceStatus{Metadata: s.metadata, Ready: s.ready, RetainedFromMicros: s.floor, HeadID: s.headID, HeadHash: s.headHash, Rows: s.rows, Bytes: s.bytes, Runs: runs, Limits: s.limits, Roles: s.roles, PendingPrune: s.pruneThrough != nil}, nil
}

// Initialize inserts a new operational source or accepts its exact existing
// configuration without mutation. It never activates an existing recovery.
func Initialize(ctx context.Context, dsn string, r Registration, drained bool) error {
	key, err := r.Network.Key()
	if err != nil || !drained || !a.CanonicalUUID(r.SourceID) || !r.Roles.Valid() || !r.Limits.Valid() {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		if err := checkRole(ctx, tx, r.Roles, "owner"); err != nil {
			return err
		}
		if err := checkIDAllocator(ctx, tx); err != nil {
			return err
		}
		chain := chainName(key)
		lock := audit.AccessLogChainLockKey(chain)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, lock); err != nil {
			return a.ErrUnavailable
		}
		existing, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM ops_activity_v1.sources WHERE network_key=$1 FOR UPDATE`, key[:]))
		if err == nil {
			if existing.metadata.SourceID != r.SourceID || existing.metadata.Configuration != a.Digest(r.Configuration) || existing.limits != r.Limits || existing.roles != r.Roles {
				return a.ErrConflict
			}
			return nil
		}
		// Distinguish absence from a malformed existing state. No upsert can
		// silently bless a damaged or recovered installation.
		var exists bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_activity_v1.sources WHERE network_key=$1)OR EXISTS(SELECT 1 FROM public.access_logs WHERE chain_name=$2)OR EXISTS(SELECT 1 FROM public.audit_chain_anchor WHERE chain_name=$2)`, key[:], chain).Scan(&exists) != nil || exists {
			return a.ErrConflict
		}
		generation := uuid.NewString()
		tag, err := tx.Exec(ctx, `INSERT INTO ops_activity_v1.sources(network_key,source_id,chain_name,chain_lock_key,generation,configuration,ready,retained_from_us,max_rows,max_bytes,max_runs,writer_role,reader_role,retention_role)VALUES($1,$2::uuid,$3,$4,$5::uuid,$6,false,0,$7,$8,$9,$10,$11,$12)`, key[:], r.SourceID, chain, lock, generation, r.Configuration[:], r.Limits.Rows, r.Limits.Bytes, r.Limits.Runs, r.Roles.Writer, r.Roles.Reader, r.Roles.Retention)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrConflict
		}
		s, err := selected(ctx, tx, Scope{key, r.SourceID, generation}, false, false)
		if err != nil {
			return err
		}
		if err := checkHead(ctx, tx, s, "owner"); err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=true WHERE network_key=$1 AND generation=$2::uuid AND NOT ready`, key[:], generation)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrUnavailable
		}
		return nil
	})
}

func ownerSelected(ctx context.Context, tx pgx.Tx, scope Scope) (sourceState, error) {
	if !scope.Valid() {
		return sourceState{}, a.ErrInvalid
	}
	if err := checkSchema(ctx, tx); err != nil {
		return sourceState{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, audit.AccessLogChainLockKey(chainName(scope.NetworkKey))); err != nil {
		return sourceState{}, a.ErrUnavailable
	}
	s, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM ops_activity_v1.sources WHERE network_key=$1 FOR UPDATE`, scope.NetworkKey[:]))
	if err != nil || s.metadata.SourceID != scope.SourceID || s.metadata.Generation != scope.ExpectedGeneration {
		return sourceState{}, a.ErrConflict
	}
	if err := checkRole(ctx, tx, s.roles, "owner"); err != nil {
		return sourceState{}, err
	}
	return s, nil
}

// BeginRecovery CASes the CURRENT generation, rotates to a new UUID and leaves
// readiness false. The owner status command supplies the new Scope for finalize.
func BeginRecovery(ctx context.Context, dsn string, scope Scope, drained bool) error {
	if !drained || !scope.Valid() {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		if _, err := ownerSelected(ctx, tx, scope); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET ready=false,generation=$3::uuid,prune_through_id=NULL WHERE network_key=$1 AND source_id=$2::uuid AND generation=$4::uuid`, scope.NetworkKey[:], scope.SourceID, uuid.NewString(), scope.ExpectedGeneration)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrConflict
		}
		return nil
	})
}

// Reconfigure is explicit drained owner work after BeginRecovery. It changes
// only config/caps; identity, roles, floor and the new generation are immutable.
func Reconfigure(ctx context.Context, dsn string, scope Scope, r Registration, drained bool) error {
	key, err := r.Network.Key()
	if !drained || err != nil || !scope.Valid() || key != scope.NetworkKey || r.SourceID != scope.SourceID || !r.Limits.Valid() || !r.Roles.Valid() {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		s, err := ownerSelected(ctx, tx, scope)
		if err != nil {
			return err
		}
		if s.ready || s.pruneThrough != nil || s.roles != r.Roles {
			return a.ErrConflict
		}
		var runs int64
		if tx.QueryRow(ctx, `SELECT count(*) FROM ops_activity_v1.runs WHERE network_key=$1`, key[:]).Scan(&runs) != nil {
			return a.ErrUnavailable
		}
		if s.rows > r.Limits.Rows || s.bytes > r.Limits.Bytes || runs > r.Limits.Runs {
			return a.ErrTooBroad
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_activity_v1.sources SET configuration=$2,max_rows=$3,max_bytes=$4,max_runs=$5 WHERE network_key=$1 AND generation=$6::uuid AND NOT ready`, key[:], r.Configuration[:], r.Limits.Rows, r.Limits.Bytes, r.Limits.Runs, scope.ExpectedGeneration)
		if err != nil || tag.RowsAffected() != 1 {
			return a.ErrConflict
		}
		return nil
	})
}

func anchor(ctx context.Context, q queryer, chain string) (int64, string, error) {
	var id int64
	var h string
	err := q.QueryRow(ctx, `SELECT last_pruned_id,last_pruned_entry_hash FROM ops_activity_v1.anchors WHERE chain_name=$1`, chain).Scan(&id, &h)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil || id < 1 {
		return 0, "", a.ErrUnavailable
	}
	if _, err := a.ParseDigestHex(h); err != nil {
		return 0, "", a.ErrUnavailable
	}
	return id, h, nil
}

func hexDigest(v a.Digest) string { return hex.EncodeToString(v[:]) }
