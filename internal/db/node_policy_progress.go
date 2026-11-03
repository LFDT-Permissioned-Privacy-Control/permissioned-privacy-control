package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"privacy-proxy/internal/nodepolicy"
	"strings"
	"time"
)

type NodePolicyProgress struct {
	DesiredVersion uint64                   `json:"desired_version"`
	Applied        *nodepolicy.AppliedState `json:"applied"`
	AcknowledgedAt *time.Time               `json:"acknowledged_at"`
}

func (d *DB) NodePolicyVersion(ctx context.Context) (uint64, error) {
	var version uint64
	err := d.conn.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&version)
	return version, err
}

// AcknowledgeNodePolicy records the node's acknowledgement of a committed
// generation. When the version advanced it also prunes the change log through
// it (raising the floor) and notifies node_policy_applied, so every OPS
// instance refreshes its node status at once; a heartbeat that only extends
// the lease does neither.
func (d *DB) AcknowledgeNodePolicy(ctx context.Context, consumer string, state nodepolicy.AppliedState) error {
	digest, err := hex.DecodeString(state.Digest)
	if err != nil || len(digest) != 32 || strings.ToLower(state.Digest) != state.Digest || state.Version == 0 || state.ExpiresAt <= 0 || strings.TrimSpace(consumer) == "" || len(consumer) > 128 {
		return fmt.Errorf("invalid node acknowledgement")
	}
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var written int
	var advanced bool
	err = tx.QueryRowContext(ctx, `WITH prev AS (SELECT version FROM node_policy_cursors WHERE consumer_id=$1),
        up AS (INSERT INTO node_policy_cursors(consumer_id,version,payload_digest,expires_at)
            SELECT $1,$2,$3,$4 FROM node_policy_clock WHERE singleton AND version >= $2
            ON CONFLICT(consumer_id) DO UPDATE SET version=EXCLUDED.version,payload_digest=EXCLUDED.payload_digest,
                expires_at=EXCLUDED.expires_at,acknowledged_at=clock_timestamp()
            WHERE node_policy_cursors.version <= EXCLUDED.version
            RETURNING version)
        SELECT (SELECT count(*) FROM up), EXISTS (SELECT 1 FROM up WHERE NOT EXISTS (SELECT 1 FROM prev WHERE prev.version >= up.version))`,
		consumer, state.Version, state.Digest, state.ExpiresAt).Scan(&written, &advanced)
	if err != nil {
		return err
	}
	if written != 1 {
		return nodepolicy.ErrFeedConflict
	}
	if advanced {
		if _, err := tx.ExecContext(ctx, `SELECT node_policy_prune($1), pg_notify('node_policy_applied', $1::text)`, int64(state.Version)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RequestFullNodePolicyExport records a change the incremental export cannot
// describe, so the next publication reads every fact.
func (d *DB) RequestFullNodePolicyExport(ctx context.Context) error {
	_, err := d.conn.ExecContext(ctx, `SELECT node_policy_mark_dirty('full','*')`)
	return err
}

// CheckNodePolicySchema refuses a database whose fact clock predates the
// change log (an earlier, rewritten V2 migration 075): its triggers would
// neither filter dependencies nor feed the incremental export.
func (d *DB) CheckNodePolicySchema(ctx context.Context) error {
	var ok bool
	if err := d.conn.QueryRowContext(ctx, `SELECT to_regclass('node_policy_changes') IS NOT NULL AND to_regclass('node_policy_outbox') IS NULL`).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errors.New("the database was migrated with an earlier V2 fact clock (migration 075); recreate it")
	}
	return nil
}
func (d *DB) NodePolicyProgress(ctx context.Context, consumer string) (NodePolicyProgress, error) {
	var out NodePolicyProgress
	var version, expiry sql.NullInt64
	var digest sql.NullString
	var ack sql.NullTime
	err := d.conn.QueryRowContext(ctx, `SELECT c.version,n.version,n.payload_digest,n.expires_at,n.acknowledged_at
        FROM node_policy_clock c LEFT JOIN node_policy_cursors n ON n.consumer_id=$1 WHERE c.singleton`, consumer).
		Scan(&out.DesiredVersion, &version, &digest, &expiry, &ack)
	if err != nil {
		return out, err
	}
	if version.Valid {
		if !digest.Valid || !expiry.Valid || !ack.Valid || version.Int64 <= 0 {
			return NodePolicyProgress{}, errors.New("invalid stored node progress")
		}
		out.Applied = &nodepolicy.AppliedState{Version: uint64(version.Int64), Digest: digest.String, ExpiresAt: expiry.Int64}
		out.AcknowledgedAt = &ack.Time
	}
	return out, nil
}
