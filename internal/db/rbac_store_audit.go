package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/rbac"
)

// Audit Log operations

// CreateAuditLog persists a rbac_audit_log row and links it to the
// rbac_audit_log hash chain (RD-858).
//
// The chain advance and the row INSERT are combined in a single SQL
// statement so a process crash between hash computation and row write
// cannot leave entry_hash NULL on a committed row — the pre-RD-858
// failure mode where verifiers couldn't distinguish "crashed mid-
// write" from "tampered".
//
// Order of operations under the chain mutex (HashChain.Append):
//  1. Reserve the row id via nextval('rbac_audit_log_id_seq').
//  2. Set created_at on the Go side (time.Now().UTC()).
//  3. Marshal old_value / new_value JSON.
//  4. Build canonical content and ask the chain for the next hash.
//  5. Execute a single INSERT that supplies id, created_at, AND
//     entry_hash. If the INSERT fails, the chain rolls back (Append
//     contract); the next CreateAuditLog uses the same prev hash.
//
// On error, falls back to the legacy chain-less INSERT so the audit
// trail still records the action — better an integrity-gap row the
// verifier will flag than a silently-dropped admin event. The reason
// is logged.
func (d *DB) CreateAuditLog(ctx context.Context, entry *rbac.AuditLogEntry) error {
	var oldValue, newValue []byte
	var err error

	if entry.OldValue != nil {
		oldValue, err = json.Marshal(entry.OldValue)
		if err != nil {
			return fmt.Errorf("failed to marshal old value: %w", err)
		}
	}

	if entry.NewValue != nil {
		newValue, err = json.Marshal(entry.NewValue)
		if err != nil {
			return fmt.Errorf("failed to marshal new value: %w", err)
		}
	}

	chain := d.getRBACAuditChain()
	if chain == nil {
		slog.Warn("rbac audit hash chain not installed, writing row without entry_hash",
			"action", entry.Action,
			"resource_type", entry.ResourceType)
		return d.insertAuditLogLegacy(ctx, entry, oldValue, newValue)
	}

	_, err = chain.Append(func(prev string) (string, func(string) error, error) {
		var id int64
		if scanErr := d.conn.QueryRowContext(ctx,
			`SELECT nextval('rbac_audit_log_id_seq')`,
		).Scan(&id); scanErr != nil {
			return "", nil, fmt.Errorf("reserve rbac_audit_log id: %w", scanErr)
		}
		// Postgres TIMESTAMP stores microsecond precision; truncate
		// Go's nanosecond-precision Now() so the hash content (built
		// before write) matches what the verifier reads back. See
		// LogAccessChained for the same gotcha.
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		content := buildRBACAuditContent(id, createdAt, entry, oldValue, newValue)

		write := func(hash string) error {
			res, execErr := d.conn.ExecContext(ctx,
				`INSERT INTO rbac_audit_log
					(id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address, created_at, entry_hash, hash_format_version)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1)`,
				id, entry.ActorID, entry.ActorExternalID, entry.Action, entry.ResourceType,
				entry.ResourceID, entry.ResourceName, entry.OrgID, oldValue, newValue, entry.IPAddress,
				createdAt, hash,
			)
			if execErr != nil {
				return fmt.Errorf("insert rbac_audit_log: %w", execErr)
			}
			if affected, _ := res.RowsAffected(); affected != 1 {
				return fmt.Errorf("insert rbac_audit_log: expected 1 row, got %d", affected)
			}
			entry.ID = id
			entry.CreatedAt = createdAt
			return nil
		}
		_ = prev
		return content, write, nil
	})
	return err
}

// insertAuditLogLegacy writes a chain-less rbac_audit_log row. Used
// only when the chain cannot be initialized (seed read failure). The
// verifier flags rows with NULL entry_hash so the integrity gap is
// surfaced rather than silently accepted.
func (d *DB) insertAuditLogLegacy(ctx context.Context, entry *rbac.AuditLogEntry, oldValue, newValue []byte) error {
	const query = `INSERT INTO rbac_audit_log (actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	          RETURNING id, created_at`
	return d.conn.QueryRowContext(ctx, query,
		entry.ActorID, entry.ActorExternalID, entry.Action, entry.ResourceType,
		entry.ResourceID, entry.ResourceName, entry.OrgID, oldValue, newValue, entry.IPAddress,
	).Scan(&entry.ID, &entry.CreatedAt)
}

// buildRBACAuditContent serializes a row's fields into the canonical
// string fed to the hash chain. **The format is part of the chain
// schema** — any change is a hash_format_version bump.
//
// Order: id | actor_external_id | action | resource_type |
// resource_id | resource_name | org_id | ip_address | created_at |
// old_value_json | new_value_json
//
// actor_id (the internal UUID) is intentionally omitted — actor_id can
// be NULL for system actors, and actor_external_id is the durable
// identity reference. Including a NULLABLE field with ad-hoc nil-
// encoding leads to format ambiguity later.
//
// Timestamps use RFC 3339 with nanosecond precision so the format is
// stable across re-reads (Go's default Time.String() is lossy and
// includes timezone names).
func buildRBACAuditContent(id int64, createdAt time.Time, entry *rbac.AuditLogEntry, oldValue, newValue []byte) string {
	resourceID := ""
	if entry.ResourceID != nil {
		resourceID = *entry.ResourceID
	}
	orgID := ""
	if entry.OrgID != nil {
		orgID = *entry.OrgID
	}
	return fmt.Sprintf("v1|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		id,
		entry.ActorExternalID,
		entry.Action,
		entry.ResourceType,
		resourceID,
		entry.ResourceName,
		orgID,
		entry.IPAddress,
		createdAt.UTC().Format(time.RFC3339Nano),
		string(oldValue),
		string(newValue),
	)
}

// ListAuditLogs returns audit log rows for super-admin / dev callers (no
// org filter). Deprecated — use ListAuditLogsScoped to apply cross-org
// filtering for JWT admin callers.
func (d *DB) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	return d.ListAuditLogsScoped(ctx, resourceType, resourceID, nil, limit, offset)
}

// ListAuditLogsScoped filters rows to those whose org_id is in
// scopedOrgIDs. Pass nil to disable filtering (super-admin path).
// Passing an empty (non-nil) slice returns zero rows (the JWT admin
// has no orgs and must see nothing).
//
// Rows with NULL org_id (pre-existing entries written before migration
// 051) are only visible when no filter is applied — they are treated
// as super-admin-only audit history.
func (d *DB) ListAuditLogsScoped(ctx context.Context, resourceType string, resourceID *string, scopedOrgIDs []string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	if scopedOrgIDs != nil && len(scopedOrgIDs) == 0 {
		// Caller is a JWT admin with no full or read-only orgs. Pre-fix
		// they could read everything; now they see nothing.
		return []*rbac.AuditLogEntry{}, nil
	}

	base := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address, created_at
	         FROM rbac_audit_log WHERE resource_type = $1`
	args := []any{resourceType}
	idx := 2

	if resourceID != nil {
		base += fmt.Sprintf(" AND resource_id = $%d", idx)
		args = append(args, *resourceID)
		idx++
	}
	if scopedOrgIDs != nil {
		base += fmt.Sprintf(" AND org_id = ANY($%d)", idx)
		args = append(args, scopedOrgIDs)
		idx++
	}
	base += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, base, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func (d *DB) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	return d.ListAuditLogsByActorScoped(ctx, actorID, nil, limit, offset)
}

func (d *DB) ListAuditLogsByActorScoped(ctx context.Context, actorID string, scopedOrgIDs []string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	if scopedOrgIDs != nil && len(scopedOrgIDs) == 0 {
		return []*rbac.AuditLogEntry{}, nil
	}

	base := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, org_id, old_value, new_value, ip_address, created_at
	         FROM rbac_audit_log WHERE actor_id = $1`
	args := []any{actorID}
	idx := 2

	if scopedOrgIDs != nil {
		base += fmt.Sprintf(" AND org_id = ANY($%d)", idx)
		args = append(args, scopedOrgIDs)
		idx++
	}
	base += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", idx, idx+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, base, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func scanAuditLogs(rows *sql.Rows) ([]*rbac.AuditLogEntry, error) {
	var entries []*rbac.AuditLogEntry
	for rows.Next() {
		entry := &rbac.AuditLogEntry{}
		var actorID, resourceID, orgID sql.NullString
		var oldValue, newValue []byte

		if err := rows.Scan(
			&entry.ID, &actorID, &entry.ActorExternalID, &entry.Action, &entry.ResourceType,
			&resourceID, &entry.ResourceName, &orgID, &oldValue, &newValue, &entry.IPAddress,
			&entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if actorID.Valid {
			entry.ActorID = &actorID.String
		}
		if resourceID.Valid {
			entry.ResourceID = &resourceID.String
		}
		if orgID.Valid {
			entry.OrgID = &orgID.String
		}

		if len(oldValue) > 0 {
			if err := json.Unmarshal(oldValue, &entry.OldValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal old value: %w", err)
			}
		}

		if len(newValue) > 0 {
			if err := json.Unmarshal(newValue, &entry.NewValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal new value: %w", err)
			}
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return entries, nil
}
