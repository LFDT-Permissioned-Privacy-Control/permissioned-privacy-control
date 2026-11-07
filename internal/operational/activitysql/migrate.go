package activitysql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/activitylog"
)

func ownerConnection(ctx context.Context, dsn string) (*pgx.Conn, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, a.ErrInvalid
	}
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	c.ConnectTimeout = 3 * time.Second
	if c.RuntimeParams == nil {
		c.RuntimeParams = map[string]string{}
	}
	c.RuntimeParams["timezone"] = "UTC"
	c.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	return conn, nil
}
func closeOwner(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}
func ownerTx(ctx context.Context, dsn string, fn func(pgx.Tx) error) error {
	c, err := ownerConnection(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeOwner(c)
	tx, err := c.Begin(ctx)
	if err != nil {
		return a.ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),pg_advisory_xact_lock(49222381407005)`); err != nil {
		return a.ErrUnavailable
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return a.ErrUnavailable
	}
	return nil
}

// Migrate owns ONLY005. Existing lean audit001..004 must already have been
// applied by their normal owner migration tool; their SQL/version authority is
// not duplicated here. Explicit caller roles must already exist.
func Migrate(ctx context.Context, dsn, writerRole, readerRole, retentionRole string, drained bool) error {
	roles := RoleNames{writerRole, readerRole, retentionRole}
	if !drained || !roles.Valid() {
		return a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	return ownerTx(ctx, dsn, func(tx pgx.Tx) error {
		var exists bool
		if tx.QueryRow(ctx, `SELECT to_regnamespace('ops_activity_v1') IS NOT NULL`).Scan(&exists) != nil {
			return a.ErrUnavailable
		}
		if exists {
			if err := checkSchema(ctx, tx); err != nil {
				return err
			}
			return checkRole(ctx, tx, roles, "owner") // never silently rewrite existing grants
		}
		if err := checkBaseline(ctx, tx); err != nil {
			return err
		}
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.access_logs WHERE chain_name LIKE 'ops-activity-v1/%')`).Scan(&exists) != nil || exists {
			return a.ErrConflict
		}
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return fmt.Errorf("%w: activity005 DDL: %v", a.ErrUnavailable, err)
		}
		if err := grantRoles(ctx, tx, roles); err != nil {
			return err
		}
		if err := checkSchema(ctx, tx); err != nil {
			return err
		}
		return checkRole(ctx, tx, roles, "owner")
	})
}

func checkBaseline(ctx context.Context, q queryer) error {
	var owner, user string
	if q.QueryRow(ctx, `SELECT pg_get_userbyid(c.relowner),current_user::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='access_logs'`).Scan(&owner, &user) != nil || owner != user {
		return fmt.Errorf("%w: require lean audit001..004 table owner", a.ErrInvalid)
	}
	var unsafe bool
	if q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('public','pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%' AND c.relkind IN('r','p','v','m')) OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND c.relname NOT IN('access_logs','audit_chain_anchor','audit_chain_checkpoint','audit_chain_reanchor','schema_version_audit'))`).Scan(&unsafe) != nil || unsafe {
		return a.ErrInvalid
	}
	var actual []byte
	if q.QueryRow(ctx, catalogQuery).Scan(&actual) != nil {
		return a.ErrInvalid
	}
	var wanted, observed map[string]any
	if json.Unmarshal(expectedCatalog, &wanted) != nil || json.Unmarshal(actual, &observed) != nil {
		return a.ErrUnavailable
	}
	newConstraints := map[string]bool{"activity_run_fk": true, "activity_variant": true}
	newIndexes := map[string]bool{"activity_completion_ordinal": true, "activity_record_uuid": true, "activity_page": true, "activity_head_ref": true}
	for category, items := range wanted {
		array, ok := items.([]any)
		if !ok {
			continue
		}
		var keep []any
		for _, item := range array {
			row := item.(map[string]any)
			if row["schema_name"] == "ops_activity_v1" || category == "functions" || category == "views" || category == "triggers" {
				continue
			}
			if category == "columns" && row["relation"] == "access_logs" && row["position"].(float64) > 15 {
				continue
			}
			if category == "constraints" && newConstraints[row["name"].(string)] {
				continue
			}
			if category == "indexes" && newIndexes[row["name"].(string)] {
				continue
			}
			keep = append(keep, row)
		}
		wanted[category] = keep
	}
	normalizeOwner(wanted, "postgres")
	normalizeOwner(observed, owner)
	x, _ := json.Marshal(wanted)
	y, _ := json.Marshal(observed)
	if !bytes.Equal(x, y) {
		return fmt.Errorf("%w: existing lean audit001..004 does not match qualified baseline", a.ErrInvalid)
	}
	return nil
}

func grantRoles(ctx context.Context, tx pgx.Tx, r RoleNames) error {
	if !r.Valid() {
		return a.ErrInvalid
	}
	w, reader, ret := pgx.Identifier{r.Writer}.Sanitize(), pgx.Identifier{r.Reader}.Sanitize(), pgx.Identifier{r.Retention}.Sanitize()
	statements := []string{
		`GRANT USAGE ON SCHEMA ops_activity_v1 TO ` + w + `,` + reader + `,` + ret,
		`GRANT SELECT ON ops_activity_v1.sources,ops_activity_v1.runs TO ` + w + `,` + reader + `,` + ret,
		`GRANT UPDATE(head_id,head_hash,row_count,byte_count) ON ops_activity_v1.sources TO ` + w,
		`GRANT INSERT ON ops_activity_v1.runs TO ` + w,
		`GRANT SELECT ON ops_activity_v1.qualified_logs TO ` + w + `,` + reader,
		`GRANT INSERT(id,external_id,method,status_code,ip_address,created_at,correlation_id,request_params,entry_hash,response_status,hash_format_version,buffer_seq,chain_name,org_id,denial_reason,activity_run_id,activity_producer_id,activity_kind,activity_ordinal,activity_observed_us,activity_record_id,activity_outcome) ON public.access_logs TO ` + w,
		`GRANT SELECT(id,chain_name,entry_hash,buffer_seq) ON public.access_logs TO ` + w,
		`GRANT USAGE ON SEQUENCE public.access_logs_id_seq,public.access_logs_buffer_range_seq TO ` + w,
		`GRANT EXECUTE ON FUNCTION ops_activity_v1.guard_log() TO ` + w,
		`GRANT SELECT ON ops_activity_v1.anchors TO ` + reader,
		`GRANT UPDATE(retained_from_us,prune_through_id,row_count,byte_count) ON ops_activity_v1.sources TO ` + ret,
		`GRANT SELECT,DELETE ON ops_activity_v1.prunable_logs TO ` + ret,
		`GRANT SELECT,INSERT ON ops_activity_v1.anchors TO ` + ret,
		`GRANT UPDATE(last_pruned_id,last_pruned_entry_hash,last_pruned_at) ON ops_activity_v1.anchors TO ` + ret,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return a.ErrUnavailable
		}
	}
	return nil
}
