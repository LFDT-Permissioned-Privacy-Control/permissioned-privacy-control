package disclosuresql

import (
	"context"

	c "privacy-proxy/internal/disclosurecase"
)

// Check effective grants, including inherited roles. Accidentally supplying
// owner/migrator or legacy broad-store credentials must not widen this adapter.
func (s *Store) checkAppPrivileges(ctx context.Context) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	var unsafe bool
	err := s.pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb
 OR has_schema_privilege(current_user,'ops_v2','CREATE')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND pg_has_role(current_user,d.datdba,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ops_v2' AND c.relname IN('disclosure_cases','disclosure_events','disclosure_schema_version') AND pg_has_role(current_user,c.relowner,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN('r','p','v','m') AND has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER'))
 OR has_table_privilege(current_user,'ops_v2.disclosure_cases','DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(current_user,'ops_v2.disclosure_events','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(current_user,'ops_v2.disclosure_events','UPDATE')
 OR has_table_privilege(current_user,'ops_v2.disclosure_schema_version','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(current_user,'ops_v2.disclosure_schema_version','UPDATE')
 FROM pg_roles r WHERE r.rolname=current_user`).Scan(&unsafe)
	if err != nil || unsafe {
		return c.ErrUnavailable
	}
	rows, err := s.pool.Query(ctx, `SELECT column_name,has_column_privilege(current_user,'ops_v2.disclosure_cases',column_name,'UPDATE') FROM information_schema.columns WHERE table_schema='ops_v2' AND table_name='disclosure_cases'`)
	if err != nil {
		return c.ErrUnavailable
	}
	defer rows.Close()
	allowed := map[string]bool{"status": true, "version": true, "revoked_at": true, "revoked_by_actor": true, "revoke_reason": true}
	for rows.Next() {
		var column string
		var update bool
		if rows.Scan(&column, &update) != nil || update != allowed[column] {
			return c.ErrUnavailable
		}
	}
	if rows.Err() != nil {
		return c.ErrUnavailable
	}
	return nil
}
