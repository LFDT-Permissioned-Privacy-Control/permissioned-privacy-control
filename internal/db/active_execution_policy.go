package db

import "context"

// HasActiveExecutionPolicy inventories both generations of execution-policy
// authority. Either an active source revision or its legacy projection needs a
// capable consumer; an inconsistent/missing counterpart must not hide it.
// Only presence is returned, never tenant IDs or policy contents.
func (d *DB) HasActiveExecutionPolicy(ctx context.Context) (bool, error) {
	var active bool
	err := d.conn.QueryRowContext(ctx, `SELECT
 EXISTS (SELECT 1 FROM configuration_revisions WHERE kind='execution-rules' AND status='active')
 OR EXISTS (SELECT 1 FROM execution_policy_revisions WHERE status='active')`).Scan(&active)
	return active, err
}
