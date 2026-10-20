package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AllowedAzureTenant represents an Azure AD tenant that is permitted to authenticate.
type AllowedAzureTenant struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Label          string    `json:"label"`
	DefaultOrgID   *string   `json:"default_org_id,omitempty"`
	DefaultGroupID *string   `json:"default_group_id,omitempty"`
	AutoProvision  bool      `json:"auto_provision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ListAllowedAzureTenants returns all allowed Azure AD tenants.
func (d *DB) ListAllowedAzureTenants(ctx context.Context) ([]AllowedAzureTenant, error) {
	query := `SELECT id, tenant_id, label, default_org_id, default_group_id, auto_provision, created_at, updated_at
	          FROM allowed_azure_tenants ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list allowed azure tenants: %w", err)
	}
	defer rows.Close()

	var tenants []AllowedAzureTenant
	for rows.Next() {
		t, err := scanAzureTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating azure tenants: %w", err)
	}

	if tenants == nil {
		tenants = []AllowedAzureTenant{}
	}
	return tenants, nil
}

// GetAllowedAzureTenant retrieves an allowed tenant by its primary key (UUID).
func (d *DB) GetAllowedAzureTenant(ctx context.Context, id string) (*AllowedAzureTenant, error) {
	query := `SELECT id, tenant_id, label, default_org_id, default_group_id, auto_provision, created_at, updated_at
	          FROM allowed_azure_tenants WHERE id = $1`

	var t AllowedAzureTenant
	var defaultOrgID, defaultGroupID sql.NullString

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&t.ID, &t.TenantID, &t.Label, &defaultOrgID, &defaultGroupID,
		&t.AutoProvision, &t.CreatedAt, &t.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed azure tenant: %w", err)
	}

	t.DefaultOrgID = nullStringPtr(defaultOrgID)
	t.DefaultGroupID = nullStringPtr(defaultGroupID)
	return &t, nil
}

// GetAllowedAzureTenantByTenantID retrieves an allowed tenant by its Azure AD tenant ID.
func (d *DB) GetAllowedAzureTenantByTenantID(ctx context.Context, tenantID string) (*AllowedAzureTenant, error) {
	query := `SELECT id, tenant_id, label, default_org_id, default_group_id, auto_provision, created_at, updated_at
	          FROM allowed_azure_tenants WHERE tenant_id = $1`

	var t AllowedAzureTenant
	var defaultOrgID, defaultGroupID sql.NullString

	err := d.conn.QueryRowContext(ctx, query, tenantID).Scan(
		&t.ID, &t.TenantID, &t.Label, &defaultOrgID, &defaultGroupID,
		&t.AutoProvision, &t.CreatedAt, &t.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get allowed azure tenant by tenant_id: %w", err)
	}

	t.DefaultOrgID = nullStringPtr(defaultOrgID)
	t.DefaultGroupID = nullStringPtr(defaultGroupID)
	return &t, nil
}

// CreateAllowedAzureTenant inserts a new allowed Azure AD tenant.
func (d *DB) CreateAllowedAzureTenant(ctx context.Context, t *AllowedAzureTenant) (*AllowedAzureTenant, error) {
	query := `INSERT INTO allowed_azure_tenants (id, tenant_id, label, default_org_id, default_group_id, auto_provision)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	err := d.conn.QueryRowContext(ctx, query,
		t.ID, t.TenantID, t.Label, t.DefaultOrgID, t.DefaultGroupID, t.AutoProvision,
	).Scan(&t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create allowed azure tenant: %w", err)
	}
	return t, nil
}

// UpdateAllowedAzureTenant updates an existing allowed Azure AD tenant.
func (d *DB) UpdateAllowedAzureTenant(ctx context.Context, t *AllowedAzureTenant) (*AllowedAzureTenant, error) {
	query := `UPDATE allowed_azure_tenants
	          SET tenant_id = $2, label = $3, default_org_id = $4, default_group_id = $5, auto_provision = $6, updated_at = now()
	          WHERE id = $1
	          RETURNING updated_at`

	err := d.conn.QueryRowContext(ctx, query,
		t.ID, t.TenantID, t.Label, t.DefaultOrgID, t.DefaultGroupID, t.AutoProvision,
	).Scan(&t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update allowed azure tenant: %w", err)
	}
	return t, nil
}

// DeleteAllowedAzureTenant removes a tenant from the allowlist.
func (d *DB) DeleteAllowedAzureTenant(ctx context.Context, id string) error {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM allowed_azure_tenants WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete allowed azure tenant: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// scanAzureTenant scans a single row from the allowed_azure_tenants table.
func scanAzureTenant(rows *sql.Rows) (AllowedAzureTenant, error) {
	var t AllowedAzureTenant
	var defaultOrgID, defaultGroupID sql.NullString

	err := rows.Scan(
		&t.ID, &t.TenantID, &t.Label, &defaultOrgID, &defaultGroupID,
		&t.AutoProvision, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return t, fmt.Errorf("failed to scan azure tenant: %w", err)
	}

	t.DefaultOrgID = nullStringPtr(defaultOrgID)
	t.DefaultGroupID = nullStringPtr(defaultGroupID)
	return t, nil
}
