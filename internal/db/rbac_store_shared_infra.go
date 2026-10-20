package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"
)

// Shared Infrastructure operations

// IsSharedInfrastructure checks if an address is registered as shared infrastructure.
func (d *DB) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM shared_infrastructure WHERE LOWER(address) = LOWER($1))`
	var exists bool
	err := d.conn.QueryRowContext(ctx, query, address).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check shared infrastructure: %w", err)
	}
	return exists, nil
}

// GetSharedInfrastructure returns the full row for a tagged address,
// or nil when not tagged. Used by the M5 codehash-pin path in
// TraceValidator — the bool IsSharedInfrastructure alone is not
// enough because we need the stored codehash to decide whether to
// trust the tag at trace time.
func (d *DB) GetSharedInfrastructure(ctx context.Context, address string) (*rbac.SharedInfrastructure, error) {
	query := `
		SELECT address, name, description, codehash, created_at
		FROM shared_infrastructure
		WHERE LOWER(address) = LOWER($1)
	`
	infra := &rbac.SharedInfrastructure{}
	var description, codehash sql.NullString
	err := d.conn.QueryRowContext(ctx, query, address).Scan(
		&infra.Address,
		&infra.Name,
		&description,
		&codehash,
		&infra.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get shared infrastructure: %w", err)
	}
	if description.Valid {
		infra.Description = description.String
	}
	if codehash.Valid {
		s := codehash.String
		infra.Codehash = &s
	}
	return infra, nil
}

// CreateSharedInfrastructure inserts a new shared infrastructure record.
func (d *DB) CreateSharedInfrastructure(ctx context.Context, infra *rbac.SharedInfrastructure) error {
	query := `
		INSERT INTO shared_infrastructure (address, name, description, codehash)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`

	var description, codehash sql.NullString
	if infra.Description != "" {
		description = sql.NullString{String: infra.Description, Valid: true}
	}
	if infra.Codehash != nil && *infra.Codehash != "" {
		codehash = sql.NullString{String: strings.ToLower(*infra.Codehash), Valid: true}
	}

	err := d.conn.QueryRowContext(ctx, query,
		strings.ToLower(infra.Address),
		infra.Name,
		description,
		codehash,
	).Scan(&infra.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to create shared infrastructure: %w", err)
	}

	return nil
}

// ListSharedInfrastructure returns all shared infrastructure records.
func (d *DB) ListSharedInfrastructure(ctx context.Context) ([]*rbac.SharedInfrastructure, error) {
	query := `
		SELECT address, name, description, codehash, created_at
		FROM shared_infrastructure
		ORDER BY created_at DESC
	`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list shared infrastructure: %w", err)
	}
	defer rows.Close()

	return scanSharedInfrastructureRows(rows)
}

// UpdateSharedInfrastructure updates the mutable fields of a shared
// infrastructure record. The address is the lookup key and is never
// updated. Returns sql.ErrNoRows when no row matches the address.
//
// Used by the admin API (KD-1): the most common mutation is
// rotating the codehash after a legitimate proxy upgrade rotated the
// bytecode at a stable address — the operator re-attests by writing
// the new keccak256(eth_getCode(addr)) into the codehash column.
func (d *DB) UpdateSharedInfrastructure(ctx context.Context, infra *rbac.SharedInfrastructure) error {
	var description, codehash sql.NullString
	if infra.Description != "" {
		description = sql.NullString{String: infra.Description, Valid: true}
	}
	if infra.Codehash != nil && *infra.Codehash != "" {
		codehash = sql.NullString{String: strings.ToLower(*infra.Codehash), Valid: true}
	}

	const query = `
		UPDATE shared_infrastructure
		SET name = $2,
		    description = $3,
		    codehash = $4
		WHERE LOWER(address) = LOWER($1)
	`
	result, err := d.conn.ExecContext(ctx, query,
		strings.ToLower(infra.Address),
		infra.Name,
		description,
		codehash,
	)
	if err != nil {
		return fmt.Errorf("failed to update shared infrastructure: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteSharedInfrastructure removes a shared infrastructure record by address.
func (d *DB) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	result, err := d.conn.ExecContext(ctx, `
		DELETE FROM shared_infrastructure
		WHERE LOWER(address) = LOWER($1)
	`, address)
	if err != nil {
		return fmt.Errorf("failed to delete shared infrastructure: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func scanSharedInfrastructureRows(rows *sql.Rows) ([]*rbac.SharedInfrastructure, error) {
	var infras []*rbac.SharedInfrastructure
	for rows.Next() {
		infra := &rbac.SharedInfrastructure{}
		var description, codehash sql.NullString

		if err := rows.Scan(
			&infra.Address,
			&infra.Name,
			&description,
			&codehash,
			&infra.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan shared infrastructure: %w", err)
		}

		if description.Valid {
			infra.Description = description.String
		}
		if codehash.Valid {
			s := codehash.String
			infra.Codehash = &s
		}

		infras = append(infras, infra)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating shared infrastructure: %w", err)
	}

	return infras, nil
}
