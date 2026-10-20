package db

import (
	"database/sql"
	"time"

	"privacy-proxy/internal/rbac"
)

// Ensure DB implements rbac.Store
var _ rbac.Store = (*DB)(nil)

// nullStringPtr converts a sql.NullString to a pointer to string, or nil if null.
func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

// nullTimePtr converts a sql.NullTime to a pointer to time.Time, or nil if null.
func nullTimePtr(ns sql.NullTime) *time.Time {
	if ns.Valid {
		return &ns.Time
	}
	return nil
}

// nullIntPtr converts a sql.NullInt32 to a pointer to int, or nil if null.
func nullIntPtr(ns sql.NullInt32) *int {
	if ns.Valid {
		val := int(ns.Int32)
		return &val
	}
	return nil
}
