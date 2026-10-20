// Package migrations provides embedded SQL migrations for tern migrator.
package migrations

import "embed"

// FS contains all SQL migration files.
//
//go:embed *.sql
var FS embed.FS
