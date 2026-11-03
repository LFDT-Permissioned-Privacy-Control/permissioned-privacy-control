// Package migrationsexec provides the embedded SQL migration set for the
// SEPARATE execution-tracking database of the Reth execution path (RD-1410).
//
// This FS is applied by the tracking-admin (owner) pool
// (EXECUTION_ADMIN_DATABASE_URL) against an already-provisioned, EMPTY
// database. It is standalone, like the audit set: it never runs the main
// migration FS, so the tracking database holds only per-transaction
// operational state:
//
//   - 001: the privacy_proxy_app (runtime) and privacy_proxy_admin (owner)
//     roles, NOLOGIN, and the admin schema grants (the audit 001 shape).
//   - 002: tracking_meta, the network singleton with the random incarnation
//     that fences asynchronous work across a recreation of this database.
//   - 003: the per-transaction tracking schema (bindings, payload ring,
//     final statuses, identity history, the global pending quota).
//   - 004: the per-principal and per-organization pending quota shares.
//
// Applied versions are tracked in schema_version_exec. The app NEVER runs
// CREATE DATABASE: infra provisions the empty database (a separate Postgres
// instance in production, or by derived default a <name>_exec database on
// the same server as DATABASE_URL); this FS then migrates it.
package migrationsexec

import "embed"

// FS contains the execution-tracking-database SQL migrations.
//
//go:embed *.sql
var FS embed.FS
