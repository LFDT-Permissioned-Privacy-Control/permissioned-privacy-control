// Package migrationsaudit provides the embedded LEAN SQL migration set for the
// SEPARATE, always-on append-only audit database (RD-1147).
//
// This FS is applied by the audit-admin (owner) pool against an
// already-provisioned, EMPTY audit database. It is INTENTIONALLY STANDALONE: it
// does NOT run the main migration FS (internal/db/migrations) and therefore
// never creates users / contracts / groups / rbac_audit_log / compliance_logs /
// the RBAC/operational schema in the audit DB. It builds ONLY:
//
//   - 001: the privacy_proxy_app (NOLOGIN, runtime) + privacy_proxy_admin
//     (NOLOGIN, owner) roles and the admin schema grants (058-style, idempotent).
//   - 002: the access_logs table (+ sequence + indexes), the three chain_name-
//     keyed hash-chain tables (audit_chain_anchor, audit_chain_checkpoint,
//     audit_chain_reanchor), and the runtime role's APPEND-ONLY grants — the
//     seal: SELECT+INSERT on access_logs, NO UPDATE/DELETE.
//
// Applied versions are tracked in a SEPARATE tern version table
// (schema_version_audit) so the sequence is independent of the main schema.
//
// The app NEVER runs CREATE DATABASE: infra provisions the empty audit database
// (a dedicated Postgres or, by derived default, a <name>_audit database on the
// same server as DATABASE_URL); this FS then migrates it.
package migrationsaudit

import "embed"

// FS contains the lean audit-database-only SQL migrations.
//
//go:embed *.sql
var FS embed.FS
