# Open Privacy Suite - Project Conventions

## Database

### PostgreSQL Access
- Use **pgx v5** (`github.com/jackc/pgx/v5`) for PostgreSQL connections
- Use `database/sql` with pgx stdlib driver for standard SQL interface
- Connection pooling handled by `database/sql`

### Migrations with Tern
- Use **tern v2** (`github.com/jackc/tern/v2`) for database migrations
- Migrations stored in `internal/db/migrations/*.sql`
- Embedded via Go embed in `internal/db/migrations/migrations.go`

#### Creating New Migrations
```bash
make db-new-migration name=add_user_preferences
```

#### Running Migrations
```bash
make db-migrate
```

### Expand-Only Migration Policy

**Production migrations must be additive only (expand-only):**

- `CREATE TABLE`, `ADD COLUMN`, `CREATE INDEX`, `ALTER TABLE ... ADD CONSTRAINT` - allowed
- `DROP TABLE`, `DROP COLUMN`, `DROP INDEX`, `ALTER TABLE ... DROP CONSTRAINT` - never in production

**DOWN migrations** are optional (development only). If a migration needs undoing in production, create a new forward migration.

### Data Migrations: Documentation & Audit Convention

Migrations that rewrite **security-relevant rows** (RBAC flags/claims/methods, grants, admin roles, compliance config) are change-management artifacts and must be self-explanatory on their own. Follow this pattern (`060_org_admin_group_invariants.sql` is a worked example):

- **Header comment block** stating: WHAT it changes, WHY (+ ticket), which rows are AFFECTED (include a detection query for rows left for manual fix), the AUTHORITATIVE-RECORD note, and the expand-only / role-separation status.
- **Never write to `rbac_audit_log` (or other hash-chained audit tables) from a migration.** Those tables are forever-append, runtime, actor-attributed, and protected by a tamper-evident hash chain that is verified on a schedule (see `site/src/app/docs/security/audit-integrity`). A hand-built SQL `INSERT` with a wrong/absent `entry_hash` would trip the integrity verifier's tamper alarm. The authoritative, traceable record of a data migration is the **migration file (git) + PR review + tern `schema_version` (applied-at timestamp)** — no audit-table write, no magic.
- **New tables** must include the `privacy_proxy_app` `GRANT` block in the same migration (append-only: `SELECT, INSERT`; operational: `SELECT, INSERT, UPDATE, DELETE`; plus the sequence grant for `BIGSERIAL`/`SERIAL`). See the new-table checklist in `058_audit_role_separation.sql`.

## Testing

```bash
make test-unit   # Go unit tests
make e2e         # End-to-end tests
```

## REST API Spec (OpenAPI)

The OpenAPI document is **generated from swaggo annotations** on the handlers
(single source of truth; served at `GET /openapi.json`, rendered in the docs
site at `/api-reference`).

- **Any new or changed HTTP endpoint must update the handler's swaggo
  annotation block in the same PR**, then run `make api-spec` and commit the
  regenerated `internal/server/apispec/`, `site/public/openapi.json`, and
  `API_ENDPOINTS.md`. CI fails on drift.
- The route↔spec coverage gate (`internal/server/openapi_coverage_test.go`)
  fails on any registered route without a spec entry. The remaining
  un-annotated legacy operations live in
  `internal/server/openapi_todo_allowlist.txt` — that file may only shrink.
- Document the **canonical path only** (`/api/v1/...`); legacy `/api/*`,
  `/eth`, root auth mounts and impersonation mirrors collapse onto it
  (see `CanonicalizeRoute`).
- Follow the annotation style of `internal/server/eth_link.go`: real request/
  response types where they exist, `APIError`/`APIMessage` for the shared
  envelopes, `@Security BearerAuth` / `@Security AdminToken` per mount, and
  operator-focused descriptions (access + fail-closed semantics; no internal
  implementation detail).

## Code Style

- Go: idiomatic, explicit error handling, table-driven tests
- Follow `gofmt` for formatting

## Running Services

See README.md for full documentation. Quick reference:

```bash
# Start Open Privacy Suite
docker-compose up -d

# Start explorer (Open Privacy Suite must be running first)
docker-compose -f ../explorer/docker-compose.privacy-proxy.yml up -d
```

**Note:** For network access from other devices, see `DEV.local.md` (gitignored) for machine-specific setup.

## Security Review

Every PR must include a security review before merging if it touches any of:

- **Auth / RBAC** — JWT handling, claims, permissions, group access
- **Visibility / redaction** — `GetBatchVisibility`, `RedactTransactions`, `RedactLogs`, event filtering
- **New or changed API endpoints** — any new route, changed parameters, changed response shape
- **Disclosure / grants** — disclosure requests, grants, visibleTo
- **Explorer API** — any endpoint that returns chain data filtered by privacy rules
- **Cross-org isolation** — contract ownership, org context, default claims

The review must check for:
1. **Data leakage** — does the response expose addresses, DIDs, org IDs, or counts that the viewer shouldn't see?
2. **Error message exposure** — are raw DB/internal errors returned to the client? (must be opaque)
3. **Rate limiting** — is the endpoint behind rate-limiting middleware?
4. **Cross-org isolation** — can a user in org A access data from org B?
5. **Fail-closed** — does a missing/invalid token, missing DB row, or query error result in denial (not accidental access)?
6. **Input validation** — are user-supplied params (addresses, hex values, DIDs) validated before use in queries?
7. **Access/visibility symmetry** — if the PR changes RPC access logic (`rbac.AccessController`, `CheckDefaultClaimsAllowed`, claim handling), also check the explorer visibility layer (`GetBatchVisibility`, `GetBatchEventAccess`) for the same scenario, and vice versa. The two layers must always agree for a given (viewer, address) pair. Two enforcement tests:
   - `TestAccessVisibilitySymmetry` in `e2e/access_visibility_symmetry_test.go` — `CheckAccess` vs `GetBatchVisibility` parity; extend when adding new access paths.
   - `TestExplorerRedactorWiring_FullStack` in `internal/server/explorer_redactor_wiring_integration_test.go` — `rbac.FilterEventLogs` vs `RedactionEngine.RedactLogs` parity; also verifies every interface-typed `Set*Resolver` on `RedactionEngine` is wired by `wireExplorerRedactor`. Extend when adding new event-rule semantics or a new explorer resolver.

## Documentation Site

The docs site lives in `site/` (Next.js + MDX). When changing auth, RBAC, security, compliance, or other user-facing logic, update the corresponding docs page in `site/src/app/docs/`. Docs should be updated in the same PR as the code change.

### Docs-only changes

For PRs that only touch `site/` (no Go or frontend code), use `--no-verify` on `git push` to skip the pre-push test suite. The tests don't cover docs and add unnecessary wait time.

### What belongs in user-facing docs

The docs site is for **operators deploying the product**. Document:
- What to configure (env vars, settings)
- What behavior to expect (features, access control rules)
- How to deploy (production requirements)

Do NOT document internal implementation details:
- Algorithm internals (encryption ciphers, circuit breaker cooldown values, semaphore design)
- Prometheus metric names (those are for the monitoring/infra team, not docs readers)
- Code-level patterns (how the resolver caches, how forwarding works internally)

Keep it operator-focused: "Set X to enable Y." Not "X uses AES-256-GCM with a 12-byte nonce to encrypt Y before writing to the database."
