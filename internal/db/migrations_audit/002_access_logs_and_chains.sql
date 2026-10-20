-- audit/002_access_logs_and_chains.sql
--
-- ── WHAT ─────────────────────────────────────────────────────────
-- Builds the entire LEAN schema of the SEPARATE append-only audit database
-- (RD-1147): the access_logs table (+ sequence + indexes) and the three
-- chain_name-keyed hash-chain tables it needs (audit_chain_anchor,
-- audit_chain_checkpoint, audit_chain_reanchor), then grants the runtime role
-- (privacy_proxy_app) its APPEND-ONLY allowlist:
--   * access_logs        → SELECT, INSERT ONLY  (the seal: no UPDATE/DELETE)
--   * audit_chain_anchor → SELECT, INSERT, UPDATE (read-modify-write; no DELETE)
--   * audit_chain_checkpoint / audit_chain_reanchor → SELECT, INSERT (append)
-- plus USAGE,UPDATE on each BIGSERIAL/SERIAL sequence the writer needs.
--
-- The DDL is the byte-for-byte end-state of the main migrations that shaped
-- access_logs + the chain tables (017/030/031/042/057-era columns, 062 buffer_seq,
-- 063 checkpoint + chain_name, 064 reanchor, 065 org_id, 066 denial_reason),
-- captured via `pg_dump --schema-only` of a main-migrated DB so the columns
-- (org_id, denial_reason, chain_name, buffer_seq, entry_hash, hash_format_version,
-- response_status, correlation_id, request_params, ...) match EXACTLY. The Go
-- access_logs read/write/verifier code is shared with the main-DB path and must
-- see an identical table shape.
--
-- ── WHY (ticket: RD-1147) ────────────────────────────────────────
-- access_logs lives ONLY here now (main dropped it, migration 068). The runtime
-- role is sealed to INSERT+SELECT so a compromised proxy / leaked runtime
-- credential can append but cannot rewrite or delete audit history. Prune
-- (UPDATE/DELETE) runs under the admin/owner DSN.
--
-- ── THE SEAL ─────────────────────────────────────────────────────
-- Unlike main migration 058 (which granted access_logs FULL CRUD to
-- privacy_proxy_app because prune ran under the app credential there), this
-- database's runtime role gets access_logs SELECT+INSERT only. That is the
-- append-only seal. Detection query (must return only SELECT and INSERT):
--   SELECT grantee, privilege_type FROM information_schema.role_table_grants
--   WHERE table_name = 'access_logs' AND grantee = 'privacy_proxy_app';
-- If it shows UPDATE/DELETE, AUDIT_DATABASE_URL is connecting as a role OTHER
-- than privacy_proxy_app (e.g. the owner in the derived-default deployment) —
-- the seal does not bite; see the deployment note in docs/configuration.
--
-- ── AUTHORITATIVE-RECORD note ────────────────────────────────────
-- Traceable record = this migration file (git) + PR review + tern
-- schema_version_audit. Writes nothing to a hash-chained audit table (chain rows
-- are runtime-written only).
--
-- ── EXPAND-ONLY / ROLE-SEPARATION status ─────────────────────────
-- Expand-only: COMPLIANT (CREATE TABLE / SEQUENCE / INDEX + GRANT only). Role
-- separation: STRENGTHENED (append-only seal). Runs ONLY against the audit
-- database; never against the main DATABASE_URL.

-- ── access_logs ──────────────────────────────────────────────────
CREATE SEQUENCE IF NOT EXISTS access_logs_id_seq
    AS integer START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;

CREATE TABLE IF NOT EXISTS access_logs (
    id                  integer NOT NULL DEFAULT nextval('access_logs_id_seq'::regclass),
    external_id         character varying(255) NOT NULL,
    method              character varying(100) NOT NULL,
    status_code         integer NOT NULL,
    ip_address          character varying(45),
    created_at          timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    correlation_id      character varying(128),
    request_params      text,
    entry_hash          character varying(128),
    response_status     integer,
    hash_format_version smallint DEFAULT 2 NOT NULL,
    buffer_seq          bigint,
    chain_name          text DEFAULT 'access_logs'::text NOT NULL,
    org_id              text,
    denial_reason       text,
    CONSTRAINT access_logs_pkey PRIMARY KEY (id)
);
ALTER SEQUENCE access_logs_id_seq OWNED BY access_logs.id;

CREATE INDEX IF NOT EXISTS idx_logs_created_at        ON access_logs USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_logs_external_id       ON access_logs USING btree (external_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_org_id     ON access_logs USING btree (org_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_org_created ON access_logs USING btree (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_correlation ON access_logs USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS access_logs_buffer_seq_uniq ON access_logs USING btree (buffer_seq) WHERE (buffer_seq IS NOT NULL);

COMMENT ON TABLE access_logs IS
    'Append-only access audit trail (RD-1147). SOLE home is this separate audit database. Runtime role privacy_proxy_app has INSERT+SELECT only; UPDATE/DELETE (retention prune) run under the admin/owner DSN. Tamper-evident hash chain + signed checkpoints + anchor live in this database.';

-- ── audit_chain_anchor (per-chain last-pruned seed) ──────────────
CREATE TABLE IF NOT EXISTS audit_chain_anchor (
    chain_name             text NOT NULL,
    last_pruned_id         bigint NOT NULL,
    last_pruned_entry_hash text NOT NULL,
    last_pruned_at         timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_chain_anchor_pkey PRIMARY KEY (chain_name)
);

-- ── audit_chain_checkpoint (signed truncation-detection roll-ups) ─
CREATE SEQUENCE IF NOT EXISTS audit_chain_checkpoint_id_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (
    id         bigint NOT NULL DEFAULT nextval('audit_chain_checkpoint_id_seq'::regclass),
    chain_name text NOT NULL,
    head_id    bigint NOT NULL,
    head_hash  text NOT NULL,
    row_count  bigint NOT NULL,
    key_id     text NOT NULL,
    signature  text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_chain_checkpoint_pkey PRIMARY KEY (id)
);
ALTER SEQUENCE audit_chain_checkpoint_id_seq OWNED BY audit_chain_checkpoint.id;
CREATE INDEX IF NOT EXISTS audit_chain_checkpoint_chain_idx ON audit_chain_checkpoint USING btree (chain_name, id DESC);

-- ── audit_chain_reanchor (signed break-glass re-anchor records) ──
CREATE SEQUENCE IF NOT EXISTS audit_chain_reanchor_id_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
CREATE TABLE IF NOT EXISTS audit_chain_reanchor (
    id           bigint NOT NULL DEFAULT nextval('audit_chain_reanchor_id_seq'::regclass),
    chain_name   text NOT NULL,
    reason       text NOT NULL,
    actor        text NOT NULL,
    from_head_id bigint NOT NULL,
    from_hash    text DEFAULT ''::text NOT NULL,
    to_head_id   bigint NOT NULL,
    to_hash      text DEFAULT ''::text NOT NULL,
    key_id       text NOT NULL,
    signature    text NOT NULL,
    created_at   timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_chain_reanchor_pkey PRIMARY KEY (id)
);
ALTER SEQUENCE audit_chain_reanchor_id_seq OWNED BY audit_chain_reanchor.id;
CREATE INDEX IF NOT EXISTS audit_chain_reanchor_chain_idx ON audit_chain_reanchor USING btree (chain_name, id DESC);

-- ── APPEND-ONLY grants for the runtime role ──────────────────────
-- THE SEAL: access_logs is SELECT + INSERT only (no UPDATE/DELETE). Prune runs
-- under the admin/owner DSN.
GRANT SELECT, INSERT ON access_logs TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE access_logs_id_seq TO privacy_proxy_app;

-- audit_chain_anchor is read-modify-write (upsert on prune) → SELECT+INSERT+UPDATE,
-- no DELETE (anchor history is itself an integrity signal). Matches main 058.
GRANT SELECT, INSERT, UPDATE ON audit_chain_anchor TO privacy_proxy_app;

-- Checkpoint + reanchor are append-only → SELECT+INSERT + sequence.
GRANT SELECT, INSERT ON audit_chain_checkpoint TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE audit_chain_checkpoint_id_seq TO privacy_proxy_app;
GRANT SELECT, INSERT ON audit_chain_reanchor TO privacy_proxy_app;
GRANT USAGE, UPDATE ON SEQUENCE audit_chain_reanchor_id_seq TO privacy_proxy_app;
