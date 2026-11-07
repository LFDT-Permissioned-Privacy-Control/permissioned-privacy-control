CREATE SCHEMA IF NOT EXISTS ops_v2;

CREATE TABLE ops_v2.disclosure_schema_version (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    version INTEGER NOT NULL CHECK (version > 0),
    source_checksum TEXT NOT NULL CHECK (source_checksum ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE ops_v2.disclosure_cases (
    case_id UUID PRIMARY KEY,
    store_epoch TEXT NOT NULL CHECK (octet_length(store_epoch) BETWEEN 1 AND 128),
    creator_actor TEXT NOT NULL CHECK (creator_actor ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
    recipient_actor TEXT NOT NULL CHECK (recipient_actor ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
    rule_id TEXT NOT NULL CHECK (octet_length(rule_id) BETWEEN 1 AND 128),
    data_org TEXT NOT NULL CHECK (data_org ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    original_rule_digest TEXT NOT NULL CHECK (original_rule_digest ~ '^sha256:[0-9a-f]{64}$'),
    original_bundle_digest TEXT NOT NULL CHECK (original_bundle_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    immutable_scope JSONB NOT NULL CHECK (jsonb_typeof(immutable_scope) = 'object' AND octet_length(immutable_scope::text) <= 98304),
    case_reference TEXT NOT NULL CHECK (octet_length(case_reference) BETWEEN 1 AND 256),
    purpose TEXT NOT NULL CHECK (octet_length(purpose) BETWEEN 1 AND 4096),
    legal_basis TEXT NOT NULL CHECK (octet_length(legal_basis) <= 2048),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '720 hours'),
    status TEXT NOT NULL CHECK (status IN ('open','closed','revoked')),
    version BIGINT NOT NULL CHECK (version >= 1),
    idempotency_key UUID NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by_actor TEXT,
    revoke_reason TEXT,
    UNIQUE (creator_actor,idempotency_key),
    CHECK ((status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by_actor IS NOT NULL AND revoked_by_actor ~ '^ops:p1:[A-Za-z0-9_-]{43}$' AND revoke_reason IS NOT NULL AND octet_length(revoke_reason) BETWEEN 1 AND 2048)
        OR (status <> 'revoked' AND revoked_at IS NULL AND revoked_by_actor IS NULL AND revoke_reason IS NULL))
);

CREATE FUNCTION ops_v2.disclosure_case_monotonic() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - ARRAY['status','version','revoked_at','revoked_by_actor','revoke_reason'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','version','revoked_at','revoked_by_actor','revoke_reason']) THEN
        RAISE EXCEPTION 'immutable disclosure case';
    END IF;
    IF OLD.status <> 'open' OR NEW.status NOT IN ('closed','revoked') OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'invalid disclosure status transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER disclosure_case_monotonic BEFORE UPDATE ON ops_v2.disclosure_cases
FOR EACH ROW EXECUTE FUNCTION ops_v2.disclosure_case_monotonic();

CREATE TABLE ops_v2.disclosure_events (
    event_id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES ops_v2.disclosure_cases(case_id) ON DELETE RESTRICT,
    store_epoch TEXT NOT NULL CHECK (octet_length(store_epoch) BETWEEN 1 AND 128),
    actor TEXT NOT NULL CHECK (actor ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
    action TEXT NOT NULL CHECK (action IN ('case_opened','case_revoked','metadata_read','audit_read','exposure_prepared')),
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','revoked')),
    rule_id TEXT NOT NULL CHECK (octet_length(rule_id) BETWEEN 1 AND 128),
    rule_digest TEXT NOT NULL CHECK (rule_digest ~ '^sha256:[0-9a-f]{64}$'),
    bundle_digest TEXT NOT NULL CHECK (bundle_digest ~ '^sha256:[0-9a-f]{64}$'),
    case_version BIGINT NOT NULL CHECK (case_version >= 1),
    prepared_at TIMESTAMPTZ NOT NULL,
    summary JSONB NOT NULL CHECK (jsonb_typeof(summary) = 'object' AND octet_length(summary::text) <= 8192),
    attempt_id UUID NOT NULL UNIQUE
);
CREATE INDEX disclosure_cases_recipient ON ops_v2.disclosure_cases(recipient_actor,created_at DESC,case_id DESC);
CREATE INDEX disclosure_cases_org ON ops_v2.disclosure_cases(data_org,created_at DESC,case_id DESC);
CREATE INDEX disclosure_cases_expiry ON ops_v2.disclosure_cases(expires_at);
CREATE INDEX disclosure_events_case ON ops_v2.disclosure_events(case_id,prepared_at DESC,event_id DESC);
CREATE INDEX disclosure_events_retention ON ops_v2.disclosure_events(prepared_at);
