CREATE SCHEMA ops_identity_v2;
REVOKE ALL ON SCHEMA ops_identity_v2 FROM PUBLIC;

CREATE TABLE ops_identity_v2.metadata (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 schema_version integer NOT NULL CHECK(schema_version=1),
 migration_checksum text NOT NULL CHECK(migration_checksum ~ '^sha256:[0-9a-f]{64}$'),
 namespace text NOT NULL CHECK(namespace ~ '^sha256:[0-9a-f]{64}$'),
 recovery_epoch uuid NOT NULL CHECK(recovery_epoch<>'00000000-0000-0000-0000-000000000000'),
 ready boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL
);
CREATE TABLE ops_identity_v2.pending_requests (
 request_id uuid PRIMARY KEY CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 namespace text NOT NULL CHECK(namespace ~ '^sha256:[0-9a-f]{64}$'),
 recovery_epoch uuid NOT NULL CHECK(recovery_epoch<>'00000000-0000-0000-0000-000000000000'),
 state_hash bytea NOT NULL UNIQUE CHECK(octet_length(state_hash)=32),
 profile_id text NOT NULL CHECK(octet_length(profile_id) BETWEEN 1 AND 128),
 profile_digest text NOT NULL CHECK(profile_digest ~ '^sha256:[0-9a-f]{64}$'),
 recipient_hash bytea NOT NULL CHECK(octet_length(recipient_hash)=32),
 encryption_key_id text NOT NULL CHECK(octet_length(encryption_key_id) BETWEEN 1 AND 128),
 secret_ciphertext bytea NOT NULL CHECK(octet_length(secret_ciphertext) BETWEEN 28 AND 2048),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(created_at<expires_at AND expires_at<=created_at+interval '300 seconds')
);
CREATE INDEX pending_expiry ON ops_identity_v2.pending_requests(expires_at);

CREATE TABLE ops_identity_v2.renewal_families (
 family_id uuid PRIMARY KEY CHECK(family_id<>'00000000-0000-0000-0000-000000000000'),
 originating_request_id uuid NOT NULL UNIQUE CHECK(originating_request_id<>'00000000-0000-0000-0000-000000000000'),
 namespace text NOT NULL CHECK(namespace ~ '^sha256:[0-9a-f]{64}$'),
 recovery_epoch uuid NOT NULL CHECK(recovery_epoch<>'00000000-0000-0000-0000-000000000000'),
 actor_id text NOT NULL CHECK(actor_id ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
 profile_id text NOT NULL CHECK(octet_length(profile_id) BETWEEN 1 AND 128),
 profile_digest text NOT NULL CHECK(profile_digest ~ '^sha256:[0-9a-f]{64}$'),
 identity_authority text NOT NULL CHECK(identity_authority='https://login.microsoftonline.com/'||source_tenant||'/v2.0'),
 source_tenant text NOT NULL CHECK(source_tenant ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND source_tenant<>'00000000-0000-0000-0000-000000000000'),
 source_subject text NOT NULL CHECK(source_subject ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND source_subject<>'00000000-0000-0000-0000-000000000000'),
 principal_kind text NOT NULL CHECK(principal_kind='human'),
 oidc_subject_hash bytea NOT NULL CHECK(octet_length(oidc_subject_hash)=32),
 login_nonce_hash bytea NOT NULL CHECK(octet_length(login_nonce_hash)=32),
 original_auth_time bigint CHECK(original_auth_time>=0),
 recipient_hash bytea NOT NULL CHECK(octet_length(recipient_hash)=32),
 generation bigint NOT NULL CHECK(generation>=0),
 current_handle_hash bytea NOT NULL CHECK(octet_length(current_handle_hash)=32),
 encryption_key_id text NOT NULL CHECK(octet_length(encryption_key_id) BETWEEN 1 AND 128),
 refresh_ciphertext bytea NOT NULL CHECK(octet_length(refresh_ciphertext) BETWEEN 28 AND 33792),
 created_at timestamptz NOT NULL,
 absolute_expires_at timestamptz NOT NULL CHECK(created_at<absolute_expires_at AND absolute_expires_at<=created_at+interval '604800 seconds'),
 last_rotated_at timestamptz NOT NULL CHECK(last_rotated_at>=created_at AND last_rotated_at<absolute_expires_at),
 revoked_at timestamptz CHECK(revoked_at>=created_at)
);
CREATE INDEX family_expiry ON ops_identity_v2.renewal_families(absolute_expires_at);
CREATE INDEX family_active_expiry ON ops_identity_v2.renewal_families(absolute_expires_at) WHERE revoked_at IS NULL;

CREATE FUNCTION ops_identity_v2.family_monotonic() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.family_id,NEW.originating_request_id,NEW.namespace,NEW.recovery_epoch,
 NEW.actor_id,NEW.profile_id,NEW.profile_digest,NEW.identity_authority,NEW.source_tenant,
 NEW.source_subject,NEW.principal_kind,NEW.oidc_subject_hash,NEW.login_nonce_hash,
 NEW.original_auth_time,NEW.recipient_hash,NEW.created_at,NEW.absolute_expires_at)
 IS DISTINCT FROM ROW(OLD.family_id,OLD.originating_request_id,OLD.namespace,OLD.recovery_epoch,
 OLD.actor_id,OLD.profile_id,OLD.profile_digest,OLD.identity_authority,OLD.source_tenant,
 OLD.source_subject,OLD.principal_kind,OLD.oidc_subject_hash,OLD.login_nonce_hash,
 OLD.original_auth_time,OLD.recipient_hash,OLD.created_at,OLD.absolute_expires_at)
 THEN RAISE EXCEPTION 'immutable renewal identity'; END IF;
 IF OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD
 THEN RAISE EXCEPTION 'renewal revocation is permanent'; END IF;
 IF NEW.generation<OLD.generation OR NEW.last_rotated_at<OLD.last_rotated_at
 THEN RAISE EXCEPTION 'renewal generation is monotonic'; END IF;
 IF ROW(NEW.current_handle_hash,NEW.encryption_key_id,NEW.refresh_ciphertext,NEW.last_rotated_at)
 IS DISTINCT FROM ROW(OLD.current_handle_hash,OLD.encryption_key_id,OLD.refresh_ciphertext,OLD.last_rotated_at)
 AND (OLD.generation=9223372036854775807 OR NEW.generation<>OLD.generation+1 OR NEW.revoked_at IS NOT NULL)
 THEN RAISE EXCEPTION 'renewal material requires one rotation'; END IF;
 IF NEW.generation<>OLD.generation AND
 (OLD.generation=9223372036854775807 OR NEW.generation<>OLD.generation+1 OR NEW.current_handle_hash=OLD.current_handle_hash OR NEW.refresh_ciphertext=OLD.refresh_ciphertext OR NEW.revoked_at IS NOT NULL)
 THEN RAISE EXCEPTION 'rotation requires replacement material'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ops_identity_v2.family_monotonic() FROM PUBLIC;
CREATE TRIGGER family_monotonic BEFORE UPDATE ON ops_identity_v2.renewal_families
FOR EACH ROW EXECUTE FUNCTION ops_identity_v2.family_monotonic();
