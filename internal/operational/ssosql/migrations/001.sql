-- Bounded structural SSO storage. Opaque ciphertext is not an authenticated grant.
CREATE SCHEMA ops_sso_v1;
REVOKE ALL ON SCHEMA ops_sso_v1 FROM PUBLIC;

CREATE TABLE ops_sso_v1.state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 schema_version smallint NOT NULL CHECK(schema_version=1),
 schema_checksum text NOT NULL CHECK(length(schema_checksum)=71),
 namespace bytea NOT NULL UNIQUE CHECK(octet_length(namespace)=32),
 epoch uuid NOT NULL CHECK(epoch<>'00000000-0000-0000-0000-000000000000'),
 broker_namespace bytea NOT NULL CHECK(octet_length(broker_namespace)=32),
 broker_epoch uuid NOT NULL CHECK(broker_epoch<>'00000000-0000-0000-0000-000000000000'),
 ready boolean NOT NULL,
 app_role name NOT NULL,
 retention_role name NOT NULL,
 max_active_rows bigint NOT NULL CHECK(max_active_rows BETWEEN 1 AND 1000000),
 max_ready_rows bigint NOT NULL CHECK(max_ready_rows BETWEEN 1 AND 1000000),
 max_active_bytes bigint NOT NULL CHECK(max_active_bytes BETWEEN 28672 AND 17179869184),
 max_all_rows bigint NOT NULL CHECK(max_all_rows BETWEEN 1 AND 1000000000),
 max_metadata_bytes bigint NOT NULL CHECK(max_metadata_bytes BETWEEN 2048 AND 2199023255552),
 audit_retention_seconds bigint NOT NULL CHECK(audit_retention_seconds BETWEEN 3600 AND 31536000),
 active_rows bigint NOT NULL DEFAULT 0 CHECK(active_rows>=0),
 ready_rows bigint NOT NULL DEFAULT 0 CHECK(ready_rows>=0),
 active_bytes bigint NOT NULL DEFAULT 0 CHECK(active_bytes>=0),
 all_rows bigint NOT NULL DEFAULT 0 CHECK(all_rows>=0),
 metadata_bytes bigint GENERATED ALWAYS AS(all_rows*2048) STORED,
 last_gc_us bigint NOT NULL DEFAULT 0 CHECK(last_gc_us BETWEEN 0 AND 253402300799999999),
 CHECK(app_role<>retention_role),
 CHECK(max_ready_rows<=max_active_rows AND max_active_rows<=max_all_rows),
 CHECK(active_rows<=max_active_rows AND ready_rows<=max_ready_rows AND ready_rows<=active_rows AND active_rows<=all_rows),
 CHECK(active_bytes<=max_active_bytes AND metadata_bytes<=max_metadata_bytes),
 CHECK((active_rows=0)=(active_bytes=0)),
 CHECK(active_bytes>=28*active_rows+28*ready_rows)
);

CREATE TABLE ops_sso_v1.transactions (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 namespace bytea NOT NULL REFERENCES ops_sso_v1.state(namespace),
 epoch uuid NOT NULL CHECK(epoch<>'00000000-0000-0000-0000-000000000000'),
 broker_epoch uuid NOT NULL CHECK(broker_epoch<>'00000000-0000-0000-0000-000000000000'),
 phase smallint NOT NULL CHECK(phase IN(1,2,3,4)),
 client_id text NOT NULL CHECK(client_id~'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
 client_catalog_digest bytea NOT NULL CHECK(octet_length(client_catalog_digest)=32),
 identity_digest bytea NOT NULL CHECK(octet_length(identity_digest)=32),
 recipient bytea NOT NULL CHECK(octet_length(recipient)=32),
 state_hash bytea NOT NULL CHECK(octet_length(state_hash)=32),
 redirect_hash bytea NOT NULL CHECK(octet_length(redirect_hash)=32),
 pkce_s256 bytea NOT NULL CHECK(octet_length(pkce_s256)=32),
 context_key_id text NOT NULL CHECK(context_key_id~'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
 context_ciphertext bytea,
 created_us bigint NOT NULL CHECK(created_us BETWEEN 0 AND 253402300799999999),
 expires_us bigint NOT NULL CHECK(expires_us>created_us AND expires_us<=253402300799999999 AND expires_us-created_us<=300000000),
 code_hash bytea CHECK(code_hash IS NULL OR octet_length(code_hash)=32),
 code_expires_us bigint,
 grant_key_id text CHECK(grant_key_id IS NULL OR grant_key_id~'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
 grant_ciphertext bytea,
 actor_id text CHECK(actor_id IS NULL OR actor_id~'^ops:p1:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'),
 profile_id text CHECK(profile_id IS NULL OR (octet_length(profile_id) BETWEEN 1 AND 128 AND profile_id~'^[A-Za-z0-9][A-Za-z0-9._-]*$')),
 profile_digest bytea CHECK(profile_digest IS NULL OR octet_length(profile_digest)=32),
 family_id uuid CHECK(family_id IS NULL OR family_id<>'00000000-0000-0000-0000-000000000000'),
 family_generation bigint CHECK(family_generation IS NULL OR family_generation>=0),
 family_handle_hash bytea CHECK(family_handle_hash IS NULL OR octet_length(family_handle_hash)=32),
 access_digest bytea CHECK(access_digest IS NULL OR octet_length(access_digest)=32),
 access_expires_us bigint,
 family_expires_us bigint,
 ready_us bigint,
 code_response_digest bytea CHECK(code_response_digest IS NULL OR octet_length(code_response_digest)=32),
 code_response_bytes integer CHECK(code_response_bytes IS NULL OR code_response_bytes BETWEEN 1 AND 32768),
 consumed_us bigint,
 token_response_digest bytea CHECK(token_response_digest IS NULL OR octet_length(token_response_digest)=32),
 token_response_bytes integer CHECK(token_response_bytes IS NULL OR token_response_bytes BETWEEN 1 AND 32768),
 retain_until_us bigint,
 active_bytes bigint GENERATED ALWAYS AS(CASE WHEN phase IN(1,2) THEN coalesce(octet_length(context_ciphertext),0)::bigint+coalesce(octet_length(grant_ciphertext),0)::bigint ELSE 0 END) STORED,
 CHECK(context_ciphertext IS NULL OR octet_length(context_ciphertext) BETWEEN 28 AND 4096),
 CHECK(grant_ciphertext IS NULL OR octet_length(grant_ciphertext) BETWEEN 28 AND 24576),
 CHECK((phase IN(1,2))=(context_ciphertext IS NOT NULL)),
 CHECK((phase=2)=(grant_ciphertext IS NOT NULL)),
 CHECK((phase=1 AND num_nonnulls(code_hash,code_expires_us,grant_key_id,actor_id,profile_id,profile_digest,family_id,family_generation,family_handle_hash,access_digest,access_expires_us,family_expires_us,ready_us,code_response_digest,code_response_bytes,retain_until_us)=0)
    OR (phase IN(2,3,4) AND num_nonnulls(code_hash,code_expires_us,grant_key_id,actor_id,profile_id,profile_digest,family_id,family_generation,family_handle_hash,access_digest,access_expires_us,family_expires_us,ready_us,code_response_digest,code_response_bytes,retain_until_us)=16)),
 CHECK((phase=3 AND consumed_us IS NOT NULL AND token_response_digest IS NOT NULL AND token_response_bytes IS NOT NULL)
    OR (phase<>3 AND consumed_us IS NULL AND token_response_digest IS NULL AND token_response_bytes IS NULL)),
 CHECK(ready_us IS NULL OR (ready_us>=created_us AND ready_us<expires_us AND code_expires_us>ready_us AND code_expires_us-ready_us<=60000000
    AND code_expires_us<=expires_us AND code_expires_us<=access_expires_us AND code_expires_us<=family_expires_us
    AND access_expires_us>ready_us AND access_expires_us-ready_us<=300000000 AND family_expires_us>ready_us
    AND retain_until_us>=code_expires_us+3600000000 AND retain_until_us-code_expires_us<=31536000000000 AND retain_until_us<=253402300799999999)),
 CHECK(consumed_us IS NULL OR (consumed_us>=ready_us AND consumed_us<code_expires_us)),
 CHECK(code_expires_us IS NULL OR code_expires_us<=253402300799999999),
 CHECK(access_expires_us IS NULL OR access_expires_us<=253402300799999999),
 CHECK(family_expires_us IS NULL OR family_expires_us<=253402300799999999)
);
CREATE UNIQUE INDEX transactions_code ON ops_sso_v1.transactions(code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX transactions_pending_expiry ON ops_sso_v1.transactions(expires_us,id) WHERE phase=1;
CREATE INDEX transactions_ready_expiry ON ops_sso_v1.transactions(code_expires_us,id) WHERE phase=2;
CREATE INDEX transactions_retention ON ops_sso_v1.transactions(retain_until_us,id) WHERE phase IN(3,4);

-- Immutable inputs and a closed one-way lifecycle. Counters are maintained by
-- the trusted store under the state-first lock, not claimed safe from its own
-- stolen write credential. No SECURITY DEFINER or generic trigger framework.
CREATE FUNCTION ops_sso_v1.guard_transaction() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,ops_sso_v1 AS $$
DECLARE owner_role text;
BEGIN
 SELECT pg_get_userbyid(nspowner) INTO STRICT owner_role FROM pg_catalog.pg_namespace WHERE nspname='ops_sso_v1';
 IF current_user=owner_role THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
   IF NEW.phase<>1 THEN RAISE EXCEPTION 'SSO initial phase';END IF;
   RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['phase','code_hash','code_expires_us','grant_key_id','grant_ciphertext','actor_id','profile_id','profile_digest','family_id','family_generation','family_handle_hash','access_digest','access_expires_us','family_expires_us','ready_us','code_response_digest','code_response_bytes','consumed_us','token_response_digest','token_response_bytes','retain_until_us','context_ciphertext','active_bytes'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['phase','code_hash','code_expires_us','grant_key_id','grant_ciphertext','actor_id','profile_id','profile_digest','family_id','family_generation','family_handle_hash','access_digest','access_expires_us','family_expires_us','ready_us','code_response_digest','code_response_bytes','consumed_us','token_response_digest','token_response_bytes','retain_until_us','context_ciphertext','active_bytes']) THEN
   RAISE EXCEPTION 'SSO immutable input';
 END IF;
 IF OLD.phase=1 AND NEW.phase=2 THEN
   IF NEW.context_ciphertext IS DISTINCT FROM OLD.context_ciphertext THEN RAISE EXCEPTION 'SSO context changed';END IF;
 ELSIF OLD.phase=2 AND NEW.phase IN(3,4) THEN
   IF (to_jsonb(NEW)-ARRAY['phase','context_ciphertext','grant_ciphertext','consumed_us','token_response_digest','token_response_bytes','active_bytes'])
      IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['phase','context_ciphertext','grant_ciphertext','consumed_us','token_response_digest','token_response_bytes','active_bytes']) THEN RAISE EXCEPTION 'SSO prepared metadata changed';END IF;
 ELSE RAISE EXCEPTION 'SSO nonmonotone phase';
 END IF;
 RETURN NEW;
END$$;
REVOKE ALL ON FUNCTION ops_sso_v1.guard_transaction() FROM PUBLIC;
CREATE TRIGGER guard_transaction BEFORE INSERT OR UPDATE ON ops_sso_v1.transactions FOR EACH ROW EXECUTE FUNCTION ops_sso_v1.guard_transaction();
REVOKE ALL ON ALL TABLES IN SCHEMA ops_sso_v1 FROM PUBLIC;
