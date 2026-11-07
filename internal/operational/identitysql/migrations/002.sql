-- Additive Privado operational flows; offline migration only.
-- Caller has drained workers and separately committed ready=false under the
-- existing offline-owner lock. All statements below are ONE upgrade transaction.
-- 001.sql bytes are immutable. Caller validates exact old shape/checksum first.

ALTER TABLE ops_identity_v2.renewal_families
 ADD COLUMN provider_kind text NOT NULL DEFAULT 'azure-human',
 ALTER COLUMN source_tenant DROP NOT NULL,
 ALTER COLUMN oidc_subject_hash DROP NOT NULL,
 ALTER COLUMN login_nonce_hash DROP NOT NULL,
 DROP CONSTRAINT renewal_families_check,
 DROP CONSTRAINT renewal_families_source_tenant_check,
 DROP CONSTRAINT renewal_families_source_subject_check;

ALTER TABLE ops_identity_v2.renewal_families
 ADD CONSTRAINT family_provider_kind CHECK(provider_kind IN('azure-human','privado')),
 ADD CONSTRAINT family_provider_shape CHECK(
  (provider_kind='azure-human'
   AND source_tenant IS NOT NULL
   AND source_tenant ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND source_tenant<>'00000000-0000-0000-0000-000000000000'
   AND source_subject ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND source_subject<>'00000000-0000-0000-0000-000000000000'
   AND identity_authority='https://login.microsoftonline.com/'||source_tenant||'/v2.0'
   AND oidc_subject_hash IS NOT NULL AND octet_length(oidc_subject_hash)=32
   AND login_nonce_hash IS NOT NULL AND octet_length(login_nonce_hash)=32)
  OR
  (provider_kind='privado' AND identity_authority='privado'
   AND source_tenant IS NULL AND oidc_subject_hash IS NULL
   AND login_nonce_hash IS NULL AND original_auth_time IS NULL
   AND octet_length(source_subject) BETWEEN 1 AND 1024
   AND source_subject ~ '^did:(iden3|polygonid):[a-z0-9]+:[a-z0-9]+:[1-9A-HJ-NP-Za-km-z]+$'
   AND octet_length(refresh_ciphertext) BETWEEN 28 AND 2048)),
 ADD CONSTRAINT family_scoped_provider_unique
  UNIQUE(family_id,namespace,recovery_epoch,provider_kind);

-- The physical refresh_ciphertext name stays unchanged for compatibility; Go
-- names the Privado payload continuity metadata. It is NOT an upstream token.
CREATE OR REPLACE FUNCTION ops_identity_v2.family_monotonic() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.family_id,NEW.originating_request_id,NEW.namespace,NEW.recovery_epoch,
 NEW.actor_id,NEW.profile_id,NEW.profile_digest,NEW.identity_authority,NEW.source_tenant,
 NEW.source_subject,NEW.principal_kind,NEW.oidc_subject_hash,NEW.login_nonce_hash,
 NEW.original_auth_time,NEW.recipient_hash,NEW.created_at,NEW.absolute_expires_at,NEW.provider_kind)
 IS DISTINCT FROM ROW(OLD.family_id,OLD.originating_request_id,OLD.namespace,OLD.recovery_epoch,
 OLD.actor_id,OLD.profile_id,OLD.profile_digest,OLD.identity_authority,OLD.source_tenant,
 OLD.source_subject,OLD.principal_kind,OLD.oidc_subject_hash,OLD.login_nonce_hash,
 OLD.original_auth_time,OLD.recipient_hash,OLD.created_at,OLD.absolute_expires_at,OLD.provider_kind)
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
 (OLD.generation=9223372036854775807 OR NEW.generation<>OLD.generation+1
 OR NEW.current_handle_hash=OLD.current_handle_hash OR NEW.refresh_ciphertext=OLD.refresh_ciphertext
 OR NEW.revoked_at IS NOT NULL)
 THEN RAISE EXCEPTION 'rotation requires replacement material'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ops_identity_v2.family_monotonic() FROM PUBLIC;

CREATE TABLE ops_identity_v2.privado_challenges (
 request_id uuid PRIMARY KEY CHECK(request_id<>'00000000-0000-0000-0000-000000000000'),
 namespace text NOT NULL CHECK(namespace ~ '^sha256:[0-9a-f]{64}$'),
 recovery_epoch uuid NOT NULL CHECK(recovery_epoch<>'00000000-0000-0000-0000-000000000000'),
 provider_kind text NOT NULL DEFAULT 'privado' CHECK(provider_kind='privado'),
 profile_id text NOT NULL CHECK(octet_length(profile_id) BETWEEN 1 AND 128),
 profile_digest text NOT NULL CHECK(profile_digest ~ '^sha256:[0-9a-f]{64}$'),
 recipient_hash bytea NOT NULL CHECK(octet_length(recipient_hash)=32),
 mode text NOT NULL CHECK(mode IN('login','renew')),
 expected_actor_id text CHECK(expected_actor_id ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
 family_id uuid CHECK(family_id<>'00000000-0000-0000-0000-000000000000'),
 current_generation bigint CHECK(current_generation>=0),
 current_handle_hash bytea CHECK(octet_length(current_handle_hash)=32),
 encryption_key_id text NOT NULL CHECK(octet_length(encryption_key_id) BETWEEN 1 AND 128),
 context_ciphertext bytea NOT NULL CHECK(octet_length(context_ciphertext) BETWEEN 28 AND 2048),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CONSTRAINT challenge_time CHECK(isfinite(created_at) AND isfinite(expires_at)
  AND created_at>='1970-01-01 00:00:00+00'::timestamptz
  AND expires_at<='9999-12-31 23:59:59+00'::timestamptz
  AND date_trunc('second',created_at)=created_at AND date_trunc('second',expires_at)=expires_at
  AND created_at<expires_at AND expires_at<=created_at+interval '300 seconds'),
 CONSTRAINT challenge_mode CHECK(
  (mode='login' AND family_id IS NULL AND current_generation IS NULL AND current_handle_hash IS NULL)
  OR (mode='renew' AND expected_actor_id IS NOT NULL AND family_id IS NOT NULL
      AND current_generation IS NOT NULL AND current_handle_hash IS NOT NULL)),
 CONSTRAINT challenge_scoped_unique UNIQUE(request_id,namespace,recovery_epoch),
 CONSTRAINT challenge_family_fk FOREIGN KEY(family_id,namespace,recovery_epoch,provider_kind)
  REFERENCES ops_identity_v2.renewal_families(family_id,namespace,recovery_epoch,provider_kind)
  ON UPDATE NO ACTION ON DELETE CASCADE NOT DEFERRABLE
);
CREATE INDEX privado_challenge_namespace ON ops_identity_v2.privado_challenges(namespace,request_id);
CREATE INDEX privado_challenge_expiry ON ops_identity_v2.privado_challenges(namespace,expires_at,request_id);

CREATE TABLE ops_identity_v2.privado_offers (
 request_id uuid PRIMARY KEY,
 namespace text NOT NULL CHECK(namespace ~ '^sha256:[0-9a-f]{64}$'),
 recovery_epoch uuid NOT NULL CHECK(recovery_epoch<>'00000000-0000-0000-0000-000000000000'),
 context_digest bytea NOT NULL CHECK(octet_length(context_digest)=32),
 proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32),
 holder_did text NOT NULL CHECK(octet_length(holder_did) BETWEEN 1 AND 1024
  AND holder_did ~ '^did:(iden3|polygonid):[a-z0-9]+:[a-z0-9]+:[1-9A-HJ-NP-Za-km-z]+$'),
 actor_id text NOT NULL CHECK(actor_id ~ '^ops:p1:[A-Za-z0-9_-]{43}$'),
 network text NOT NULL CHECK(octet_length(network) BETWEEN 3 AND 128 AND network ~ '^[a-z0-9]+:[a-z0-9]+$'),
 profile_id text NOT NULL CHECK(octet_length(profile_id) BETWEEN 1 AND 128),
 profile_digest text NOT NULL CHECK(profile_digest ~ '^sha256:[0-9a-f]{64}$'),
 source_auth_digest text NOT NULL CHECK(source_auth_digest ~ '^sha256:[0-9a-f]{64}$'),
 identity_digest text NOT NULL CHECK(identity_digest ~ '^sha256:[0-9a-f]{64}$'),
 profile_plan_digest text NOT NULL CHECK(profile_plan_digest ~ '^sha256:[0-9a-f]{64}$'),
 network_plan_digest text NOT NULL CHECK(network_plan_digest ~ '^sha256:[0-9a-f]{64}$'),
 document_plan_digest text NOT NULL CHECK(document_plan_digest ~ '^sha256:[0-9a-f]{64}$'),
 claims_as_of bigint NOT NULL CHECK(claims_as_of BETWEEN 0 AND 253402300799),
 not_after bigint NOT NULL CHECK(not_after BETWEEN 1 AND 253402300799),
 verified_at bigint NOT NULL CHECK(verified_at BETWEEN 0 AND 253402300799),
 encryption_key_id text NOT NULL CHECK(octet_length(encryption_key_id) BETWEEN 1 AND 128),
 proof_ciphertext bytea NOT NULL CHECK(octet_length(proof_ciphertext) BETWEEN 28 AND 1048604),
 CONSTRAINT offer_times CHECK(claims_as_of<=verified_at AND verified_at<not_after
  AND not_after<=claims_as_of+300),
 CONSTRAINT offer_challenge_fk FOREIGN KEY(request_id,namespace,recovery_epoch)
  REFERENCES ops_identity_v2.privado_challenges(request_id,namespace,recovery_epoch)
  ON UPDATE NO ACTION ON DELETE CASCADE NOT DEFERRABLE
);
CREATE INDEX privado_offer_namespace ON ops_identity_v2.privado_offers(namespace,request_id);

CREATE FUNCTION ops_identity_v2.privado_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'immutable Privado flow';
END $$;
REVOKE ALL ON FUNCTION ops_identity_v2.privado_immutable() FROM PUBLIC;
CREATE TRIGGER privado_challenge_immutable BEFORE UPDATE ON ops_identity_v2.privado_challenges
FOR EACH ROW EXECUTE FUNCTION ops_identity_v2.privado_immutable();
CREATE TRIGGER privado_offer_immutable BEFORE UPDATE ON ops_identity_v2.privado_offers
FOR EACH ROW EXECUTE FUNCTION ops_identity_v2.privado_immutable();

ALTER TABLE ops_identity_v2.metadata DROP CONSTRAINT metadata_schema_version_check;
ALTER TABLE ops_identity_v2.metadata ADD CONSTRAINT metadata_schema_version_check
 CHECK(schema_version=2) NOT VALID;

-- SAME TRANSACTION, owner driver now performs a parameterized metadata update:
-- UPDATE ... SET schema_version=2,migration_checksum=$checksum,ready=false,...;
-- ALTER TABLE ... VALIDATE CONSTRAINT metadata_schema_version_check;
-- Install exact ACLs and verify normalized catalog manifest before COMMIT.
-- A later separately verified owner transaction may set ready=true.
