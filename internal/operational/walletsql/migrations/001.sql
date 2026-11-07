CREATE SCHEMA ops_wallet_v2;
REVOKE ALL ON SCHEMA ops_wallet_v2 FROM PUBLIC;
CREATE TABLE ops_wallet_v2.schema_version (
 singleton boolean PRIMARY KEY CHECK(singleton),version integer NOT NULL CHECK(version=1),source_checksum text NOT NULL
);
CREATE TABLE ops_wallet_v2.store_state (
 namespace bytea PRIMARY KEY CHECK(octet_length(namespace)=32),generation uuid NOT NULL,
 ready boolean NOT NULL,revocation_coverage_digest bytea NOT NULL CHECK(octet_length(revocation_coverage_digest)=32)
);
CREATE TABLE ops_wallet_v2.wallet_links (
 namespace bytea NOT NULL CHECK(octet_length(namespace)=32),actor_id text NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),
 address bytea NOT NULL CHECK(octet_length(address)=20),proof_kind text NOT NULL CHECK(proof_kind IN('eip191_v2','legacy_revoked')),
 message bytea,signature bytea,message_hash bytea,accepted_at timestamptz,
 revoked boolean NOT NULL,revoked_at timestamptz,
 PRIMARY KEY(namespace,actor_id,address),
 CHECK ((revoked AND revoked_at IS NOT NULL) OR (NOT revoked AND revoked_at IS NULL)),
 CHECK ((proof_kind='eip191_v2' AND message IS NOT NULL AND octet_length(message) BETWEEN 1 AND 4096 AND signature IS NOT NULL AND octet_length(signature)=65 AND message_hash IS NOT NULL AND octet_length(message_hash)=32 AND accepted_at IS NOT NULL)
 OR (proof_kind='legacy_revoked' AND revoked AND message IS NULL AND signature IS NULL AND message_hash IS NULL AND accepted_at IS NULL))
);
CREATE INDEX wallet_links_active_address ON ops_wallet_v2.wallet_links(namespace,address) WHERE NOT revoked;
CREATE TABLE ops_wallet_v2.wallet_challenges (
 namespace bytea NOT NULL CHECK(octet_length(namespace)=32),generation uuid NOT NULL,
 actor_id text NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),nonce bytea NOT NULL CHECK(octet_length(nonce)=32),
 address bytea NOT NULL CHECK(octet_length(address)=20),message bytea NOT NULL CHECK(octet_length(message) BETWEEN 1 AND 4096),
 issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 PRIMARY KEY(namespace,generation,nonce),CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '300 seconds')
);
CREATE INDEX wallet_challenges_actor ON ops_wallet_v2.wallet_challenges(namespace,actor_id);
CREATE INDEX wallet_challenges_expiry ON ops_wallet_v2.wallet_challenges(expires_at);
CREATE FUNCTION ops_wallet_v2.wallet_link_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF ROW(NEW.namespace,NEW.actor_id,NEW.address,NEW.proof_kind,NEW.message,NEW.signature,NEW.message_hash,NEW.accepted_at)
 IS DISTINCT FROM ROW(OLD.namespace,OLD.actor_id,OLD.address,OLD.proof_kind,OLD.message,OLD.signature,OLD.message_hash,OLD.accepted_at) THEN
  RAISE EXCEPTION 'wallet proof is immutable';
 END IF;
 IF OLD.revoked AND (NOT NEW.revoked OR NEW.revoked_at>OLD.revoked_at) THEN
  RAISE EXCEPTION 'wallet revocation is monotonic';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER wallet_link_monotonic BEFORE UPDATE ON ops_wallet_v2.wallet_links FOR EACH ROW EXECUTE FUNCTION ops_wallet_v2.wallet_link_monotonic();
