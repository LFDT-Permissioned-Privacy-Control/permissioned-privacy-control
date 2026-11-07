CREATE SCHEMA ops_admission_v2;
REVOKE ALL ON SCHEMA ops_admission_v2 FROM PUBLIC;
CREATE TABLE ops_admission_v2.schema_version(singleton boolean PRIMARY KEY CHECK(singleton),version integer NOT NULL CHECK(version=1),source_checksum text NOT NULL);
CREATE TABLE ops_admission_v2.network_state(
 network_key bytea PRIMARY KEY CHECK(octet_length(network_key)=32),environment text NOT NULL CHECK(octet_length(environment) BETWEEN 1 AND 128),
 chain_id text NOT NULL CHECK(chain_id~'^[1-9][0-9]{0,19}$' AND chain_id::numeric<=18446744073709551615),
 genesis_hash bytea NOT NULL CHECK(octet_length(genesis_hash)=32),deployment_id text NOT NULL CHECK(octet_length(deployment_id) BETWEEN 1 AND 128),
 generation uuid NOT NULL,ready boolean NOT NULL,coverage_digest bytea NOT NULL CHECK(octet_length(coverage_digest)=32),history_floor timestamptz
);
CREATE TABLE ops_admission_v2.travel_records(
 id uuid PRIMARY KEY,network_key bytea NOT NULL CHECK(octet_length(network_key)=32),org_id uuid NOT NULL,actor_id text NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),
 originator_data jsonb NOT NULL CHECK(jsonb_typeof(originator_data)='object' AND octet_length(originator_data::text)<=65536),
 beneficiary_data jsonb NOT NULL CHECK(jsonb_typeof(beneficiary_data)='object' AND octet_length(beneficiary_data::text)<=65536),
 transfer_type text NOT NULL CHECK(transfer_type IN('eth','erc20')),token bytea CHECK(token IS NULL OR octet_length(token)=20),beneficiary bytea NOT NULL CHECK(octet_length(beneficiary)=20),
 amount_wei text NOT NULL CHECK(amount_wei~'^[1-9][0-9]{0,77}$' AND amount_wei::numeric<=115792089237316195423570985008687907853269984665640564039457584007913129639935),
 amount_fiat numeric NOT NULL CHECK(amount_fiat>0 AND amount_fiat<1e100),currency text NOT NULL CHECK(currency IN('usd','eur','chf','gbp','aed')),
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL CHECK(expires_at>created_at),used_at timestamptz,used_tx_hash bytea CHECK(used_tx_hash IS NULL OR octet_length(used_tx_hash)=32),
 created_by_actor text NOT NULL CHECK(octet_length(created_by_actor) BETWEEN 1 AND 128),creation_policy_digest bytea NOT NULL CHECK(octet_length(creation_policy_digest)=32),quote_digest bytea NOT NULL CHECK(octet_length(quote_digest)=32),
 CHECK((transfer_type='eth' AND token IS NULL)OR(transfer_type='erc20' AND token IS NOT NULL)),CHECK((used_at IS NULL)=(used_tx_hash IS NULL))
);
CREATE UNIQUE INDEX travel_scoped_used_hash ON ops_admission_v2.travel_records(network_key,org_id,actor_id,used_tx_hash)WHERE used_at IS NOT NULL;
CREATE INDEX travel_unused_lookup ON ops_admission_v2.travel_records(network_key,org_id,actor_id,beneficiary,currency,created_at DESC,id DESC)WHERE used_at IS NULL;
CREATE INDEX travel_org_page ON ops_admission_v2.travel_records(network_key,org_id,created_at DESC,id DESC);
CREATE TABLE ops_admission_v2.compliance_events(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,network_key bytea NOT NULL CHECK(octet_length(network_key)=32),tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 actor_id text NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),org_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('root_native','root_erc20','admission_only')),coverage text NOT NULL,
 from_address bytea CHECK(from_address IS NULL OR octet_length(from_address)=20),to_address bytea CHECK(to_address IS NULL OR octet_length(to_address)=20),token bytea CHECK(token IS NULL OR octet_length(token)=20),amount_wei text CHECK(amount_wei IS NULL OR(length(amount_wei)<=78 AND amount_wei~'^(0|[1-9][0-9]*)$' AND amount_wei::numeric<=115792089237316195423570985008687907853269984665640564039457584007913129639935)),
 amount_fiat numeric CHECK(amount_fiat IS NULL OR(amount_fiat>=0 AND amount_fiat<1e100)),threshold_fiat numeric CHECK(threshold_fiat IS NULL OR(threshold_fiat>=0 AND threshold_fiat<1e100)),
 currency text CHECK(currency IS NULL OR currency IN('usd','eur','chf','gbp','aed')),decision text NOT NULL CHECK(decision IN('allowed','denied')),monitored boolean NOT NULL,reason text NOT NULL CHECK(octet_length(reason)<=2048),
 record_id uuid REFERENCES ops_admission_v2.travel_records(id)ON DELETE RESTRICT,decision_at timestamptz NOT NULL,policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 quote_digest bytea CHECK(quote_digest IS NULL OR octet_length(quote_digest)=32),quote_id text,quote_source text,quote_value numeric,quote_as_of timestamptz,quote_observed_at timestamptz,
 anchor_hash bytea NOT NULL CHECK(octet_length(anchor_hash)=32),anchor_number numeric NOT NULL CHECK(anchor_number>=0 AND anchor_number<=18446744073709551615),anchor_timestamp numeric NOT NULL CHECK(anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615),evidence_profile text NOT NULL,
 CHECK((kind='admission_only' AND coverage IN('not_detected','disabled','relay_request')AND from_address IS NULL AND to_address IS NULL AND token IS NULL AND amount_wei IS NULL AND amount_fiat IS NULL AND threshold_fiat IS NULL AND currency IS NULL AND record_id IS NULL AND quote_digest IS NULL AND decision='allowed' AND NOT monitored AND reason='')
 OR(kind IN('root_native','root_erc20')AND coverage='root_transfer' AND from_address IS NOT NULL AND to_address IS NOT NULL AND amount_wei IS NOT NULL AND currency IS NOT NULL AND((kind='root_native'AND token IS NULL)OR(kind='root_erc20'AND token IS NOT NULL)))),
 CHECK((quote_digest IS NULL AND quote_id IS NULL AND quote_source IS NULL AND quote_value IS NULL AND quote_as_of IS NULL AND quote_observed_at IS NULL)
 OR(quote_digest IS NOT NULL AND octet_length(quote_id) BETWEEN 1 AND 100 AND octet_length(quote_source) BETWEEN 1 AND 128 AND quote_value>0 AND quote_value<1e12 AND quote_as_of IS NOT NULL AND quote_observed_at IS NOT NULL AND amount_fiat IS NOT NULL))
);
CREATE INDEX compliance_org_page ON ops_admission_v2.compliance_events(network_key,org_id,decision_at DESC,id DESC);
CREATE INDEX compliance_scoped_record ON ops_admission_v2.compliance_events(network_key,org_id,actor_id,tx_hash)WHERE record_id IS NOT NULL;
CREATE TABLE ops_admission_v2.qualified_tx_origins(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),actor_id text NOT NULL CHECK(octet_length(actor_id) BETWEEN 1 AND 128),org_id uuid NOT NULL,first_admitted_at timestamptz NOT NULL,
 witness_id bytea NOT NULL CHECK(octet_length(witness_id)=32),anchor_hash bytea NOT NULL CHECK(octet_length(anchor_hash)=32),anchor_number numeric NOT NULL CHECK(anchor_number>=0 AND anchor_number<=18446744073709551615),anchor_timestamp numeric NOT NULL CHECK(anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615),evidence_profile text NOT NULL,
 wallet_version bytea NOT NULL CHECK(octet_length(wallet_version)=32),decision_at timestamptz NOT NULL,manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),compliance_digest bytea NOT NULL CHECK(octet_length(compliance_digest)=32),wallet_evidence_at timestamptz NOT NULL,
 PRIMARY KEY(network_key,tx_hash)
);
CREATE TABLE ops_admission_v2.extra_privacy_witnesses(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),witness_id bytea NOT NULL CHECK(octet_length(witness_id)=32),
 anchor_hash bytea NOT NULL CHECK(octet_length(anchor_hash)=32),anchor_number numeric NOT NULL CHECK(anchor_number>=0 AND anchor_number<=18446744073709551615),anchor_timestamp numeric NOT NULL CHECK(anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615),evidence_profile text NOT NULL,
 wallet_version bytea NOT NULL CHECK(octet_length(wallet_version)=32),decision_at timestamptz NOT NULL,manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),compliance_digest bytea NOT NULL CHECK(octet_length(compliance_digest)=32),wallet_evidence_at timestamptz NOT NULL,
 PRIMARY KEY(network_key,tx_hash,witness_id),FOREIGN KEY(network_key,tx_hash)REFERENCES ops_admission_v2.qualified_tx_origins(network_key,tx_hash)ON DELETE RESTRICT
);
CREATE FUNCTION ops_admission_v2.valid_recipients(values_ text[])RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT cardinality(values_) BETWEEN 1 AND 32 AND array_ndims(values_)=1 AND array_lower(values_,1)=1
 AND NOT EXISTS(SELECT 1 FROM unnest(values_)v WHERE v IS NULL OR octet_length(v)>128 OR v!~'^ops:p1:[A-Za-z0-9_-]{43}$')
 AND cardinality(values_)=(SELECT count(DISTINCT v)FROM unnest(values_)v)
 AND values_=(SELECT array_agg(v ORDER BY v COLLATE "C")FROM unnest(values_)v)
 AND octet_length(array_to_string(values_,''))<=4096
$$;
CREATE TABLE ops_admission_v2.tx_shares(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),sender_actor_id text NOT NULL CHECK(octet_length(sender_actor_id) BETWEEN 1 AND 128),sender_org_id uuid NOT NULL,
 recipients text[] NOT NULL CHECK(ops_admission_v2.valid_recipients(recipients)),recipient_digest bytea NOT NULL CHECK(octet_length(recipient_digest)=32),declared_at timestamptz NOT NULL,
 anchor_hash bytea NOT NULL CHECK(octet_length(anchor_hash)=32),anchor_number numeric NOT NULL CHECK(anchor_number>=0 AND anchor_number<=18446744073709551615),anchor_timestamp numeric NOT NULL CHECK(anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),wallet_version bytea NOT NULL CHECK(octet_length(wallet_version)=32),wallet_evidence_at timestamptz NOT NULL,
 PRIMARY KEY(network_key,tx_hash)
);
CREATE INDEX shares_recipients ON ops_admission_v2.tx_shares USING gin(recipients);
CREATE FUNCTION ops_admission_v2.travel_record_monotonic()RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN IF OLD.used_at IS NOT NULL THEN RAISE EXCEPTION 'used record cannot be deleted';END IF;RETURN OLD;END IF;
 IF ROW(NEW.id,NEW.network_key,NEW.org_id,NEW.actor_id,NEW.originator_data,NEW.beneficiary_data,NEW.transfer_type,NEW.token,NEW.beneficiary,NEW.amount_wei,NEW.amount_fiat,NEW.currency,NEW.created_at,NEW.expires_at,NEW.created_by_actor,NEW.creation_policy_digest,NEW.quote_digest)
 IS DISTINCT FROM ROW(OLD.id,OLD.network_key,OLD.org_id,OLD.actor_id,OLD.originator_data,OLD.beneficiary_data,OLD.transfer_type,OLD.token,OLD.beneficiary,OLD.amount_wei,OLD.amount_fiat,OLD.currency,OLD.created_at,OLD.expires_at,OLD.created_by_actor,OLD.creation_policy_digest,OLD.quote_digest)THEN RAISE EXCEPTION 'record is immutable';END IF;
 IF OLD.used_at IS NOT NULL AND ROW(NEW.used_at,NEW.used_tx_hash)IS DISTINCT FROM ROW(OLD.used_at,OLD.used_tx_hash)THEN RAISE EXCEPTION 'record binding is immutable';END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER travel_record_monotonic BEFORE UPDATE OR DELETE ON ops_admission_v2.travel_records FOR EACH ROW EXECUTE FUNCTION ops_admission_v2.travel_record_monotonic();
