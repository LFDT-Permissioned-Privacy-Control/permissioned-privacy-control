-- Offline only. Stop all old processes and fence recovery readiness before
-- upgrading an existing network. Runtime startup never executes this file.
ALTER TABLE ops_admission_v2.schema_version DROP CONSTRAINT schema_version_version_check;
ALTER TABLE ops_admission_v2.schema_version ADD CONSTRAINT schema_version_version_check CHECK(version IN (1,2));

CREATE TABLE ops_admission_v2.creation_capacity(
 network_key bytea PRIMARY KEY REFERENCES ops_admission_v2.network_state(network_key) ON DELETE RESTRICT,
 work_count bigint NOT NULL DEFAULT 0 CHECK(work_count BETWEEN 0 AND 100000),
 plan_count bigint NOT NULL DEFAULT 0 CHECK(plan_count BETWEEN 0 AND 200000),
 plan_bytes bigint NOT NULL DEFAULT 0 CHECK(plan_bytes BETWEEN 0 AND 1073741824),
 wallet_ref_count bigint NOT NULL DEFAULT 0 CHECK(wallet_ref_count BETWEEN 0 AND 800000),
 factory_ref_count bigint NOT NULL DEFAULT 0 CHECK(factory_ref_count BETWEEN 0 AND 800000)
);

CREATE TABLE ops_admission_v2.creation_plans(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 version integer NOT NULL CHECK(version=1),
 payload bytea NOT NULL CHECK(octet_length(payload) BETWEEN 1 AND 65536),
 entry_count integer NOT NULL CHECK(entry_count BETWEEN 1 AND 128),
 root_org uuid NOT NULL,
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 runtime_digest bytea NOT NULL CHECK(octet_length(runtime_digest)=32),
 chain_id text NOT NULL CHECK(chain_id~'^[1-9][0-9]{0,19}$' AND chain_id::numeric<=18446744073709551615),
 evidence_profile text NOT NULL CHECK(evidence_profile IN('geth-prague-lifecycle-signed/v1','geth-prague-lifecycle-guard/v1')),
 created_at timestamptz NOT NULL,
 PRIMARY KEY(network_key,tx_hash,plan_digest),
 FOREIGN KEY(network_key)REFERENCES ops_admission_v2.creation_capacity(network_key)ON DELETE RESTRICT
);

CREATE TABLE ops_admission_v2.creation_authority_refs(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 seed_digest bytea NOT NULL CHECK(octet_length(seed_digest)=32),
 plan_digest bytea NOT NULL CHECK(octet_length(plan_digest)=32),
 kind text NOT NULL CHECK(kind IN('WALLET','FACTORY')),
 branch smallint NOT NULL CHECK(branch BETWEEN 1 AND 8),
 wallet_actor text CHECK(wallet_actor IS NULL OR wallet_actor~'^ops:p1:[A-Za-z0-9_-]{43}$'),
 wallet_org uuid,
 witness_id bytea CHECK(witness_id IS NULL OR octet_length(witness_id)=32),
 anchor_hash bytea NOT NULL CHECK(octet_length(anchor_hash)=32),
 anchor_number numeric NOT NULL CHECK(anchor_number>=0 AND anchor_number<=18446744073709551615),
 anchor_timestamp numeric NOT NULL CHECK(anchor_timestamp>=0 AND anchor_timestamp<=18446744073709551615),
 evidence_profile text NOT NULL CHECK(evidence_profile IN('geth-prague-lifecycle-signed/v1','geth-prague-lifecycle-guard/v1')),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 runtime_digest bytea NOT NULL CHECK(octet_length(runtime_digest)=32),
 captured_at timestamptz NOT NULL,
 PRIMARY KEY(network_key,tx_hash,seed_digest),
 UNIQUE(network_key,tx_hash,kind,branch),
 FOREIGN KEY(network_key,tx_hash,plan_digest)REFERENCES ops_admission_v2.creation_plans(network_key,tx_hash,plan_digest)ON DELETE RESTRICT,
 CHECK((kind='WALLET' AND wallet_actor IS NOT NULL AND wallet_org IS NOT NULL AND witness_id IS NOT NULL)
    OR(kind='FACTORY' AND wallet_actor IS NULL AND wallet_org IS NULL AND witness_id IS NULL))
);
CREATE INDEX creation_refs_plan ON ops_admission_v2.creation_authority_refs(network_key,tx_hash,plan_digest);

CREATE TABLE ops_admission_v2.creation_work(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 generation bigint NOT NULL CHECK(generation>=1),
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL CHECK(updated_at>=created_at),
 PRIMARY KEY(network_key,tx_hash),
 FOREIGN KEY(network_key)REFERENCES ops_admission_v2.creation_capacity(network_key)ON DELETE RESTRICT
);

INSERT INTO ops_admission_v2.creation_capacity(network_key)SELECT network_key FROM ops_admission_v2.network_state;
