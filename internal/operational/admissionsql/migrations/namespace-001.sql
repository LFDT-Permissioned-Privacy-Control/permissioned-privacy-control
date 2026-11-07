-- Historical contract namespace facts, schema1. Offline owner migration only.
-- No change to ops_admission_v2 schema001/002/003, versions, or existing grants.
CREATE SCHEMA ops_history_namespace_v1;
REVOKE ALL ON SCHEMA ops_history_namespace_v1 FROM PUBLIC;

CREATE TABLE ops_history_namespace_v1.namespace_network_state(
 network_key BYTEA PRIMARY KEY CHECK(octet_length(network_key)=32),
 schema_version SMALLINT NOT NULL CHECK(schema_version=1),
 expected_admission_generation UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>=1),
 ready BOOLEAN NOT NULL,
 completeness_digest BYTEA CHECK(octet_length(completeness_digest)=32),
 model_id TEXT NOT NULL CHECK(model_id='prague-ordinary-runtime/v1'),
 era_entry_number BIGINT NOT NULL CHECK(era_entry_number>=0),
 era_entry_hash BYTEA NOT NULL CHECK(octet_length(era_entry_hash)=32),
 era_entry_timestamp BIGINT NOT NULL CHECK(era_entry_timestamp>=0),
 era_end_timestamp_exclusive BIGINT NOT NULL CHECK(era_end_timestamp_exclusive>era_entry_timestamp),
 max_lifetimes BIGINT NOT NULL CHECK(max_lifetimes BETWEEN 1 AND 1000000),
 max_transfers BIGINT NOT NULL CHECK(max_transfers BETWEEN 1 AND 1000000),
 max_cohorts BIGINT NOT NULL CHECK(max_cohorts BETWEEN 1 AND 10000),
 max_revoked_cohorts BIGINT NOT NULL CHECK(max_revoked_cohorts BETWEEN 1 AND 10000),
 max_lifetimes_per_address INTEGER NOT NULL CHECK(max_lifetimes_per_address BETWEEN 1 AND 32),
 max_transfers_per_segment INTEGER NOT NULL CHECK(max_transfers_per_segment BETWEEN 1 AND 64),
 lifetime_count BIGINT NOT NULL CHECK(lifetime_count BETWEEN 0 AND max_lifetimes),
 transfer_count BIGINT NOT NULL CHECK(transfer_count BETWEEN 0 AND max_transfers),
 cohort_count BIGINT NOT NULL CHECK(cohort_count BETWEEN 0 AND max_cohorts),
 revoked_cohort_count BIGINT NOT NULL CHECK(revoked_cohort_count BETWEEN 0 AND max_revoked_cohorts),
 FOREIGN KEY(network_key) REFERENCES ops_admission_v2.network_state(network_key),
 CHECK(NOT ready OR completeness_digest IS NOT NULL)
);

CREATE TABLE ops_history_namespace_v1.namespace_cohorts(
 network_key BYTEA NOT NULL,
 cohort_id UUID NOT NULL,
 semantic_digest BYTEA NOT NULL CHECK(octet_length(semantic_digest)=32),
 first_raw_artifact_digest BYTEA NOT NULL CHECK(octet_length(first_raw_artifact_digest)=32),
 statement_count INTEGER NOT NULL CHECK(statement_count BETWEEN 1 AND 4096),
 canonical_bytes INTEGER NOT NULL CHECK(canonical_bytes BETWEEN 1 AND 4194304),
 recorded_at TIMESTAMPTZ NOT NULL CHECK(isfinite(recorded_at)),
 PRIMARY KEY(network_key,cohort_id),
 UNIQUE(network_key,semantic_digest),
 FOREIGN KEY(network_key) REFERENCES ops_history_namespace_v1.namespace_network_state(network_key)
);

-- evidence_kind:1 pre-era finite,2 Prague finite,3 Prague checkpoint.
-- physical_kind:0 pre-era explicit UUID,1 preexisting at era entry,2 born in era.
-- label_kind:1 Org,2 Public. Root/transfer cut indices are canonical boundaries.
CREATE TABLE ops_history_namespace_v1.legacy_contract_lifetimes(
 network_key BYTEA NOT NULL,
 statement_digest BYTEA NOT NULL CHECK(octet_length(statement_digest)=32),
 cohort_id UUID NOT NULL,
 address BYTEA NOT NULL CHECK(octet_length(address)=20),
 evidence_kind SMALLINT NOT NULL CHECK(evidence_kind IN(1,2,3)),
 segment_key BYTEA NOT NULL CHECK(octet_length(segment_key)=32),
 lifetime_id UUID,
 runtime_hash BYTEA NOT NULL CHECK(octet_length(runtime_hash)=32),
 runtime_length INTEGER NOT NULL CHECK(runtime_length BETWEEN 1 AND 1048576),
 initial_kind SMALLINT NOT NULL CHECK(initial_kind IN(1,2)),
 initial_org UUID,
 physical_kind SMALLINT NOT NULL CHECK(physical_kind IN(0,1,2)),
 birth_number BIGINT CHECK(birth_number>=0),
 birth_hash BYTEA CHECK(octet_length(birth_hash)=32),
 birth_tx_hash BYTEA CHECK(octet_length(birth_tx_hash)=32),
 birth_index BIGINT CHECK(birth_index BETWEEN 0 AND 4294967295),
 birth_record INTEGER CHECK(birth_record BETWEEN 0 AND 4095),
 start_number BIGINT CHECK(start_number>=0),
 start_hash BYTEA CHECK(octet_length(start_hash)=32),
 start_index BIGINT CHECK(start_index BETWEEN 0 AND 4294967295),
 end_number BIGINT CHECK(end_number>=0),
 end_hash BYTEA CHECK(octet_length(end_hash)=32),
 end_index BIGINT CHECK(end_index BETWEEN 0 AND 4294967295),
 checkpoint_number BIGINT CHECK(checkpoint_number>=0),
 checkpoint_hash BYTEA CHECK(octet_length(checkpoint_hash)=32),
 proof_digest BYTEA CHECK(octet_length(proof_digest)=32),
 PRIMARY KEY(network_key,statement_digest),
 FOREIGN KEY(network_key,cohort_id) REFERENCES ops_history_namespace_v1.namespace_cohorts(network_key,cohort_id),
 CHECK((initial_kind=1 AND initial_org IS NOT NULL) OR(initial_kind=2 AND initial_org IS NULL)),
 CHECK((physical_kind=0 AND evidence_kind=1 AND lifetime_id IS NOT NULL) OR
       (physical_kind IN(1,2) AND evidence_kind IN(2,3) AND lifetime_id IS NULL)),
 CHECK((physical_kind=2 AND birth_number IS NOT NULL AND birth_hash IS NOT NULL AND birth_tx_hash IS NOT NULL AND birth_index IS NOT NULL AND birth_record IS NOT NULL) OR
       (physical_kind IN(0,1) AND birth_number IS NULL AND birth_hash IS NULL AND birth_tx_hash IS NULL AND birth_index IS NULL AND birth_record IS NULL)),
 CHECK((evidence_kind IN(1,2) AND start_number IS NOT NULL AND start_hash IS NOT NULL AND start_index IS NOT NULL AND end_number IS NOT NULL AND end_hash IS NOT NULL AND end_index IS NOT NULL AND checkpoint_number IS NULL AND checkpoint_hash IS NULL AND proof_digest IS NULL AND (start_number,start_index)<(end_number,end_index)) OR
       (evidence_kind=3 AND start_number IS NULL AND start_hash IS NULL AND start_index IS NULL AND end_number IS NULL AND end_hash IS NULL AND end_index IS NULL AND checkpoint_number IS NOT NULL AND checkpoint_hash IS NOT NULL AND proof_digest IS NOT NULL))
);
CREATE INDEX namespace_lifetimes_address ON ops_history_namespace_v1.legacy_contract_lifetimes(network_key,address,statement_digest);
CREATE INDEX namespace_lifetimes_segment ON ops_history_namespace_v1.legacy_contract_lifetimes(network_key,segment_key,statement_digest);

-- segment_kind:1 pre-era UUID,2 normalized Prague. Legacy basis is an immutable
-- original witness for pre-era key identity, not permission to ignore its deny.
CREATE TABLE ops_history_namespace_v1.namespace_transfers(
 network_key BYTEA NOT NULL,
 transfer_digest BYTEA NOT NULL CHECK(octet_length(transfer_digest)=32),
 cohort_id UUID NOT NULL,
 address BYTEA NOT NULL CHECK(octet_length(address)=20),
 segment_kind SMALLINT NOT NULL CHECK(segment_kind IN(1,2)),
 segment_key BYTEA NOT NULL CHECK(octet_length(segment_key)=32),
 legacy_basis_digest BYTEA CHECK(octet_length(legacy_basis_digest)=32),
 initial_kind SMALLINT NOT NULL CHECK(initial_kind IN(1,2)),
 initial_org UUID,
 parent_digest BYTEA CHECK(octet_length(parent_digest)=32),
 previous_kind SMALLINT NOT NULL CHECK(previous_kind IN(1,2)),
 previous_org UUID,
 new_kind SMALLINT NOT NULL CHECK(new_kind IN(1,2)),
 new_org UUID,
 effective_number BIGINT NOT NULL CHECK(effective_number>=0),
 effective_hash BYTEA NOT NULL CHECK(octet_length(effective_hash)=32),
 effective_index BIGINT NOT NULL CHECK(effective_index BETWEEN 0 AND 4294967295),
 PRIMARY KEY(network_key,transfer_digest),
 FOREIGN KEY(network_key,cohort_id) REFERENCES ops_history_namespace_v1.namespace_cohorts(network_key,cohort_id),
 FOREIGN KEY(network_key,parent_digest) REFERENCES ops_history_namespace_v1.namespace_transfers(network_key,transfer_digest),
 FOREIGN KEY(network_key,legacy_basis_digest) REFERENCES ops_history_namespace_v1.legacy_contract_lifetimes(network_key,statement_digest),
 CHECK(parent_digest IS NULL OR parent_digest<>transfer_digest),
 CHECK((segment_kind=1 AND legacy_basis_digest IS NOT NULL) OR(segment_kind=2 AND legacy_basis_digest IS NULL)),
 CHECK((initial_kind=1 AND initial_org IS NOT NULL) OR(initial_kind=2 AND initial_org IS NULL)),
 CHECK((previous_kind=1 AND previous_org IS NOT NULL) OR(previous_kind=2 AND previous_org IS NULL)),
 CHECK((new_kind=1 AND new_org IS NOT NULL) OR(new_kind=2 AND new_org IS NULL)),
 CHECK(previous_kind<>new_kind OR previous_org IS DISTINCT FROM new_org)
);
CREATE INDEX namespace_transfers_segment ON ops_history_namespace_v1.namespace_transfers(network_key,segment_key,effective_number,effective_index,transfer_digest);
CREATE INDEX namespace_transfers_address ON ops_history_namespace_v1.namespace_transfers(network_key,address,effective_number,effective_index,transfer_digest);

CREATE TABLE ops_history_namespace_v1.revoked_namespace_cohorts(
 network_key BYTEA NOT NULL,
 cohort_id UUID NOT NULL,
 reason TEXT NOT NULL CHECK(reason IN('source-compromise','restore-gap')),
 recorded_at TIMESTAMPTZ NOT NULL CHECK(isfinite(recorded_at)),
 PRIMARY KEY(network_key,cohort_id),
 FOREIGN KEY(network_key,cohort_id) REFERENCES ops_history_namespace_v1.namespace_cohorts(network_key,cohort_id)
);

REVOKE ALL ON ALL TABLES IN SCHEMA ops_history_namespace_v1 FROM PUBLIC;
-- Owner adapter applies exact quoted role grants AFTER validating role binding:
-- GRANT USAGE ON SCHEMA ops_history_namespace_v1,ops_admission_v2 TO reader;
-- GRANT SELECT ON the five namespace tables TO reader;
-- GRANT SELECT ON ONLY the existing nine A2 factsReadTables TO reader.
-- No DML, sequence, function, CREATE, default-privilege or existing-role changes.
-- All tables are owner-only mutable offline; serving role is never owner.
-- Immutable original rows are never updated/deleted by any product API. Owner
-- corruption remains checked by exact catalog+present-row restore validation.
