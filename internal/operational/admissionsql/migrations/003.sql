-- Explicit offline upgrade. Drain all older processes before publication;
-- no runtime constructor executes DDL or retroqualifies existing intent rows.
ALTER TABLE ops_admission_v2.schema_version DROP CONSTRAINT schema_version_version_check;
ALTER TABLE ops_admission_v2.schema_version ADD CONSTRAINT schema_version_version_check CHECK(version IN(1,2,3));
ALTER TABLE ops_admission_v2.creation_plans DROP CONSTRAINT creation_plans_version_check;
ALTER TABLE ops_admission_v2.creation_plans ADD CONSTRAINT creation_plans_version_check CHECK(version IN(1,2));

ALTER TABLE ops_admission_v2.creation_capacity
 ADD COLUMN capture_coverage_count bigint NOT NULL DEFAULT 0 CHECK(capture_coverage_count BETWEEN 0 AND 1600000),
 ADD COLUMN capture_coverage_bytes bigint NOT NULL DEFAULT 0 CHECK(capture_coverage_bytes BETWEEN 0 AND 3276800000),
 ADD COLUMN revoked_epoch_count bigint NOT NULL DEFAULT 0 CHECK(revoked_epoch_count BETWEEN 0 AND 1600000),
 ADD COLUMN header_count bigint NOT NULL DEFAULT 0 CHECK(header_count BETWEEN 0 AND 10000000),
 ADD COLUMN birth_count bigint NOT NULL DEFAULT 0 CHECK(birth_count BETWEEN 0 AND 2000000),
 ADD COLUMN association_count bigint NOT NULL DEFAULT 0 CHECK(association_count BETWEEN 0 AND 8000000),
 ADD CONSTRAINT creation_coverage_ref_capacity CHECK(capture_coverage_count<=wallet_ref_count+factory_ref_count),
 ADD CONSTRAINT creation_revoke_capacity CHECK(revoked_epoch_count<=capture_coverage_count);

CREATE TABLE ops_admission_v2.creation_observer_state(
 network_key bytea PRIMARY KEY REFERENCES ops_admission_v2.network_state(network_key)ON DELETE RESTRICT,
 observer_epoch uuid NOT NULL,
 ready boolean NOT NULL DEFAULT false,
 quarantine text NOT NULL CHECK(quarantine IN('none','awaiting-canonical','uncertain-capture-trust','deep-reorg','below-floor','coverage-gap','node-mismatch')),
 floor_number bigint NOT NULL CHECK(floor_number>=0),
 floor_hash bytea NOT NULL CHECK(octet_length(floor_hash)=32),
 head_number bigint NOT NULL CHECK(head_number>=floor_number),
 head_hash bytea NOT NULL CHECK(octet_length(head_hash)=32),
 header_version bigint NOT NULL CHECK(header_version>=1),
 reorg_epoch bigint NOT NULL DEFAULT 0 CHECK(reorg_epoch>=0),
 lease_owner uuid,
 lease_fence bigint NOT NULL DEFAULT 0 CHECK(lease_fence>=0),
 lease_expires timestamptz,
 last_confirmed timestamptz,
 capture_epoch uuid NOT NULL,
 capture_ready boolean NOT NULL DEFAULT false,
 source_set_digest bytea NOT NULL CHECK(octet_length(source_set_digest)=32),
 reference_binding_digest bytea NOT NULL CHECK(octet_length(reference_binding_digest)=32),
 caught_up_assertion text NOT NULL CHECK(caught_up_assertion='operator-managed-canonical-head/v1'),
 known_tip_number bigint CHECK(known_tip_number>=0),
 known_tip_hash bytea CHECK(octet_length(known_tip_hash)=32),
 capture_heartbeat_until timestamptz,
 CHECK((lease_owner IS NULL)=(lease_expires IS NULL)),
 CHECK((known_tip_number IS NULL)=(known_tip_hash IS NULL)),
 CHECK(lease_expires IS NULL OR(isfinite(lease_expires)AND lease_expires>='1970-01-01 UTC'::timestamptz AND lease_expires<'10000-01-01 UTC'::timestamptz)),
 CHECK(last_confirmed IS NULL OR(isfinite(last_confirmed)AND last_confirmed>='1970-01-01 UTC'::timestamptz AND last_confirmed<'10000-01-01 UTC'::timestamptz)),
 CHECK(capture_heartbeat_until IS NULL OR(isfinite(capture_heartbeat_until)AND capture_heartbeat_until>='1970-01-01 UTC'::timestamptz AND capture_heartbeat_until<'10000-01-01 UTC'::timestamptz)),
 CHECK(NOT ready OR quarantine='none'),
 CHECK(NOT capture_ready OR(ready AND quarantine='none'AND capture_heartbeat_until IS NOT NULL AND known_tip_number=head_number AND known_tip_hash=head_hash))
);

CREATE TABLE ops_admission_v2.creation_headers(
 network_key bytea NOT NULL REFERENCES ops_admission_v2.creation_observer_state(network_key)ON DELETE RESTRICT,
 number bigint NOT NULL CHECK(number>=0),
 hash bytea NOT NULL CHECK(octet_length(hash)=32),
 parent_hash bytea NOT NULL CHECK(octet_length(parent_hash)=32),
 timestamp numeric NOT NULL CHECK(timestamp>=0 AND timestamp<=18446744073709551615),
 PRIMARY KEY(network_key,number),
 UNIQUE(network_key,hash)
);

CREATE TABLE ops_admission_v2.creation_capture_coverage(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 seed_digest bytea NOT NULL CHECK(octet_length(seed_digest)=32),
 version integer NOT NULL CHECK(version=1),
 policy text NOT NULL CHECK(policy='same-node-caught-up/v1'),
 plan_version integer NOT NULL CHECK(plan_version=2),
 admission_generation uuid NOT NULL,
 state_coverage bytea NOT NULL CHECK(octet_length(state_coverage)=32),
 observer_epoch uuid NOT NULL,
 capture_epoch uuid NOT NULL,
 source_set_digest bytea NOT NULL CHECK(octet_length(source_set_digest)=32),
 reference_binding_digest bytea NOT NULL CHECK(octet_length(reference_binding_digest)=32),
 ingress_binding_digest bytea NOT NULL CHECK(octet_length(ingress_binding_digest)=32),
 h_number bigint NOT NULL CHECK(h_number>=0),
 h_hash bytea NOT NULL CHECK(octet_length(h_hash)=32),
 h_parent bytea NOT NULL CHECK(octet_length(h_parent)=32),
 h_timestamp numeric NOT NULL CHECK(h_timestamp>=0 AND h_timestamp<=18446744073709551615),
 latest_number bigint NOT NULL CHECK(latest_number>=h_number),
 latest_hash bytea NOT NULL CHECK(octet_length(latest_hash)=32),
 latest_parent bytea NOT NULL CHECK(octet_length(latest_parent)=32),
 latest_timestamp numeric NOT NULL CHECK(latest_timestamp>=0 AND latest_timestamp<=18446744073709551615),
 header_version bigint NOT NULL CHECK(header_version>=1),
 lease_fence bigint NOT NULL CHECK(lease_fence>=1),
 probe_started_at timestamptz NOT NULL,
 probe_finished_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 logical_bytes smallint NOT NULL CHECK(logical_bytes BETWEEN 1 AND 2048),
 PRIMARY KEY(network_key,tx_hash,seed_digest),
 UNIQUE(network_key,capture_epoch,tx_hash,seed_digest),
 FOREIGN KEY(network_key,tx_hash,seed_digest)REFERENCES ops_admission_v2.creation_authority_refs(network_key,tx_hash,seed_digest)ON DELETE RESTRICT,
 CHECK(isfinite(probe_started_at)AND probe_started_at>='1970-01-01 UTC'::timestamptz AND probe_started_at<'10000-01-01 UTC'::timestamptz),
 CHECK(isfinite(probe_finished_at)AND probe_finished_at>=probe_started_at AND probe_finished_at<=probe_started_at+interval'2 seconds'),
 CHECK(isfinite(valid_until)AND valid_until>=probe_finished_at AND valid_until<=probe_finished_at+interval'5 seconds')
);

-- A deny-only cohort points to one real immutable covered-ref witness; this
-- indexed FK avoids an independent epoch catalog or heartbeat history.
CREATE TABLE ops_admission_v2.revoked_creation_capture_epochs(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 capture_epoch uuid NOT NULL,
 witness_tx_hash bytea NOT NULL CHECK(octet_length(witness_tx_hash)=32),
 witness_seed_digest bytea NOT NULL CHECK(octet_length(witness_seed_digest)=32),
 reason text NOT NULL CHECK(reason IN('freshness-unproven','source-binding-compromise','restore-coverage-gap')),
 revoked_at timestamptz NOT NULL CHECK(isfinite(revoked_at)AND revoked_at>='1970-01-01 UTC'::timestamptz AND revoked_at<'10000-01-01 UTC'::timestamptz),
 PRIMARY KEY(network_key,capture_epoch),
 FOREIGN KEY(network_key,capture_epoch,witness_tx_hash,witness_seed_digest)REFERENCES ops_admission_v2.creation_capture_coverage(network_key,capture_epoch,tx_hash,seed_digest)ON DELETE RESTRICT
);

ALTER TABLE ops_admission_v2.creation_work
 ADD COLUMN processed_generation bigint NOT NULL DEFAULT 0 CHECK(processed_generation>=0 AND processed_generation<=generation),
 ADD COLUMN next_attempt_at timestamptz,
 ADD COLUMN retry_count integer NOT NULL DEFAULT 0 CHECK(retry_count>=0),
 ADD COLUMN outcome text NOT NULL DEFAULT 'pending' CHECK(outcome IN('pending','not-included','covered','uncovered','unsupported','conflict')),
 ADD COLUMN inclusion_hash bytea CHECK(octet_length(inclusion_hash)=32),
 ADD COLUMN inclusion_number bigint CHECK(inclusion_number>=0),
 ADD COLUMN last_reorg_epoch bigint NOT NULL DEFAULT 0 CHECK(last_reorg_epoch>=0),
 ADD CONSTRAINT work_inclusion_pair CHECK((inclusion_hash IS NULL)=(inclusion_number IS NULL)),
 ADD CONSTRAINT work_finite_attempt CHECK(next_attempt_at IS NULL OR(isfinite(next_attempt_at)AND next_attempt_at>='1970-01-01 UTC'::timestamptz AND next_attempt_at<'10000-01-01 UTC'::timestamptz));
CREATE INDEX creation_work_changed_generation ON ops_admission_v2.creation_work(network_key,tx_hash)WHERE processed_generation<generation;
CREATE INDEX creation_work_due ON ops_admission_v2.creation_work(network_key,next_attempt_at,tx_hash);
CREATE INDEX creation_work_reorg ON ops_admission_v2.creation_work(network_key,last_reorg_epoch,tx_hash);

CREATE TABLE ops_admission_v2.creation_births(
 network_key bytea NOT NULL REFERENCES ops_admission_v2.creation_observer_state(network_key)ON DELETE RESTRICT,
 address bytea NOT NULL CHECK(octet_length(address)=20),
 inclusion_hash bytea NOT NULL CHECK(octet_length(inclusion_hash)=32),
 inclusion_number bigint NOT NULL CHECK(inclusion_number>=0),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 tx_index integer NOT NULL CHECK(tx_index>=0),
 actual_creation_record integer NOT NULL CHECK(actual_creation_record BETWEEN 0 AND 4095),
 creator bytea NOT NULL CHECK(octet_length(creator)=20),
 kind text NOT NULL CHECK(kind IN('CREATE','CREATE2')),
 tuple_digest bytea NOT NULL CHECK(octet_length(tuple_digest)=32),
 creation_parent integer CHECK(creation_parent>=0 AND creation_parent<actual_creation_record),
 output_hash bytea NOT NULL CHECK(octet_length(output_hash)=32),
 output_length integer NOT NULL CHECK(output_length BETWEEN 1 AND 1048576),
 evidence_profile text NOT NULL CHECK(evidence_profile='reth-prague-included-creations/v1'),
 proof_digest bytea NOT NULL CHECK(octet_length(proof_digest)=32),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)AND observed_at>='1970-01-01 UTC'::timestamptz AND observed_at<'10000-01-01 UTC'::timestamptz),
 PRIMARY KEY(network_key,address,inclusion_hash),
 UNIQUE(network_key,tx_hash,inclusion_hash,actual_creation_record)
);
CREATE INDEX creation_births_inclusion ON ops_admission_v2.creation_births(network_key,inclusion_number,inclusion_hash);
CREATE INDEX creation_births_transaction ON ops_admission_v2.creation_births(network_key,tx_hash);

CREATE TABLE ops_admission_v2.creation_authority_associations(
 network_key bytea NOT NULL CHECK(octet_length(network_key)=32),
 tx_hash bytea NOT NULL CHECK(octet_length(tx_hash)=32),
 inclusion_hash bytea NOT NULL CHECK(octet_length(inclusion_hash)=32),
 actual_creation_record integer NOT NULL CHECK(actual_creation_record BETWEEN 0 AND 4095),
 seed_digest bytea NOT NULL CHECK(octet_length(seed_digest)=32),
 planned_entry smallint NOT NULL CHECK(planned_entry BETWEEN 0 AND 127),
 namespace uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('WALLET','FACTORY')),
 wallet_actor text CHECK(wallet_actor~'^ops:p1:[A-Za-z0-9_-]{43}$'),
 factory_root smallint CHECK(factory_root BETWEEN 0 AND 127),
 qualification_digest bytea NOT NULL CHECK(octet_length(qualification_digest)=32),
 PRIMARY KEY(network_key,tx_hash,inclusion_hash,actual_creation_record,seed_digest,planned_entry),
 FOREIGN KEY(network_key,tx_hash,inclusion_hash,actual_creation_record)REFERENCES ops_admission_v2.creation_births(network_key,tx_hash,inclusion_hash,actual_creation_record)ON DELETE RESTRICT,
 FOREIGN KEY(network_key,tx_hash,seed_digest)REFERENCES ops_admission_v2.creation_capture_coverage(network_key,tx_hash,seed_digest)ON DELETE RESTRICT,
 CHECK((kind='WALLET'AND wallet_actor IS NOT NULL AND factory_root IS NULL)OR(kind='FACTORY'AND wallet_actor IS NULL AND factory_root IS NOT NULL))
);
CREATE INDEX creation_associations_namespace ON ops_admission_v2.creation_authority_associations(network_key,namespace,tx_hash,inclusion_hash,actual_creation_record);
