-- Private B1 exact005 specification. Explicit owner offline migration only.
-- Existing audit001..004 bytes unchanged; source read is SEALED-only, no markers.
CREATE SCHEMA ops_activity_v1;
REVOKE ALL ON SCHEMA ops_activity_v1 FROM PUBLIC;
CREATE TABLE ops_activity_v1.sources (
 network_key bytea PRIMARY KEY CHECK(octet_length(network_key)=32),
 source_id uuid NOT NULL UNIQUE,
 chain_name text NOT NULL UNIQUE,
 chain_lock_key bigint NOT NULL,
 generation uuid NOT NULL,
 configuration bytea NOT NULL CHECK(octet_length(configuration)=32),
 ready boolean NOT NULL DEFAULT false,
 retained_from_us bigint NOT NULL CHECK(retained_from_us BETWEEN 0 AND 253402300799999999),
 head_id bigint NOT NULL DEFAULT 0 CHECK(head_id>=0),
 head_hash text NOT NULL DEFAULT '',
 row_count bigint NOT NULL DEFAULT 0 CHECK(row_count>=0),
 byte_count bigint NOT NULL DEFAULT 0 CHECK(byte_count>=0),
 max_rows bigint NOT NULL CHECK(max_rows BETWEEN 1 AND 1000000000),
 max_bytes bigint NOT NULL CHECK(max_bytes BETWEEN 1 AND 1099511627776),
 max_runs integer NOT NULL CHECK(max_runs BETWEEN 1 AND 1000000),
 writer_role name NOT NULL,
 reader_role name NOT NULL,
 retention_role name NOT NULL,
 prune_through_id bigint CHECK(prune_through_id>0),
 CHECK(chain_name='ops-activity-v1/'||encode(network_key,'hex')),
 CHECK((head_id=0 AND head_hash='') OR (head_id>0 AND head_hash~'^[0-9a-f]{64}$')),
 CHECK(row_count<=max_rows AND byte_count<=max_bytes),
 UNIQUE(network_key,chain_name)
);
CREATE TABLE ops_activity_v1.runs (
 run_id uuid PRIMARY KEY,
 network_key bytea NOT NULL,
 producer_id uuid NOT NULL,
 chain_name text NOT NULL,
 generation uuid NOT NULL,
 configuration bytea NOT NULL CHECK(octet_length(configuration)=32),
 range_index bigint NOT NULL UNIQUE CHECK(range_index BETWEEN 1 AND 8388607),
 registered_at timestamptz NOT NULL,
 FOREIGN KEY(network_key,chain_name) REFERENCES ops_activity_v1.sources(network_key,chain_name),
 UNIQUE(run_id,producer_id,chain_name)
);
ALTER TABLE public.access_logs
 ADD COLUMN activity_run_id uuid,
 ADD COLUMN activity_producer_id uuid,
 ADD COLUMN activity_kind smallint,
 ADD COLUMN activity_ordinal bigint,
 ADD COLUMN activity_observed_us bigint,
 ADD COLUMN activity_record_id uuid,
 ADD COLUMN activity_outcome text,
 ADD CONSTRAINT activity_run_fk FOREIGN KEY(activity_run_id,activity_producer_id,chain_name)
 REFERENCES ops_activity_v1.runs(run_id,producer_id,chain_name),
 ADD CONSTRAINT activity_variant CHECK(CASE WHEN activity_kind IS NULL THEN
    activity_run_id IS NULL AND activity_producer_id IS NULL AND activity_ordinal IS NULL AND
    activity_observed_us IS NULL AND activity_record_id IS NULL AND activity_outcome IS NULL
    AND chain_name !~ '^ops-activity-v1/'
 ELSE activity_run_id IS NOT NULL AND activity_producer_id IS NOT NULL AND activity_kind=1 AND
    activity_ordinal IS NOT NULL AND activity_ordinal>0 AND activity_observed_us IS NOT NULL AND
    activity_observed_us BETWEEN 0 AND 253402300799999999 AND activity_record_id IS NOT NULL AND
    activity_outcome IS NOT NULL AND chain_name~'^ops-activity-v1/[0-9a-f]{64}$' AND
    hash_format_version=2 AND buffer_seq IS NOT NULL AND buffer_seq>0 AND entry_hash IS NOT NULL AND entry_hash~'^[0-9a-f]{64}$' AND
    request_params IS NOT NULL AND octet_length(request_params) BETWEEN 1 AND 2048 AND
    created_at IS NOT NULL AND response_status IS NOT NULL AND ip_address IS NOT NULL AND
    correlation_id=activity_record_id::text AND denial_reason IS NULL
 END);
CREATE UNIQUE INDEX activity_completion_ordinal ON public.access_logs(chain_name,activity_run_id,activity_ordinal) WHERE activity_kind=1;
CREATE UNIQUE INDEX activity_record_uuid ON public.access_logs(chain_name,activity_record_id) WHERE activity_kind=1;
CREATE INDEX activity_page ON public.access_logs(chain_name,org_id,external_id,activity_observed_us,activity_producer_id,activity_run_id,activity_ordinal,activity_record_id) WHERE activity_kind=1;
CREATE UNIQUE INDEX activity_head_ref ON public.access_logs(chain_name,entry_hash) WHERE activity_kind=1;
CREATE FUNCTION ops_activity_v1.guard_log() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record; s record; e jsonb; expected jsonb;
BEGIN
 IF NEW.activity_kind IS NULL AND NEW.chain_name !~ '^ops-activity-v1/' THEN RETURN NEW; END IF;
 SELECT * INTO STRICT r FROM ops_activity_v1.runs WHERE run_id=NEW.activity_run_id;
 SELECT * INTO STRICT s FROM ops_activity_v1.sources WHERE network_key=r.network_key;
 IF current_user<>s.writer_role AND current_user<>pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='ops_activity_v1')) THEN
  RAISE EXCEPTION 'activity writer role mismatch';
 END IF;
 IF NEW.activity_producer_id<>r.producer_id OR NEW.chain_name<>r.chain_name OR
    NEW.buffer_seq<=r.range_index*1099511627776 OR NEW.buffer_seq>r.range_index*1099511627776+1099511627775 THEN
  RAISE EXCEPTION 'activity range mismatch';
 END IF;
 IF NOT s.ready AND current_user<>pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='ops_activity_v1')) THEN RAISE EXCEPTION 'activity source is unready'; END IF;
 e:=NEW.request_params::jsonb;
 IF jsonb_typeof(e)<>'object' OR jsonb_typeof(e->'z')<>'string' OR
    (e->>'z'<>'' AND e->>'z'!~'^[0-9a-f]{64}$') OR
    NOT(e->'e'='null'::jsonb OR (jsonb_typeof(e->'e')='number' AND (e->>'e')::bigint BETWEEN -2147483648 AND 2147483647)) THEN
  RAISE EXCEPTION 'activity closed metadata mismatch';
 END IF;
  IF NEW.activity_ordinal<1 OR NEW.method!~'^[A-Za-z][A-Za-z0-9_.]{0,99}$' OR
     length(NEW.external_id)>255 OR NEW.external_id LIKE '%|%' OR NEW.ip_address LIKE '%|%' OR
     NEW.response_status NOT BETWEEN 100 AND 599 OR
     NEW.activity_outcome NOT IN('success','invalid','unauthenticated','denied','evaluation-failed','unavailable','unconfirmed') OR
     NEW.status_code<>(CASE NEW.activity_outcome WHEN 'success' THEN 200 WHEN 'invalid' THEN 400
      WHEN 'unauthenticated' THEN 401 WHEN 'denied' THEN 403 WHEN 'evaluation-failed' THEN 422
      WHEN 'unavailable' THEN 503 WHEN 'unconfirmed' THEN 502 END) OR
     (NEW.activity_outcome='success' AND (e->'e'<>'null'::jsonb OR NEW.response_status NOT BETWEEN 200 AND 299)) OR
     (COALESCE(NEW.org_id,'')<>'' AND (NEW.external_id='' OR e->>'z'='')) THEN
   RAISE EXCEPTION 'activity completion mismatch';
  END IF;
 expected:=jsonb_build_object('v',1,'k',NEW.activity_kind,'n',encode(r.network_key,'hex'),
  'g',r.generation::text,'x',encode(r.configuration,'hex'),'p',r.producer_id::text,
  'r',r.run_id::text,'q',NEW.activity_record_id::text,'o',NEW.activity_ordinal::text,
  't',NEW.activity_observed_us,'a',NEW.external_id,'d',COALESCE(NEW.org_id,''),'z',e->>'z',
  'm',NEW.method,'i',NEW.ip_address,'h',NEW.response_status,'e',e->'e','u',NEW.activity_outcome,
  's',NEW.status_code,'b',NEW.buffer_seq::text);
 IF e IS DISTINCT FROM expected OR extract(epoch FROM NEW.created_at)::numeric*1000000<>NEW.activity_observed_us::numeric THEN
  RAISE EXCEPTION 'activity envelope/index mismatch';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ops_activity_v1.guard_log() FROM PUBLIC;
CREATE TRIGGER activity_guard BEFORE INSERT ON public.access_logs
 FOR EACH ROW EXECUTE FUNCTION ops_activity_v1.guard_log();

-- Reader never receives SELECT(request_params) over legacy rows. The exact
-- owner-backed security-barrier projection is a DB privilege boundary, not policy.
CREATE VIEW ops_activity_v1.qualified_logs WITH(security_barrier=true) AS
 SELECT l.id,l.external_id,l.method,l.status_code,l.ip_address,l.created_at,
 l.correlation_id,l.request_params,l.entry_hash,l.response_status,l.hash_format_version,
 l.buffer_seq,l.chain_name,l.org_id,l.activity_run_id,l.activity_producer_id,l.activity_kind,
 l.activity_ordinal,l.activity_observed_us,l.activity_record_id,l.activity_outcome
 FROM public.access_logs l JOIN ops_activity_v1.runs r ON
 (l.activity_run_id,l.activity_producer_id,l.chain_name)=(r.run_id,r.producer_id,r.chain_name)
 WHERE l.activity_kind IS NOT NULL AND
 l.buffer_seq>r.range_index*1099511627776 AND l.buffer_seq<=r.range_index*1099511627776+1099511627775;
REVOKE ALL ON ALL TABLES IN SCHEMA ops_activity_v1 FROM PUBLIC;


-- Dedicated retention gets DELETE only on this single-table projection, never
-- the raw base table. It cannot address legacy rows. UPDATE of sealed rows is
-- forbidden. Anchor projection is scoped to the reserved chain prefix.
CREATE VIEW ops_activity_v1.prunable_logs AS
 SELECT id,chain_name,activity_observed_us,octet_length(request_params) AS encoded_bytes,entry_hash
 FROM public.access_logs WHERE activity_kind=1 AND chain_name~'^ops-activity-v1/[0-9a-f]{64}$';
CREATE VIEW ops_activity_v1.anchors AS SELECT chain_name,last_pruned_id,last_pruned_entry_hash,last_pruned_at
 FROM public.audit_chain_anchor WHERE chain_name~'^ops-activity-v1/[0-9a-f]{64}$' WITH LOCAL CHECK OPTION;
CREATE FUNCTION ops_activity_v1.guard_delete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s record;
BEGIN
 IF OLD.chain_name !~ '^ops-activity-v1/' THEN RETURN OLD; END IF;
 SELECT * INTO STRICT s FROM ops_activity_v1.sources WHERE chain_name=OLD.chain_name;
 IF (current_user<>s.retention_role AND current_user<>pg_get_userbyid((SELECT nspowner FROM pg_namespace WHERE nspname='ops_activity_v1'))) OR
    s.prune_through_id IS NULL OR OLD.id>s.prune_through_id OR s.retained_from_us<=OLD.activity_observed_us OR
    NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND mode='ExclusiveLock' AND objsubid=1 AND
      classid::bigint=((s.chain_lock_key>>32)&4294967295) AND objid::bigint=(s.chain_lock_key&4294967295)) THEN
  RAISE EXCEPTION 'activity deletion requires scoped prefix intent/floor/chain lock';
 END IF;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION ops_activity_v1.guard_delete() FROM PUBLIC;
CREATE TRIGGER activity_delete_guard BEFORE DELETE ON public.access_logs FOR EACH ROW EXECUTE FUNCTION ops_activity_v1.guard_delete();
CREATE FUNCTION ops_activity_v1.guard_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.chain_name~'^ops-activity-v1/' OR NEW.chain_name~'^ops-activity-v1/' THEN RAISE EXCEPTION 'activity rows immutable'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION ops_activity_v1.guard_update() FROM PUBLIC;
CREATE TRIGGER activity_update_guard BEFORE UPDATE ON public.access_logs FOR EACH ROW EXECUTE FUNCTION ops_activity_v1.guard_update();
REVOKE ALL ON ALL TABLES IN SCHEMA ops_activity_v1 FROM PUBLIC;
