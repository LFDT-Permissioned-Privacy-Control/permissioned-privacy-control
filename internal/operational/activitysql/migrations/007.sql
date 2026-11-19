-- Explicit drained owner upgrade: exact closed v1/v2 completion guard.
-- No history, source/run identity, index, grant or hash-algorithm changes.
CREATE OR REPLACE FUNCTION ops_activity_v1.guard_log()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
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
 IF e->>'v'='2' THEN
  IF jsonb_typeof(e->'c') IS DISTINCT FROM 'string' OR length(e->>'c')>64 OR NOT (CASE
   WHEN e->>'c'='not_recorded' THEN true
   WHEN e->>'c'='invalid_request_shape' THEN NEW.activity_outcome='invalid'
   WHEN e->>'c' IN('auth_required','credentials_expired') THEN NEW.activity_outcome='unauthenticated'
   WHEN e->>'c' IN('method_not_allowed','sender_not_linked','access_denied','compliance_blocked','deploy_claim_required','trace_access_denied','policy_no_matching_rule','policy_argument_constraint','policy_malformed_calldata','policy_ownership','policy_value_constraint','policy_depth_constraint','policy_unsupported_create','policy_caller_constraint','policy_operational_claim') THEN NEW.activity_outcome='denied'
   WHEN e->>'c' IN('execution_unavailable','tracing_unavailable','request_cancelled') THEN NEW.activity_outcome='unavailable'
   WHEN e->>'c'='submission_outcome_unknown' THEN NEW.activity_outcome='unconfirmed'
   WHEN e->>'c' IN('policy_no_frames_observed','policy_invalid_context','policy_invalid_facts') THEN NEW.activity_outcome='evaluation-failed'
   ELSE false END) THEN
   RAISE EXCEPTION 'activity reason/outcome mismatch';
  END IF;
  expected:=jsonb_set(expected,'{v}','2'::jsonb)||jsonb_build_object('c',e->'c');
 ELSIF (e->>'v') IS DISTINCT FROM '1' THEN
  RAISE EXCEPTION 'activity wire version mismatch';
 END IF;
 IF e IS DISTINCT FROM expected OR extract(epoch FROM NEW.created_at)::numeric*1000000<>NEW.activity_observed_us::numeric THEN
  RAISE EXCEPTION 'activity envelope/index mismatch';
 END IF;
 RETURN NEW;
END $function$;
