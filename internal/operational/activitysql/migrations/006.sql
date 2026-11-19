-- Additive admin investigation order; no envelope, history or grants change.
-- Apply only through the drained activity owner migration tooling.
CREATE INDEX activity_org_page ON public.access_logs
 (chain_name,org_id,activity_observed_us DESC,activity_producer_id DESC,
 activity_run_id DESC,activity_ordinal DESC,activity_record_id DESC)
 WHERE activity_kind=1;
