-- Preserve the exact execution/cancellation intent when generic schedule
-- occurrence recovery reaches its retry ceiling.  Reconciliation remains a
-- fixed-core operation; the database records evidence but does not infer a
-- child outcome or execute work.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=223) THEN
  RAISE EXCEPTION 'MIGRATION_0224_PREDECESSOR_0223_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.application_schedule_occurrence
 ADD COLUMN inspection_origin_status text CHECK(
  inspection_origin_status IS NULL OR inspection_origin_status IN(
   'running','submitted','cancel_requested'));

CREATE OR REPLACE FUNCTION epm.application_schedule_dispatch_recover()
RETURNS TABLE(schedule_claims integer,occurrence_claims integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE schedules integer;DECLARE occurrences integer;
BEGIN
 UPDATE epm.application_schedule_state SET
  dispatch_generation=dispatch_generation+1,dispatch_claimant=NULL,
  dispatch_lease_until=NULL,updated_at=transaction_timestamp()
 WHERE dispatch_claimant IS NOT NULL
  AND dispatch_lease_until<=clock_timestamp();
 GET DIAGNOSTICS schedules=ROW_COUNT;

 UPDATE epm.application_schedule_occurrence o SET
  attempt_count=o.attempt_count+1,
  inspection_origin_status=CASE WHEN o.attempt_count+1 >=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN o.status ELSE o.inspection_origin_status END,
  status=CASE WHEN o.attempt_count+1 >=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN 'needs_inspection' ELSE o.status END,
  next_attempt_at=CASE WHEN o.attempt_count+1 >=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN NULL ELSE clock_timestamp()+make_interval(secs=>
    ((v.definition#>>'{retryPolicy,backoffSeconds}')::integer)) END,
  claim_generation=o.claim_generation+1,claimant=NULL,lease_until=NULL,
  error_code='APPLICATION_SCHEDULE_LEASE_EXPIRED',
  updated_at=transaction_timestamp()
 FROM epm.application_schedule_version v
 WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
  AND o.claimant IS NOT NULL AND o.lease_until<=clock_timestamp()
  AND o.status IN('running','submitted','cancel_requested');
 GET DIAGNOSTICS occurrences=ROW_COUNT;
 RETURN QUERY SELECT schedules,occurrences;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_dispatch_recover()
 FROM PUBLIC,epm_runtime,epm_analyst,epm_security,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.application_schedule_dispatch_recover()
 TO epm_worker;
GRANT UPDATE(inspection_origin_status)
 ON epm.application_schedule_occurrence TO epm_runtime;
