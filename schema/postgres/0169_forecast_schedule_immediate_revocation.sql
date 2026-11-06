-- Make revoked scheduled authority visible on the next worker poll, not only
-- once another business occurrence becomes due.  The due checkpoint is
-- retained so an explicitly authorized resume can apply its catch-up policy.
CREATE OR REPLACE FUNCTION epm.forecast_schedule_worker_block_revoked()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 SELECT s.*,v.delegation_id,v.delegation_version,v.execution_issuer,
   v.execution_subject
 INTO candidate FROM epm.planning_forecast_schedule_state s
 JOIN epm.planning_forecast_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 WHERE s.active_version IS NOT NULL AND s.dispatch_status='Active'
  AND NOT epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   v.delegation_id,v.delegation_version,v.execution_issuer,v.execution_subject,
   'facts.planning.forecast.occurrence.request',s.schedule_id,s.active_version)
 ORDER BY s.workspace_id,s.application_id,s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE epm.planning_forecast_schedule_state SET dispatch_status='Blocked',
  blocked_code='FORECAST_EXECUTION_DELEGATION_REVOKED',
  blocked_at=clock_timestamp(),dispatch_claimant=NULL,
  dispatch_lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=candidate.workspace_id
  AND application_id=candidate.application_id
  AND schedule_id=candidate.schedule_id;
 INSERT INTO epm.planning_forecast_schedule_event(
  workspace_id,application_id,schedule_id,event_type,schedule_version,
  prior_last_due_at,reason_code)
 VALUES(candidate.workspace_id,candidate.application_id,candidate.schedule_id,
  'Blocked',candidate.active_version,candidate.last_due_at,
  'FORECAST_EXECUTION_DELEGATION_REVOKED');
 RETURN true;
END $$;

REVOKE ALL ON FUNCTION epm.forecast_schedule_worker_block_revoked() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_schedule_worker_block_revoked()
 TO epm_worker;
