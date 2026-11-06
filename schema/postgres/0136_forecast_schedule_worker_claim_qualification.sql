-- Forward repair for RETURNS TABLE variable collisions in the schedule claim.
-- Behavior, ordering, locking, delegation and privilege boundaries are the
-- migration-0102 contract; only joins are made explicit.
CREATE OR REPLACE FUNCTION epm.forecast_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
  dispatch_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
    RAISE EXCEPTION 'FORECAST_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  SELECT s.* INTO candidate
    FROM epm.planning_forecast_schedule_state s
    JOIN epm.planning_forecast_schedule_version v ON
      (v.workspace_id,v.application_id,v.schedule_id,v.version)=
      (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
    JOIN epm.application a ON a.workspace_id=s.workspace_id
      AND a.application_id=s.application_id
    JOIN epm.application_state ast ON ast.workspace_id=s.workspace_id
      AND ast.application_id=s.application_id
    JOIN epm.workspace w ON w.workspace_id=s.workspace_id
    LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
   WHERE s.active_version IS NOT NULL
     AND (s.dispatch_lease_until IS NULL OR s.dispatch_lease_until<=clock_timestamp())
     AND v.first_due_at<=clock_timestamp()
     AND (s.last_due_at IS NULL OR
          s.last_due_at+make_interval(secs=>v.interval_seconds)<=clock_timestamp())
     AND a.status='Active' AND w.status='Active' AND ast.processing_mode='Active'
     AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
          v.delegation_id,v.delegation_version,v.execution_issuer,
          v.execution_subject,'facts.planning.forecast.occurrence.request',
          s.schedule_id,s.active_version)
   ORDER BY d.last_claim_sequence NULLS FIRST,
     COALESCE(s.last_due_at,v.first_due_at),s.workspace_id,s.application_id,s.schedule_id
   FOR UPDATE OF s SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE epm.planning_forecast_schedule_state s SET
    dispatch_generation=s.dispatch_generation+1,dispatch_claimant=p_claimant,
    dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
   WHERE s.workspace_id=candidate.workspace_id
     AND s.application_id=candidate.application_id
     AND s.schedule_id=candidate.schedule_id;
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.schedule_id,candidate.dispatch_generation+1;
END $$;

REVOKE ALL ON FUNCTION epm.forecast_schedule_worker_claim(text,integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_schedule_worker_claim(text,integer)
  TO epm_worker;
