-- Forward repair: qualify every occurrence column that can collide with a
-- RETURNS TABLE output variable.  Signature, security boundary and behavior
-- remain identical to migration 0102.
CREATE OR REPLACE FUNCTION epm.forecast_occurrence_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
  status text,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 5 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'FORECAST_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('epm.forecast.occurrence.dispatch',0));
  IF (SELECT count(*) FROM epm.planning_forecast_occurrence global_active
       WHERE global_active.status IN ('running','cancel_requested')
         AND global_active.lease_until>clock_timestamp())>=p_global_limit
  THEN RETURN; END IF;
  SELECT o.* INTO candidate FROM epm.planning_forecast_occurrence o
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state ast USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
   WHERE (o.status='ready' OR
          (o.status IN ('running','cancel_requested') AND o.lease_until<=clock_timestamp()))
     AND a.status='Active' AND w.status='Active' AND ast.processing_mode='Active'
     AND (SELECT count(*) FROM epm.planning_forecast_occurrence active
           WHERE active.workspace_id=o.workspace_id
             AND active.status IN ('running','cancel_requested')
             AND active.lease_until>clock_timestamp())<p_workspace_limit
     AND (SELECT count(*) FROM epm.planning_forecast_occurrence active
           WHERE active.workspace_id=o.workspace_id
             AND active.application_id=o.application_id
             AND active.status IN ('running','cancel_requested')
             AND active.lease_until>clock_timestamp())<p_application_limit
   ORDER BY d.last_claim_sequence NULLS FIRST,
     (o.status='cancel_requested') DESC,o.due_at,o.created_at,o.occurrence_id
   FOR UPDATE OF o SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE epm.planning_forecast_occurrence o SET
    status=CASE WHEN o.status='ready' THEN 'running' ELSE o.status END,
    claim_generation=o.claim_generation+1,claimant=p_claimant,
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
   WHERE o.workspace_id=candidate.workspace_id
     AND o.application_id=candidate.application_id
     AND o.occurrence_id=candidate.occurrence_id;
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.occurrence_id,
    CASE WHEN candidate.status='ready' THEN 'running' ELSE candidate.status END,
    candidate.claim_generation+1;
END $$;

REVOKE ALL ON FUNCTION
  epm.forecast_occurrence_worker_claim(text,integer,integer,integer,integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.forecast_occurrence_worker_claim(text,integer,integer,integer,integer)
  TO epm_worker;
