-- Worker-only fair global dispatch for rolling-forecast schedules and
-- occurrences.  SECURITY DEFINER exposes only bounded queue control data;
-- epm_worker receives no global SELECT on business or forecast tables.

ALTER TABLE epm.planning_forecast_schedule_state
  ADD COLUMN dispatch_generation bigint NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
  ADD COLUMN dispatch_claimant text CHECK(dispatch_claimant IS NULL OR length(dispatch_claimant) BETWEEN 1 AND 200),
  ADD COLUMN dispatch_lease_until timestamptz,
  ADD CONSTRAINT forecast_schedule_dispatch_lease_check CHECK(
    (dispatch_claimant IS NULL)=(dispatch_lease_until IS NULL));

CREATE INDEX planning_forecast_schedule_due_dispatch
  ON epm.planning_forecast_schedule_state(active_version,dispatch_lease_until,
    workspace_id,application_id,schedule_id) WHERE active_version IS NOT NULL;

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
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state ast USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
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

CREATE OR REPLACE FUNCTION epm.forecast_occurrence_worker_settle_failed(
  p_workspace text,p_application text,p_occurrence text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.planning_forecast_occurrence SET status='failed',
    error_code='FORECAST_EXECUTION_AUTHORIZATION_REVOKED',claimant=NULL,
    lease_until=NULL,updated_at=transaction_timestamp()
   WHERE workspace_id=p_workspace AND application_id=p_application
     AND occurrence_id=p_occurrence AND status IN ('running','cancel_requested')
     AND claim_generation=p_generation AND claimant=p_claimant
     AND lease_until>=clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

CREATE OR REPLACE FUNCTION epm.forecast_schedule_worker_release(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.planning_forecast_schedule_state SET dispatch_claimant=NULL,
    dispatch_lease_until=NULL,updated_at=transaction_timestamp()
   WHERE workspace_id=p_workspace AND application_id=p_application
     AND schedule_id=p_schedule AND dispatch_generation=p_generation
     AND dispatch_claimant=p_claimant;
  GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

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
  IF (SELECT count(*) FROM epm.planning_forecast_occurrence
       WHERE status IN ('running','cancel_requested')
         AND lease_until>clock_timestamp())>=p_global_limit THEN RETURN; END IF;
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

REVOKE ALL ON FUNCTION epm.forecast_schedule_worker_claim(text,integer),
  epm.forecast_schedule_worker_release(text,text,text,bigint,text),
  epm.forecast_occurrence_worker_claim(text,integer,integer,integer,integer),
  epm.forecast_occurrence_worker_settle_failed(text,text,text,bigint,text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_schedule_worker_claim(text,integer),
  epm.forecast_schedule_worker_release(text,text,text,bigint,text),
  epm.forecast_occurrence_worker_claim(text,integer,integer,integer,integer),
  epm.forecast_occurrence_worker_settle_failed(text,text,text,bigint,text)
  TO epm_worker;
