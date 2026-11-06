-- Fair, generation-fenced background advancement of already sealed plans.
-- The worker receives the recorded verified principal and never Python source.

ALTER TABLE epm.python_program_workflow
  ADD COLUMN claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),
  ADD COLUMN claimant text CHECK(claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
  ADD COLUMN lease_until timestamptz,
  ADD CONSTRAINT python_workflow_claim_pair CHECK(
    (claimant IS NULL)=(lease_until IS NULL));

CREATE INDEX python_workflow_ready_queue ON epm.python_program_workflow
  (status,created_at,workspace_id,application_id)
  WHERE status IN ('accepted','running','cancel_requested');

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.python_program_workflow SET claim_generation=claim_generation+1,
    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp()
    AND status IN ('accepted','running','cancel_requested');
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,workflow_id text,
  build_id text,issuer text,subject_id text,status text,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 30 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'PYTHON_WORKFLOW_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.workflow.dispatch',0));
  IF (SELECT count(*) FROM epm.python_program_workflow
      WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global_limit THEN
    RETURN;
  END IF;
  SELECT w.* INTO candidate FROM epm.python_program_workflow w
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.workspace ws USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
    WHERE w.status IN ('accepted','running','cancel_requested')
      AND w.claimant IS NULL AND a.status='Active' AND ws.status='Active'
      AND s.processing_mode='Active'
      AND (SELECT count(*) FROM epm.python_program_workflow active
           WHERE active.workspace_id=w.workspace_id AND active.claimant IS NOT NULL
             AND active.lease_until>clock_timestamp())<p_workspace_limit
      AND (SELECT count(*) FROM epm.python_program_workflow active
           WHERE active.workspace_id=w.workspace_id
             AND active.application_id=w.application_id AND active.claimant IS NOT NULL
             AND active.lease_until>clock_timestamp())<p_application_limit
    ORDER BY d.last_claim_sequence NULLS FIRST,w.updated_at,w.workflow_id
    FOR UPDATE OF w SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE epm.python_program_workflow w SET claim_generation=w.claim_generation+1,
    claimant=p_claimant,lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
    WHERE w.workspace_id=candidate.workspace_id
      AND w.application_id=candidate.application_id
      AND w.workflow_id=candidate.workflow_id;
  candidate.claim_generation:=candidate.claim_generation+1;
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.workflow_id,candidate.build_id,candidate.issuer,candidate.subject_id,
    candidate.status,candidate.claim_generation;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_release(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.python_program_workflow SET claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_settle(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  IF p_error NOT IN ('PYTHON_WORKFLOW_AUTHORIZATION_REVOKED',
                     'PYTHON_WORKFLOW_STALE_CONTEXT') THEN
    RAISE EXCEPTION 'PYTHON_WORKFLOW_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
  END IF;
  UPDATE epm.python_program_workflow SET
    status=CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(
      COALESCE(result->'checkpoints','[]'::jsonb)) c WHERE (c->>'committed')::boolean)
      THEN 'partially_published' ELSE 'failed' END,
    result=jsonb_set(COALESCE(result,'{}'::jsonb),'{errorCode}',to_jsonb(p_error)),
    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN ('accepted','running','cancel_requested');
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

REVOKE ALL ON FUNCTION epm.python_workflow_worker_recover(),
  epm.python_workflow_worker_claim(text,integer,integer,integer,integer),
  epm.python_workflow_worker_release(text,text,text,bigint,text),
  epm.python_workflow_worker_settle(text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_workflow_worker_recover(),
  epm.python_workflow_worker_claim(text,integer,integer,integer,integer),
  epm.python_workflow_worker_release(text,text,text,bigint,text),
  epm.python_workflow_worker_settle(text,text,text,bigint,text,text) TO epm_worker;
