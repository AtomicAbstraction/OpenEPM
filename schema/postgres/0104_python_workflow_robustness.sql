-- Renewable workflow leases and durable poison-work escalation.

ALTER TABLE epm.python_program_workflow
  ADD COLUMN worker_failures integer NOT NULL DEFAULT 0 CHECK(worker_failures>=0),
  ADD COLUMN worker_error_code text
    CHECK(worker_error_code IS NULL OR length(worker_error_code) BETWEEN 1 AND 200);

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_renew(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'PYTHON_WORKFLOW_WORKER_RENEW_INVALID' USING ERRCODE='22023';
  END IF;
  UPDATE epm.python_program_workflow SET
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN ('accepted','running','cancel_requested');
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_release(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.python_program_workflow SET claimant=NULL,lease_until=NULL,
    worker_failures=0,worker_error_code=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_unexpected(
  p_workspace text,p_application text,p_workflow text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
  IF p_error IS NULL OR length(p_error) NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'PYTHON_WORKFLOW_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
  END IF;
  UPDATE epm.python_program_workflow SET
    worker_failures=worker_failures+1,worker_error_code=p_error,
    status=CASE WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
    result=CASE WHEN worker_failures+1>=3 THEN jsonb_set(
      COALESCE(result,'{}'::jsonb),'{errorCode}',to_jsonb(p_error)) ELSE result END,
    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN ('accepted','running','cancel_requested')
  RETURNING CASE WHEN worker_failures>=3 THEN 'needs_inspection' ELSE 'retry' END
    INTO outcome;
  RETURN outcome;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.python_program_workflow SET
    worker_failures=worker_failures+1,
    worker_error_code='PYTHON_WORKFLOW_LEASE_EXPIRED',
    status=CASE WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
    result=CASE WHEN worker_failures+1>=3 THEN jsonb_set(
      COALESCE(result,'{}'::jsonb),'{errorCode}',
      to_jsonb('PYTHON_WORKFLOW_LEASE_EXPIRED'::text)) ELSE result END,
    claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp()
    AND status IN ('accepted','running','cancel_requested');
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed;
END $$;

REVOKE ALL ON FUNCTION
  epm.python_workflow_worker_renew(text,text,text,bigint,text,integer),
  epm.python_workflow_worker_unexpected(text,text,text,bigint,text,text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.python_workflow_worker_renew(text,text,text,bigint,text,integer),
  epm.python_workflow_worker_unexpected(text,text,text,bigint,text,text)
  TO epm_worker;
