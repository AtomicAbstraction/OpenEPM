BEGIN;
-- Technical builds inspect immutable source without permission to publish it.
-- Live run and each business publisher retain their separate Active checks.
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=286) THEN
    RAISE EXCEPTION 'MIGRATION_0287_REQUIRES_0286';
  END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.python_build_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0; step integer:=0;
BEGIN
  UPDATE epm.python_program_build b SET status='failed',
    error_code='PYTHON_BUILD_PROGRAM_UNAVAILABLE',
    updated_at=transaction_timestamp()
  WHERE b.status IN ('accepted','ready') AND NOT EXISTS (
    SELECT 1 FROM epm.python_program_version v
    JOIN epm.python_environment_current e ON
      e.workspace_id=v.workspace_id AND e.application_id=v.application_id
      AND e.environment_id=v.environment_id AND e.version=v.environment_version
      AND e.status='Active'
    JOIN epm.application a ON a.workspace_id=b.workspace_id
      AND a.application_id=b.application_id
    JOIN epm.application_state s ON s.workspace_id=b.workspace_id
      AND s.application_id=b.application_id
    JOIN epm.workspace w ON w.workspace_id=b.workspace_id
    WHERE v.workspace_id=b.workspace_id AND v.application_id=b.application_id
      AND v.program_id=b.program_id AND v.version=b.program_version
      AND a.status='Active' AND w.status='Active' 
      AND s.processing_mode='Active');
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;

  UPDATE epm.python_program_build b SET
    status=CASE WHEN b.status='cancel_requested' THEN 'cancelled'
                WHEN b.attempts<3 THEN 'ready' ELSE 'failed' END,
    error_code=CASE WHEN b.status='cancel_requested' THEN NULL
                    WHEN b.attempts>=3 THEN 'PYTHON_BUILD_ATTEMPTS_EXHAUSTED'
                    ELSE NULL END,
    claim_generation=b.claim_generation+1,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE b.status IN ('running','cancel_requested')
    AND b.lease_until<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;
  RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.python_build_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,build_id text,issuer text,
  subject_id text,request_digest text,program_id text,program_version integer,
  parameter_values jsonb,environment_id text,environment_version integer,
  status text,claim_generation bigint,attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 65 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'PYTHON_BUILD_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.build.dispatch',0));
  IF (SELECT count(*) FROM epm.python_program_build b
      WHERE b.status IN ('running','cancel_requested'))>=p_global_limit THEN
    RETURN;
  END IF;
  SELECT b.*,v.environment_id,v.environment_version INTO candidate
    FROM epm.python_program_build b
    JOIN epm.python_program_version v ON
      v.workspace_id=b.workspace_id AND v.application_id=b.application_id
      AND v.program_id=b.program_id AND v.version=b.program_version
    JOIN epm.python_environment_current e ON
      e.workspace_id=v.workspace_id AND e.application_id=v.application_id
      AND e.environment_id=v.environment_id AND e.version=v.environment_version
      AND e.status='Active'
    JOIN epm.application a ON a.workspace_id=b.workspace_id
      AND a.application_id=b.application_id
    JOIN epm.application_state s ON s.workspace_id=b.workspace_id
      AND s.application_id=b.application_id
    JOIN epm.workspace w ON w.workspace_id=b.workspace_id
    LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=b.workspace_id
    WHERE b.status IN ('accepted','ready') AND b.attempts<3
      AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
      AND (SELECT count(*) FROM epm.python_program_build active
           WHERE active.workspace_id=b.workspace_id
             AND active.status IN ('running','cancel_requested'))<p_workspace_limit
      AND (SELECT count(*) FROM epm.python_program_build active
           WHERE active.workspace_id=b.workspace_id
             AND active.application_id=b.application_id
             AND active.status IN ('running','cancel_requested'))<p_application_limit
    ORDER BY d.last_claim_sequence NULLS FIRST,b.created_at,b.build_id
    FOR UPDATE OF b SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE epm.python_program_build b SET status='running',
    claim_generation=b.claim_generation+1,claimant=p_claimant,
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    attempts=b.attempts+1,updated_at=transaction_timestamp()
  WHERE b.workspace_id=candidate.workspace_id
    AND b.application_id=candidate.application_id
    AND b.build_id=candidate.build_id;
  candidate.status:='running';
  candidate.claim_generation:=candidate.claim_generation+1;
  candidate.attempts:=candidate.attempts+1;
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.build_id,candidate.issuer,candidate.subject_id,
    candidate.request_digest,candidate.program_id,candidate.program_version,
    candidate.parameter_values,candidate.environment_id,
    candidate.environment_version,candidate.status,
    candidate.claim_generation,candidate.attempts;
END $$;

REVOKE ALL ON FUNCTION epm.python_build_worker_recover(),
  epm.python_build_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_build_worker_recover(),
  epm.python_build_worker_claim(text,integer,integer,integer,integer) TO epm_worker;
COMMIT;
