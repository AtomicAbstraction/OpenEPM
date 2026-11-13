BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=362) THEN
    RAISE EXCEPTION 'MIGRATION_0363_REQUIRES_0362';
  END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.python_build_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0;step integer:=0;BEGIN
 UPDATE epm.python_program_build b SET status='failed',error_code='PYTHON_BUILD_PROGRAM_UNAVAILABLE',
  updated_at=transaction_timestamp() WHERE b.status IN('accepted','ready') AND NOT EXISTS(
  SELECT 1 FROM epm.python_program_definition d JOIN epm.python_environment_definition e ON
   (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
   (d.workspace_id,d.application_id,d.environment_id,d.environment_state_token)
  JOIN epm.application a ON (a.workspace_id,a.application_id)=
   (d.workspace_id,d.application_id)
  JOIN epm.application_state s ON (s.workspace_id,s.application_id)=
   (d.workspace_id,d.application_id)
  JOIN epm.workspace w ON w.workspace_id=d.workspace_id
  WHERE (d.workspace_id,d.application_id,d.program_id,d.source_token)=
   (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
   AND e.status='Active' AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active');
 GET DIAGNOSTICS step=ROW_COUNT;changed:=changed+step;
 UPDATE epm.python_program_build b SET status=CASE WHEN b.status='cancel_requested' THEN 'cancelled'
  WHEN b.attempts<3 THEN 'ready' ELSE 'failed' END,error_code=CASE
  WHEN b.status='cancel_requested' THEN NULL WHEN b.attempts>=3 THEN
  'PYTHON_BUILD_ATTEMPTS_EXHAUSTED' END,claim_generation=b.claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE b.status IN('running','cancel_requested') AND b.lease_until<=clock_timestamp();
 GET DIAGNOSTICS step=ROW_COUNT;RETURN changed+step;END$$;

CREATE OR REPLACE FUNCTION epm.python_build_worker_claim(p_claimant text,p_lease_seconds integer,
 p_global_limit integer,p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,build_id text,issuer text,
 subject_id text,request_digest text,program_id text,program_source_token text,
 parameter_values jsonb,environment_id text,environment_state_token text,status text,
 claim_generation bigint,attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$DECLARE candidate record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 65 AND 300 OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'PYTHON_BUILD_WORKER_CLAIM_INVALID' USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.build.dispatch',0));
 IF(SELECT count(*) FROM epm.python_program_build capacity
    WHERE capacity.status IN('running','cancel_requested'))>=p_global_limit THEN RETURN;END IF;
 SELECT b.*,d.environment_id,d.environment_state_token INTO candidate
 FROM epm.python_program_build b JOIN epm.python_program_definition d ON
  (d.workspace_id,d.application_id,d.program_id,d.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 JOIN epm.python_environment_definition e ON
  (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
  (d.workspace_id,d.application_id,d.environment_id,d.environment_state_token)
 JOIN epm.application a ON (a.workspace_id,a.application_id)=
  (d.workspace_id,d.application_id)
 JOIN epm.application_state s ON (s.workspace_id,s.application_id)=
  (d.workspace_id,d.application_id)
 JOIN epm.workspace w ON w.workspace_id=d.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch dispatch ON dispatch.workspace_id=b.workspace_id
 WHERE b.status IN('accepted','ready') AND b.attempts<3 AND e.status='Active'
  AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
  AND(SELECT count(*) FROM epm.python_program_build x WHERE x.workspace_id=b.workspace_id
   AND x.status IN('running','cancel_requested'))<p_workspace_limit
  AND(SELECT count(*) FROM epm.python_program_build x WHERE x.workspace_id=b.workspace_id
   AND x.application_id=b.application_id AND x.status IN('running','cancel_requested'))<p_application_limit
 ORDER BY dispatch.last_claim_sequence NULLS FIRST,b.created_at,b.build_id
 FOR UPDATE OF b SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.python_program_build target SET status='running',claim_generation=target.claim_generation+1,
  claimant=p_claimant,lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  attempts=target.attempts+1,updated_at=transaction_timestamp()
 WHERE(target.workspace_id,target.application_id,target.build_id)=
  (candidate.workspace_id,candidate.application_id,candidate.build_id);
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=excluded.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,candidate.build_id,
  candidate.issuer,candidate.subject_id,candidate.request_digest,candidate.program_id,
  candidate.program_source_token,candidate.parameter_values,candidate.environment_id,
  candidate.environment_state_token,'running'::text,candidate.claim_generation+1,
  candidate.attempts+1;END$$;

REVOKE ALL ON FUNCTION epm.python_build_worker_recover(),
 epm.python_build_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_build_worker_recover(),
 epm.python_build_worker_claim(text,integer,integer,integer,integer) TO epm_worker;
COMMIT;
