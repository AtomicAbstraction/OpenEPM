BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=381) THEN
  RAISE EXCEPTION 'MIGRATION_0382_REQUIRES_0381';
 END IF;
END $migration$;

-- Cancellation is the durable execution intent. Worker faults can park it,
-- never infer final receipts or resume execution. Three unsuccessful quanta
-- exhaust the existing budget; only a current, explicit Cancel re-arms it.
-- Existing ambiguous needs_inspection/terminal records are not backfilled:
-- their prior intent cannot be inferred from a missing checkpoint.


CREATE OR REPLACE FUNCTION epm.python_workflow_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,workflow_id text,
  build_id text,issuer text,subject_id text,verified_groups text[],status text,
  claim_generation bigint)
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
      AND (w.status<>'cancel_requested' OR w.worker_failures<3)
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
    candidate.verified_groups,candidate.status,candidate.claim_generation;
END $$;

DROP FUNCTION epm.python_workflow_worker_settle(text,text,text,bigint,text,text);

CREATE FUNCTION epm.python_workflow_worker_settle(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('PYTHON_WORKFLOW_AUTHORIZATION_REVOKED','PYTHON_WORKFLOW_STALE_CONTEXT') THEN
  RAISE EXCEPTION 'PYTHON_WORKFLOW_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.python_program_workflow SET
  worker_failures=CASE WHEN status='cancel_requested' THEN worker_failures+1 ELSE worker_failures END,
  worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE p_error END,
  claim_generation=claim_generation+CASE WHEN status='cancel_requested' THEN 1 ELSE 0 END,
  status=CASE WHEN status='cancel_requested' THEN status
    WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(result->'checkpoints','[]'::jsonb)) c
      WHERE(c->>'committed')::boolean) THEN 'partially_published' ELSE 'failed' END,
  result=jsonb_set(coalesce(result,'{}'::jsonb),'{errorCode}',to_jsonb(p_error)),
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested')
 RETURNING status INTO outcome;
 RETURN outcome;
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
    worker_failures=worker_failures+1,worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE p_error END,
    status=CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
    result=CASE WHEN worker_failures+1>=3 THEN jsonb_set(
      COALESCE(result,'{}'::jsonb),'{errorCode}',to_jsonb(p_error)) ELSE result END,
    claim_generation=claim_generation+CASE WHEN status='cancel_requested' THEN 1 ELSE 0 END,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND workflow_id=p_workflow AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN ('accepted','running','cancel_requested')
  RETURNING CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures>=3 THEN 'needs_inspection' ELSE 'retry' END
    INTO outcome;
  RETURN outcome;
END $$;

CREATE OR REPLACE FUNCTION epm.python_workflow_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  UPDATE epm.python_program_workflow SET
    worker_failures=worker_failures+1,
    worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE 'PYTHON_WORKFLOW_LEASE_EXPIRED' END,
    status=CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
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

-- Runtime can only re-arm an idle parked cancellation in its existing scope.
-- The fixed current-authority/owner-or-admin control transaction holds the
-- exact parent row before calling this narrow helper; no worker columns are
-- granted for arbitrary runtime UPDATE, and active claims cannot be stolen.
CREATE FUNCTION epm.python_workflow_rearm_cancel(
 p_workspace text,p_application text,p_workflow text,p_generation bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.python_program_workflow SET
  worker_failures=0,worker_error_code=NULL,result=result-'errorCode',
  claim_generation=claim_generation+1,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true)
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND status='cancel_requested' AND worker_failures>=3
  AND claimant IS NULL AND lease_until IS NULL;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION epm.python_workflow_worker_settle(text,text,text,bigint,text,text),
 epm.python_workflow_rearm_cancel(text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_workflow_worker_settle(text,text,text,bigint,text,text) TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.python_workflow_rearm_cancel(text,text,text,bigint) TO epm_runtime;


CREATE OR REPLACE FUNCTION epm.application_rule_worker_claim(
 p_claimant text,p_lease_seconds integer,p_global_limit integer,
 p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,workflow_id text,
 rule_id text,issuer text,subject_id text,verified_groups text[],status text,
 claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
    OR p_lease_seconds NOT BETWEEN 30 AND 300
    OR p_global_limit NOT BETWEEN 1 AND 10000
    OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
    OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application.rule.dispatch',0));
 IF(SELECT count(*) FROM epm.application_rule_workflow
    WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global_limit
 THEN RETURN;END IF;
 SELECT w.* INTO candidate FROM epm.application_rule_workflow w
 JOIN epm.application a USING(workspace_id,application_id)
 JOIN epm.application_state s USING(workspace_id,application_id)
 JOIN epm.workspace ws USING(workspace_id)
 LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
 WHERE w.status IN('accepted','running','cancel_requested')
  AND (w.status<>'cancel_requested' OR w.worker_failures<3)
      AND w.claimant IS NULL AND a.status='Active' AND ws.status='Active'
  AND s.processing_mode='Active'
  AND(SELECT count(*) FROM epm.application_rule_workflow active
      WHERE active.workspace_id=w.workspace_id AND active.claimant IS NOT NULL
       AND active.lease_until>clock_timestamp())<p_workspace_limit
  AND(SELECT count(*) FROM epm.application_rule_workflow active
      WHERE active.workspace_id=w.workspace_id
       AND active.application_id=w.application_id AND active.claimant IS NOT NULL
       AND active.lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,w.updated_at,w.workflow_id
 FOR UPDATE OF w SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_rule_workflow w SET
  claim_generation=w.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE w.workspace_id=candidate.workspace_id
  AND w.application_id=candidate.application_id
  AND w.workflow_id=candidate.workflow_id;
 candidate.claim_generation:=candidate.claim_generation+1;
 INSERT INTO epm.worker_workspace_dispatch(
  workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.workflow_id,candidate.rule_id,candidate.issuer,candidate.subject_id,
  candidate.verified_groups,candidate.status,candidate.claim_generation;
END $$;

DROP FUNCTION epm.application_rule_worker_settle(text,text,text,bigint,text,text);

CREATE FUNCTION epm.application_rule_worker_settle(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('APPLICATION_RULE_AUTHORIZATION_REVOKED','APPLICATION_RULE_STALE_CONTEXT') THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_rule_workflow SET
  worker_failures=CASE WHEN status='cancel_requested' THEN worker_failures+1 ELSE worker_failures END,
  worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE p_error END,
  claim_generation=claim_generation+CASE WHEN status='cancel_requested' THEN 1 ELSE 0 END,
  status=CASE WHEN status='cancel_requested' THEN status
    WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(result->'checkpoints','[]'::jsonb)) c
      WHERE(c->>'committed')::boolean) THEN 'partially_published' ELSE 'failed' END,
  result=jsonb_set(coalesce(result,'{}'::jsonb),'{errorCode}',to_jsonb(p_error)),
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested')
 RETURNING status INTO outcome;
 RETURN outcome;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_unexpected(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error IS NULL OR length(p_error) NOT BETWEEN 1 AND 200 THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_rule_workflow SET worker_failures=worker_failures+1,
  worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE p_error END,
  status=CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
  result=CASE WHEN worker_failures+1>=3 THEN
   jsonb_set(result,'{errorCode}',to_jsonb(p_error)) ELSE result END,
  claim_generation=claim_generation+CASE WHEN status='cancel_requested' THEN 1 ELSE 0 END,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested')
 RETURNING CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures>=3 THEN 'needs_inspection' ELSE 'retry' END
 INTO outcome;RETURN outcome;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE epm.application_rule_workflow SET
  worker_failures=worker_failures+1,
  worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE 'APPLICATION_RULE_LEASE_EXPIRED' END,
  status=CASE WHEN status='cancel_requested' THEN status
    WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
  result=CASE WHEN worker_failures+1>=3 THEN jsonb_set(result,'{errorCode}',
    to_jsonb('APPLICATION_RULE_LEASE_EXPIRED'::text)) ELSE result END,
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp()
  AND status IN('accepted','running','cancel_requested');
 GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed;
END $$;

-- Runtime can only re-arm an idle parked cancellation in its existing scope.
-- The fixed current-authority/owner-or-admin control transaction holds the
-- exact parent row before calling this narrow helper; no worker columns are
-- granted for arbitrary runtime UPDATE, and active claims cannot be stolen.
CREATE FUNCTION epm.application_rule_rearm_cancel(
 p_workspace text,p_application text,p_workflow text,p_generation bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.application_rule_workflow SET
  worker_failures=0,worker_error_code=NULL,result=result-'errorCode',
  claim_generation=claim_generation+1,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true)
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND status='cancel_requested' AND worker_failures>=3
  AND claimant IS NULL AND lease_until IS NULL;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION epm.application_rule_worker_settle(text,text,text,bigint,text,text),
 epm.application_rule_rearm_cancel(text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_rule_worker_settle(text,text,text,bigint,text,text) TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.application_rule_rearm_cancel(text,text,text,bigint) TO epm_runtime;


COMMIT;
SELECT '0382 applied' AS migration;
