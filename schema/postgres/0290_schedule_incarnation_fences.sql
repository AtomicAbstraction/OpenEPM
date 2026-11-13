-- Every worker lease belongs to one application incarnation. A recycled
-- application ID, schedule ID, claimant and generation cannot revive a callback.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=289) THEN
  RAISE EXCEPTION 'MIGRATION_0290_REQUIRES_0289';
 END IF;
END $$;

DROP FUNCTION epm.application_schedule_worker_renew(text,text,text,bigint,text,integer);

CREATE FUNCTION epm.application_schedule_worker_renew(
  p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
  p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_RENEW_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_state SET
    dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_renew(text,text,bigint,text,bigint,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_renew(text,text,bigint,text,bigint,text,integer) TO epm_worker;

DROP FUNCTION epm.application_schedule_worker_release(text,text,text,bigint,text);

CREATE FUNCTION epm.application_schedule_worker_release(
 p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
 p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.application_schedule_state SET dispatch_claimant=NULL,
  dispatch_lease_until=NULL,dispatch_failure_count=0,
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
  AND dispatch_lease_until>clock_timestamp();
 RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_release(text,text,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_release(text,text,bigint,text,bigint,text) TO epm_worker;

DROP FUNCTION epm.application_schedule_worker_block(text,text,text,bigint,text,text);

CREATE FUNCTION epm.application_schedule_worker_block(
  p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_error NOT IN('APPLICATION_SCHEDULE_AUTHORITY_INVALID',
                    'APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED',
                    'APPLICATION_SCHEDULE_DEFINITION_CORRUPT',
                    'TOKEN_ISSUE_TIME_UNAVAILABLE',
                    'TECHNICAL_AUTHORITY_INVALID') THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_BLOCK_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_state SET dispatch_error_code=p_error,
    dispatch_claimant=NULL,dispatch_lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_block(text,text,bigint,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_block(text,text,bigint,text,bigint,text,text) TO epm_worker;

DROP FUNCTION epm.application_schedule_worker_settle_unexpected(text,text,text,bigint,text,text);

CREATE FUNCTION epm.application_schedule_worker_settle_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
 p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('APPLICATION_SCHEDULE_WORKER_FAILED',
                   'APPLICATION_SCHEDULE_WORKER_LEASE_EXPIRED') THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_ERROR_INVALID'
   USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_schedule_state SET
  dispatch_failure_count=LEAST(3,dispatch_failure_count+1),
  dispatch_error_code=CASE WHEN dispatch_failure_count+1>=3
    THEN 'APPLICATION_SCHEDULE_WORKER_RETRY_LIMIT' ELSE NULL END,
  dispatch_next_attempt_at=CASE WHEN dispatch_failure_count+1>=3 THEN NULL
    ELSE clock_timestamp()+make_interval(secs=>
      CASE dispatch_failure_count WHEN 0 THEN 1 ELSE 5 END) END,
  dispatch_generation=dispatch_generation+1,
  dispatch_claimant=NULL,dispatch_lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
 RETURNING CASE WHEN dispatch_failure_count>=3
   THEN 'blocked' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) TO epm_worker;

DROP FUNCTION epm.application_schedule_occurrence_worker_renew(text,text,text,bigint,text,integer);

CREATE FUNCTION epm.application_schedule_occurrence_worker_renew(
  p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,p_generation bigint,
  p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_RENEW_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_occurrence SET
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
    AND occurrence_id=p_occurrence AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN('running','submitted','cancel_requested');
  RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_occurrence_worker_renew(text,text,bigint,text,bigint,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_occurrence_worker_renew(text,text,bigint,text,bigint,text,integer) TO epm_worker;

DROP FUNCTION epm.application_schedule_occurrence_worker_release(text,text,text,bigint,text);

CREATE FUNCTION epm.application_schedule_occurrence_worker_release(
  p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  UPDATE epm.application_schedule_occurrence SET claimant=NULL,
    lease_until=NULL,error_code=NULL,updated_at=transaction_timestamp()
  WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
    AND occurrence_id=p_occurrence AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_occurrence_worker_release(text,text,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_occurrence_worker_release(text,text,bigint,text,bigint,text) TO epm_worker;

DROP FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(text,text,text,bigint,text,text);

CREATE FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,p_generation bigint,
 p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('APPLICATION_SCHEDULE_WORKER_FAILED',
                   'APPLICATION_SCHEDULE_LEASE_EXPIRED') THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_ERROR_INVALID'
   USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_schedule_occurrence o SET
  attempt_count=o.attempt_count+1,
  inspection_origin_status=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN o.status ELSE o.inspection_origin_status END,
  status=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN 'needs_inspection' ELSE o.status END,
  next_attempt_at=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN NULL ELSE clock_timestamp()+make_interval(secs=>
    ((v.definition#>>'{retryPolicy,backoffSeconds}')::integer)) END,
  claim_generation=o.claim_generation+1,claimant=NULL,lease_until=NULL,
  error_code=p_error,updated_at=transaction_timestamp()
 FROM epm.application_schedule_version v
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
  AND o.workspace_id=p_workspace AND o.application_id=p_application
  AND o.occurrence_id=p_occurrence AND o.claim_generation=p_generation
  AND o.claimant=p_claimant
  AND o.status IN('running','submitted','cancel_requested')
 RETURNING CASE WHEN o.status='needs_inspection'
  THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) TO epm_worker;

DROP FUNCTION epm.python_schedule_worker_release(text,text,text,bigint,text);

CREATE FUNCTION epm.python_schedule_worker_release(
 p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
 p_claimant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer;
BEGIN
 UPDATE epm.python_program_schedule_state SET dispatch_claimant=NULL,
  dispatch_lease_until=NULL,dispatch_failure_count=0,
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant;
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;
END $$;

REVOKE ALL ON FUNCTION epm.python_schedule_worker_release(text,text,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_release(text,text,bigint,text,bigint,text) TO epm_worker;

DROP FUNCTION epm.python_schedule_worker_settle_unexpected(text,text,text,bigint,text,text);

CREATE FUNCTION epm.python_schedule_worker_settle_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_schedule text,p_generation bigint,
 p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('PYTHON_SCHEDULE_MATERIALIZATION_FAILED',
                   'PYTHON_SCHEDULE_INFRASTRUCTURE_FAILURE',
                   'PYTHON_SCHEDULE_MATERIALIZATION_LEASE_EXPIRED') THEN
  RAISE EXCEPTION 'PYTHON_SCHEDULE_MATERIALIZATION_ERROR_INVALID'
   USING ERRCODE='22023';
 END IF;
 UPDATE epm.python_program_schedule_state SET
  dispatch_failure_count=LEAST(3,dispatch_failure_count+1),
  dispatch_error_code=CASE WHEN dispatch_failure_count+1>=3
   THEN 'PYTHON_SCHEDULE_MATERIALIZATION_RETRY_LIMIT' ELSE NULL END,
  dispatch_next_attempt_at=CASE WHEN dispatch_failure_count+1>=3 THEN NULL
   ELSE clock_timestamp()+make_interval(secs=>
    CASE dispatch_failure_count WHEN 0 THEN 1 ELSE 5 END) END,
  dispatch_generation=dispatch_generation+1,
  dispatch_claimant=NULL,dispatch_lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
 RETURNING CASE WHEN dispatch_failure_count>=3
  THEN 'blocked' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.python_schedule_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_settle_unexpected(text,text,bigint,text,bigint,text,text) TO epm_worker;

DROP FUNCTION epm.python_occurrence_worker_release(text,text,text,bigint,text);

CREATE FUNCTION epm.python_occurrence_worker_release(p_workspace text,p_application text,p_schema_epoch bigint,
 p_occurrence text,p_generation bigint,p_claimant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE n integer;BEGIN
 UPDATE epm.python_program_occurrence SET claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp() WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace
  AND application_id=p_application AND occurrence_id=p_occurrence
  AND claim_generation=p_generation AND claimant=p_claimant;
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;

REVOKE ALL ON FUNCTION epm.python_occurrence_worker_release(text,text,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_occurrence_worker_release(text,text,bigint,text,bigint,text) TO epm_worker;

DROP FUNCTION epm.python_occurrence_worker_unexpected(text,text,text,bigint,text,text);

CREATE FUNCTION epm.python_occurrence_worker_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,p_generation bigint,
 p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;BEGIN
 IF p_error NOT IN ('PYTHON_SCHEDULE_WORKER_FAILED',
                    'PYTHON_SCHEDULE_INFRASTRUCTURE_FAILURE')
 THEN RAISE EXCEPTION 'PYTHON_SCHEDULE_WORKER_ERROR_INVALID'
   USING ERRCODE='22023';END IF;
 UPDATE epm.python_program_occurrence SET
   worker_failures=LEAST(3,worker_failures+1),
   status=CASE WHEN worker_failures+1>=3
     THEN 'needs_inspection' ELSE status END,
   error_code=CASE WHEN worker_failures+1>=3 THEN p_error ELSE error_code END,
   next_attempt_at=CASE WHEN worker_failures+1>=3 THEN NULL ELSE
     clock_timestamp()+make_interval(secs=>
       CASE worker_failures WHEN 0 THEN 1 ELSE 5 END) END,
   claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
   AND occurrence_id=p_occurrence AND claim_generation=p_generation
   AND claimant=p_claimant AND lease_until>clock_timestamp()
   AND status IN
     ('running','building','running_program','cancel_requested')
 RETURNING CASE WHEN worker_failures>=3
   THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.python_occurrence_worker_unexpected(text,text,bigint,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_occurrence_worker_unexpected(text,text,bigint,text,bigint,text,text) TO epm_worker;

DROP FUNCTION epm.application_schedule_worker_claim(text,integer,integer,integer,integer);

CREATE FUNCTION epm.application_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
  dispatch_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 30 AND 300
  OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_CLAIM_INVALID'
   USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application.schedule.dispatch',0));
 IF (SELECT count(*) FROM epm.application_schedule_state
  WHERE dispatch_claimant IS NOT NULL
   AND dispatch_lease_until>clock_timestamp())>=p_global_limit THEN RETURN;END IF;
 SELECT s.*,state.schema_epoch INTO candidate FROM epm.application_schedule_state s
 JOIN epm.application_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 JOIN epm.application a ON a.workspace_id=s.workspace_id
  AND a.application_id=s.application_id
 JOIN epm.application_state state ON state.workspace_id=s.workspace_id
  AND state.application_id=s.application_id
 JOIN epm.workspace ws ON ws.workspace_id=s.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE s.active_version IS NOT NULL AND s.dispatch_error_code IS NULL
  AND s.dispatch_claimant IS NULL
  AND (s.dispatch_next_attempt_at IS NULL
    OR s.dispatch_next_attempt_at<=clock_timestamp())
  AND a.status='Active' AND ws.status='Active' AND state.processing_mode='Active'
  AND (v.definition#>>'{recurrence,firstDueAt}')::timestamptz<=clock_timestamp()
  AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>
    (v.definition#>>'{recurrence,intervalSeconds}')::integer)<=clock_timestamp())
  AND (SELECT count(*) FROM epm.application_schedule_state active
   WHERE active.workspace_id=s.workspace_id AND active.dispatch_claimant IS NOT NULL
    AND active.dispatch_lease_until>clock_timestamp())<p_workspace_limit
  AND (SELECT count(*) FROM epm.application_schedule_state active
   WHERE active.workspace_id=s.workspace_id AND active.application_id=s.application_id
    AND active.dispatch_claimant IS NOT NULL
    AND active.dispatch_lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,COALESCE(s.last_due_at,
  (v.definition#>>'{recurrence,firstDueAt}')::timestamptz),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_schedule_state target SET
  dispatch_generation=target.dispatch_generation+1,
  dispatch_claimant=p_claimant,
  dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE target.workspace_id=candidate.workspace_id
  AND target.application_id=candidate.application_id
  AND target.schedule_id=candidate.schedule_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.schedule_id,candidate.dispatch_generation+1,candidate.schema_epoch;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_claim(text,integer,integer,integer,integer) TO epm_worker;

DROP FUNCTION epm.application_schedule_occurrence_worker_claim(text,integer,integer,integer,integer);

CREATE FUNCTION epm.application_schedule_occurrence_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
  status text,claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 30 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_CLAIM_INVALID'
      USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.application.schedule.occurrence.dispatch',0));
  IF (SELECT count(*) FROM epm.application_schedule_occurrence
      WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())
      >=p_global_limit THEN RETURN;END IF;
  SELECT o.*,state.schema_epoch INTO candidate FROM epm.application_schedule_occurrence o
  JOIN epm.application a ON a.workspace_id=o.workspace_id
    AND a.application_id=o.application_id
  JOIN epm.application_state state ON state.workspace_id=o.workspace_id
    AND state.application_id=o.application_id
  JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
  LEFT JOIN epm.worker_workspace_dispatch d
    ON d.workspace_id=o.workspace_id
  WHERE o.status IN('ready','running','submitted','cancel_requested')
    AND o.claimant IS NULL
    AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
    AND a.status='Active' AND ws.status='Active'
    AND state.processing_mode='Active'
    AND (SELECT count(*) FROM epm.application_schedule_occurrence active
      WHERE active.workspace_id=o.workspace_id AND active.claimant IS NOT NULL
        AND active.lease_until>clock_timestamp())<p_workspace_limit
    AND (SELECT count(*) FROM epm.application_schedule_occurrence active
      WHERE active.workspace_id=o.workspace_id
        AND active.application_id=o.application_id
        AND active.claimant IS NOT NULL
        AND active.lease_until>clock_timestamp())<p_application_limit
  ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
  FOR UPDATE OF o SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN;END IF;
  UPDATE epm.application_schedule_occurrence target SET
    status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
    claim_generation=target.claim_generation+1,claimant=p_claimant,
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE target.workspace_id=candidate.workspace_id
    AND target.application_id=candidate.application_id
    AND target.occurrence_id=candidate.occurrence_id;
  INSERT INTO epm.worker_workspace_dispatch(
    workspace_id,last_claim_sequence,claim_count)
  VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
  ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
    last_claim_sequence=EXCLUDED.last_claim_sequence,
    claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.occurrence_id,
    CASE WHEN candidate.status='ready' THEN 'running' ELSE candidate.status END,
    candidate.claim_generation+1,candidate.schema_epoch;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_occurrence_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_occurrence_worker_claim(text,integer,integer,integer,integer) TO epm_worker;

DROP FUNCTION epm.python_schedule_worker_claim(text,integer);

CREATE FUNCTION epm.python_schedule_worker_claim(
 p_claimant text,p_lease integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
 dispatch_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease NOT BETWEEN 5 AND 300 THEN
  RAISE EXCEPTION 'PYTHON_SCHEDULE_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 SELECT s.*,state.schema_epoch INTO c FROM epm.python_program_schedule_state s
 JOIN epm.application_state state ON state.workspace_id=s.workspace_id
  AND state.application_id=s.application_id
 JOIN epm.application app ON app.workspace_id=s.workspace_id
  AND app.application_id=s.application_id
 JOIN epm.workspace ws ON ws.workspace_id=s.workspace_id
 JOIN epm.python_program_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE state.processing_mode='Active' AND app.status='Active'
  AND ws.status='Active' AND s.active_version IS NOT NULL AND s.dispatch_error_code IS NULL
  AND (s.dispatch_lease_until IS NULL
    OR s.dispatch_lease_until<=clock_timestamp())
  AND (s.dispatch_next_attempt_at IS NULL
    OR s.dispatch_next_attempt_at<=clock_timestamp())
  AND v.first_due_at<=clock_timestamp()
  AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(
    secs=>v.interval_seconds)<=clock_timestamp())
  AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   v.delegation_id,v.delegation_version,v.execution_issuer,
   v.execution_subject,'python.program.build',s.schedule_id,s.active_version)
  AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   v.delegation_id,v.delegation_version,v.execution_issuer,
   v.execution_subject,'python.program.run',s.schedule_id,s.active_version)
 ORDER BY d.last_claim_sequence NULLS FIRST,
  COALESCE(s.last_due_at,v.first_due_at),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 IF c.dispatch_claimant IS NOT NULL THEN
  PERFORM epm.python_schedule_worker_settle_unexpected(c.workspace_id,
   c.application_id,c.schema_epoch,c.schedule_id,c.dispatch_generation,c.dispatch_claimant,
   'PYTHON_SCHEDULE_MATERIALIZATION_LEASE_EXPIRED');
  RETURN;
 END IF;
 UPDATE epm.python_program_schedule_state target SET
  dispatch_generation=target.dispatch_generation+1,
  dispatch_claimant=p_claimant,
  dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease),
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE target.workspace_id=c.workspace_id
  AND target.application_id=c.application_id
  AND target.schedule_id=c.schedule_id;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.schedule_id,
  c.dispatch_generation+1,c.schema_epoch;
END $$;

REVOKE ALL ON FUNCTION epm.python_schedule_worker_claim(text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_claim(text,integer) TO epm_worker;

DROP FUNCTION epm.python_occurrence_worker_claim(text,integer,integer,integer,integer);

CREATE FUNCTION epm.python_occurrence_worker_claim(
 p_claimant text,p_lease integer,p_global integer,p_workspace integer,
 p_application integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
 status text,claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
 OR p_lease NOT BETWEEN 5 AND 300
 OR p_application NOT BETWEEN 1 AND p_workspace
 OR p_workspace NOT BETWEEN 1 AND p_global
 THEN RAISE EXCEPTION 'PYTHON_OCCURRENCE_CLAIM_INVALID'
   USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(
   hashtextextended('epm.python.occurrence.dispatch',0));
 IF (SELECT count(*) FROM epm.python_program_occurrence
     WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global
 THEN RETURN;END IF;
 SELECT o.*,state.schema_epoch INTO c FROM epm.python_program_occurrence o
 JOIN epm.application_state state ON state.workspace_id=o.workspace_id
  AND state.application_id=o.application_id
 JOIN epm.application app ON app.workspace_id=o.workspace_id
  AND app.application_id=o.application_id
 JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE state.processing_mode='Active' AND app.status='Active'
  AND ws.status='Active' AND o.status IN
   ('ready','running','building','running_program','cancel_requested')
 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
 AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
 AND (SELECT count(*) FROM epm.python_program_occurrence x
      WHERE x.workspace_id=o.workspace_id AND x.claimant IS NOT NULL
        AND x.lease_until>clock_timestamp())<p_workspace
 AND (SELECT count(*) FROM epm.python_program_occurrence x
      WHERE x.workspace_id=o.workspace_id
        AND x.application_id=o.application_id AND x.claimant IS NOT NULL
        AND x.lease_until>clock_timestamp())<p_application
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
 FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;

 -- A process disappeared without releasing its lease.  Count that ownership
 -- generation exactly once and defer/quarantine it instead of immediately
 -- reclaiming the same poison occurrence forever.
 IF c.claimant IS NOT NULL THEN
   UPDATE epm.python_program_occurrence target SET
     worker_failures=LEAST(3,target.worker_failures+1),
     status=CASE WHEN target.worker_failures+1>=3
       THEN 'needs_inspection' ELSE target.status END,
     error_code=CASE WHEN target.worker_failures+1>=3
       THEN 'PYTHON_SCHEDULE_WORKER_RETRY_LIMIT' ELSE target.error_code END,
     next_attempt_at=CASE WHEN target.worker_failures+1>=3 THEN NULL ELSE
       clock_timestamp()+make_interval(secs=>
         CASE target.worker_failures WHEN 0 THEN 1 ELSE 5 END) END,
     claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
   WHERE target.workspace_id=c.workspace_id
     AND target.application_id=c.application_id
     AND target.occurrence_id=c.occurrence_id
     AND target.claim_generation=c.claim_generation
     AND target.claimant=c.claimant
     AND target.lease_until<=clock_timestamp();
   RETURN;
 END IF;

 UPDATE epm.python_program_occurrence target SET
   status=CASE WHEN target.status='ready' THEN 'running'
               ELSE target.status END,
   claim_generation=target.claim_generation+1,claimant=p_claimant,
   lease_until=clock_timestamp()+make_interval(secs=>p_lease),
   next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE target.workspace_id=c.workspace_id
   AND target.application_id=c.application_id
   AND target.occurrence_id=c.occurrence_id;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.occurrence_id,
   CASE WHEN c.status='ready' THEN 'running' ELSE c.status END,
   c.claim_generation+1,c.schema_epoch;
END $$;

REVOKE ALL ON FUNCTION epm.python_occurrence_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_occurrence_worker_claim(text,integer,integer,integer,integer) TO epm_worker;

CREATE OR REPLACE FUNCTION epm.application_schedule_dispatch_recover()
RETURNS TABLE(schedule_claims integer,occurrence_claims integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item record;DECLARE schedules integer:=0;DECLARE occurrences integer:=0;
BEGIN
 FOR item IN SELECT workspace_id,application_id,schedule_id,
   dispatch_generation,dispatch_claimant
  FROM epm.application_schedule_state
  WHERE dispatch_claimant IS NOT NULL
   AND dispatch_lease_until<=clock_timestamp()
  FOR UPDATE SKIP LOCKED
 LOOP
  IF epm.application_schedule_worker_settle_unexpected(
    item.workspace_id,item.application_id,
    (SELECT incarnation.schema_epoch FROM epm.application_state incarnation
     WHERE incarnation.workspace_id=item.workspace_id
      AND incarnation.application_id=item.application_id),item.schedule_id,
    item.dispatch_generation,item.dispatch_claimant,
    'APPLICATION_SCHEDULE_WORKER_LEASE_EXPIRED') IS NOT NULL THEN
   schedules:=schedules+1;
  END IF;
 END LOOP;
 FOR item IN SELECT workspace_id,application_id,occurrence_id,
   claim_generation,claimant
  FROM epm.application_schedule_occurrence
  WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp()
   AND status IN('running','submitted','cancel_requested')
  FOR UPDATE SKIP LOCKED
 LOOP
  IF epm.application_schedule_occurrence_worker_settle_unexpected(
    item.workspace_id,item.application_id,
    (SELECT incarnation.schema_epoch FROM epm.application_state incarnation
     WHERE incarnation.workspace_id=item.workspace_id
      AND incarnation.application_id=item.application_id),item.occurrence_id,
    item.claim_generation,item.claimant,
    'APPLICATION_SCHEDULE_LEASE_EXPIRED') IS NOT NULL THEN
   occurrences:=occurrences+1;
  END IF;
 END LOOP;
 RETURN QUERY SELECT schedules,occurrences;
END $$;

COMMIT;
