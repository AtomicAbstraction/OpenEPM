-- Bound unexpected generic application-schedule worker failures.  Explicit
-- failures and expired leases use the same generation-fenced settlement
-- functions, so poison work is deferred and eventually quarantined while
-- unrelated schedules remain dispatchable.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=273) THEN
  RAISE EXCEPTION 'MIGRATION_0274_REQUIRES_0273';
 END IF;
END $$;

ALTER TABLE epm.application_schedule_state
 ADD COLUMN dispatch_failure_count integer NOT NULL DEFAULT 0
   CHECK(dispatch_failure_count BETWEEN 0 AND 3);
ALTER TABLE epm.application_schedule_state
 ADD COLUMN dispatch_next_attempt_at timestamptz;

CREATE FUNCTION epm.application_schedule_worker_settle_unexpected(
 p_workspace text,p_application text,p_schedule text,p_generation bigint,
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
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
 RETURNING CASE WHEN dispatch_failure_count>=3
   THEN 'blocked' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

CREATE FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(
 p_workspace text,p_application text,p_occurrence text,p_generation bigint,
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
 WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
  AND o.workspace_id=p_workspace AND o.application_id=p_application
  AND o.occurrence_id=p_occurrence AND o.claim_generation=p_generation
  AND o.claimant=p_claimant
  AND o.status IN('running','submitted','cancel_requested')
 RETURNING CASE WHEN o.status='needs_inspection'
  THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

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
    item.workspace_id,item.application_id,item.schedule_id,
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
    item.workspace_id,item.application_id,item.occurrence_id,
    item.claim_generation,item.claimant,
    'APPLICATION_SCHEDULE_LEASE_EXPIRED') IS NOT NULL THEN
   occurrences:=occurrences+1;
  END IF;
 END LOOP;
 RETURN QUERY SELECT schedules,occurrences;
END $$;

CREATE OR REPLACE FUNCTION epm.application_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
  dispatch_generation bigint)
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
 SELECT s.* INTO candidate FROM epm.application_schedule_state s
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
  candidate.schedule_id,candidate.dispatch_generation+1;
END $$;

-- A completed materialization ownership generation breaks the poison streak.
-- Unexpected settlement never calls release, so this reset cannot erase a
-- failed attempt or bypass its durable due time.
CREATE OR REPLACE FUNCTION epm.application_schedule_worker_release(
 p_workspace text,p_application text,p_schedule text,p_generation bigint,
 p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.application_schedule_state SET dispatch_claimant=NULL,
  dispatch_lease_until=NULL,dispatch_failure_count=0,
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
  AND dispatch_lease_until>clock_timestamp();
 RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text),
 epm.application_schedule_occurrence_worker_settle_unexpected(
 text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text),
 epm.application_schedule_occurrence_worker_settle_unexpected(
 text,text,text,bigint,text,text) TO epm_worker;

COMMENT ON FUNCTION epm.application_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text) IS
 'Generation-fenced bounded settlement for schedule materialization faults and expired claims.';
COMMENT ON FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(
 text,text,text,bigint,text,text) IS
 'Generation-fenced bounded settlement shared by explicit occurrence faults and expired claims.';
