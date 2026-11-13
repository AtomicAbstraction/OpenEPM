-- Generation-fenced reconciliation for uncertain aggregate worker outcomes.
-- A worker may lose acknowledgement after the private result or seal commits;
-- it must inspect durable state before scheduling another scan.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=268) THEN
    RAISE EXCEPTION 'MIGRATION_0269_PREDECESSOR_0268_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
  ADD COLUMN next_attempt_at timestamptz,
  ADD COLUMN last_claimant text,
  ADD CONSTRAINT cube_aggregate_next_attempt_state_check
    CHECK(next_attempt_at IS NULL OR status='ready'),
  ADD CONSTRAINT cube_aggregate_last_claimant_check
    CHECK(last_claimant IS NULL OR length(last_claimant) BETWEEN 1 AND 200);

UPDATE epm.cube_aggregate_query SET last_claimant=claimant
 WHERE status IN ('running','cancel_requested') AND claimant IS NOT NULL;

CREATE INDEX cube_aggregate_ready_retry_queue
  ON epm.cube_aggregate_query(
    next_attempt_at,accepted_at,workspace_id,application_id,query_id)
  WHERE status='ready';

CREATE FUNCTION epm.clear_cube_aggregate_retry_schedule()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.status<>'ready' THEN NEW.next_attempt_at:=NULL; END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.clear_cube_aggregate_retry_schedule() FROM PUBLIC;
CREATE TRIGGER cube_aggregate_clear_retry_schedule
  BEFORE UPDATE OF status ON epm.cube_aggregate_query
  FOR EACH ROW EXECUTE FUNCTION epm.clear_cube_aggregate_retry_schedule();

CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0; step integer:=0;
BEGIN
  UPDATE epm.cube_aggregate_query SET status='failed',
    error_code='CUBE_AGGREGATE_REQUEST_EXPIRED',next_attempt_at=NULL,
    updated_at=transaction_timestamp()
  WHERE status='ready' AND expires_at<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;

  UPDATE epm.cube_aggregate_query SET
    status=CASE WHEN status='cancel_requested' THEN 'cancelled'
                WHEN attempts<3 AND expires_at>clock_timestamp() THEN 'ready'
                ELSE 'failed' END,
    error_code=CASE WHEN status='cancel_requested' THEN NULL
                    WHEN expires_at<=clock_timestamp()
                      THEN 'CUBE_AGGREGATE_REQUEST_EXPIRED'
                    WHEN attempts>=3
                      THEN 'CUBE_AGGREGATE_RETRY_LIMIT' ELSE NULL END,
    next_attempt_at=CASE
      WHEN status='running' AND attempts<3 AND expires_at>clock_timestamp()
      THEN clock_timestamp()+make_interval(
        secs=>least(60,(1::bigint<<greatest(0,least(attempts-1,5)))::integer))
      ELSE NULL END,
    claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE status IN ('running','cancel_requested')
    AND lease_until<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;
  RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,query_id text,issuer text,
  subject_id text,status text,claim_generation bigint,normalized_request jsonb,
  verified_groups text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 5 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'CUBE_AGGREGATE_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.cube.aggregate.dispatch',0));
  IF (SELECT count(*) FROM epm.cube_aggregate_query running_query
      WHERE running_query.status='running')>=p_global_limit THEN RETURN; END IF;
  SELECT q.* INTO candidate FROM epm.cube_aggregate_query q
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d
      ON d.workspace_id=q.workspace_id
    WHERE q.status IN ('computed','ready')
      AND (q.status='computed' OR q.next_attempt_at IS NULL
           OR q.next_attempt_at<=clock_timestamp())
      AND q.expires_at>clock_timestamp()
      AND a.status='Active' AND w.status='Active'
      AND s.processing_mode='Active'
      AND q.authorization_scope_digest IS NOT NULL
      AND (SELECT count(*) FROM epm.cube_aggregate_query active
        WHERE active.workspace_id=q.workspace_id
          AND active.status='running')<p_workspace_limit
      AND (SELECT count(*) FROM epm.cube_aggregate_query active
        WHERE active.workspace_id=q.workspace_id
          AND active.application_id=q.application_id
          AND active.status='running')<p_application_limit
    ORDER BY (q.status='computed') DESC,
      d.last_claim_sequence NULLS FIRST,q.next_attempt_at NULLS FIRST,
      q.accepted_at,q.query_id
    FOR UPDATE OF q SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  IF candidate.status='ready' THEN
    UPDATE epm.cube_aggregate_query q SET status='running',
      claim_generation=q.claim_generation+1,claimant=p_claimant,
      last_claimant=p_claimant,next_attempt_at=NULL,
      lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
      attempts=q.attempts+1,updated_at=transaction_timestamp()
    WHERE q.workspace_id=candidate.workspace_id
      AND q.application_id=candidate.application_id
      AND q.query_id=candidate.query_id;
    candidate.status:='running';
    candidate.claim_generation:=candidate.claim_generation+1;
  END IF;
  INSERT INTO epm.worker_workspace_dispatch(
    workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,
      nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.query_id,candidate.issuer,candidate.subject_id,candidate.status,
    candidate.claim_generation,candidate.normalized_request,
    candidate.verified_groups;
END $$;

CREATE FUNCTION epm.cube_aggregate_worker_unexpected(
  p_workspace text,p_application text,p_query text,p_generation bigint,
  p_claimant text)
RETURNS TABLE(outcome text,error_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE current epm.cube_aggregate_query%ROWTYPE;
BEGIN
  IF p_workspace IS NULL OR p_application IS NULL OR p_query IS NULL
     OR p_generation<1 OR p_claimant IS NULL
     OR length(p_claimant) NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'CUBE_AGGREGATE_WORKER_UNEXPECTED_INVALID'
      USING ERRCODE='22023';
  END IF;
  SELECT * INTO current FROM epm.cube_aggregate_query q
   WHERE q.workspace_id=p_workspace AND q.application_id=p_application
     AND q.query_id=p_query FOR UPDATE;
  IF NOT FOUND OR current.claim_generation<>p_generation
     OR current.last_claimant IS DISTINCT FROM p_claimant THEN
    RETURN QUERY SELECT 'stale'::text,NULL::text; RETURN;
  END IF;
  IF current.status IN ('computed','sealed','cancelled','failed','expired') THEN
    RETURN QUERY SELECT current.status,current.error_code; RETURN;
  END IF;
  IF current.status='cancel_requested' AND current.claimant=p_claimant
     AND current.lease_until>clock_timestamp() THEN
    UPDATE epm.cube_aggregate_query SET status='cancelled',claimant=NULL,
      lease_until=NULL,next_attempt_at=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=p_workspace AND application_id=p_application
       AND query_id=p_query;
    RETURN QUERY SELECT 'cancelled'::text,NULL::text; RETURN;
  END IF;
  IF current.status<>'running' OR current.claimant IS DISTINCT FROM p_claimant
     OR current.lease_until<=clock_timestamp() THEN
    RETURN QUERY SELECT 'stale'::text,NULL::text; RETURN;
  END IF;
  IF current.expires_at<=clock_timestamp() THEN
    UPDATE epm.cube_aggregate_query SET status='failed',claimant=NULL,
      lease_until=NULL,next_attempt_at=NULL,
      error_code='CUBE_AGGREGATE_REQUEST_EXPIRED',
      updated_at=transaction_timestamp()
     WHERE workspace_id=p_workspace AND application_id=p_application
       AND query_id=p_query;
    RETURN QUERY SELECT 'failed'::text,
      'CUBE_AGGREGATE_REQUEST_EXPIRED'::text; RETURN;
  END IF;
  IF current.attempts>=3 THEN
    UPDATE epm.cube_aggregate_query SET status='failed',claimant=NULL,
      lease_until=NULL,next_attempt_at=NULL,
      error_code='CUBE_AGGREGATE_RETRY_LIMIT',
      updated_at=transaction_timestamp()
     WHERE workspace_id=p_workspace AND application_id=p_application
       AND query_id=p_query;
    RETURN QUERY SELECT 'failed'::text,
      'CUBE_AGGREGATE_RETRY_LIMIT'::text; RETURN;
  END IF;
  UPDATE epm.cube_aggregate_query SET status='ready',claimant=NULL,
    lease_until=NULL,error_code=NULL,
    next_attempt_at=clock_timestamp()+make_interval(
      secs=>least(60,(1::bigint<<greatest(0,least(current.attempts-1,5)))::integer)),
    updated_at=transaction_timestamp()
   WHERE workspace_id=p_workspace AND application_id=p_application
     AND query_id=p_query;
  RETURN QUERY SELECT 'ready'::text,NULL::text;
END $$;

REVOKE ALL ON FUNCTION
  epm.cube_aggregate_worker_unexpected(text,text,text,bigint,text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.cube_aggregate_worker_unexpected(text,text,text,bigint,text)
TO epm_worker;
