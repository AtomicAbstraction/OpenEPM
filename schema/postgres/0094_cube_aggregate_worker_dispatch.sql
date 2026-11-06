-- Narrow owner-mediated dispatch for the read-only aggregate technical queue.
-- The worker receives queue control data only.  Cube reads, authorization and
-- final visibility continue through epm_runtime under the stored identity.

CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0; step integer:=0;
BEGIN
  UPDATE epm.cube_aggregate_query SET status='failed',
    error_code='CUBE_AGGREGATE_REQUEST_EXPIRED',updated_at=transaction_timestamp()
  WHERE status='ready' AND expires_at<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;

  UPDATE epm.cube_aggregate_query SET
    status=CASE WHEN status='cancel_requested' THEN 'cancelled'
                WHEN attempts<3 AND expires_at>clock_timestamp() THEN 'ready'
                ELSE 'failed' END,
    error_code=CASE WHEN status='cancel_requested' THEN NULL
                    WHEN expires_at<=clock_timestamp() THEN 'CUBE_AGGREGATE_REQUEST_EXPIRED'
                    WHEN attempts>=3 THEN 'CUBE_AGGREGATE_RETRY_LIMIT' ELSE NULL END,
    claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE status IN ('running','cancel_requested') AND lease_until<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT; changed:=changed+step;
  RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,query_id text,issuer text,
  subject_id text,status text,claim_generation bigint,normalized_request jsonb)
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
  PERFORM pg_advisory_xact_lock(hashtextextended('epm.cube.aggregate.dispatch',0));
  IF (SELECT count(*) FROM epm.cube_aggregate_query running_query
      WHERE running_query.status='running')>=p_global_limit THEN
    RETURN;
  END IF;
  SELECT q.* INTO candidate FROM epm.cube_aggregate_query q
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=q.workspace_id
    WHERE q.status IN ('computed','ready') AND q.expires_at>clock_timestamp()
      AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
      AND (SELECT count(*) FROM epm.cube_aggregate_query active
           WHERE active.workspace_id=q.workspace_id AND active.status='running')<p_workspace_limit
      AND (SELECT count(*) FROM epm.cube_aggregate_query active
           WHERE active.workspace_id=q.workspace_id AND active.application_id=q.application_id
             AND active.status='running')<p_application_limit
    ORDER BY (q.status='computed') DESC,d.last_claim_sequence NULLS FIRST,
      q.accepted_at,q.query_id FOR UPDATE OF q SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  IF candidate.status='ready' THEN
    UPDATE epm.cube_aggregate_query q SET status='running',
      claim_generation=q.claim_generation+1,claimant=p_claimant,
      lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
      attempts=q.attempts+1,updated_at=transaction_timestamp()
    WHERE q.workspace_id=candidate.workspace_id AND q.application_id=candidate.application_id
      AND q.query_id=candidate.query_id;
    candidate.status:='running'; candidate.claim_generation:=candidate.claim_generation+1;
  END IF;
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.query_id,candidate.issuer,candidate.subject_id,candidate.status,
    candidate.claim_generation,candidate.normalized_request;
END $$;

CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_settle(
  p_workspace text,p_application text,p_query text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  IF p_error NOT IN ('CUBE_AGGREGATE_AUTHORIZATION_REVOKED',
                     'CUBE_AGGREGATE_COMPUTE_FAILED') THEN
    RAISE EXCEPTION 'CUBE_AGGREGATE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
  END IF;
  UPDATE epm.cube_aggregate_query SET status='failed',error_code=p_error,
    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application AND query_id=p_query
    AND status IN ('running','cancel_requested') AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

REVOKE ALL ON FUNCTION epm.cube_aggregate_worker_recover(),
  epm.cube_aggregate_worker_claim(text,integer,integer,integer,integer),
  epm.cube_aggregate_worker_settle(text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.cube_aggregate_worker_recover(),
  epm.cube_aggregate_worker_claim(text,integer,integer,integer,integer),
  epm.cube_aggregate_worker_settle(text,text,text,bigint,text,text) TO epm_worker;
