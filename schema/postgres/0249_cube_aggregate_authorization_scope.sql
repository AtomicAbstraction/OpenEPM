-- Bind durable aggregate work and cached result visibility to the exact
-- server-resolved direct-plus-Keycloak-group dimensional authorization scope.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=248) THEN
        RAISE EXCEPTION 'MIGRATION_0249_PREDECESSOR_0248_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.cube_aggregate_query
    ADD CONSTRAINT cube_aggregate_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT cube_aggregate_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

-- Historical technical queries cannot prove the current effective group
-- scope.  They remain immutable evidence but are deliberately unreadable by
-- the fixed repository, which requires a non-null matching digest.

DROP FUNCTION epm.cube_aggregate_worker_claim(
    text,integer,integer,integer,integer);

CREATE FUNCTION epm.cube_aggregate_worker_claim(
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
      WHERE running_query.status='running')>=p_global_limit THEN
    RETURN;
  END IF;
  SELECT q.* INTO candidate FROM epm.cube_aggregate_query q
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d
      ON d.workspace_id=q.workspace_id
    WHERE q.status IN ('computed','ready')
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
      d.last_claim_sequence NULLS FIRST,q.accepted_at,q.query_id
    FOR UPDATE OF q SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  IF candidate.status='ready' THEN
    UPDATE epm.cube_aggregate_query q SET status='running',
      claim_generation=q.claim_generation+1,claimant=p_claimant,
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

REVOKE ALL ON FUNCTION epm.cube_aggregate_worker_claim(
    text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.cube_aggregate_worker_claim(
    text,integer,integer,integer,integer) TO epm_worker;
