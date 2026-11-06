-- Bind durable Python-generated workflows to the verified Keycloak groups
-- and exact server-resolved dimensional authorization scope admitted with the
-- sealed plan.  Workers may replay only those recorded claims, while the
-- current-directory fence removes memberships that have since been revoked.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=250) THEN
        RAISE EXCEPTION 'MIGRATION_0251_PREDECESSOR_0250_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.python_program_workflow
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.python_program_workflow
    ADD CONSTRAINT python_program_workflow_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT python_program_workflow_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

-- The workflow lowers each unit into the ordinary durable job queue.  Preserve
-- the same admitted claims there as well; otherwise the final publisher would
-- reconstruct only issuer/subject and silently lose group-derived authority.
-- Existing jobs receive an empty claim set and therefore fail closed rather
-- than manufacturing a group membership that was never recorded.
ALTER TABLE epm.job
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[];

ALTER TABLE epm.job
    ADD CONSTRAINT job_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL);

-- Historical workflows cannot prove which verified group claims and
-- dimensional scope admitted them. They remain claimable only so the normal
-- generation-fenced worker can encounter the missing digest and settle them
-- through the existing fail-closed state machine; no historical unit can be
-- advanced or published without a non-null matching digest.

DROP FUNCTION epm.python_workflow_worker_claim(
    text,integer,integer,integer,integer);

CREATE FUNCTION epm.python_workflow_worker_claim(
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

REVOKE ALL ON FUNCTION epm.python_workflow_worker_claim(
    text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_workflow_worker_claim(
    text,integer,integer,integer,integer) TO epm_worker;
