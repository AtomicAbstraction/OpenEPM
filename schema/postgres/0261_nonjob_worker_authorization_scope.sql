-- Return sealed authority to fixed non-job workers without table privileges.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=260) THEN
        RAISE EXCEPTION 'MIGRATION_0261_PREDECESSOR_0260_REQUIRED';
    END IF;
END $migration$;

CREATE FUNCTION epm.cube_aggregate_worker_authority(
    p_workspace text,p_application text,p_query text,p_generation bigint,
    p_claimant text)
RETURNS TABLE(verified_groups text[],authorization_scope_digest text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT q.verified_groups,q.authorization_scope_digest
  FROM epm.cube_aggregate_query q
  WHERE q.workspace_id=p_workspace AND q.application_id=p_application
    AND q.query_id=p_query AND q.claim_generation=p_generation
    AND q.authorization_scope_digest IS NOT NULL
    AND (q.status='computed' OR (q.status='running'
      AND q.claimant=p_claimant AND q.lease_until>clock_timestamp()))
$$;

CREATE FUNCTION epm.python_workflow_worker_authority(
    p_workspace text,p_application text,p_workflow text,p_generation bigint,
    p_claimant text)
RETURNS TABLE(verified_groups text[],authorization_scope_digest text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT w.verified_groups,w.authorization_scope_digest
  FROM epm.python_program_workflow w
  WHERE w.workspace_id=p_workspace AND w.application_id=p_application
    AND w.workflow_id=p_workflow AND w.claim_generation=p_generation
    AND w.claimant=p_claimant AND w.lease_until>clock_timestamp()
    AND w.status IN ('accepted','running','cancel_requested')
    AND w.authorization_scope_digest IS NOT NULL
$$;

CREATE FUNCTION epm.application_rule_worker_authority(
    p_workspace text,p_application text,p_workflow text,p_generation bigint,
    p_claimant text)
RETURNS TABLE(verified_groups text[],authorization_scope_digest text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT w.verified_groups,w.authorization_scope_digest
  FROM epm.application_rule_workflow w
  WHERE w.workspace_id=p_workspace AND w.application_id=p_application
    AND w.workflow_id=p_workflow AND w.claim_generation=p_generation
    AND w.claimant=p_claimant AND w.lease_until>clock_timestamp()
    AND w.status IN ('accepted','running','cancel_requested')
    AND w.authorization_scope_digest IS NOT NULL
$$;

REVOKE ALL ON FUNCTION
  epm.cube_aggregate_worker_authority(text,text,text,bigint,text),
  epm.python_workflow_worker_authority(text,text,text,bigint,text),
  epm.application_rule_worker_authority(text,text,text,bigint,text)
FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.cube_aggregate_worker_authority(text,text,text,bigint,text),
  epm.python_workflow_worker_authority(text,text,text,bigint,text),
  epm.application_rule_worker_authority(text,text,text,bigint,text)
TO epm_worker;
