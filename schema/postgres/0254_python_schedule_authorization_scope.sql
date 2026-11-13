-- Preserve the exact verified group and dimensional authorization scope on
-- generic Python schedules. Historical schedule versions remain immutable
-- and fail closed because their scope digest is NULL.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=253) THEN
        RAISE EXCEPTION 'MIGRATION_0254_PREDECESSOR_0253_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.python_program_schedule_version
    ADD COLUMN execution_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.python_program_schedule_version
    ADD CONSTRAINT python_schedule_execution_groups_check CHECK (
        cardinality(execution_groups)<=100
        AND array_position(execution_groups,NULL) IS NULL),
    ADD CONSTRAINT python_schedule_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

ALTER TABLE epm.python_program_schedule_state
    ADD COLUMN dispatch_error_code text NULL;

ALTER TABLE epm.python_program_build
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.python_program_build
    ADD CONSTRAINT python_build_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT python_build_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

CREATE OR REPLACE FUNCTION epm.python_schedule_worker_claim(
    p_claimant text,p_lease integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
    dispatch_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
    OR p_lease NOT BETWEEN 5 AND 300 THEN
   RAISE EXCEPTION 'PYTHON_SCHEDULE_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 SELECT s.* INTO c FROM epm.python_program_schedule_state s
 JOIN epm.python_program_schedule_version v ON
   (v.workspace_id,v.application_id,v.schedule_id,v.version)=
   (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE s.active_version IS NOT NULL
   AND s.dispatch_error_code IS NULL
   AND (s.dispatch_lease_until IS NULL
        OR s.dispatch_lease_until<=clock_timestamp())
   AND v.first_due_at<=clock_timestamp()
   AND (s.last_due_at IS NULL
        OR s.last_due_at+make_interval(secs=>v.interval_seconds)
           <=clock_timestamp())
   AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
     v.delegation_id,v.delegation_version,v.execution_issuer,
     v.execution_subject,'python.program.build',s.schedule_id,s.active_version)
   AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
     v.delegation_id,v.delegation_version,v.execution_issuer,
     v.execution_subject,'python.program.run',s.schedule_id,s.active_version)
 ORDER BY d.last_claim_sequence NULLS FIRST,
   COALESCE(s.last_due_at,v.first_due_at),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE epm.python_program_schedule_state target
 SET dispatch_generation=target.dispatch_generation+1,
   dispatch_claimant=p_claimant,
   dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease)
 WHERE target.workspace_id=c.workspace_id
   AND target.application_id=c.application_id
   AND target.schedule_id=c.schedule_id;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.schedule_id,
   c.dispatch_generation+1;
END $$;

COMMENT ON COLUMN epm.python_program_schedule_version.execution_groups IS
    'Immutable verified group upper bound copied from the exact delegation';
COMMENT ON COLUMN epm.python_program_schedule_version.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope sealed at save time';
COMMENT ON COLUMN epm.python_program_schedule_state.dispatch_error_code IS
    'Durable fail-closed materialization block until a fresh version is activated';
COMMENT ON COLUMN epm.python_program_build.verified_groups IS
    'Immutable verified group upper bound admitted with this technical build';
COMMENT ON COLUMN epm.python_program_build.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at build admission';
