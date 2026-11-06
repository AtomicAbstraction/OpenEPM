-- Bound Python schedule materialization faults.  Explicit failures and dead
-- worker leases share one generation-fenced settlement policy; occurrence
-- reconciliation from 0270 is deliberately unchanged.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=274) THEN
  RAISE EXCEPTION 'MIGRATION_0275_REQUIRES_0274';
 END IF;
END $$;

ALTER TABLE epm.python_program_schedule_state
 ADD COLUMN dispatch_failure_count integer NOT NULL DEFAULT 0
  CHECK(dispatch_failure_count BETWEEN 0 AND 3);
ALTER TABLE epm.python_program_schedule_state
 ADD COLUMN dispatch_next_attempt_at timestamptz;

CREATE FUNCTION epm.python_schedule_worker_settle_unexpected(
 p_workspace text,p_application text,p_schedule text,p_generation bigint,
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
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant
 RETURNING CASE WHEN dispatch_failure_count>=3
  THEN 'blocked' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

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
 WHERE s.active_version IS NOT NULL AND s.dispatch_error_code IS NULL
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
   c.application_id,c.schedule_id,c.dispatch_generation,c.dispatch_claimant,
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
  c.dispatch_generation+1;
END $$;

CREATE OR REPLACE FUNCTION epm.python_schedule_worker_release(
 p_workspace text,p_application text,p_schedule text,p_generation bigint,
 p_claimant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer;
BEGIN
 UPDATE epm.python_program_schedule_state SET dispatch_claimant=NULL,
  dispatch_lease_until=NULL,dispatch_failure_count=0,
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant;
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;
END $$;

REVOKE ALL ON FUNCTION epm.python_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text) TO epm_worker;

COMMENT ON FUNCTION epm.python_schedule_worker_settle_unexpected(
 text,text,text,bigint,text,text) IS
 'Generation-fenced bounded settlement shared by explicit materialization faults and expired schedule claims.';
