-- Bounded, generation-fenced recovery for scheduled Python execution.
-- Child build/run admission is already keyed by the occurrence identifier, so
-- a retry can reconcile a lost acknowledgement without creating a second
-- child.  Persist failure/backoff state on the occurrence and quarantine a
-- poison item after three failed worker ownership generations.
ALTER TABLE epm.python_program_occurrence
  ADD COLUMN worker_failures integer NOT NULL DEFAULT 0
    CHECK(worker_failures BETWEEN 0 AND 3);
ALTER TABLE epm.python_program_occurrence
  ADD COLUMN next_attempt_at timestamptz;

CREATE OR REPLACE FUNCTION epm.python_occurrence_worker_claim(
 p_claimant text,p_lease integer,p_global integer,p_workspace integer,
 p_application integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
 status text,claim_generation bigint)
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
 SELECT o.* INTO c FROM epm.python_program_occurrence o
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE o.status IN
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
   c.claim_generation+1;
END $$;

CREATE FUNCTION epm.python_occurrence_worker_unexpected(
 p_workspace text,p_application text,p_occurrence text,p_generation bigint,
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
 WHERE workspace_id=p_workspace AND application_id=p_application
   AND occurrence_id=p_occurrence AND claim_generation=p_generation
   AND claimant=p_claimant AND lease_until>clock_timestamp()
   AND status IN
     ('running','building','running_program','cancel_requested')
 RETURNING CASE WHEN worker_failures>=3
   THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.python_occurrence_worker_unexpected(
 text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_occurrence_worker_unexpected(
 text,text,text,bigint,text,text) TO epm_worker;

COMMENT ON FUNCTION epm.python_occurrence_worker_unexpected(
 text,text,text,bigint,text,text) IS
 'Generation-fenced bounded settlement for an unexpected Python schedule worker fault; returns retry, needs_inspection, or NULL for a stale owner.';
