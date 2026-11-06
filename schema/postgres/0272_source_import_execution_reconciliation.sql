-- Bound source-import worker retries and give explicit failures and expired
-- leases one generation-fenced settlement contract.  Publication recovery
-- remains receipt-first in the worker; this migration only settles an attempt
-- after that reconciliation did not find the atomic source-batch result.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=271) THEN
    RAISE EXCEPTION 'MIGRATION_0272_REQUIRES_0271';
  END IF;
END $$;

ALTER TABLE epm.source_import_execution
  ADD COLUMN attempt_count integer NOT NULL DEFAULT 0
    CHECK(attempt_count BETWEEN 0 AND 3);
ALTER TABLE epm.source_import_execution
  ADD COLUMN next_attempt_at timestamptz;

CREATE FUNCTION epm.source_import_execution_worker_settle_failure(
  p_workspace text,p_application text,p_request text,p_generation bigint,
  p_claimant text,p_error text,p_terminal boolean) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error IS NULL OR length(p_error) NOT BETWEEN 1 AND 200
    OR p_terminal IS NULL THEN
   RAISE EXCEPTION 'IMPORT_EXECUTION_SETTLEMENT_INVALID'
     USING ERRCODE='22023';
 END IF;
 UPDATE epm.source_import_execution SET
   attempt_count=LEAST(3,attempt_count+1),
   status=CASE WHEN cancel_requested THEN 'Cancelled'
               WHEN p_terminal OR attempt_count+1>=3 THEN 'Failed'
               ELSE 'Accepted' END,
   error_code=CASE WHEN cancel_requested THEN NULL
                   WHEN NOT p_terminal AND attempt_count+1>=3
                     THEN 'IMPORT_EXECUTION_RETRY_LIMIT'
                   ELSE p_error END,
   next_attempt_at=CASE
     WHEN cancel_requested OR p_terminal OR attempt_count+1>=3 THEN NULL
     ELSE clock_timestamp()+make_interval(secs=>
       CASE attempt_count WHEN 0 THEN 1 ELSE 5 END) END,
   claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
   AND request_id=p_request AND claim_generation=p_generation
   AND claimant=p_claimant AND status IN ('Claimed','Publishing')
 RETURNING CASE WHEN status='Accepted' THEN 'retry' ELSE status END
 INTO outcome;
 RETURN outcome;
END $$;
REVOKE ALL ON FUNCTION epm.source_import_execution_worker_settle_failure(
 text,text,text,bigint,text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.source_import_execution_worker_settle_failure(
 text,text,text,bigint,text,text,boolean) TO epm_worker;

CREATE OR REPLACE FUNCTION epm.source_import_execution_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,request_id text,
  claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 10 AND 600
  OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
   RAISE EXCEPTION 'IMPORT_EXECUTION_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.import.execution.dispatch',0));
 SELECT r.* INTO candidate FROM epm.source_import_execution r
 JOIN epm.application a ON a.workspace_id=r.workspace_id AND a.application_id=r.application_id
 JOIN epm.application_state s ON s.workspace_id=r.workspace_id AND s.application_id=r.application_id
 JOIN epm.workspace w ON w.workspace_id=r.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=r.workspace_id
 WHERE (r.status='Accepted' OR
       (r.status IN ('Claimed','Publishing') AND r.lease_until<=clock_timestamp()))
  AND (r.next_attempt_at IS NULL OR r.next_attempt_at<=clock_timestamp())
  AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
  AND (SELECT count(*) FROM epm.source_import_execution x
       WHERE x.status IN ('Claimed','Publishing') AND x.lease_until>clock_timestamp())<p_global_limit
  AND (SELECT count(*) FROM epm.source_import_execution x
       WHERE x.workspace_id=r.workspace_id AND x.status IN ('Claimed','Publishing')
       AND x.lease_until>clock_timestamp())<p_workspace_limit
  AND (SELECT count(*) FROM epm.source_import_execution x
       WHERE x.workspace_id=r.workspace_id AND x.application_id=r.application_id
       AND x.status IN ('Claimed','Publishing') AND x.lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,r.created_at,r.workspace_id,
  r.application_id,r.request_id FOR UPDATE OF r SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;

 -- A dead owner is settled exactly like an explicit retryable failure.  Do
 -- not hand the same row to a successor in this transaction: the durable due
 -- time lets other applications and work proceed before this row is retried.
 IF candidate.status IN ('Claimed','Publishing') THEN
   PERFORM epm.source_import_execution_worker_settle_failure(
     candidate.workspace_id,candidate.application_id,candidate.request_id,
     candidate.claim_generation,candidate.claimant,
     'IMPORT_EXECUTION_RETRYABLE_CONTROL_LOSS',false);
   RETURN;
 END IF;

 UPDATE epm.source_import_execution r SET status='Claimed',
  claim_generation=r.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  next_attempt_at=NULL,error_code=NULL,updated_at=transaction_timestamp()
 WHERE r.workspace_id=candidate.workspace_id AND r.application_id=candidate.application_id
  AND r.request_id=candidate.request_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,candidate.request_id,
  candidate.claim_generation+1;
END $$;

COMMENT ON FUNCTION epm.source_import_execution_worker_settle_failure(
 text,text,text,bigint,text,text,boolean) IS
 'Generation-fenced bounded settlement after receipt-first source-import reconciliation; explicit retryable failures and expired leases share the same three-attempt policy.';
