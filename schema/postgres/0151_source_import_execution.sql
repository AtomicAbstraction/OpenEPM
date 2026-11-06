-- Durable technical execution of a sealed source batch. Migration 0150 is
-- intentionally owned by the preceding integration packet.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=150) THEN
    RAISE EXCEPTION 'MIGRATION_0151_REQUIRES_0150';
  END IF;
END $$;

CREATE TABLE epm.source_import_execution (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[0-9a-f]{32}$'),
    batch_id text NOT NULL,
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
      CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    preview_token text NOT NULL CHECK (length(preview_token) BETWEEN 1 AND 16384),
    status text NOT NULL CHECK (status IN
      ('Accepted','Claimed','Publishing','Completed','Failed','Cancelled')),
    claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation>=0),
    claimant text CHECK (claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
    lease_until timestamptz,
    cancel_requested boolean NOT NULL DEFAULT false,
    result jsonb,
    error_code text CHECK (error_code IS NULL OR length(error_code)<=200),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,request_id),
    UNIQUE (workspace_id,application_id,issuer,subject_id,idempotency_key),
    FOREIGN KEY (workspace_id,application_id,batch_id)
      REFERENCES epm.source_batch(workspace_id,application_id,batch_id)
      ON DELETE RESTRICT,
    CHECK ((status IN ('Claimed','Publishing')) =
           (claimant IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (status<>'Completed' OR result IS NOT NULL),
    CHECK (status<>'Cancelled' OR cancel_requested)
);
CREATE INDEX source_import_execution_dispatch ON epm.source_import_execution
  (workspace_id,application_id,status,lease_until,created_at);

GRANT SELECT,INSERT,UPDATE ON epm.source_import_execution TO epm_runtime;
GRANT SELECT,UPDATE ON epm.source_import_execution TO epm_worker;
GRANT SELECT ON epm.source_import_execution TO epm_lifecycle;
ALTER TABLE epm.source_import_execution ENABLE ROW LEVEL SECURITY;
CREATE POLICY source_import_execution_runtime_scope
  ON epm.source_import_execution TO epm_runtime
  USING (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
  WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
CREATE POLICY source_import_execution_worker_scope
  ON epm.source_import_execution TO epm_worker
  USING (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true))
  WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true));
CREATE POLICY source_import_execution_lifecycle_read
  ON epm.source_import_execution FOR SELECT TO epm_lifecycle
  USING (workspace_id=current_setting('epm.workspace_id',true));

CREATE FUNCTION epm.source_import_execution_worker_claim(
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
 UPDATE epm.source_import_execution r SET status='Claimed',
  claim_generation=r.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  error_code=NULL,updated_at=transaction_timestamp()
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
REVOKE ALL ON FUNCTION epm.source_import_execution_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.source_import_execution_worker_claim(text,integer,integer,integer,integer) TO epm_worker;

-- Add the child before source_batch in the owner reset dependency inventory.
DO $$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'source_batch_row','source_batch_chunk',$pattern$;
DECLARE new_pair text := $pattern$'source_import_execution','source_batch_row','source_batch_chunk',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0151_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0151_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $$;

-- Refuse destructive reset while an import can still publish or be adopted.
DO $$
DECLARE definition text; revised text;
DECLARE anchor text := $pattern$    IF EXISTS (SELECT 1 FROM epm.source_batch WHERE workspace_id=p_workspace_id
        AND status IN ('staging','ready')) THEN
        RAISE EXCEPTION 'UNPUBLISHED_SOURCE_BATCHES';
    END IF;$pattern$;
DECLARE guard text := $pattern$    IF EXISTS (SELECT 1 FROM epm.source_import_execution
        WHERE workspace_id=p_workspace_id
          AND status IN ('Accepted','Claimed','Publishing')) THEN
        RAISE EXCEPTION 'UNSETTLED_IMPORT_EXECUTIONS';
    END IF;
$pattern$;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(anchor IN definition)=0 OR position(guard IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0151_ACTIVE_GUARD_MISMATCH';
 END IF;
 revised:=replace(definition,anchor,guard||anchor);
 IF revised=definition THEN RAISE EXCEPTION 'RESET_0151_ACTIVE_GUARD_MISMATCH'; END IF;
 EXECUTE revised;
END $$;
