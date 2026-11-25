DO $migration$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=408) THEN
   RAISE EXCEPTION 'MIGRATION_0409_REQUIRES_0408';
 END IF;
END $migration$;

-- A child may commit before the worker can copy its durable receipt to the
-- parent checkpoint. Settle the exact claim from the same publication cut.
CREATE OR REPLACE FUNCTION epm.application_rule_worker_settle(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
 w epm.application_rule_workflow%ROWTYPE;
 child record;
 old_point jsonb;
 points jsonb := '[]'::jsonb;
 n integer := 0;
 prior_committed boolean := true;
 any_committed boolean := false;
 valid boolean := true;
 outcome text;
BEGIN
 IF p_error IS NULL OR p_error NOT IN('APPLICATION_RULE_AUTHORIZATION_REVOKED','APPLICATION_RULE_STALE_CONTEXT') THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 -- A stale worker cannot take an application publication fence without a
 -- matching live claim. Recheck the same claim under the final parent lock.
 IF NOT EXISTS (SELECT 1 FROM epm.application_rule_workflow
   WHERE (workspace_id,application_id,workflow_id,claim_generation,claimant)=
         (p_workspace,p_application,p_workflow,p_generation,p_claimant)
     AND lease_until>clock_timestamp() AND status IN('accepted','running','cancel_requested')) THEN
   RETURN NULL;
 END IF;
 PERFORM 1 FROM epm.application_state WHERE (workspace_id,application_id)=(p_workspace,p_application)
 FOR UPDATE;
 SELECT * INTO w FROM epm.application_rule_workflow
 WHERE (workspace_id,application_id,workflow_id,claim_generation,claimant)=
       (p_workspace,p_application,p_workflow,p_generation,p_claimant)
   AND lease_until>clock_timestamp() AND status IN('accepted','running','cancel_requested')
 FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF w.status='cancel_requested' THEN
   outcome := w.status;
 ELSE
   FOR child IN
     SELECT c.unit_ordinal,c.job_id,j.status,j.admission_origin_kind,j.idempotency_key,j.issuer,j.subject_id,
       j.receipt_revision,j.program_digest,r.operation_id,r.committed_revision,r.command_digest,r.actor_id
     FROM epm.application_rule_workflow_child c
     JOIN epm.job j USING(workspace_id,application_id,job_id)
     LEFT JOIN epm.operation_receipt r
       ON (r.workspace_id,r.application_id,r.operation_id)=(j.workspace_id,j.application_id,j.job_id)
     WHERE (c.workspace_id,c.application_id,c.workflow_id)=(p_workspace,p_application,p_workflow)
     ORDER BY c.unit_ordinal
   LOOP
     n := n+1;
     old_point := (w.result->'checkpoints')->(n-1);
     IF child.unit_ordinal<>n OR n>(w.result->>'unitCount')::integer OR NOT prior_committed
       OR n>jsonb_array_length(w.result->'checkpoints')+1
       OR (child.issuer,child.subject_id,child.admission_origin_kind,child.idempotency_key)
          IS DISTINCT FROM (w.issuer,w.subject_id,'application_rule'::text,'rule-'||p_workflow||'-'||n)
       OR (old_point IS NOT NULL AND (old_point->>'jobId',old_point->>'ordinal')
           IS DISTINCT FROM (child.job_id,n::text))
     THEN valid := false; EXIT; END IF;
     -- Only an unconfirmed checkpoint may acquire a receipt during settlement.
     -- An earlier confirmed receipt with another identity needs inspection.
     IF old_point IS NOT NULL AND (
       jsonb_typeof(old_point->'committed') IS DISTINCT FROM 'boolean'
       OR (old_point->'receiptId') IS DISTINCT FROM
          (CASE WHEN old_point->'committed'='true'::jsonb
                THEN to_jsonb(child.job_id) ELSE 'null'::jsonb END)
     ) THEN valid := false; EXIT; END IF;
     prior_committed := child.status='published';
     IF prior_committed THEN
       IF child.receipt_revision IS NULL OR
         (child.operation_id,child.committed_revision,child.command_digest,child.actor_id)
           IS DISTINCT FROM (child.job_id,child.receipt_revision,child.program_digest,w.subject_id)
       THEN valid := false; EXIT; END IF;
       any_committed := true;
     ELSIF child.operation_id IS NOT NULL OR child.receipt_revision IS NOT NULL
       OR old_point->>'committed'='true' THEN
       valid := false; EXIT;
     END IF;
     points := points || jsonb_build_array(jsonb_build_object('ordinal',n,'jobId',child.job_id,
       'committed',prior_committed,'receiptId',CASE WHEN prior_committed THEN child.job_id END));
   END LOOP;
   valid := valid AND n>=jsonb_array_length(w.result->'checkpoints');
   outcome := CASE WHEN NOT valid THEN 'needs_inspection' WHEN any_committed THEN 'partially_published' ELSE 'failed' END;
   IF valid THEN w.result := jsonb_set(w.result,'{checkpoints}',points); END IF;
 END IF;
 UPDATE epm.application_rule_workflow SET
  worker_failures=CASE WHEN status='cancel_requested' THEN worker_failures+1 ELSE worker_failures END,
  worker_error_code=CASE WHEN status='cancel_requested' AND worker_failures+1>=3
    THEN 'WORKFLOW_CANCELLATION_RECOVERY_PARKED' ELSE p_error END,
  claim_generation=claim_generation+CASE WHEN status='cancel_requested' THEN 1 ELSE 0 END,
  status=outcome,result=jsonb_set(w.result,'{errorCode}',to_jsonb(p_error)),
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE (workspace_id,application_id,workflow_id,claim_generation,claimant)=
       (p_workspace,p_application,p_workflow,p_generation,p_claimant) AND lease_until>clock_timestamp()
 RETURNING status INTO outcome;
 RETURN outcome;
END $$;
