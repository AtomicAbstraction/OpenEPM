-- Fair background advancement and universal task projection for immutable
-- generic application rules. The sealed rule plan and ordinary child jobs
-- remain authoritative; this migration creates no second execution engine.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=217) THEN
  RAISE EXCEPTION 'MIGRATION_0218_PREDECESSOR_0217_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.application_rule_workflow
 ADD COLUMN worker_failures integer NOT NULL DEFAULT 0 CHECK(worker_failures>=0);

CREATE OR REPLACE FUNCTION epm.application_rule_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE epm.application_rule_workflow SET
  worker_failures=worker_failures+1,
  worker_error_code='APPLICATION_RULE_LEASE_EXPIRED',
  status=CASE WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
  result=CASE WHEN worker_failures+1>=3 THEN jsonb_set(result,'{errorCode}',
    to_jsonb('APPLICATION_RULE_LEASE_EXPIRED'::text)) ELSE result END,
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp()
  AND status IN('accepted','running','cancel_requested');
 GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_claim(
 p_claimant text,p_lease_seconds integer,p_global_limit integer,
 p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,workflow_id text,
 rule_id text,issuer text,subject_id text,status text,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
    OR p_lease_seconds NOT BETWEEN 30 AND 300
    OR p_global_limit NOT BETWEEN 1 AND 10000
    OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
    OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application.rule.dispatch',0));
 IF(SELECT count(*) FROM epm.application_rule_workflow
    WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global_limit
 THEN RETURN;END IF;
 SELECT w.* INTO candidate FROM epm.application_rule_workflow w
 JOIN epm.application a USING(workspace_id,application_id)
 JOIN epm.application_state s USING(workspace_id,application_id)
 JOIN epm.workspace ws USING(workspace_id)
 LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
 WHERE w.status IN('accepted','running','cancel_requested')
  AND w.claimant IS NULL AND a.status='Active' AND ws.status='Active'
  AND s.processing_mode='Active'
  AND(SELECT count(*) FROM epm.application_rule_workflow active
      WHERE active.workspace_id=w.workspace_id AND active.claimant IS NOT NULL
       AND active.lease_until>clock_timestamp())<p_workspace_limit
  AND(SELECT count(*) FROM epm.application_rule_workflow active
      WHERE active.workspace_id=w.workspace_id
       AND active.application_id=w.application_id AND active.claimant IS NOT NULL
       AND active.lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,w.updated_at,w.workflow_id
 FOR UPDATE OF w SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_rule_workflow w SET
  claim_generation=w.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE w.workspace_id=candidate.workspace_id
  AND w.application_id=candidate.application_id
  AND w.workflow_id=candidate.workflow_id;
 candidate.claim_generation:=candidate.claim_generation+1;
 INSERT INTO epm.worker_workspace_dispatch(
  workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.workflow_id,candidate.rule_id,candidate.issuer,candidate.subject_id,
  candidate.status,candidate.claim_generation;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_renew(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_RENEW_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_rule_workflow SET
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested');RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_release(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.application_rule_workflow SET claimant=NULL,lease_until=NULL,
  worker_failures=0,worker_error_code=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp();RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_settle(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_error NOT IN('APPLICATION_RULE_AUTHORIZATION_REVOKED',
                   'APPLICATION_RULE_STALE_CONTEXT') THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_rule_workflow SET
  status=CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(
   coalesce(result->'checkpoints','[]'::jsonb)) c
   WHERE(c->>'committed')::boolean) THEN 'partially_published' ELSE 'failed' END,
  result=jsonb_set(result,'{errorCode}',to_jsonb(p_error)),
  claimant=NULL,lease_until=NULL,worker_error_code=p_error,
  updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested');RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION epm.application_rule_worker_unexpected(
 p_workspace text,p_application text,p_workflow text,p_generation bigint,
 p_claimant text,p_error text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error IS NULL OR length(p_error) NOT BETWEEN 1 AND 200 THEN
  RAISE EXCEPTION 'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_rule_workflow SET worker_failures=worker_failures+1,
  worker_error_code=p_error,
  status=CASE WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
  result=CASE WHEN worker_failures+1>=3 THEN
   jsonb_set(result,'{errorCode}',to_jsonb(p_error)) ELSE result END,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND workflow_id=p_workflow AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>clock_timestamp()
  AND status IN('accepted','running','cancel_requested')
 RETURNING CASE WHEN worker_failures>=3 THEN 'needs_inspection' ELSE 'retry' END
 INTO outcome;RETURN outcome;
END $$;

REVOKE ALL ON FUNCTION epm.application_rule_worker_recover(),
 epm.application_rule_worker_claim(text,integer,integer,integer,integer),
 epm.application_rule_worker_renew(text,text,text,bigint,text,integer),
 epm.application_rule_worker_release(text,text,text,bigint,text),
 epm.application_rule_worker_settle(text,text,text,bigint,text,text),
 epm.application_rule_worker_unexpected(text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_rule_worker_recover(),
 epm.application_rule_worker_claim(text,integer,integer,integer,integer),
 epm.application_rule_worker_renew(text,text,text,bigint,text,integer),
 epm.application_rule_worker_release(text,text,text,bigint,text),
 epm.application_rule_worker_settle(text,text,text,bigint,text,text),
 epm.application_rule_worker_unexpected(text,text,text,bigint,text,text) TO epm_worker;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task ADD CONSTRAINT task_task_id_check CHECK(
 task_id~'^[0-9a-f]{32}$'
 OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','t:','u:','w:')
   AND substring(task_id from 3)~'^[0-9a-f]{32}$')
 OR task_id~'^d:[0-9a-f]{64}$'
 OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
   AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
 'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
 'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
 'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
 'ExpressionRuleSequence','FullAggregateSequence','SourceBatch',
 'AssignmentEscalation','ApplicationTaskFlowOccurrence','ApplicationRuleWorkflow')),
 ADD COLUMN source_application_rule_workflow_id text GENERATED ALWAYS AS
  (CASE WHEN source_family='ApplicationRuleWorkflow' THEN source_id END) STORED,
 ADD CONSTRAINT task_source_application_rule_workflow_fkey
  FOREIGN KEY(workspace_id,application_id,source_application_rule_workflow_id)
  REFERENCES epm.application_rule_workflow(workspace_id,application_id,workflow_id)
  ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_application_rule_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE RETURN CASE native
 WHEN 'accepted' THEN 'Accepted' WHEN 'running' THEN 'Running'
 WHEN 'cancel_requested' THEN 'InterruptRequested'
 WHEN 'cancelled' THEN 'Interrupted' WHEN 'published' THEN 'Succeeded'
 WHEN 'partially_published' THEN 'PartiallySucceeded'
 WHEN 'failed' THEN 'Failed' WHEN 'needs_inspection' THEN 'NeedsInspection' END;

CREATE FUNCTION epm.project_application_rule_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected text:='u:'||NEW.workflow_id;
BEGIN
 normalized:=epm.normalized_application_rule_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_APPLICATION_RULE_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected,task_sequence,
   'BusinessExecution','ApplicationRuleWorkflow',NEW.workflow_id,NEW.issuer,
   NEW.subject_id,'application.rule.run','long',normalized,NEW.status,
   NEW.status IN('accepted','running','cancel_requested'),false,
   NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('accepted','running','cancel_requested'),
   updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id
   AND source_family='ApplicationRuleWorkflow' AND source_id=NEW.workflow_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.worker_error_code,
  transaction_timestamp());RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_application_rule_task_status(text),
 epm.project_application_rule_task() FROM PUBLIC;

WITH numbered AS(
 SELECT w.*,coalesce(c.last_sequence,0)+row_number()OVER(
  PARTITION BY w.workspace_id,w.application_id ORDER BY w.created_at,w.workflow_id)
  AS task_sequence FROM epm.application_rule_workflow w
 LEFT JOIN epm.task_cursor c USING(workspace_id,application_id))
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'u:'||workflow_id,task_sequence,
 'BusinessExecution','ApplicationRuleWorkflow',workflow_id,issuer,subject_id,
 'application.rule.run','long',epm.normalized_application_rule_task_status(status),
 status,status IN('accepted','running','cancel_requested'),false,created_at,updated_at
FROM numbered;
INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'u:'||workflow_id,1,
 epm.normalized_application_rule_task_status(status),status,claim_generation,
 NULL,worker_error_code,updated_at FROM epm.application_rule_workflow;
INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;
CREATE TRIGGER aa_application_rule_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.application_rule_workflow FOR EACH ROW
EXECUTE FUNCTION epm.project_application_rule_task();

-- The task projection FK changes the reviewed reset graph. Its replacement
-- fingerprint was derived on an isolated clean 0001-0218 schema.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
 'd4c3b3b04a02295c411d1310870df538b83b6a29bf61d8d1a964b48df66ec8c1';
DECLARE new_fingerprint constant text:=
 '1358844c2bc77c9d5023f8b0cca542642ca18317c4d586c3984cdd539c9d0bc3';
BEGIN
 definition:=pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
 IF position(old_fingerprint IN definition)=0
    OR position(new_fingerprint IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0218_FINGERPRINT_DEFINITION_MISMATCH';END IF;
 revised:=replace(definition,old_fingerprint,new_fingerprint);
 EXECUTE revised;
END $migration$;
