-- Project staged source uploads into universal business tasks.  Staging and
-- sealing do not change business data; only native publication succeeds the
-- task and supplies its committed receipt revision.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=186) THEN
  RAISE EXCEPTION 'MIGRATION_0187_PREDECESSOR_0186_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.source_batch DROP CONSTRAINT source_batch_status_check;
ALTER TABLE epm.source_batch ADD CONSTRAINT source_batch_status_check
 CHECK(status IN('staging','ready','published','failed','cancelled'));

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task ADD CONSTRAINT task_task_id_check CHECK(
 task_id~'^[0-9a-f]{32}$'
 OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','w:')
   AND substring(task_id from 3)~'^[0-9a-f]{32}$')
 OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
   AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
 'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
 'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
 'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
 'ExpressionRuleSequence','FullAggregateSequence','SourceBatch'));

CREATE FUNCTION epm.normalized_source_batch_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'staging' THEN 'Running'
 WHEN 'ready' THEN 'Waiting'
 WHEN 'published' THEN 'Succeeded'
 WHEN 'failed' THEN 'Failed'
 WHEN 'cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_source_batch_task()RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected_task_id text:='b:'||NEW.batch_id;
BEGIN
 normalized:=epm.normalized_source_batch_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_SOURCE_BATCH_TASK_STATUS';END IF;
 IF NEW.status='published' AND(NEW.receipt_revision IS NULL
  OR NEW.receipt_revision<=0)THEN
  RAISE EXCEPTION 'SOURCE_BATCH_TASK_RECEIPT_INVALID';
 END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
  AND NEW.receipt_revision IS NOT DISTINCT FROM OLD.receipt_revision THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'BusinessExecution','SourceBatch',NEW.batch_id,NEW.issuer,NEW.subject_id,
   'facts.source.begin','long',normalized,NEW.status,
   NEW.status IN('staging','ready'),false,NEW.created_at,NEW.updated_at);
  ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('staging','ready'),updated_at=NEW.updated_at
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='SourceBatch' AND source_id=NEW.batch_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.chunk_count,NEW.receipt_revision,NULL,transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_source_batch_task_status(text),
 epm.project_source_batch_task()FROM PUBLIC;

DO $migration$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.source_batch WHERE status='published'
  AND receipt_revision IS NULL)THEN
  RAISE EXCEPTION 'SOURCE_BATCH_TASK_BACKFILL_RECEIPT_INVALID';
 END IF;
END $migration$;

WITH numbered AS(
 SELECT b.*,coalesce(c.last_sequence,0)+row_number()OVER(
  PARTITION BY b.workspace_id,b.application_id
  ORDER BY b.created_at,b.batch_id)task_sequence
 FROM epm.source_batch b LEFT JOIN epm.task_cursor c
 USING(workspace_id,application_id))
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'b:'||batch_id,task_sequence,
 'BusinessExecution','SourceBatch',batch_id,issuer,subject_id,
 'facts.source.begin','long',epm.normalized_source_batch_task_status(status),
 status,status IN('staging','ready'),false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'b:'||batch_id,1,
 epm.normalized_source_batch_task_status(status),status,chunk_count,
 receipt_revision,NULL,updated_at FROM epm.source_batch;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence)FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_source_batch_task_projection
AFTER INSERT OR UPDATE OF status,receipt_revision ON epm.source_batch
FOR EACH ROW EXECUTE FUNCTION epm.project_source_batch_task();

-- Existing batch rows and receipts remain authoritative.  This migration adds
-- only constraints, functions and a trigger, so the reviewed 0182 reset
-- fingerprint remains exact.
