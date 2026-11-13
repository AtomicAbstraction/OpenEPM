-- Admit manual rerun for only reconstructible terminal direct-write jobs.
-- Delegated, dependent and calculation jobs remain fail-closed nonrerunnable.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=190) THEN
  RAISE EXCEPTION 'MIGRATION_0191_PREDECESSOR_0190_REQUIRED';
 END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.project_job_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE can_rerun boolean;
BEGIN
 normalized:=epm.normalized_job_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_JOB_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 can_rerun:=NEW.status IN('failed','cancelled')
  AND NEW.function_name IN(
   'facts.numeric.batch','facts.text.batch','facts.line-detail.replace')
  AND NEW.python_workflow_id IS NULL
  AND NOT EXISTS(SELECT 1 FROM epm.job_dependency d
    WHERE d.workspace_id=NEW.workspace_id
      AND d.application_id=NEW.application_id AND d.job_id=NEW.job_id);
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
   task_class,source_family,source_id,issuer,subject_id,function_name,
   resource_class,status,native_status,interruptible,rerun_supported,
   created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,NEW.job_id,task_sequence,
   'BusinessExecution','Job',NEW.job_id,NEW.issuer,NEW.subject_id,
   NEW.function_name,NEW.resource_class,normalized,NEW.status,
   NEW.status IN('accepted','ready','running','staged','cancel_requested'),
   can_rerun,NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN(
    'accepted','ready','running','staged','cancel_requested'),
   rerun_supported=can_rerun,updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='Job' AND source_id=NEW.job_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=NEW.job_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,NEW.job_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NEW.receipt_revision,NEW.error_code,
  transaction_timestamp());RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_job_task() FROM PUBLIC;

UPDATE epm.task t SET rerun_supported=(
 j.status IN('failed','cancelled')
 AND j.function_name IN(
  'facts.numeric.batch','facts.text.batch','facts.line-detail.replace')
 AND j.python_workflow_id IS NULL
 AND NOT EXISTS(SELECT 1 FROM epm.job_dependency d
  WHERE d.workspace_id=j.workspace_id AND d.application_id=j.application_id
   AND d.job_id=j.job_id))
FROM epm.job j WHERE t.workspace_id=j.workspace_id
 AND t.application_id=j.application_id AND t.source_family='Job'
 AND t.source_id=j.job_id;

-- No relation, key or reset inventory changes are introduced.
