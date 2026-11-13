-- Admit owner-only manual rerun for failed/cancelled Python workflows that
-- have no committed unit.  The new workflow reuses the exact sealed plan but
-- receives a distinct identity and rechecks current native execution gates.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=193) THEN
  RAISE EXCEPTION 'MIGRATION_0194_PREDECESSOR_0193_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.python_program_workflow
 ADD COLUMN rerun_of_workflow_id text,
 ADD CONSTRAINT python_program_workflow_rerun_not_self
  CHECK(rerun_of_workflow_id IS NULL OR rerun_of_workflow_id<>workflow_id),
 ADD CONSTRAINT python_program_workflow_rerun_source_fkey
  FOREIGN KEY(workspace_id,application_id,rerun_of_workflow_id)
  REFERENCES epm.python_program_workflow(workspace_id,application_id,workflow_id)
  ON DELETE RESTRICT;

CREATE INDEX python_program_workflow_rerun_source
 ON epm.python_program_workflow(
  workspace_id,application_id,rerun_of_workflow_id)
 WHERE rerun_of_workflow_id IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.project_python_workflow_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected_task_id text:='w:'||NEW.workflow_id;
DECLARE can_rerun boolean;
BEGIN
 normalized:=epm.normalized_python_workflow_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_PYTHON_WORKFLOW_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 can_rerun:=NEW.status IN('failed','cancelled') AND NOT EXISTS(
  SELECT 1 FROM jsonb_array_elements(
   coalesce(NEW.result->'checkpoints','[]'::jsonb)) AS checkpoint
  WHERE checkpoint->>'committed'='true');
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
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'BusinessExecution','PythonWorkflow',NEW.workflow_id,NEW.issuer,
   NEW.subject_id,'python.program.run','long',normalized,NEW.status,
   NEW.status IN('accepted','running','cancel_requested'),can_rerun,
   NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('accepted','running','cancel_requested'),
   rerun_supported=can_rerun,updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='PythonWorkflow' AND source_id=NEW.workflow_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.worker_error_code,
  transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_python_workflow_task() FROM PUBLIC;

UPDATE epm.task t SET rerun_supported=(w.status IN('failed','cancelled')
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
  coalesce(w.result->'checkpoints','[]'::jsonb)) AS checkpoint
  WHERE checkpoint->>'committed'='true'))
FROM epm.python_program_workflow w
WHERE t.workspace_id=w.workspace_id AND t.application_id=w.application_id
 AND t.source_family='PythonWorkflow' AND t.source_id=w.workflow_id;

-- The table inventory is unchanged. The reviewed FK graph changes because of
-- the new self-reference; a workspace reset deletes both rows together.
DO $migration$
DECLARE definition text;revised text;
DECLARE old_fingerprint constant text:=
 '343305de079073f393f10966dd4781c1e4e8d555e60635042a9c6ee590d1e9e7';
DECLARE new_fingerprint constant text:=
 '9a442a6dbf353ec15f1dc1cf5a9a595d800e3bc91cab3432011837389071946a';
BEGIN
 definition:=pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
 IF position(old_fingerprint IN definition)=0
    OR position(new_fingerprint IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0194_FINGERPRINT_DEFINITION_MISMATCH';
 END IF;
 revised:=replace(definition,old_fingerprint,new_fingerprint);
 EXECUTE revised;
END $migration$;
