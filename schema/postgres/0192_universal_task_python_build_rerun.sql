-- Admit owner-only manual rerun for failed or cancelled Python builds.
-- A rerun creates a distinct build, preserves explicit source lineage and
-- reuses native admission to recheck current delegation, revisions,
-- publication, environment and rule-run authority.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=191) THEN
  RAISE EXCEPTION 'MIGRATION_0192_PREDECESSOR_0191_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.python_program_build
 ADD COLUMN rerun_of_build_id text,
 ADD CONSTRAINT python_program_build_rerun_not_self
  CHECK(rerun_of_build_id IS NULL OR rerun_of_build_id<>build_id),
 ADD CONSTRAINT python_program_build_rerun_source_fkey
  FOREIGN KEY(workspace_id,application_id,rerun_of_build_id)
  REFERENCES epm.python_program_build(workspace_id,application_id,build_id)
  ON DELETE RESTRICT;

CREATE INDEX python_program_build_rerun_source
 ON epm.python_program_build(workspace_id,application_id,rerun_of_build_id)
 WHERE rerun_of_build_id IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.project_python_build_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected_task_id text:='p:'||NEW.build_id;
DECLARE can_rerun boolean;
BEGIN
 normalized:=epm.normalized_python_build_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_PYTHON_BUILD_TASK_STATUS';
 END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 can_rerun:=NEW.status IN('failed','cancelled');
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
   'TechnicalExecution','PythonBuild',NEW.build_id,NEW.issuer,NEW.subject_id,
   'python.program.build','medium',normalized,NEW.status,
   NEW.status IN('accepted','ready','running','cancel_requested'),can_rerun,
   NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('accepted','ready','running','cancel_requested'),
   rerun_supported=can_rerun,updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='PythonBuild' AND source_id=NEW.build_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_python_build_task() FROM PUBLIC;

UPDATE epm.task t SET rerun_supported=b.status IN('failed','cancelled')
FROM epm.python_program_build b
WHERE t.workspace_id=b.workspace_id AND t.application_id=b.application_id
 AND t.source_family='PythonBuild' AND t.source_id=b.build_id;

-- The table inventory is unchanged. The reviewed FK graph changes because of
-- the new self-reference; deleting all workspace build rows in one statement
-- removes source and rerun rows together.
DO $migration$
DECLARE definition text;revised text;
DECLARE old_fingerprint constant text:=
 '8d33b8f39a6cb9165b44f87dae51b5bd3f0c45a0907d6b428070cddc1a337590';
DECLARE new_fingerprint constant text:=
 '85d945348d81f9384de3711063309443de20b599d3a5cca15c0ba59ef1ba7bb9';
BEGIN
 definition:=pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
 IF position(old_fingerprint IN definition)=0
    OR position(new_fingerprint IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0192_FINGERPRINT_DEFINITION_MISMATCH';
 END IF;
 revised:=replace(definition,old_fingerprint,new_fingerprint);
 EXECUTE revised;
END $migration$;
