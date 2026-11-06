-- Project sealed-plan business workflows into the universal task log.  Native
-- workflow/child-job records remain authoritative and preserve partial commit.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=177) THEN
    RAISE EXCEPTION 'MIGRATION_0178_PREDECESSOR_0177_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task DROP CONSTRAINT task_status_check;
ALTER TABLE epm.task_event DROP CONSTRAINT task_event_status_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','p:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')),
  ADD CONSTRAINT task_source_family_check CHECK
    (source_family IN ('Job','CubeAggregate','PythonBuild','PythonWorkflow')),
  ADD CONSTRAINT task_status_check CHECK(status IN
    ('Accepted','Waiting','Running','InterruptRequested','Interrupted',
     'Succeeded','PartiallySucceeded','Failed','NeedsInspection')),
  ADD COLUMN source_python_workflow_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='PythonWorkflow' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_python_workflow_fkey
    FOREIGN KEY(workspace_id,application_id,source_python_workflow_id)
    REFERENCES epm.python_program_workflow(workspace_id,application_id,workflow_id)
    ON DELETE CASCADE;
ALTER TABLE epm.task_event ADD CONSTRAINT task_event_status_check CHECK(status IN
  ('Accepted','Waiting','Running','InterruptRequested','Interrupted',
   'Succeeded','PartiallySucceeded','Failed','NeedsInspection'));

CREATE FUNCTION epm.normalized_python_workflow_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'running' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'published' THEN 'Succeeded'
  WHEN 'partially_published' THEN 'PartiallySucceeded'
  WHEN 'failed' THEN 'Failed'
  WHEN 'needs_inspection' THEN 'NeedsInspection'
END;

CREATE FUNCTION epm.project_python_workflow_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'w:'||NEW.workflow_id;
BEGIN
  normalized := epm.normalized_python_workflow_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_PYTHON_WORKFLOW_TASK_STATUS'; END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN
    INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
      VALUES(NEW.workspace_id,NEW.application_id,1)
      ON CONFLICT(workspace_id,application_id) DO UPDATE
        SET last_sequence=epm.task_cursor.last_sequence+1
      RETURNING last_sequence INTO task_sequence;
    INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
      task_class,source_family,source_id,issuer,subject_id,function_name,
      resource_class,status,native_status,interruptible,rerun_supported,
      created_at,updated_at)
    VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
      'BusinessExecution','PythonWorkflow',NEW.workflow_id,NEW.issuer,
      NEW.subject_id,'python.program.run','long',normalized,NEW.status,
      NEW.status IN ('accepted','running','cancel_requested'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN ('accepted','running','cancel_requested'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id AND source_family='PythonWorkflow'
      AND source_id=NEW.workflow_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
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
REVOKE ALL ON FUNCTION epm.normalized_python_workflow_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_python_workflow_task() FROM PUBLIC;

WITH numbered AS (
  SELECT w.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY w.workspace_id,w.application_id
    ORDER BY w.created_at,w.workflow_id) AS task_sequence
  FROM epm.python_program_workflow w
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'w:'||workflow_id,task_sequence,
  'BusinessExecution','PythonWorkflow',workflow_id,issuer,subject_id,
  'python.program.run','long',epm.normalized_python_workflow_task_status(status),
  status,status IN ('accepted','running','cancel_requested'),false,
  created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'w:'||workflow_id,1,
  epm.normalized_python_workflow_task_status(status),status,claim_generation,
  NULL,worker_error_code,updated_at FROM epm.python_program_workflow;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_python_workflow_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation ON epm.python_program_workflow
FOR EACH ROW EXECUTE FUNCTION epm.project_python_workflow_task();

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'f73737f97effcee367f2d1e982e8f0d05be5e727ccd221532afd2003d4c17ea6';
DECLARE new_fingerprint constant text :=
  'c60d12f083dc86e7bce3f0e8d894289ee20694f33a9fbcdd19ae08409b151ca4';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0178_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
