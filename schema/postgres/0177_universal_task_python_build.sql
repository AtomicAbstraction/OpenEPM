-- Project isolated Python plan builds into the universal technical task log.
-- The build record remains authoritative; this projection never executes
-- authored source, seals a plan, or publishes business effects.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=176) THEN
    RAISE EXCEPTION 'MIGRATION_0177_PREDECESSOR_0176_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','p:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')),
  ADD CONSTRAINT task_source_family_check CHECK
    (source_family IN ('Job','CubeAggregate','PythonBuild')),
  ADD COLUMN source_python_build_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='PythonBuild' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_python_build_fkey
    FOREIGN KEY(workspace_id,application_id,source_python_build_id)
    REFERENCES epm.python_program_build(workspace_id,application_id,build_id)
    ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_python_build_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'sealed' THEN 'Succeeded'
  WHEN 'failed' THEN 'Failed'
END;

CREATE FUNCTION epm.project_python_build_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'p:'||NEW.build_id;
BEGIN
  normalized := epm.normalized_python_build_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_PYTHON_BUILD_TASK_STATUS'; END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation THEN
    RETURN NEW;
  END IF;
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
      'TechnicalExecution','PythonBuild',NEW.build_id,NEW.issuer,NEW.subject_id,
      'python.program.build','medium',normalized,NEW.status,
      NEW.status IN ('accepted','ready','running','cancel_requested'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('accepted','ready','running','cancel_requested'),
      updated_at=NEW.updated_at
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND source_family='PythonBuild' AND source_id=NEW.build_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND task_id=projected_task_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_python_build_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_python_build_task() FROM PUBLIC;

WITH numbered AS (
  SELECT b.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY b.workspace_id,b.application_id
    ORDER BY b.created_at,b.build_id) AS task_sequence
  FROM epm.python_program_build b
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'p:'||build_id,task_sequence,
  'TechnicalExecution','PythonBuild',build_id,issuer,subject_id,
  'python.program.build','medium',
  epm.normalized_python_build_task_status(status),status,
  status IN ('accepted','ready','running','cancel_requested'),false,
  created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'p:'||build_id,1,
  epm.normalized_python_build_task_status(status),status,claim_generation,
  NULL,error_code,updated_at FROM epm.python_program_build;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id
ON CONFLICT(workspace_id,application_id) DO UPDATE
SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_python_build_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation ON epm.python_program_build
FOR EACH ROW EXECUTE FUNCTION epm.project_python_build_task();

-- The reset inventory already deletes task_event/task/task_cursor before the
-- native build tables.  Update only its reviewed structural fingerprint.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '82b7b16966f420a3db8c033f34f02cc9f4334ad6c74b96e0c211a661948bbb6d';
DECLARE new_fingerprint constant text :=
  'f73737f97effcee367f2d1e982e8f0d05be5e727ccd221532afd2003d4c17ea6';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0177_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
