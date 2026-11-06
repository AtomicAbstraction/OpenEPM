-- Project durable Python schedule occurrences into the universal task log.
-- Native occurrence rows, schedule policy and child build/workflow records
-- remain authoritative.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=181) THEN
    RAISE EXCEPTION 'MIGRATION_0182_PREDECESSOR_0181_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','f:','i:','p:','s:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence')),
  ADD COLUMN source_python_schedule_occurrence_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='PythonScheduleOccurrence' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_python_schedule_occurrence_fkey FOREIGN KEY
    (workspace_id,application_id,source_python_schedule_occurrence_id)
    REFERENCES epm.python_program_occurrence
      (workspace_id,application_id,occurrence_id) ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_python_schedule_occurrence_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'building' THEN 'Running'
  WHEN 'running_program' THEN 'Running'
  WHEN 'published' THEN 'Succeeded'
  WHEN 'failed' THEN 'Failed'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'needs_inspection' THEN 'NeedsInspection'
END;

CREATE FUNCTION epm.project_python_schedule_occurrence_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE authority record;
DECLARE projected_task_id text := 's:'||NEW.occurrence_id;
BEGIN
  normalized := epm.normalized_python_schedule_occurrence_task_status(NEW.status);
  IF normalized IS NULL THEN
    RAISE EXCEPTION 'UNKNOWN_PYTHON_SCHEDULE_OCCURRENCE_TASK_STATUS';
  END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN
    SELECT execution_issuer,execution_subject INTO STRICT authority
      FROM epm.python_program_schedule_version
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND schedule_id=NEW.schedule_id AND version=NEW.schedule_version;
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
      'BusinessExecution','PythonScheduleOccurrence',NEW.occurrence_id,
      authority.execution_issuer,authority.execution_subject,
      'python.schedule.run','long',normalized,NEW.status,
      NEW.status IN ('ready','running','building','running_program',
                     'cancel_requested'),false,NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('ready','running','building','running_program','cancel_requested'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id
      AND source_family='PythonScheduleOccurrence'
      AND source_id=NEW.occurrence_id;
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
REVOKE ALL ON FUNCTION epm.normalized_python_schedule_occurrence_task_status(text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_python_schedule_occurrence_task() FROM PUBLIC;

WITH numbered AS (
  SELECT o.*,v.execution_issuer,v.execution_subject,
    COALESCE(c.last_sequence,0)+row_number() OVER(
      PARTITION BY o.workspace_id,o.application_id
      ORDER BY o.created_at,o.occurrence_id) AS task_sequence
  FROM epm.python_program_occurrence o
  JOIN epm.python_program_schedule_version v
    ON (v.workspace_id,v.application_id,v.schedule_id,v.version)=
       (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
  LEFT JOIN epm.task_cursor c ON c.workspace_id=o.workspace_id
    AND c.application_id=o.application_id
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'s:'||occurrence_id,task_sequence,
  'BusinessExecution','PythonScheduleOccurrence',occurrence_id,
  execution_issuer,execution_subject,'python.schedule.run','long',
  epm.normalized_python_schedule_occurrence_task_status(status),status,
  status IN ('ready','running','building','running_program','cancel_requested'),
  false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'s:'||occurrence_id,1,
  epm.normalized_python_schedule_occurrence_task_status(status),status,
  claim_generation,NULL,error_code,updated_at FROM epm.python_program_occurrence;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_python_schedule_occurrence_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.python_program_occurrence
FOR EACH ROW EXECUTE FUNCTION epm.project_python_schedule_occurrence_task();

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'a4e4f22168ff3aa521c25d486a530b37f5fb189739ff588e11db811d043d1bb3';
DECLARE new_fingerprint constant text :=
  '8d33b8f39a6cb9165b44f87dae51b5bd3f0c45a0907d6b428070cddc1a337590';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0182_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
